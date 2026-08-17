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
        direct_ballots::{
            PAIR_CHARACTER_AUXILIARY_COUNT, PAIR_CHARACTER_CIPHERTEXT_COUNT,
            PAIR_CHARACTER_LANE_COUNT, PAIR_CHARACTER_LANE_DEGREE, PairCharacterEncoderProfileTerm,
            pair_character_encoder_profile_terms, pair_character_plaintexts,
        },
        evaluator::engine::{negacyclic_mul, signed_residue},
        modular_arithmetic::add_mod,
        setup::{VerifiedAcceptedSetupAuthorityHandle, with_verified_accepted_setup_authority},
    },
    encoding::{CanonicalError, CanonicalErrorCode},
    foundation::{
        ActionPrivateRandomness, AuthenticatedCheckpointContinuationSource, CanonicalItem,
        CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter, CanonicalTuple,
        DistributionPurpose, FOUNDATION_PROFILE, FoundationSchemaError, Hash512,
        OrdinaryProofCoinInput, PrivateRandomCursor, PrivateRandomnessAttemptIdentifier,
        PrivateRandomnessDomain, ProofApplicationSlot, RefusalReason, SelectedSuiteCapability,
        StreamDescriptor, VerificationResult, hash_foundation_tuple_512,
        resolve_prepared_ordinary_proof_attempt_source,
    },
    hashing::hash_framed_parts_512,
};

use super::*;
#[cfg(test)]
use crate::bgv::proof_suite::selected_ballot_validity_relation_compilation;
use crate::bgv::proof_suite::{
    CommonProofGenerationAuthorization, CommonProofGenerationPreparationError,
    CommonProofGenerationSources, CommonProofPrivateCoinCoordinateCapacity, CommonProofProverError,
    CommonProofRelationPlanCapability, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialReplayIdentity,
    CommonProofSourcePolynomialRequest, CommonProofSourceProviderMemoryAccounting,
    CommonProofVerifierError, PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    PreparedCommonProofGeneration, PrivateRandomnessCommonProofCoinError,
    PrivateRandomnessCommonProofCoinSource, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofEvaluationDomain, ProofFieldError, ProofLeafVisibility, ProofPolynomialError,
    ProofTreeRole, ProvidedCommonProofSourcePolynomial, RelationProofTreeInput,
    SelectedApplicationStatementContext, VerifiedRelationColumnEvaluator,
    VerifiedRelationColumnEvaluatorMemoryAccounting, canonical_selected_ballot_validity_statement,
    decode_selected_ballot_validity_statement, verified_application_statement_hash,
};

const OPTION_COUNT: usize = FOUNDATION_PROFILE.option_count as usize;
const MINIMUM_SCORE: u64 = FOUNDATION_PROFILE.minimum_score as u64;
const MAXIMUM_SCORE: u64 = FOUNDATION_PROFILE.maximum_score as u64;
const BGV_CIPHERTEXT_COMPONENT_COUNT: usize = 2;
const PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT: usize =
    match PAIR_CHARACTER_CIPHERTEXT_COUNT.checked_mul(BGV_CIPHERTEXT_COMPONENT_COUNT) {
        Some(polynomial_count) => polynomial_count,
        None => panic!("pair-character ciphertext polynomial count overflow"),
    };
const NEGACYCLIC_CONVOLUTION_RING_DEGREE_FACTOR: usize = 2;
const PRIVATE_NEGACYCLIC_PRODUCT_OPERAND_COUNT: usize = 2;
const BALLOT_WITNESS_COEFFICIENT_VECTOR_COUNT_PER_CIPHERTEXT: usize =
    match PAIR_CHARACTER_AUXILIARY_COUNT.checked_add(BGV_CIPHERTEXT_COMPONENT_COUNT) {
        Some(component_and_auxiliary_count) => match component_and_auxiliary_count.checked_add(1) {
            Some(vector_count) => vector_count,
            None => panic!("ballot witness coefficient vector count overflow"),
        },
        None => panic!("ballot witness coefficient vector count overflow"),
    };
const BALLOT_WITNESS_COEFFICIENT_VECTOR_COUNT: usize = match PAIR_CHARACTER_CIPHERTEXT_COUNT
    .checked_mul(BALLOT_WITNESS_COEFFICIENT_VECTOR_COUNT_PER_CIPHERTEXT)
{
    Some(vector_count) => vector_count,
    None => panic!("ballot witness coefficient catalog count overflow"),
};
const RANDOMIZER_CONVOLUTION_RING_COEFFICIENT_FACTOR: usize =
    match PAIR_CHARACTER_CIPHERTEXT_COUNT.checked_mul(NEGACYCLIC_CONVOLUTION_RING_DEGREE_FACTOR) {
        Some(coefficient_factor) => coefficient_factor,
        None => panic!("randomizer convolution coefficient count overflow"),
    };
const PRIVATE_NEGACYCLIC_PRODUCT_SCRATCH_RING_COEFFICIENT_FACTOR: usize =
    match PRIVATE_NEGACYCLIC_PRODUCT_OPERAND_COUNT
        .checked_mul(NEGACYCLIC_CONVOLUTION_RING_DEGREE_FACTOR)
    {
        Some(coefficient_factor) => coefficient_factor,
        None => panic!("private negacyclic scratch coefficient count overflow"),
    };
const PAIR_CHARACTER_PROFILE_LAGRANGE_WEIGHT_COUNT: usize = PAIR_CHARACTER_LANE_COUNT;
const RADIX: i128 = 3;
const VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL: u64 = 7;
const BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL: u64 = 8;
const BALLOT_SOURCE_RESTART_BINDING_DOMAIN: &str =
    "sealed-lattice/proof/ballot-source-restart-binding/v1";
const BALLOT_SOURCE_POLYNOMIAL_REPLAY_DOMAIN: &str =
    "sealed-lattice/proof/ballot-source-polynomial-replay/v1";
const BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x1303;
const BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_VERSION: u16 = 2;
const BALLOT_ENCRYPTION_COIN_CONTEXT_HASH_DOMAIN: &str =
    "sealed-lattice/ballot/encryption-coin-context/v2";
const BALLOT_ENCRYPTION_DISTRIBUTION_PURPOSES: [DistributionPurpose; 3] = [
    DistributionPurpose::BallotEncryptionEphemeralSecret,
    DistributionPurpose::BallotEncryptionErrorZero,
    DistributionPurpose::BallotEncryptionErrorOne,
];

type BallotResiduePolynomialRecord = (u16, u16, u64, Arc<[u64]>);
pub(crate) type BallotCiphertextPolynomialCatalogEntry = (u16, u16, u16, u64, Arc<[u64]>);

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
    #[cfg(test)]
    pub(crate) const fn canonical_ciphertext_byte_length(self) -> u64 {
        self.canonical_ciphertext_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn canonical_ciphertext_chunk_count(self) -> u32 {
        self.canonical_ciphertext_chunk_count
    }

    #[cfg(test)]
    pub(crate) const fn canonical_ciphertext_descriptor_encoded_byte_length(self) -> u64 {
        self.canonical_ciphertext_descriptor_encoded_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn canonical_ciphertext_descriptor_digest_catalog_byte_length(self) -> u64 {
        self.canonical_ciphertext_descriptor_digest_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn ciphertext_readback_polynomial_catalog_byte_length(self) -> u64 {
        self.ciphertext_readback_polynomial_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn decoded_ciphertext_residue_byte_length(self) -> u64 {
        self.decoded_ciphertext_residue_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn provider_bound_public_residue_byte_length(self) -> u64 {
        self.provider_bound_public_residue_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn provider_witness_coefficient_byte_length(self) -> u64 {
        self.provider_witness_coefficient_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn provider_precomputed_transform_byte_length(self) -> u64 {
        self.provider_precomputed_transform_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn provider_value_cache_byte_length(self) -> u64 {
        self.provider_value_cache_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn provider_transient_scratch_byte_length(self) -> u64 {
        self.provider_transient_scratch_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn provider_buffer_live_set_peak_byte_length(self) -> u64 {
        self.provider_buffer_live_set_peak_byte_length
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

    #[cfg(test)]
    pub(crate) const fn maximum_boundary_copied_buffer_byte_length(self) -> u64 {
        self.maximum_boundary_copied_buffer_byte_length
    }
}

#[cfg(test)]
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
    let ciphertext_polynomial_count = u64::try_from(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT)
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let public_key_polynomial_count = u64::try_from(BGV_CIPHERTEXT_COMPONENT_COUNT)
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let public_material_polynomial_count_per_limb = public_key_polynomial_count
        .checked_add(ciphertext_polynomial_count)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let canonical_ciphertext_byte_length = ring_degree
        .checked_mul(ciphertext_polynomial_count)
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
        .checked_mul(ciphertext_polynomial_count)
        .and_then(|count| {
            u64::try_from(size_of::<(u16, u16, u64, Arc<[u64]>)>())
                .ok()
                .and_then(|entry_byte_length| count.checked_mul(entry_byte_length))
        })
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let decoded_ciphertext_residue_byte_length = ring_degree
        .checked_mul(ciphertext_polynomial_count)
        .and_then(|count| count.checked_mul(limb_count))
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_bound_public_residue_byte_length = ring_degree
        .checked_mul(public_material_polynomial_count_per_limb)
        .and_then(|count| count.checked_mul(limb_count))
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_witness_coefficient_byte_length = ring_degree
        .checked_mul(
            u64::try_from(BALLOT_WITNESS_COEFFICIENT_VECTOR_COUNT)
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
        )
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_precomputed_transform_byte_length = ring_degree
        .checked_mul(
            u64::try_from(RANDOMIZER_CONVOLUTION_RING_COEFFICIENT_FACTOR)
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
        )
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_value_cache_byte_length = ring_degree
        .checked_mul(16)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_transient_scratch_byte_length = ring_degree
        .checked_mul(
            u64::try_from(PRIVATE_NEGACYCLIC_PRODUCT_SCRATCH_RING_COEFFICIENT_FACTOR)
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
        )
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
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
        .checked_mul(public_material_polynomial_count_per_limb)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let public_material_catalog_and_arc_header_byte_length = checked_slice_byte_length::<
        [BoundResiduePolynomial; BGV_CIPHERTEXT_COMPONENT_COUNT],
    >(source_plan.data_moduli().len())?
    .checked_add(checked_slice_byte_length::<
        [BoundResiduePolynomial; PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT],
    >(source_plan.data_moduli().len())?)
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
    // Exact same-secret row-code openings replay source polynomials after the
    // initial pass. Retain the authenticated witness and its precomputed
    // transforms until `finish_source_replay`; the phase-local value cache is
    // still released at each boundary.
    let provider_post_source_finish_persistent_resident_byte_length =
        provider_loading_persistent_resident_byte_length;
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

fn canonical_ballot_encryption_coin_context(
    application_slot: ProofApplicationSlot,
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    ciphertext_ordinal: usize,
) -> Result<CanonicalTuple, BallotValidityAdapterError> {
    if ciphertext_ordinal >= PAIR_CHARACTER_CIPHERTEXT_COUNT {
        return Err(BallotValidityAdapterError::InvalidStatementBinding);
    }
    let ciphertext_ordinal = u16::try_from(ciphertext_ordinal)
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    Ok(CanonicalTuple::new(
        BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_IDENTIFIER,
        BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_VERSION,
        vec![
            CanonicalItem::nested_tuple(&application_slot.canonical_tuple()?)
                .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?,
            CanonicalItem::hash512(verified_setup_source_hash),
            CanonicalItem::unsigned16(ciphertext_ordinal),
        ],
    ))
}

fn ballot_encryption_coin_context_hash(
    application_slot: ProofApplicationSlot,
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    ciphertext_ordinal: usize,
) -> Result<Hash512, BallotValidityAdapterError> {
    let canonical_coin_context_bytes = canonical_ballot_encryption_coin_context(
        application_slot,
        verified_setup_source_hash,
        ciphertext_ordinal,
    )?
    .encode()
    .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?;
    hash_foundation_tuple_512(
        BALLOT_ENCRYPTION_COIN_CONTEXT_HASH_DOMAIN,
        &[CanonicalItem::variable_bytes(canonical_coin_context_bytes)
            .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?],
    )
    .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)
}

/// The common witness shared by every RNS limb of one ballot encryption.
///
/// Construction checks the score domain, exact selected batch encoding, and
/// the encryption-noise support. The nonzero attempt identifier is generated
/// by the ballot encryption operation and is retained across a resumed proof;
/// it prevents a restarted provider from being rebound to a different secret
/// witness that happens to have the same public ciphertext.
struct BallotValidityCiphertextEncryptionSecret {
    auxiliary_left_coefficients: Zeroizing<Vec<u64>>,
    auxiliary_right_coefficients: Zeroizing<Vec<u64>>,
    message_coefficients: Zeroizing<Vec<u64>>,
    randomizer_coefficients: Zeroizing<Vec<i64>>,
    error_zero_coefficients: Zeroizing<Vec<i64>>,
    error_one_coefficients: Zeroizing<Vec<i64>>,
}

struct BallotValidityEncryptionAttemptSecret {
    scores: Zeroizing<[u64; OPTION_COUNT]>,
    ciphertexts: [BallotValidityCiphertextEncryptionSecret; PAIR_CHARACTER_CIPHERTEXT_COUNT],
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
    ) -> Result<(Self, [PrivateRandomCursor; 6]), BallotValidityAdapterError> {
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
        let attempt_identifier = action_private_randomness
            .ballot_encryption_attempt_identifier(injected_encryption_attempt_identifier);
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let maximum_candidate_draws =
            selected_suite.maximum_private_sampler_candidate_draws_per_output();
        let scores: Zeroizing<[u64; OPTION_COUNT]> = Zeroizing::new(
            <[u64; OPTION_COUNT]>::try_from(scores)
                .map_err(|_| BallotValidityAdapterError::InvalidWitness)?,
        );
        let pair_character_plaintexts =
            pair_character_plaintexts(&scores[..], source_plan.plaintext_modulus(), ring_degree)?;
        let mut ciphertext_secrets = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        let mut cursors = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT * 3);
        for (ciphertext_ordinal, plaintext) in pair_character_plaintexts.iter().enumerate() {
            let coin_context_hash = ballot_encryption_coin_context_hash(
                application_slot,
                verified_setup_source_hash,
                ciphertext_ordinal,
            )?;
            let mut randomizer_stream = action_private_randomness.begin_stream(
                PrivateRandomnessDomain::ballot_encryption_distribution(
                    BALLOT_ENCRYPTION_DISTRIBUTION_PURPOSES[0].canonical_code(),
                )?,
                coin_context_hash,
                attempt_identifier,
            )?;
            let mut error_zero_stream = action_private_randomness.begin_stream(
                PrivateRandomnessDomain::ballot_encryption_distribution(
                    BALLOT_ENCRYPTION_DISTRIBUTION_PURPOSES[1].canonical_code(),
                )?,
                coin_context_hash,
                attempt_identifier,
            )?;
            let mut error_one_stream = action_private_randomness.begin_stream(
                PrivateRandomnessDomain::ballot_encryption_distribution(
                    BALLOT_ENCRYPTION_DISTRIBUTION_PURPOSES[2].canonical_code(),
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
                error_zero_coefficients
                    .push(i64::from(error_zero_stream.sample_centered_binomial(2)?));
                error_one_coefficients
                    .push(i64::from(error_one_stream.sample_centered_binomial(2)?));
            }
            cursors.extend([
                randomizer_stream.cursor(),
                error_zero_stream.cursor(),
                error_one_stream.cursor(),
            ]);
            ciphertext_secrets.push(BallotValidityCiphertextEncryptionSecret {
                auxiliary_left_coefficients: Zeroizing::new(
                    plaintext.auxiliary_left_coefficients().to_vec(),
                ),
                auxiliary_right_coefficients: Zeroizing::new(
                    plaintext.auxiliary_right_coefficients().to_vec(),
                ),
                message_coefficients: Zeroizing::new(plaintext.message_coefficients().to_vec()),
                randomizer_coefficients,
                error_zero_coefficients,
                error_one_coefficients,
            });
        }
        let ciphertexts = ciphertext_secrets
            .try_into()
            .map_err(|_| BallotValidityAdapterError::InvalidWitness)?;
        let cursors = cursors
            .try_into()
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        Ok((
            Self::from_zeroizing_encryption_attempt(
                source_plan,
                scores,
                ciphertexts,
                Zeroizing::new(*attempt_identifier.as_bytes()),
            )?,
            cursors,
        ))
    }

    #[cfg(test)]
    fn from_encryption_attempt(
        source_plan: &BallotValiditySourcePlan,
        scores: &[u64],
        randomizer_coefficients: [Vec<i64>; PAIR_CHARACTER_CIPHERTEXT_COUNT],
        error_zero_coefficients: [Vec<i64>; PAIR_CHARACTER_CIPHERTEXT_COUNT],
        error_one_coefficients: [Vec<i64>; PAIR_CHARACTER_CIPHERTEXT_COUNT],
        encryption_attempt_identifier: [u8; 32],
    ) -> Result<Self, BallotValidityAdapterError> {
        let encryption_attempt_identifier = Zeroizing::new(encryption_attempt_identifier);
        let scores: Zeroizing<[u64; OPTION_COUNT]> = Zeroizing::new(
            <[u64; OPTION_COUNT]>::try_from(scores)
                .map_err(|_| BallotValidityAdapterError::InvalidWitness)?,
        );
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let plaintexts =
            pair_character_plaintexts(&scores[..], source_plan.plaintext_modulus(), ring_degree)?;
        let mut randomizers = randomizer_coefficients.into_iter();
        let mut errors_zero = error_zero_coefficients.into_iter();
        let mut errors_one = error_one_coefficients.into_iter();
        let ciphertexts = plaintexts
            .iter()
            .map(|plaintext| {
                Ok(BallotValidityCiphertextEncryptionSecret {
                    auxiliary_left_coefficients: Zeroizing::new(
                        plaintext.auxiliary_left_coefficients().to_vec(),
                    ),
                    auxiliary_right_coefficients: Zeroizing::new(
                        plaintext.auxiliary_right_coefficients().to_vec(),
                    ),
                    message_coefficients: Zeroizing::new(plaintext.message_coefficients().to_vec()),
                    randomizer_coefficients: Zeroizing::new(
                        randomizers
                            .next()
                            .ok_or(BallotValidityAdapterError::InvalidWitness)?,
                    ),
                    error_zero_coefficients: Zeroizing::new(
                        errors_zero
                            .next()
                            .ok_or(BallotValidityAdapterError::InvalidWitness)?,
                    ),
                    error_one_coefficients: Zeroizing::new(
                        errors_one
                            .next()
                            .ok_or(BallotValidityAdapterError::InvalidWitness)?,
                    ),
                })
            })
            .collect::<Result<Vec<_>, BallotValidityAdapterError>>()?
            .try_into()
            .map_err(|_| BallotValidityAdapterError::InvalidWitness)?;
        Self::from_zeroizing_encryption_attempt(
            source_plan,
            scores,
            ciphertexts,
            encryption_attempt_identifier,
        )
    }

    fn from_zeroizing_encryption_attempt(
        source_plan: &BallotValiditySourcePlan,
        scores: Zeroizing<[u64; OPTION_COUNT]>,
        ciphertexts: [BallotValidityCiphertextEncryptionSecret; PAIR_CHARACTER_CIPHERTEXT_COUNT],
        encryption_attempt_identifier: Zeroizing<[u8; 32]>,
    ) -> Result<Self, BallotValidityAdapterError> {
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        if scores
            .iter()
            .any(|score| !(MINIMUM_SCORE..=MAXIMUM_SCORE).contains(score))
            || ciphertexts.iter().any(|ciphertext| {
                ciphertext.auxiliary_left_coefficients.len() != ring_degree
                    || ciphertext.auxiliary_right_coefficients.len() != ring_degree
                    || ciphertext.message_coefficients.len() != ring_degree
                    || ciphertext.randomizer_coefficients.len() != ring_degree
                    || ciphertext.error_zero_coefficients.len() != ring_degree
                    || ciphertext.error_one_coefficients.len() != ring_degree
                    || ciphertext
                        .randomizer_coefficients
                        .iter()
                        .any(|coefficient| !(-1..=1).contains(coefficient))
                    || ciphertext
                        .error_zero_coefficients
                        .iter()
                        .chain(ciphertext.error_one_coefficients.iter())
                        .any(|coefficient| !(-2..=2).contains(coefficient))
            })
        {
            return Err(BallotValidityAdapterError::InvalidWitness);
        }

        let expected_plaintexts =
            pair_character_plaintexts(&scores[..], source_plan.plaintext_modulus(), ring_degree)?;
        if ciphertexts
            .iter()
            .zip(expected_plaintexts.iter())
            .any(|(ciphertext, expected)| {
                ciphertext.auxiliary_left_coefficients.as_slice()
                    != expected.auxiliary_left_coefficients()
                    || ciphertext.auxiliary_right_coefficients.as_slice()
                        != expected.auxiliary_right_coefficients()
                    || ciphertext.message_coefficients.as_slice() != expected.message_coefficients()
            })
        {
            return Err(BallotValidityAdapterError::InvalidWitness);
        }

        Ok(Self {
            secret: Arc::new(BallotValidityEncryptionAttemptSecret {
                scores,
                ciphertexts,
                encryption_attempt_identifier,
            }),
        })
    }

    fn scores(&self) -> &[u64; OPTION_COUNT] {
        &self.secret.scores
    }

    fn auxiliary_coefficients(
        &self,
        ciphertext_ordinal: usize,
        auxiliary_ordinal: usize,
    ) -> Option<&[u64]> {
        let ciphertext = self.secret.ciphertexts.get(ciphertext_ordinal)?;
        match auxiliary_ordinal {
            0 => Some(&ciphertext.auxiliary_left_coefficients),
            1 => Some(&ciphertext.auxiliary_right_coefficients),
            2 => Some(&ciphertext.message_coefficients),
            _ => None,
        }
    }

    fn randomizer_coefficients(&self, ciphertext_ordinal: usize) -> Option<&[i64]> {
        Some(
            &self
                .secret
                .ciphertexts
                .get(ciphertext_ordinal)?
                .randomizer_coefficients,
        )
    }

    fn error_coefficients(
        &self,
        ciphertext_ordinal: usize,
        component_ordinal: usize,
    ) -> Option<&[i64]> {
        let ciphertext = self.secret.ciphertexts.get(ciphertext_ordinal)?;
        match component_ordinal {
            0 => Some(&ciphertext.error_zero_coefficients),
            1 => Some(&ciphertext.error_one_coefficients),
            _ => None,
        }
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
    public_key_by_limb: Box<[[BoundResiduePolynomial; BGV_CIPHERTEXT_COMPONENT_COUNT]]>,
    ciphertext_by_limb: Box<[[BoundResiduePolynomial; PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT]]>,
}

impl BallotValidityBoundPublicMaterial {
    fn resident_owned_payload_byte_length(&self) -> Option<u64> {
        let public_key_array_payload = self.public_key_by_limb.len().checked_mul(size_of::<
            [BoundResiduePolynomial; BGV_CIPHERTEXT_COMPONENT_COUNT],
        >())?;
        let ciphertext_array_payload = self.ciphertext_by_limb.len().checked_mul(size_of::<
            [BoundResiduePolynomial; PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT],
        >())?;
        let outer_payload =
            u64::try_from(public_key_array_payload.checked_add(ciphertext_array_payload)?).ok()?;
        self.public_key_by_limb
            .iter()
            .flat_map(|components| components.iter())
            .chain(
                self.ciphertext_by_limb
                    .iter()
                    .flat_map(|components| components.iter()),
            )
            .try_fold(outer_payload, |total, polynomial| {
                u64::try_from(polynomial.coefficients.len())
                    .ok()?
                    .checked_mul(u64::try_from(size_of::<u64>()).ok()?)
                    .and_then(|payload| total.checked_add(payload))
            })
    }
}

/// Ciphertext polynomials retained only after a complete ballot-ciphertext
/// stream has matched its canonical descriptor and full-object digest.
#[derive(Clone)]
pub(crate) struct BallotValidityAuthenticatedCiphertext {
    full_object_digest: [u8; 64],
    polynomials: Vec<BallotResiduePolynomialRecord>,
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
    proof_coin_input: OrdinaryProofCoinInput,
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

        let (witness, _) = BallotValidityEncryptionAttemptWitness::sample_from_action_randomness(
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
            proof_coin_input,
            witness,
            public_material,
            generated_ciphertext,
        })
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) fn proof_attempt_identifier(
        &self,
    ) -> Result<PrivateRandomnessAttemptIdentifier, BallotValidityAdapterError> {
        self.action_private_randomness
            .ordinary_proof_attempt_identifier(&self.proof_coin_input)
            .map_err(BallotValidityAdapterError::from)
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
        let checkpoint_schedule_digest = relation_plan.checkpoint_schedule_digest()?;
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
        if checkpoint_continuation.checkpoint_schedule_digest()
            != relation_plan.checkpoint_schedule_digest()?
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        let attempt_source = resolve_prepared_ordinary_proof_attempt_source(
            &self.action_private_randomness,
            self.proof_coin_input,
            checkpoint_continuation,
        )
        .map_err(BallotValidityAdapterError::from)?;
        let authorization =
            CommonProofGenerationAuthorization::from_ordinary_authenticated_attempt(
                attempt_source,
                &relation_plan,
                self.public_material.protocol_version,
                &self.canonical_application_statement_bytes,
            )?;
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .map_err(BallotValidityAdapterError::from)?;
        let relation_trees = proof_created_relation_tree_inputs_from_checked_variant(variant)?;
        let private_coins = self.private_coin_source(compilation, authorization.binding_hash())?;
        let source_polynomials = self.source_polynomial_provider(compilation)?;
        PreparedCommonProofGeneration::from_row_code_whir_sources(
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
    fn encrypt_with_public_key_polynomials(
        source_plan: &BallotValiditySourcePlan,
        public_key_polynomials: Vec<BallotResiduePolynomialRecord>,
        witness: &BallotValidityEncryptionAttemptWitness,
    ) -> Result<Self, BallotValidityAdapterError> {
        let public_key_by_limb = checked_polynomial_sequence::<BGV_CIPHERTEXT_COMPONENT_COUNT>(
            source_plan,
            public_key_polynomials,
        )?;
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let plaintext_modulus = i64::try_from(source_plan.plaintext_modulus())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let mut ciphertext_by_limb: Vec<[Arc<[u64]>; PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT]> =
            Vec::with_capacity(source_plan.data_moduli().len());
        for (data_modulus_ordinal, modulus) in source_plan.data_moduli().iter().copied().enumerate()
        {
            let public_key_limb = public_key_by_limb
                .get(data_modulus_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
            let mut flattened_components =
                Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT);
            for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
                let randomizer_coefficients = witness
                    .randomizer_coefficients(ciphertext_ordinal)
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                let randomizer_residues = Zeroizing::new(
                    randomizer_coefficients
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
                let message_coefficients = witness
                    .auxiliary_coefficients(ciphertext_ordinal, 2)
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                let error_zero_coefficients = witness
                    .error_coefficients(ciphertext_ordinal, 0)
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                let error_one_coefficients = witness
                    .error_coefficients(ciphertext_ordinal, 1)
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                let complete_ciphertext_components = (|| {
                    for coefficient_ordinal in 0..ring_degree {
                        let scaled_error_zero = error_zero_coefficients[coefficient_ordinal]
                            .checked_mul(plaintext_modulus)
                            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
                        let scaled_error_one = error_one_coefficients[coefficient_ordinal]
                            .checked_mul(plaintext_modulus)
                            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
                        component_zero[coefficient_ordinal] = add_mod(
                            add_mod(
                                component_zero[coefficient_ordinal],
                                signed_residue(scaled_error_zero, modulus),
                                modulus,
                            )?,
                            message_coefficients[coefficient_ordinal],
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
                flattened_components.push(Arc::<[u64]>::from(component_zero));
                flattened_components.push(Arc::<[u64]>::from(component_one));
            }
            ciphertext_by_limb.push(
                flattened_components
                    .try_into()
                    .map_err(|_| BallotValidityAdapterError::InvalidPublicMaterial)?,
            );
        }

        let mut polynomials = Vec::with_capacity(
            ciphertext_by_limb.len() * PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT,
        );
        for flattened_component_ordinal in
            0..u16::try_from(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT)
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?
        {
            for (data_modulus_ordinal, (modulus, components)) in source_plan
                .data_moduli()
                .iter()
                .copied()
                .zip(&ciphertext_by_limb)
                .enumerate()
            {
                polynomials.push((
                    flattened_component_ordinal,
                    u16::try_from(data_modulus_ordinal)
                        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                    modulus,
                    Arc::clone(&components[usize::from(flattened_component_ordinal)]),
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
    polynomials: Box<[BallotResiduePolynomialRecord]>,
    polynomial_ordinal: usize,
    coefficient_ordinal: usize,
    coefficient_byte_offset: usize,
}

impl BallotValidityCiphertextReadback {
    fn new(
        source_plan: &BallotValiditySourcePlan,
        ciphertext: BallotValidityAuthenticatedCiphertext,
    ) -> Result<Self, BallotValidityAdapterError> {
        require_checked_polynomial_sequence::<PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT>(
            source_plan,
            &ciphertext.polynomials,
        )?;
        let level = source_plan
            .active_data_modulus_indices()
            .len()
            .checked_sub(1)
            .and_then(|level| u16::try_from(level).ok())
            .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
        let mut header = [0_u8; 4];
        header[..2].copy_from_slice(&level.to_le_bytes());
        header[2..].copy_from_slice(
            &u16::try_from(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT)
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?
                .to_le_bytes(),
        );
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
    polynomials: Vec<BallotResiduePolynomialRecord>,
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
                                .checked_mul(
                                    u64::try_from(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT)
                                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                                )
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
            polynomials: Vec::with_capacity(
                source_plan.data_moduli().len() * PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT,
            ),
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
            || usize::from(self.component_ordinal) != PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT
            || self.data_modulus_ordinal != 0
            || self.coefficient_ordinal != 0
            || self.partial_coefficient_byte_length != 0
            || !self.current_polynomial.is_empty()
            || self.polynomials.len()
                != self.data_moduli.len() * PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT
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
                if level != self.expected_level
                    || usize::from(component_count) != PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT
                {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
        }

        while byte_offset < bytes.len() {
            if usize::from(self.component_ordinal) >= PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT {
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
    polynomials: &[BallotResiduePolynomialRecord],
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
        .checked_mul(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT)
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
) -> Result<Vec<BallotResiduePolynomialRecord>, BallotValidityAdapterError> {
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
            .checked_mul(BGV_CIPHERTEXT_COMPONENT_COUNT)
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
        public_key_polynomials: Vec<BallotResiduePolynomialRecord>,
        ciphertext_polynomials: Vec<BallotResiduePolynomialRecord>,
    ) -> Result<Self, BallotValidityAdapterError> {
        if protocol_version == 0
            || suite_identifier == [0_u8; 64]
            || verified_setup_source_hash == [0_u8; 64]
            || ballot_ciphertext_digest == [0_u8; 64]
        {
            return Err(BallotValidityAdapterError::InvalidPublicMaterial);
        }
        let public_key_by_limb = checked_polynomial_sequence::<BGV_CIPHERTEXT_COMPONENT_COUNT>(
            source_plan,
            public_key_polynomials,
        )?
        .into_boxed_slice();
        let ciphertext_by_limb = checked_polynomial_sequence::<
            PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT,
        >(source_plan, ciphertext_polynomials)?
        .into_boxed_slice();
        Ok(Self {
            protocol_version,
            suite_identifier,
            verified_setup_source_hash,
            ballot_ciphertext_digest,
            public_key_by_limb,
            ciphertext_by_limb,
        })
    }

    #[cfg(test)]
    pub(crate) const fn verified_setup_source_hash(&self) -> [u8; 64] {
        self.verified_setup_source_hash
    }

    pub(crate) const fn ballot_ciphertext_digest(&self) -> [u8; 64] {
        self.ballot_ciphertext_digest
    }

    pub(crate) fn authenticated_ciphertext_catalog(
        &self,
    ) -> Result<Vec<BallotCiphertextPolynomialCatalogEntry>, BallotValidityAdapterError> {
        let mut catalog = Vec::with_capacity(
            self.ciphertext_by_limb.len() * PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT,
        );
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            for component_ordinal in 0..BGV_CIPHERTEXT_COMPONENT_COUNT {
                let flattened_component_ordinal = ciphertext_ordinal
                    .checked_mul(BGV_CIPHERTEXT_COMPONENT_COUNT)
                    .and_then(|ordinal| ordinal.checked_add(component_ordinal))
                    .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
                for (data_modulus_index, limb) in self.ciphertext_by_limb.iter().enumerate() {
                    let polynomial = &limb[flattened_component_ordinal];
                    catalog.push((
                        u16::try_from(ciphertext_ordinal)
                            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                        u16::try_from(component_ordinal)
                            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                        u16::try_from(data_modulus_index)
                            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                        polynomial.modulus,
                        Arc::clone(&polynomial.coefficients),
                    ));
                }
            }
        }
        Ok(catalog)
    }

    fn polynomial(
        &self,
        source_kind: u16,
        ciphertext_ordinal: u16,
        component_ordinal: u16,
        data_modulus_index: u16,
    ) -> Option<&BoundResiduePolynomial> {
        match source_kind {
            1 if ciphertext_ordinal == 0 => self
                .public_key_by_limb
                .get(usize::from(data_modulus_index))?
                .get(usize::from(component_ordinal)),
            2 => {
                let flattened_component_ordinal = usize::from(ciphertext_ordinal)
                    .checked_mul(BGV_CIPHERTEXT_COMPONENT_COUNT)?
                    .checked_add(usize::from(component_ordinal))?;
                self.ciphertext_by_limb
                    .get(usize::from(data_modulus_index))?
                    .get(flattened_component_ordinal)
            }
            _ => None,
        }
    }
}

fn checked_polynomial_sequence<const COMPONENT_COUNT: usize>(
    source_plan: &BallotValiditySourcePlan,
    polynomials: Vec<BallotResiduePolynomialRecord>,
) -> Result<Vec<[BoundResiduePolynomial; COMPONENT_COUNT]>, BallotValidityAdapterError> {
    require_checked_polynomial_sequence::<COMPONENT_COUNT>(source_plan, &polynomials)?;
    let mut ordered_polynomials = polynomials.into_iter();
    let mut components_by_limb = (0..source_plan.data_moduli().len())
        .map(|_| core::array::from_fn(|_| None))
        .collect::<Vec<[Option<BoundResiduePolynomial>; COMPONENT_COUNT]>>();
    for component_ordinal in 0..COMPONENT_COUNT {
        for limb_components in &mut components_by_limb {
            let (_, _, modulus, coefficients) = ordered_polynomials
                .next()
                .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
            limb_components[component_ordinal] = Some(BoundResiduePolynomial {
                modulus,
                coefficients,
            });
        }
    }
    components_by_limb
        .into_iter()
        .map(|components| {
            components
                .into_iter()
                .map(|component| component.ok_or(BallotValidityAdapterError::InvalidPublicMaterial))
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| BallotValidityAdapterError::InvalidPublicMaterial)
        })
        .collect()
}

fn require_checked_polynomial_sequence<const COMPONENT_COUNT: usize>(
    source_plan: &BallotValiditySourcePlan,
    polynomials: &[BallotResiduePolynomialRecord],
) -> Result<(), BallotValidityAdapterError> {
    let ring_degree = usize::try_from(source_plan.ring_degree())
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let expected_count = source_plan
        .active_data_modulus_indices()
        .len()
        .checked_mul(COMPONENT_COUNT)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    if polynomials.len() != expected_count {
        return Err(BallotValidityAdapterError::InvalidPublicMaterial);
    }

    let mut ordered_polynomials = polynomials.iter();
    for component_ordinal in 0..COMPONENT_COUNT {
        let component_ordinal = u16::try_from(component_ordinal)
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
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
    randomizer_convolution_evaluations:
        Option<[Zeroizing<Vec<ProofBaseFieldElement>>; PAIR_CHARACTER_CIPHERTEXT_COUNT]>,
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
            .checked_mul(NEGACYCLIC_CONVOLUTION_RING_DEGREE_FACTOR)
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
        let trace_domain = ProofEvaluationDomain::new_subgroup(trace_size)?;
        let convolution_domain = ProofEvaluationDomain::new_subgroup(convolution_size)?;
        let mut randomizer_convolution_evaluations =
            Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_COUNT);
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            let mut evaluations = Zeroizing::new(Vec::with_capacity(trace_size));
            for coefficient in witness
                .randomizer_coefficients(ciphertext_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidWitness)?
                .iter()
                .copied()
            {
                evaluations.push(base_field_from_signed(i128::from(coefficient))?);
            }
            convolution_domain.evaluate_base_polynomial_in_place(&mut evaluations)?;
            randomizer_convolution_evaluations.push(evaluations);
        }
        let randomizer_convolution_evaluations = randomizer_convolution_evaluations
            .try_into()
            .map_err(|_| BallotValidityAdapterError::InvalidWitness)?;
        let relation_plan_variant_hash = variant.canonical_hash()?;
        let relation_plan_hash = compilation.relation_plan().canonical_hash()?;
        let ordered_source_columns = variant
            .ordered_columns()
            .iter()
            .enumerate()
            .map(|(column_index, descriptor)| {
                let column_ordinal = u32::try_from(column_index)
                    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
                let has_recipe = compilation.source_plan().recipe(column_ordinal).is_some();
                let has_verifier_source = compilation
                    .source_plan()
                    .verifier_source(column_ordinal)
                    .is_some();
                match (has_recipe, has_verifier_source) {
                    (true, false) | (false, true) => Ok(Some((column_ordinal, descriptor.clone()))),
                    (false, false) => Ok(None),
                    (true, true) => Err(BallotValidityAdapterError::InvalidColumn),
                }
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

    #[cfg(test)]
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
        let source_derivation_bytes = canonical_source_derivation_bytes(recipe, verifier_source)?;
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
            BallotValidityWitnessValueSource::ScoreIndicator {
                option_ordinal,
                score_bucket_ordinal,
            } => {
                let score = witness
                    .scores()
                    .get(usize::from(option_ordinal))
                    .copied()
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                Ok(Zeroizing::new(vec![
                    i128::from(
                        score == MINIMUM_SCORE + u64::from(score_bucket_ordinal),
                    );
                    ring_degree
                ]))
            }
            BallotValidityWitnessValueSource::PairCharacterAuxiliaryCoefficient {
                ciphertext_ordinal,
                auxiliary_ordinal,
            } => Ok(Zeroizing::new(
                witness
                    .auxiliary_coefficients(
                        usize::from(ciphertext_ordinal),
                        usize::from(auxiliary_ordinal),
                    )
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?
                    .iter()
                    .copied()
                    .map(i128::from)
                    .collect(),
            )),
            BallotValidityWitnessValueSource::ReversedRandomizerShifted { ciphertext_ordinal } => {
                Ok(Zeroizing::new(
                    witness
                        .randomizer_coefficients(usize::from(ciphertext_ordinal))
                        .ok_or(BallotValidityAdapterError::InvalidWitness)?
                        .iter()
                        .rev()
                        .map(|coefficient| i128::from(*coefficient) + 1)
                        .collect(),
                ))
            }
            BallotValidityWitnessValueSource::ErrorShifted {
                ciphertext_ordinal,
                component_ordinal,
            } => Ok(Zeroizing::new(
                witness
                    .error_coefficients(
                        usize::from(ciphertext_ordinal),
                        usize::from(component_ordinal),
                    )
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?
                    .iter()
                    .map(|coefficient| i128::from(*coefficient) + 2)
                    .collect(),
            )),
            BallotValidityWitnessValueSource::EncoderReduction {
                ciphertext_ordinal,
                auxiliary_ordinal,
            } => {
                let auxiliary_coefficients = witness
                    .auxiliary_coefficients(
                        usize::from(ciphertext_ordinal),
                        usize::from(auxiliary_ordinal),
                    )
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                let reductions = self
                    .source_plan
                    .encoder_reductions_for_scores(
                        witness.scores(),
                        ciphertext_ordinal,
                        auxiliary_ordinal,
                        auxiliary_coefficients,
                    )
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                Ok(Zeroizing::new(
                    reductions.into_iter().map(i128::from).collect(),
                ))
            }
            BallotValidityWitnessValueSource::PairCharacterProductQuotient {
                ciphertext_ordinal,
            } => self.pair_character_product_quotient(ciphertext_ordinal),
            BallotValidityWitnessValueSource::EncryptionQuotient {
                ciphertext_ordinal,
                data_modulus_index,
                component_ordinal,
            } => {
                self.encryption_quotient(ciphertext_ordinal, data_modulus_index, component_ordinal)
            }
        }
    }

    fn pair_character_product_quotient(
        &self,
        ciphertext_ordinal: u16,
    ) -> Result<Zeroizing<Vec<i128>>, BallotValidityAdapterError> {
        let witness = self.retained_witness()?;
        let ciphertext_ordinal_usize = usize::from(ciphertext_ordinal);
        let left = witness
            .auxiliary_coefficients(ciphertext_ordinal_usize, 0)
            .ok_or(BallotValidityAdapterError::InvalidWitness)?;
        let right = witness
            .auxiliary_coefficients(ciphertext_ordinal_usize, 1)
            .ok_or(BallotValidityAdapterError::InvalidWitness)?;
        let message = witness
            .auxiliary_coefficients(ciphertext_ordinal_usize, 2)
            .ok_or(BallotValidityAdapterError::InvalidWitness)?;
        let product = self.exact_private_negacyclic_product(left, right)?;
        let plaintext_modulus = i128::from(self.source_plan.plaintext_modulus());
        let mut quotient = Zeroizing::new(Vec::with_capacity(product.len()));
        for (message_coefficient, product_coefficient) in
            message.iter().copied().zip(product.iter().copied())
        {
            let numerator = i128::from(message_coefficient)
                .checked_sub(product_coefficient)
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
            if numerator % plaintext_modulus != 0 {
                return Err(BallotValidityAdapterError::InvalidWitness);
            }
            let coefficient = numerator / plaintext_modulus;
            if coefficient.unsigned_abs()
                > u128::from(
                    self.source_plan
                        .pair_character_product_quotient_absolute_bound(),
                )
            {
                return Err(BallotValidityAdapterError::NoWrapBoundViolated);
            }
            quotient.push(coefficient);
        }
        Ok(quotient)
    }

    fn encryption_quotient(
        &self,
        ciphertext_ordinal: u16,
        data_modulus_index: u16,
        component_ordinal: u16,
    ) -> Result<Zeroizing<Vec<i128>>, BallotValidityAdapterError> {
        let public_key = self
            .public_material
            .polynomial(1, 0, component_ordinal, data_modulus_index)
            .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
        let ciphertext = self
            .public_material
            .polynomial(2, ciphertext_ordinal, component_ordinal, data_modulus_index)
            .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
        if public_key.modulus != ciphertext.modulus {
            return Err(BallotValidityAdapterError::InvalidPublicMaterial);
        }
        let mut quotient =
            self.exact_negacyclic_product(public_key, usize::from(ciphertext_ordinal))?;
        let witness = self.retained_witness()?;
        let error_coefficients = witness
            .error_coefficients(
                usize::from(ciphertext_ordinal),
                usize::from(component_ordinal),
            )
            .ok_or(BallotValidityAdapterError::InvalidWitness)?;
        let message_coefficients = witness
            .auxiliary_coefficients(usize::from(ciphertext_ordinal), 2)
            .ok_or(BallotValidityAdapterError::InvalidWitness)?;
        let modulus = i128::from(public_key.modulus);
        let plaintext_modulus = i128::from(self.source_plan.plaintext_modulus());
        for (coefficient_ordinal, ciphertext_coefficient) in
            ciphertext.coefficients.iter().copied().enumerate()
        {
            let plaintext = if component_ordinal == 0 {
                i128::from(message_coefficients[coefficient_ordinal])
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
        ciphertext_ordinal: usize,
    ) -> Result<Zeroizing<Vec<i128>>, BallotValidityAdapterError> {
        let witness = self.retained_witness()?;
        let randomizer_l1_norm = witness
            .randomizer_coefficients(ciphertext_ordinal)
            .ok_or(BallotValidityAdapterError::InvalidWitness)?
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
        let randomizer_convolution_evaluations = self
            .randomizer_convolution_evaluations
            .as_ref()
            .and_then(|evaluations| evaluations.get(ciphertext_ordinal))
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

    fn exact_private_negacyclic_product(
        &self,
        left: &[u64],
        right: &[u64],
    ) -> Result<Zeroizing<Vec<i128>>, BallotValidityAdapterError> {
        let ring_degree = self.trace_domain.size();
        if left.len() != ring_degree || right.len() != ring_degree {
            return Err(BallotValidityAdapterError::InvalidWitness);
        }
        let absolute_bound = u128::try_from(ring_degree)
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?
            .checked_mul(u128::from(self.source_plan.plaintext_modulus() - 1).pow(2))
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
        if absolute_bound >= u128::from(PROOF_BASE_FIELD_MODULUS / 2) {
            return Err(BallotValidityAdapterError::NoWrapBoundViolated);
        }
        let mut left_evaluations = Zeroizing::new(
            left.iter()
                .copied()
                .map(ProofBaseFieldElement::from_canonical)
                .collect::<Result<Vec<_>, _>>()?,
        );
        let mut right_evaluations = Zeroizing::new(
            right
                .iter()
                .copied()
                .map(ProofBaseFieldElement::from_canonical)
                .collect::<Result<Vec<_>, _>>()?,
        );
        self.convolution_domain
            .evaluate_base_polynomial_in_place(&mut left_evaluations)?;
        self.convolution_domain
            .evaluate_base_polynomial_in_place(&mut right_evaluations)?;
        if left_evaluations.len() != right_evaluations.len() {
            return Err(BallotValidityAdapterError::InvalidWitness);
        }
        for (left_value, right_value) in left_evaluations.iter_mut().zip(right_evaluations.iter()) {
            *left_value = left_value.multiply(*right_value);
        }
        self.convolution_domain
            .interpolate_base_polynomial_in_place(&mut left_evaluations)?;
        left_evaluations.resize(self.convolution_domain.size(), ProofBaseFieldElement::ZERO);
        let mut product = Zeroizing::new(Vec::with_capacity(ring_degree));
        for coefficient_ordinal in 0..ring_degree {
            product.push(centered_base_field_value(
                left_evaluations[coefficient_ordinal]
                    .subtract(left_evaluations[coefficient_ordinal + ring_degree]),
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
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        let accounting = ballot_validity_carrier_buffer_accounting(&self.source_plan)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        Ok(CommonProofSourceProviderMemoryAccounting::new(
            accounting.provider_loading_persistent_resident_byte_length(),
            accounting.provider_post_source_finish_persistent_resident_byte_length(),
            accounting.provider_additional_loading_transient_byte_length(),
            accounting.transferred_source_polynomial_byte_length(),
        ))
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
        if self.next_source_column_position != self.ordered_source_columns.len() {
            self.release_secret_material();
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_value_source = None;
        Ok(())
    }

    fn poll_replayed_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if self.next_source_column_position != self.ordered_source_columns.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let result = self
            .ordered_source_columns
            .binary_search_by_key(&request.column_ordinal(), |(column_ordinal, _)| {
                *column_ordinal
            })
            .map_err(|_| CommonProofProverError::InvalidColumn)
            .and_then(|source_position| {
                self.cached_value_source = None;
                let result =
                    self.provide_source_polynomial_at_position(request, source_position, false);
                self.cached_value_source = None;
                result
            });
        if result.is_err() {
            self.release_secret_material();
        }
        result.map(CommonProofSourcePolynomialProviderPoll::Ready)
    }

    fn finish_source_replay(&mut self) -> Result<(), CommonProofProverError> {
        if self.next_source_column_position != self.ordered_source_columns.len() {
            self.release_secret_material();
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.release_secret_material();
        Ok(())
    }
}

impl BallotValiditySourcePolynomialAdapter {
    fn provide_source_polynomial_once(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<ProvidedCommonProofSourcePolynomial, CommonProofProverError> {
        self.provide_source_polynomial_at_position(request, self.next_source_column_position, true)
    }

    fn provide_source_polynomial_at_position(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
        source_position: usize,
        advances_initial_position: bool,
    ) -> Result<ProvidedCommonProofSourcePolynomial, CommonProofProverError> {
        let expected_column_ordinal = self
            .ordered_source_columns
            .get(source_position)
            .map(|(column_ordinal, _)| *column_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let expected_descriptor = self
            .ordered_source_columns
            .get(source_position)
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
        if advances_initial_position {
            self.next_source_column_position = self
                .next_source_column_position
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
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
        if public_material.public_key_by_limb[limb_ordinal]
            .iter()
            .chain(public_material.ciphertext_by_limb[limb_ordinal].iter())
            .any(|polynomial| polynomial.modulus != modulus)
        {
            return Err(BallotValidityAdapterError::InvalidPublicMaterial);
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
        matches!(
            descriptor.origin(),
            RelationColumnOrigin::VerifierSequence { .. }
        )
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
        BallotValidityWitnessValueSource::ScoreIndicator {
            option_ordinal,
            score_bucket_ordinal,
        } => {
            bytes.extend_from_slice(&1_u16.to_le_bytes());
            bytes.extend_from_slice(&option_ordinal.to_le_bytes());
            bytes.extend_from_slice(&score_bucket_ordinal.to_le_bytes());
        }
        BallotValidityWitnessValueSource::PairCharacterAuxiliaryCoefficient {
            ciphertext_ordinal,
            auxiliary_ordinal,
        } => {
            bytes.extend_from_slice(&2_u16.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
            bytes.extend_from_slice(&auxiliary_ordinal.to_le_bytes());
        }
        BallotValidityWitnessValueSource::ReversedRandomizerShifted { ciphertext_ordinal } => {
            bytes.extend_from_slice(&4_u16.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
        }
        BallotValidityWitnessValueSource::ErrorShifted {
            ciphertext_ordinal,
            component_ordinal,
        } => {
            bytes.extend_from_slice(&5_u16.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
            bytes.extend_from_slice(&component_ordinal.to_le_bytes());
        }
        BallotValidityWitnessValueSource::EncoderReduction {
            ciphertext_ordinal,
            auxiliary_ordinal,
        } => {
            bytes.extend_from_slice(&6_u16.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
            bytes.extend_from_slice(&auxiliary_ordinal.to_le_bytes());
        }
        BallotValidityWitnessValueSource::PairCharacterProductQuotient { ciphertext_ordinal } => {
            bytes.extend_from_slice(&7_u16.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
        }
        BallotValidityWitnessValueSource::EncryptionQuotient {
            ciphertext_ordinal,
            data_modulus_index,
            component_ordinal,
        } => {
            bytes.extend_from_slice(&8_u16.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
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
            ciphertext_ordinal,
            component_ordinal,
            data_modulus_index,
        } => {
            bytes.extend_from_slice(&1_u16.to_le_bytes());
            bytes.extend_from_slice(&source_kind.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
            bytes.extend_from_slice(&component_ordinal.to_le_bytes());
            bytes.extend_from_slice(&data_modulus_index.to_le_bytes());
        }
        BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
            ciphertext_ordinal,
            auxiliary_ordinal,
            option_ordinal,
        } => {
            bytes.extend_from_slice(&2_u16.to_le_bytes());
            bytes.extend_from_slice(&ciphertext_ordinal.to_le_bytes());
            bytes.extend_from_slice(&auxiliary_ordinal.to_le_bytes());
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
    match source {
        BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
            source_kind,
            ciphertext_ordinal,
            component_ordinal,
            data_modulus_index,
        } => {
            let coefficients = &public_material
                .polynomial(
                    source_kind,
                    ciphertext_ordinal,
                    component_ordinal,
                    data_modulus_index,
                )
                .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?
                .coefficients;
            coefficients
                .iter()
                .copied()
                .map(ProofBaseFieldElement::from_canonical)
                .collect::<Result<Vec<_>, _>>()
                .map_err(Into::into)
        }
        BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
            ciphertext_ordinal,
            auxiliary_ordinal,
            option_ordinal,
        } => {
            let residues = source_plan
                .encoder_profile_sequence(ciphertext_ordinal, auxiliary_ordinal, option_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidColumn)?;
            residues
                .into_iter()
                .map(ProofBaseFieldElement::from_canonical)
                .collect::<Result<Vec<_>, _>>()
                .map_err(Into::into)
        }
    }
}

struct CachedCoefficientColumn {
    column_ordinal: u32,
    coefficients: Vec<ProofBaseFieldElement>,
}

struct CachedPairCharacterLagrangeWeights {
    point_coordinates: [u64; PROOF_CHALLENGE_EXTENSION_DEGREE],
    weights: Vec<ProofChallengeExtensionElement>,
}

fn pair_character_profile_lagrange_weight_index(lane_block_ordinal: usize) -> Option<usize> {
    (lane_block_ordinal < PAIR_CHARACTER_LANE_COUNT).then_some(lane_block_ordinal)
}

fn invert_extension_elements_in_place(
    values: &mut [ProofChallengeExtensionElement],
) -> Result<(), BallotValidityAdapterError> {
    let mut prefix_products = Vec::with_capacity(values.len());
    let mut accumulated_product = ProofChallengeExtensionElement::ONE;
    for value in values.iter().copied() {
        if value.is_zero() {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        prefix_products.push(accumulated_product);
        accumulated_product = accumulated_product.multiply(value);
    }
    let mut accumulated_inverse = accumulated_product.inverse()?;
    for value_ordinal in (0..values.len()).rev() {
        let value = values[value_ordinal];
        values[value_ordinal] = accumulated_inverse.multiply(prefix_products[value_ordinal]);
        accumulated_inverse = accumulated_inverse.multiply(value);
    }
    Ok(())
}

/// Verifier-sequence adapter rebuilt only from authenticated setup and ballot
/// ciphertext material. One coefficient polynomial at a time is retained for
/// authenticated out-of-domain-point evaluation. Deterministic encoder sequences use a
/// compact sparse subgroup interpolation cache and are never materialized as
/// full columns or committed in a proof tree.
pub(crate) struct BallotValidityVerifiedColumnEvaluator {
    source_plan: BallotValiditySourcePlan,
    public_material: BallotValidityBoundPublicMaterial,
    trace_domain: ProofEvaluationDomain,
    source_by_column: Vec<Option<BallotValidityVerifierColumnSource>>,
    cached_column: Option<CachedCoefficientColumn>,
    cached_pair_character_lagrange_weights: Option<CachedPairCharacterLagrangeWeights>,
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
                        ciphertext_ordinal,
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
                    let expected_source_component_ordinal = match source_kind {
                        1 if ciphertext_ordinal == 0 => u64::from(component_ordinal),
                        2 => u64::from(ciphertext_ordinal)
                            .checked_mul(
                                u64::try_from(BGV_CIPHERTEXT_COMPONENT_COUNT)
                                    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                            )
                            .and_then(|ordinal| ordinal.checked_add(u64::from(component_ordinal)))
                            .ok_or(BallotValidityAdapterError::IntegerOverflow)?,
                        _ => return Err(BallotValidityAdapterError::InvalidColumn),
                    };
                    if *protocol_source_kind != source_kind
                        || source_coordinates
                            != &[
                                expected_source_component_ordinal,
                                u64::from(data_modulus_index),
                            ]
                        || statement_binding_path.len() != 1
                        || statement_binding_path[0].step_kind() != SelectorPathStepKind::TupleField
                        || statement_binding_path[0].argument() != expected_field_ordinal
                    {
                        return Err(BallotValidityAdapterError::InvalidColumn);
                    }
                    let polynomial = public_material
                        .polynomial(
                            source_kind,
                            ciphertext_ordinal,
                            component_ordinal,
                            data_modulus_index,
                        )
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
                    BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
                        ciphertext_ordinal,
                        auxiliary_ordinal,
                        option_ordinal,
                    },
                    RelationVerifierSource::DirectBallotPairCharacterEncoderProfile {
                        ring_degree,
                        plaintext_modulus,
                        ciphertext_ordinal: declared_ciphertext_ordinal,
                        auxiliary_ordinal: declared_auxiliary_ordinal,
                        option_count,
                        option_ordinal: declared_option_ordinal,
                    },
                ) => {
                    if *ring_degree != compilation.source_plan().ring_degree()
                        || *plaintext_modulus != compilation.source_plan().plaintext_modulus()
                        || *declared_ciphertext_ordinal != ciphertext_ordinal
                        || *declared_auxiliary_ordinal != auxiliary_ordinal
                        || usize::from(*option_count) != OPTION_COUNT
                        || *declared_option_ordinal != option_ordinal
                        || descriptor.canonical_residue_modulus()
                            != Some(SuiteModulusReference::plaintext())
                        || compilation
                            .source_plan()
                            .encoder_profile_sequence(
                                ciphertext_ordinal,
                                auxiliary_ordinal,
                                option_ordinal,
                            )
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
            cached_column: None,
            cached_pair_character_lagrange_weights: None,
        })
    }

    fn derive_coefficients(
        &self,
        column_index: usize,
    ) -> Result<Vec<ProofBaseFieldElement>, BallotValidityAdapterError> {
        let source = self
            .source_by_column
            .get(column_index)
            .and_then(Option::as_ref)
            .copied()
            .ok_or(BallotValidityAdapterError::InvalidColumn)?;
        if matches!(
            source,
            BallotValidityVerifierColumnSource::PairCharacterEncoderProfile { .. }
        ) {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        let mut coefficients =
            verifier_source_trace_rows(&self.source_plan, &self.public_material, source)?;
        self.trace_domain
            .interpolate_base_polynomial_in_place(&mut coefficients)?;
        Ok(coefficients)
    }

    fn ensure_cached_column(
        &mut self,
        column_ordinal: u32,
    ) -> Result<(), BallotValidityAdapterError> {
        let column_index = usize::try_from(column_ordinal)
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        if column_index >= self.source_by_column.len() {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        let needs_derivation = self
            .cached_column
            .as_ref()
            .is_none_or(|cached| cached.column_ordinal != column_ordinal);
        if needs_derivation {
            let coefficients = self.derive_coefficients(column_index)?;
            self.cached_column = Some(CachedCoefficientColumn {
                column_ordinal,
                coefficients,
            });
        }
        Ok(())
    }

    fn build_pair_character_lagrange_weights(
        &self,
        point: ProofChallengeExtensionElement,
    ) -> Result<CachedPairCharacterLagrangeWeights, BallotValidityAdapterError> {
        let ring_degree = u64::try_from(self.trace_domain.size())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let vanishing_value = point
            .power(ring_degree)
            .subtract(ProofChallengeExtensionElement::ONE);
        if vanishing_value.is_zero() {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        let inverse_ring_degree = ProofBaseFieldElement::from_canonical(ring_degree)?.inverse()?;
        let common_factor = vanishing_value.multiply_base(inverse_ring_degree);
        let mut inverse_denominators =
            Vec::with_capacity(PAIR_CHARACTER_PROFILE_LAGRANGE_WEIGHT_COUNT);
        for lane_block_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
            let trace_row_ordinal = lane_block_ordinal
                .checked_mul(PAIR_CHARACTER_LANE_DEGREE)
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
            let domain_point = self.trace_domain.point(trace_row_ordinal)?;
            inverse_denominators
                .push(point.subtract(ProofChallengeExtensionElement::from_base(domain_point)));
        }
        if inverse_denominators.len() != PAIR_CHARACTER_PROFILE_LAGRANGE_WEIGHT_COUNT {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        invert_extension_elements_in_place(&mut inverse_denominators)?;
        for lane_block_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
            let trace_row_ordinal = lane_block_ordinal
                .checked_mul(PAIR_CHARACTER_LANE_DEGREE)
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
            let weight_index = pair_character_profile_lagrange_weight_index(lane_block_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidColumn)?;
            let domain_point = self.trace_domain.point(trace_row_ordinal)?;
            inverse_denominators[weight_index] = common_factor
                .multiply_base(domain_point)
                .multiply(inverse_denominators[weight_index]);
        }
        Ok(CachedPairCharacterLagrangeWeights {
            point_coordinates: point.canonical_coordinates(),
            weights: inverse_denominators,
        })
    }

    fn evaluate_pair_character_encoder_profile(
        &mut self,
        point: ProofChallengeExtensionElement,
        ciphertext_ordinal: u16,
        auxiliary_ordinal: u16,
        option_ordinal: u16,
    ) -> Result<ProofChallengeExtensionElement, BallotValidityAdapterError> {
        let point_coordinates = point.canonical_coordinates();
        let needs_weights = self
            .cached_pair_character_lagrange_weights
            .as_ref()
            .is_none_or(|cached| cached.point_coordinates != point_coordinates);
        if needs_weights {
            let weights = self.build_pair_character_lagrange_weights(point)?;
            self.cached_pair_character_lagrange_weights = Some(weights);
        }
        let terms = pair_character_encoder_profile_terms(
            ciphertext_ordinal,
            auxiliary_ordinal,
            option_ordinal,
        )?;
        let weights = &self
            .cached_pair_character_lagrange_weights
            .as_ref()
            .ok_or(BallotValidityAdapterError::InvalidColumn)?
            .weights;
        let mut evaluation = ProofChallengeExtensionElement::ZERO;
        for term in terms {
            let expected_trace_row_ordinal = term
                .lane_block_ordinal()
                .checked_mul(PAIR_CHARACTER_LANE_DEGREE)
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
            if term.trace_row_ordinal() != expected_trace_row_ordinal {
                return Err(BallotValidityAdapterError::InvalidColumn);
            }
            let weight_index =
                pair_character_profile_lagrange_weight_index(term.lane_block_ordinal())
                    .ok_or(BallotValidityAdapterError::InvalidColumn)?;
            let term_value = ProofBaseFieldElement::from_canonical(term.value())?;
            evaluation = evaluation.add(
                weights
                    .get(weight_index)
                    .copied()
                    .ok_or(BallotValidityAdapterError::InvalidColumn)?
                    .multiply_base(term_value),
            );
        }
        Ok(evaluation)
    }
}

impl VerifiedRelationColumnEvaluator for BallotValidityVerifiedColumnEvaluator {
    fn memory_accounting(
        &self,
    ) -> Result<VerifiedRelationColumnEvaluatorMemoryAccounting, CommonProofVerifierError> {
        let checked_payload = |count: usize, value_byte_length: usize| {
            u64::try_from(count)
                .ok()
                .and_then(|count| {
                    u64::try_from(value_byte_length)
                        .ok()
                        .and_then(|width| count.checked_mul(width))
                })
                .ok_or(CommonProofVerifierError::InvalidTreeLayout)
        };
        let fixed_and_input_resident_byte_length = [
            u64::try_from(size_of::<Self>())
                .map_err(|_| CommonProofVerifierError::InvalidTreeLayout)?,
            self.source_plan
                .resident_owned_payload_byte_length()
                .ok_or(CommonProofVerifierError::InvalidTreeLayout)?,
            self.public_material
                .resident_owned_payload_byte_length()
                .ok_or(CommonProofVerifierError::InvalidTreeLayout)?,
            checked_payload(
                self.source_by_column.capacity(),
                size_of::<Option<BallotValidityVerifierColumnSource>>(),
            )?,
        ]
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        if !self.source_by_column.iter().any(Option::is_some) {
            return Err(CommonProofVerifierError::InvalidTreeLayout);
        }
        let trace_column_byte_length =
            checked_payload(self.trace_domain.size(), size_of::<ProofBaseFieldElement>())?;
        let pair_character_lagrange_cache_byte_length = checked_payload(
            PAIR_CHARACTER_PROFILE_LAGRANGE_WEIGHT_COUNT,
            size_of::<ProofChallengeExtensionElement>(),
        )?;
        let maximum_cached_column_resident_byte_length = trace_column_byte_length
            .checked_add(pair_character_lagrange_cache_byte_length)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        // A point change retains the preceding compact cache while the new
        // denominator and prefix-product vectors coexist. An authenticated
        // column change instead retains one trace column while deriving one.
        let lagrange_build_transient_byte_length = pair_character_lagrange_cache_byte_length
            .checked_mul(2)
            .ok_or(CommonProofVerifierError::InvalidTreeLayout)?;
        let sparse_term_transient_byte_length = checked_payload(
            PAIR_CHARACTER_LANE_COUNT,
            size_of::<PairCharacterEncoderProfileTerm>(),
        )?;
        let maximum_evaluation_transient_byte_length = trace_column_byte_length
            .max(lagrange_build_transient_byte_length)
            .max(sparse_term_transient_byte_length);
        VerifiedRelationColumnEvaluatorMemoryAccounting::new(
            fixed_and_input_resident_byte_length,
            maximum_cached_column_resident_byte_length,
            maximum_evaluation_transient_byte_length,
        )
    }

    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement> {
        let column_index = usize::try_from(column_ordinal).ok()?;
        let source = self
            .source_by_column
            .get(column_index)
            .and_then(Option::as_ref)
            .copied()?;
        match source {
            BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
                ciphertext_ordinal,
                auxiliary_ordinal,
                option_ordinal,
            } => self
                .evaluate_pair_character_encoder_profile(
                    point,
                    ciphertext_ordinal,
                    auxiliary_ordinal,
                    option_ordinal,
                )
                .ok(),
            BallotValidityVerifierColumnSource::AuthenticatedPolynomial { .. } => {
                self.ensure_cached_column(column_ordinal).ok()?;
                let coefficients = &self.cached_column.as_ref()?.coefficients;
                Some(coefficients.iter().rev().fold(
                    ProofChallengeExtensionElement::ZERO,
                    |accumulated, coefficient| {
                        accumulated
                            .multiply(point)
                            .add(ProofChallengeExtensionElement::from_base(*coefficient))
                    },
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource,
        CommonProofSourcePolynomialRequestContext, construct_pre_challenge_relation_columns,
    };
    use crate::foundation::{
        ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessDerivationInput, ActionRandomnessRoot,
        ParticipantIdentity, PrivateRandomnessStream, selected_suite_capability_for_tests,
    };
    use std::collections::BTreeSet;

    struct DeterministicPrivateCoins {
        initial_sample: u64,
        next_sample_by_coordinate:
            std::collections::BTreeMap<CommonProofPrivateCoinCoordinate, u64>,
    }

    impl DeterministicPrivateCoins {
        fn new(initial_sample: u64) -> Self {
            Self {
                initial_sample,
                next_sample_by_coordinate: std::collections::BTreeMap::new(),
            }
        }
    }

    impl CommonProofPrivateCoinSource for DeterministicPrivateCoins {
        type Error = ();

        fn private_randomness_attempt_identifier(
            &self,
        ) -> crate::foundation::PrivateRandomnessAttemptIdentifier {
            crate::foundation::PrivateRandomnessAttemptIdentifier::for_test([0xb1; 32])
        }

        fn sample_modulo(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            let next_sample = self
                .next_sample_by_coordinate
                .entry(coordinate)
                .or_insert(self.initial_sample);
            let value = *next_sample % modulus;
            *next_sample = next_sample.wrapping_add(1);
            Ok(value)
        }

        fn fill_raw_bytes(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let next_sample = self
                .next_sample_by_coordinate
                .entry(coordinate)
                .or_insert(self.initial_sample);
            for byte in destination {
                *byte = *next_sample as u8;
                *next_sample = next_sample.wrapping_add(1);
            }
            Ok(())
        }

        fn replay_modulo_samples(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
            destination: &mut [u64],
        ) -> Result<(), Self::Error> {
            let expected_end = self
                .next_sample_by_coordinate
                .get(&coordinate)
                .copied()
                .ok_or(())?;
            for (sample_ordinal, sampled) in destination.iter_mut().enumerate() {
                *sampled = self.initial_sample.wrapping_add(sample_ordinal as u64) % modulus;
            }
            if self.initial_sample.wrapping_add(destination.len() as u64) != expected_end {
                return Err(());
            }
            Ok(())
        }
    }

    #[test]
    fn selected_ballot_carrier_accounting_matches_production_buffers() {
        let accounting = selected_ballot_validity_carrier_buffer_accounting()
            .expect("selected ballot carrier accounting derives");
        assert_eq!(accounting.canonical_ciphertext_byte_length(), 12_058_628);
        assert_eq!(accounting.canonical_ciphertext_chunk_count(), 12);
        assert!(accounting.canonical_ciphertext_descriptor_encoded_byte_length() > 0);
        let canonical_ciphertext_chunk_count =
            u64::from(accounting.canonical_ciphertext_chunk_count());
        assert_eq!(
            accounting.canonical_ciphertext_descriptor_digest_catalog_byte_length(),
            canonical_ciphertext_chunk_count
                * u64::try_from(size_of::<Hash512>()).expect("hash width fits u64")
                + 2 * u64::try_from(size_of::<usize>()).expect("word width fits u64")
        );
        assert_eq!(
            accounting.ciphertext_readback_polynomial_catalog_byte_length(),
            u64::try_from(
                PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT
                    .checked_mul(
                        selected_ballot_validity_relation_compilation()
                            .expect("selected compilation derives")
                            .source_plan()
                            .data_moduli()
                            .len(),
                    )
                    .expect("ciphertext polynomial catalog length derives"),
            )
            .expect("catalog length fits u64")
                * u64::try_from(size_of::<(u16, u16, u64, Arc<[u64]>)>())
                    .expect("entry width fits u64")
        );
        assert_eq!(
            accounting.decoded_ciphertext_residue_byte_length(),
            24_117_248,
        );
        assert_eq!(
            accounting.provider_bound_public_residue_byte_length(),
            36_175_872,
        );
        assert_eq!(
            accounting.provider_witness_coefficient_byte_length(),
            3_145_728,
        );
        assert_eq!(
            accounting.provider_precomputed_transform_byte_length(),
            1_048_576,
        );
        assert_eq!(accounting.provider_value_cache_byte_length(), 524_288);
        assert_eq!(
            accounting.provider_transient_scratch_byte_length(),
            1_048_576,
        );
        assert_eq!(
            accounting.provider_buffer_live_set_peak_byte_length(),
            41_943_040,
        );
        assert_eq!(
            accounting.transferred_source_polynomial_byte_length(),
            262_144,
        );
        assert_eq!(
            accounting.maximum_boundary_copied_buffer_byte_length(),
            1_048_576,
        );
    }

    const TEST_RING_DEGREE: u64 = crate::bgv::direct_ballots::PAIR_CHARACTER_RING_DEGREE as u64;
    const TEST_PLAINTEXT_MODULUS: u64 =
        crate::bgv::direct_ballots::PAIR_CHARACTER_PLAINTEXT_MODULUS;
    const TEST_DATA_MODULUS: u64 = crate::bgv::parameters::DATA_PRIMES[0];
    const TEST_EVALUATION_DOMAIN_SIZE: u64 =
        crate::bgv::proof_suite::selected_profile::SELECTED_EVALUATION_DOMAIN_SIZE;

    fn check_context() -> RelationPlanCheckContext {
        crate::bgv::proof_suite::selected_profile::selected_relation_plan_check_context(
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected ballot relation context")
    }

    fn compilation() -> CompiledBallotValidityRelation {
        compile_ballot_validity_relation(
            &BallotValidityRelationPlanInput {
                ring_degree: TEST_RING_DEGREE,
                evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive:
                    crate::bgv::proof_suite::selected_profile::SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
                active_data_modulus_indices: vec![0],
                plaintext_modulus: TEST_PLAINTEXT_MODULUS,
                reserved_slot_rule: 1,
            },
            &check_context(),
        )
        .expect("ballot relation compilation")
    }

    fn ballot_randomness_context() -> (
        SelectedSuiteCapability,
        ActionPrivateRandomness,
        ProofApplicationSlot,
        [u8; Hash512::BYTE_LENGTH],
    ) {
        let selected_suite = selected_suite_capability_for_tests();
        let suite_identifier = Hash512::from_bytes(selected_suite.suite_identifier());
        let ceremony_context_hash = Hash512::from_bytes([0x42; Hash512::BYTE_LENGTH]);
        let action_context_hash = Hash512::from_bytes([0x43; Hash512::BYTE_LENGTH]);
        let participant_identity =
            ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]);
        let action_private_randomness = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x45; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(ActionRandomnessDerivationInput::new(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            participant_identity,
        ))
        .expect("ballot action randomness derives");
        let application_slot = ProofApplicationSlot::new(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            Some(0),
            None,
            Some(7),
        )
        .expect("ballot application slot");
        (
            selected_suite,
            action_private_randomness,
            application_slot,
            [0x46; Hash512::BYTE_LENGTH],
        )
    }

    fn sample_test_ballot_distribution(
        stream: &mut PrivateRandomnessStream<'_>,
        purpose: u16,
        maximum_candidate_draws_per_output: u32,
    ) -> i64 {
        match purpose {
            purpose
                if purpose
                    == DistributionPurpose::BallotEncryptionEphemeralSecret.canonical_code() =>
            {
                i64::from(
                    stream
                        .sample_centered_ternary(maximum_candidate_draws_per_output)
                        .expect("ternary ballot coefficient samples"),
                )
            }
            purpose
                if purpose == DistributionPurpose::BallotEncryptionErrorZero.canonical_code()
                    || purpose
                        == DistributionPurpose::BallotEncryptionErrorOne.canonical_code() =>
            {
                i64::from(
                    stream
                        .sample_centered_binomial(2)
                        .expect("centered-binomial ballot coefficient samples"),
                )
            }
            _ => panic!("test purpose must be a ballot-encryption distribution"),
        }
    }

    #[test]
    fn two_ciphertext_ballot_randomness_is_canonical_distinct_and_reconstructible() {
        let compilation = compilation();
        let (selected_suite, action_private_randomness, application_slot, setup_source_hash) =
            ballot_randomness_context();
        let scores = (0..OPTION_COUNT)
            .map(|option_ordinal| 1 + (option_ordinal as u64 * 7 + 3) % 10)
            .collect::<Vec<_>>();
        let first_attempt_identifier = [0x51; 32];
        let changed_attempt_identifier = [0x52; 32];

        let canonical_contexts = [0_usize, 1].map(|ciphertext_ordinal| {
            canonical_ballot_encryption_coin_context(
                application_slot,
                setup_source_hash,
                ciphertext_ordinal,
            )
            .expect("canonical ballot-encryption coin context")
        });
        for (ciphertext_ordinal, context) in canonical_contexts.iter().enumerate() {
            assert_eq!(
                context.schema_identifier,
                BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_IDENTIFIER
            );
            assert_eq!(
                context.schema_version,
                BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_VERSION
            );
            assert_eq!(context.items.len(), 3);
            assert_eq!(
                context.items[2],
                CanonicalItem::unsigned16(
                    u16::try_from(ciphertext_ordinal).expect("ciphertext ordinal fits u16")
                )
            );
        }
        let mut ordinal_mutation = canonical_contexts[0].clone();
        ordinal_mutation.items[2] = CanonicalItem::unsigned16(1);
        assert_eq!(ordinal_mutation, canonical_contexts[1]);
        assert_eq!(
            canonical_ballot_encryption_coin_context(
                application_slot,
                setup_source_hash,
                PAIR_CHARACTER_CIPHERTEXT_COUNT,
            )
            .err(),
            Some(BallotValidityAdapterError::InvalidStatementBinding)
        );

        let context_hashes = [0_usize, 1].map(|ciphertext_ordinal| {
            ballot_encryption_coin_context_hash(
                application_slot,
                setup_source_hash,
                ciphertext_ordinal,
            )
            .expect("ballot-encryption coin context hash")
        });
        assert_ne!(context_hashes[0], context_hashes[1]);

        let (first_witness, first_cursors) =
            BallotValidityEncryptionAttemptWitness::sample_from_action_randomness(
                compilation.source_plan(),
                &selected_suite,
                &action_private_randomness,
                application_slot,
                setup_source_hash,
                &scores,
                Zeroizing::new(first_attempt_identifier),
            )
            .expect("both ballot ciphertext randomness groups sample");
        assert_eq!(
            first_witness.encryption_attempt_identifier(),
            first_attempt_identifier
        );
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            let randomizer = first_witness
                .randomizer_coefficients(ciphertext_ordinal)
                .expect("ciphertext randomizer");
            let error_zero = first_witness
                .error_coefficients(ciphertext_ordinal, 0)
                .expect("ciphertext first error");
            let error_one = first_witness
                .error_coefficients(ciphertext_ordinal, 1)
                .expect("ciphertext second error");
            assert_eq!(randomizer.len(), TEST_RING_DEGREE as usize);
            assert_eq!(error_zero.len(), TEST_RING_DEGREE as usize);
            assert_eq!(error_one.len(), TEST_RING_DEGREE as usize);
            assert!(randomizer.iter().all(|value| (-1..=1).contains(value)));
            assert!(error_zero.iter().all(|value| (-2..=2).contains(value)));
            assert!(error_one.iter().all(|value| (-2..=2).contains(value)));
        }

        let expected_purpose_order = [
            DistributionPurpose::BallotEncryptionEphemeralSecret.canonical_code(),
            DistributionPurpose::BallotEncryptionErrorZero.canonical_code(),
            DistributionPurpose::BallotEncryptionErrorOne.canonical_code(),
            DistributionPurpose::BallotEncryptionEphemeralSecret.canonical_code(),
            DistributionPurpose::BallotEncryptionErrorZero.canonical_code(),
            DistributionPurpose::BallotEncryptionErrorOne.canonical_code(),
        ];
        assert_eq!(
            first_cursors.map(PrivateRandomCursor::purpose),
            expected_purpose_order
        );
        assert!(
            first_cursors[..3]
                .iter()
                .all(|cursor| cursor.derivation_context_hash() == context_hashes[0])
        );
        assert!(
            first_cursors[3..]
                .iter()
                .all(|cursor| cursor.derivation_context_hash() == context_hashes[1])
        );
        assert!(
            first_cursors
                .iter()
                .all(|cursor| { cursor.stream_attempt_identifier() == first_attempt_identifier })
        );
        let starting_coordinates = first_cursors
            .iter()
            .map(|cursor| {
                PrivateRandomCursor::new(
                    cursor.family(),
                    cursor.purpose(),
                    cursor.derivation_context_hash(),
                    cursor.stream_attempt_identifier(),
                    0,
                    None,
                )
                .expect("canonical starting cursor")
                .encode()
                .expect("starting cursor encodes")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(starting_coordinates.len(), first_cursors.len());

        let (reconstructed_witness, reconstructed_cursors) =
            BallotValidityEncryptionAttemptWitness::sample_from_action_randomness(
                compilation.source_plan(),
                &selected_suite,
                &action_private_randomness,
                application_slot,
                setup_source_hash,
                &scores,
                Zeroizing::new(first_attempt_identifier),
            )
            .expect("same ballot attempt reconstructs");
        assert_eq!(reconstructed_cursors, first_cursors);
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            assert_eq!(
                reconstructed_witness.randomizer_coefficients(ciphertext_ordinal),
                first_witness.randomizer_coefficients(ciphertext_ordinal)
            );
            assert_eq!(
                reconstructed_witness.error_coefficients(ciphertext_ordinal, 0),
                first_witness.error_coefficients(ciphertext_ordinal, 0)
            );
            assert_eq!(
                reconstructed_witness.error_coefficients(ciphertext_ordinal, 1),
                first_witness.error_coefficients(ciphertext_ordinal, 1)
            );
        }

        let (changed_witness, changed_cursors) =
            BallotValidityEncryptionAttemptWitness::sample_from_action_randomness(
                compilation.source_plan(),
                &selected_suite,
                &action_private_randomness,
                application_slot,
                setup_source_hash,
                &scores,
                Zeroizing::new(changed_attempt_identifier),
            )
            .expect("changed ballot attempt samples");
        assert!(
            (0..PAIR_CHARACTER_CIPHERTEXT_COUNT).any(|ciphertext_ordinal| {
                changed_witness.randomizer_coefficients(ciphertext_ordinal)
                    != first_witness.randomizer_coefficients(ciphertext_ordinal)
                    || changed_witness.error_coefficients(ciphertext_ordinal, 0)
                        != first_witness.error_coefficients(ciphertext_ordinal, 0)
                    || changed_witness.error_coefficients(ciphertext_ordinal, 1)
                        != first_witness.error_coefficients(ciphertext_ordinal, 1)
            })
        );
        for (first_cursor, changed_cursor) in first_cursors.iter().zip(changed_cursors) {
            assert_eq!(first_cursor.family(), changed_cursor.family());
            assert_eq!(first_cursor.purpose(), changed_cursor.purpose());
            assert_eq!(
                first_cursor.derivation_context_hash(),
                changed_cursor.derivation_context_hash()
            );
            assert_ne!(
                first_cursor.stream_attempt_identifier(),
                changed_cursor.stream_attempt_identifier()
            );
        }

        let attempt_identifier = action_private_randomness
            .ballot_encryption_attempt_identifier(Zeroizing::new(first_attempt_identifier));
        let maximum_candidate_draws =
            selected_suite.maximum_private_sampler_candidate_draws_per_output();
        for (coordinate_ordinal, cursor) in first_cursors.iter().enumerate() {
            let ciphertext_ordinal =
                coordinate_ordinal / BALLOT_ENCRYPTION_DISTRIBUTION_PURPOSES.len();
            let purpose = cursor.purpose();
            let domain = PrivateRandomnessDomain::ballot_encryption_distribution(purpose)
                .expect("ballot distribution domain");
            let mut uninterrupted = action_private_randomness
                .begin_stream(
                    domain,
                    context_hashes[ciphertext_ordinal],
                    attempt_identifier,
                )
                .expect("uninterrupted ballot stream starts");
            for _ in 0..TEST_RING_DEGREE {
                sample_test_ballot_distribution(
                    &mut uninterrupted,
                    purpose,
                    maximum_candidate_draws,
                );
            }
            assert_eq!(uninterrupted.cursor(), *cursor);
            let expected_suffix = sample_test_ballot_distribution(
                &mut uninterrupted,
                purpose,
                maximum_candidate_draws,
            );
            let mut resumed = action_private_randomness
                .resume_stream(
                    domain,
                    context_hashes[ciphertext_ordinal],
                    attempt_identifier,
                    *cursor,
                )
                .expect("exact ballot cursor resumes");
            let resumed_suffix =
                sample_test_ballot_distribution(&mut resumed, purpose, maximum_candidate_draws);
            assert_eq!(resumed_suffix, expected_suffix);
            assert_eq!(resumed.cursor(), uninterrupted.cursor());
        }

        let first_domain =
            PrivateRandomnessDomain::ballot_encryption_distribution(first_cursors[0].purpose())
                .expect("first ballot distribution domain");
        let cross_context_error = action_private_randomness
            .resume_stream(
                first_domain,
                context_hashes[1],
                attempt_identifier,
                first_cursors[0],
            )
            .expect_err("a cursor cannot cross ciphertext contexts");
        assert_eq!(
            cross_context_error.refusal_reason,
            RefusalReason::WrongContext
        );
    }

    fn witness(
        compilation: &CompiledBallotValidityRelation,
    ) -> BallotValidityEncryptionAttemptWitness {
        let scores = (0..OPTION_COUNT)
            .map(|option_ordinal| 1 + (option_ordinal as u64 * 7 + 3) % 10)
            .collect::<Vec<_>>();
        let randomizer_coefficients = core::array::from_fn(|ciphertext_ordinal| {
            (0..TEST_RING_DEGREE)
                .map(|ordinal| [-1_i64, 0, 1][(ordinal as usize + ciphertext_ordinal) % 3])
                .collect::<Vec<_>>()
        });
        let error_zero_coefficients = core::array::from_fn(|ciphertext_ordinal| {
            (0..TEST_RING_DEGREE)
                .map(|ordinal| [-2_i64, -1, 0, 1, 2][(ordinal as usize + ciphertext_ordinal) % 5])
                .collect::<Vec<_>>()
        });
        let error_one_coefficients = core::array::from_fn(|ciphertext_ordinal| {
            (0..TEST_RING_DEGREE)
                .map(|ordinal| {
                    [2_i64, 0, -2, 1, -1][(ordinal as usize + ciphertext_ordinal * 2) % 5]
                })
                .collect::<Vec<_>>()
        });
        BallotValidityEncryptionAttemptWitness::from_encryption_attempt(
            compilation.source_plan(),
            &scores,
            randomizer_coefficients,
            error_zero_coefficients,
            error_one_coefficients,
            [41_u8; 32],
        )
        .expect("valid witness")
    }

    fn public_material(
        compilation: &CompiledBallotValidityRelation,
        witness: &BallotValidityEncryptionAttemptWitness,
    ) -> BallotValidityBoundPublicMaterial {
        let public_key = [
            (0..TEST_RING_DEGREE)
                .map(|ordinal| (ordinal * 29 + 17) % TEST_DATA_MODULUS)
                .collect::<Vec<_>>(),
            (0..TEST_RING_DEGREE)
                .map(|ordinal| (ordinal * ordinal + 31) % TEST_DATA_MODULUS)
                .collect::<Vec<_>>(),
        ];
        let mut ciphertext = Vec::with_capacity(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT);
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            let randomizer_residues = witness
                .randomizer_coefficients(ciphertext_ordinal)
                .expect("ciphertext randomizer")
                .iter()
                .copied()
                .map(|coefficient| signed_residue(coefficient, TEST_DATA_MODULUS))
                .collect::<Vec<_>>();
            for (component_ordinal, public_polynomial) in public_key.iter().enumerate() {
                let mut encrypted =
                    negacyclic_mul(public_polynomial, &randomizer_residues, TEST_DATA_MODULUS)
                        .expect("test public-key product");
                let errors = witness
                    .error_coefficients(ciphertext_ordinal, component_ordinal)
                    .expect("ciphertext errors");
                let message = witness
                    .auxiliary_coefficients(ciphertext_ordinal, 2)
                    .expect("ciphertext message");
                for (coefficient_ordinal, encrypted_coefficient) in encrypted.iter_mut().enumerate()
                {
                    let scaled_error = i64::try_from(TEST_PLAINTEXT_MODULUS)
                        .expect("small plaintext modulus")
                        * errors[coefficient_ordinal];
                    *encrypted_coefficient = add_mod(
                        *encrypted_coefficient,
                        signed_residue(scaled_error, TEST_DATA_MODULUS),
                        TEST_DATA_MODULUS,
                    )
                    .expect("canonical scaled-error sum");
                    if component_ordinal == 0 {
                        *encrypted_coefficient = add_mod(
                            *encrypted_coefficient,
                            message[coefficient_ordinal],
                            TEST_DATA_MODULUS,
                        )
                        .expect("canonical message sum");
                    }
                }
                ciphertext.push(encrypted);
            }
        }
        BallotValidityBoundPublicMaterial::from_authenticated_polynomial_sequences(
            compilation.source_plan(),
            1,
            [17_u8; 64],
            [19_u8; 64],
            [23_u8; 64],
            vec![
                (0, 0, TEST_DATA_MODULUS, public_key[0].clone().into()),
                (1, 0, TEST_DATA_MODULUS, public_key[1].clone().into()),
            ],
            ciphertext
                .into_iter()
                .enumerate()
                .map(|(component_ordinal, coefficients)| {
                    (
                        u16::try_from(component_ordinal).expect("component ordinal"),
                        0,
                        TEST_DATA_MODULUS,
                        coefficients.into(),
                    )
                })
                .collect(),
        )
        .expect("authenticated public material")
    }

    fn ballot_ciphertext_stream_bytes(material: &BallotValidityBoundPublicMaterial) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT)
                .expect("ciphertext polynomial count fits u16")
                .to_le_bytes(),
        );
        for component_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT {
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
        assert_eq!(
            authenticated.polynomials.len(),
            PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT
        );
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
        for component_ordinal in
            0..u16::try_from(BGV_CIPHERTEXT_COMPONENT_COUNT).expect("component count fits u16")
        {
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
        assert_eq!(
            authenticated.polynomials.len(),
            PAIR_CHARACTER_CIPHERTEXT_POLYNOMIAL_COUNT
        );
        for (ciphertext_polynomial_ordinal, polynomial) in
            authenticated.polynomials.iter().enumerate()
        {
            assert_eq!(
                polynomial.0,
                u16::try_from(ciphertext_polynomial_ordinal).unwrap()
            );
            assert_eq!(
                polynomial.3.as_ref(),
                expected_material.ciphertext_by_limb[0][ciphertext_polynomial_ordinal]
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
            let has_recipe = compilation.source_plan().recipe(column_ordinal).is_some();
            let has_verifier_source = compilation
                .source_plan()
                .verifier_source(column_ordinal)
                .is_some();
            if !has_recipe && !has_verifier_source {
                continue;
            }
            assert_ne!(has_recipe, has_verifier_source);
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
    fn private_negacyclic_product_matches_an_independent_sparse_dense_oracle() {
        let compilation = compilation();
        let active_witness = witness(&compilation);
        let material = public_material(&compilation, &active_witness);
        let provider = BallotValiditySourcePolynomialAdapter::from_bound_inputs(
            &compilation,
            1,
            [17_u8; 64],
            [13_u8; 64],
            active_witness,
            material,
        )
        .expect("provider");
        let ring_degree = usize::try_from(TEST_RING_DEGREE).expect("ring degree fits usize");
        let left_nonzero = [(0_usize, 3_u64), (1, 5), (ring_degree - 1, 7)];
        let right_nonzero = [(0_usize, 11_u64), (2, 13), (ring_degree - 2, 17)];
        let mut left = vec![0_u64; ring_degree];
        let mut right = vec![0_u64; ring_degree];
        for (coefficient_ordinal, value) in left_nonzero {
            left[coefficient_ordinal] = value;
        }
        for (coefficient_ordinal, value) in right_nonzero {
            right[coefficient_ordinal] = value;
        }

        let mut expected = vec![0_i128; ring_degree];
        for (left_ordinal, left_value) in left_nonzero {
            for (right_ordinal, right_value) in right_nonzero {
                let linear_ordinal = left_ordinal + right_ordinal;
                let product = i128::from(left_value) * i128::from(right_value);
                if linear_ordinal < ring_degree {
                    expected[linear_ordinal] += product;
                } else {
                    expected[linear_ordinal - ring_degree] -= product;
                }
            }
        }

        assert_eq!(
            provider
                .exact_private_negacyclic_product(&left, &right)
                .expect("exact private negacyclic product")
                .as_slice(),
            expected
        );
    }

    #[test]
    fn witness_clones_share_one_secret_owner_and_release_on_last_owner() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let weak_secret = witness.secret_weak_reference();
        let plaintext_allocation = witness
            .auxiliary_coefficients(0, 2)
            .expect("first ciphertext message")
            .as_ptr();
        let shared_witness = witness.clone();

        assert_eq!(witness.secret_owner_count(), 2);
        assert_eq!(
            plaintext_allocation,
            shared_witness
                .auxiliary_coefficients(0, 2)
                .expect("shared first ciphertext message")
                .as_ptr()
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
        let first_secret_source_column = provider
            .ordered_source_columns
            .iter()
            .map(|(column_ordinal, _)| *column_ordinal)
            .find(|column_ordinal| provider.source_plan.recipe(*column_ordinal).is_some())
            .expect("the ballot plan has a recipe-backed secret source column");
        provider
            .derive_source_polynomial(first_secret_source_column)
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
    fn provider_replays_authenticated_sources_before_releasing_secret_material() {
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
        let mut private_coins = DeterministicPrivateCoins::new(1);

        let constructed = construct_pre_challenge_relation_columns(
            variant,
            request_context,
            &mut provider,
            &mut private_coins,
            128,
        )
        .expect("all pre-challenge source columns construct");
        assert_ne!(constructed.source_replay_identity_digest(), [0_u8; 64]);
        assert!(!provider.secret_material_is_released());
        let (replayed_column_ordinal, replayed_descriptor) = provider
            .ordered_source_columns
            .first()
            .cloned()
            .expect("ballot relation has a source column");
        assert!(matches!(
            provider.poll_replayed_source_polynomial(
                request_context.request(replayed_column_ordinal, &replayed_descriptor)
            ),
            Ok(CommonProofSourcePolynomialProviderPoll::Ready(_))
        ));
        provider
            .finish_source_replay()
            .expect("source replay finishes");
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
        let mut randomizers = core::array::from_fn(|ciphertext_ordinal| {
            witness
                .randomizer_coefficients(ciphertext_ordinal)
                .expect("ciphertext randomizer")
                .to_vec()
        });
        randomizers[0][17] = 2;
        let errors_zero = core::array::from_fn(|ciphertext_ordinal| {
            witness
                .error_coefficients(ciphertext_ordinal, 0)
                .expect("ciphertext zero-component errors")
                .to_vec()
        });
        let errors_one = core::array::from_fn(|ciphertext_ordinal| {
            witness
                .error_coefficients(ciphertext_ordinal, 1)
                .expect("ciphertext one-component errors")
                .to_vec()
        });
        assert_eq!(
            BallotValidityEncryptionAttemptWitness::from_encryption_attempt(
                compilation.source_plan(),
                witness.scores(),
                randomizers,
                errors_zero,
                errors_one,
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
        let (
            column_ordinal,
            source_kind,
            ciphertext_ordinal,
            component_ordinal,
            data_modulus_index,
        ) = evaluator
            .source_by_column
            .iter()
            .enumerate()
            .find_map(|(column_index, source)| {
                let BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
                    source_kind,
                    ciphertext_ordinal,
                    component_ordinal,
                    data_modulus_index,
                } = source.as_ref()?
                else {
                    return None;
                };
                Some((
                    u32::try_from(column_index).expect("column ordinal"),
                    *source_kind,
                    *ciphertext_ordinal,
                    *component_ordinal,
                    *data_modulus_index,
                ))
            })
            .expect("authenticated public polynomial source");
        let rows = material
            .polynomial(
                source_kind,
                ciphertext_ordinal,
                component_ordinal,
                data_modulus_index,
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
        let expected = coefficients.iter().rev().fold(
            ProofChallengeExtensionElement::ZERO,
            |accumulated, coefficient| {
                accumulated
                    .multiply(point)
                    .add(ProofChallengeExtensionElement::from_base(*coefficient))
            },
        );
        assert_eq!(
            evaluator.evaluate_at_extension_point(column_ordinal, point),
            Some(expected)
        );
        let cached = evaluator.cached_column.as_ref().expect("coefficient cache");
        assert_eq!(cached.column_ordinal, column_ordinal);
        assert_eq!(cached.coefficients.len(), TEST_RING_DEGREE as usize);

        let last_option_ordinal = u16::try_from(OPTION_COUNT - 1).expect("last option ordinal");
        let selected_profile_coordinates = [
            (0, 0, 0),
            (0, 1, last_option_ordinal),
            (1, 0, 0),
            (1, 1, last_option_ordinal),
        ];
        let profile_columns_and_coefficients = selected_profile_coordinates.map(
            |(expected_ciphertext_ordinal, expected_auxiliary_ordinal, expected_option_ordinal)| {
                let column_ordinal = evaluator
                    .source_by_column
                    .iter()
                    .enumerate()
                    .find_map(|(column_index, source)| match source {
                        Some(BallotValidityVerifierColumnSource::PairCharacterEncoderProfile {
                            ciphertext_ordinal,
                            auxiliary_ordinal,
                            option_ordinal,
                        }) if (*ciphertext_ordinal, *auxiliary_ordinal, *option_ordinal)
                            == (
                                expected_ciphertext_ordinal,
                                expected_auxiliary_ordinal,
                                expected_option_ordinal,
                            ) =>
                        {
                            Some(u32::try_from(column_index).expect("column ordinal"))
                        }
                        _ => None,
                    })
                    .expect("selected pair-character encoder profile source");
                let profile_rows = compilation
                    .source_plan()
                    .encoder_profile_sequence(
                        expected_ciphertext_ordinal,
                        expected_auxiliary_ordinal,
                        expected_option_ordinal,
                    )
                    .expect("encoder profile sequence")
                    .into_iter()
                    .map(ProofBaseFieldElement::from_canonical)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("canonical encoder profile");
                assert!(
                    profile_rows
                        .iter()
                        .any(|value| *value != ProofBaseFieldElement::ZERO)
                );
                let profile_coefficients = trace_domain
                    .interpolate_base_polynomial(&profile_rows)
                    .expect("independent full-sequence interpolation");
                (column_ordinal, profile_coefficients)
            },
        );
        let second_point =
            ProofChallengeExtensionElement::from_canonical_coordinates([17, 19, 23, 29, 31])
                .expect("second extension point");
        for evaluation_point in [point, second_point] {
            let mut retained_cache_allocation = None;
            for (profile_column_ordinal, profile_coefficients) in &profile_columns_and_coefficients
            {
                let expected_profile = profile_coefficients.iter().rev().fold(
                    ProofChallengeExtensionElement::ZERO,
                    |accumulated, coefficient| {
                        accumulated
                            .multiply(evaluation_point)
                            .add(ProofChallengeExtensionElement::from_base(*coefficient))
                    },
                );
                assert_eq!(
                    evaluator
                        .evaluate_at_extension_point(*profile_column_ordinal, evaluation_point,),
                    Some(expected_profile),
                );
                let cached_lagrange_weights = evaluator
                    .cached_pair_character_lagrange_weights
                    .as_ref()
                    .expect("compact pair-character Lagrange cache");
                assert_eq!(
                    cached_lagrange_weights.point_coordinates,
                    evaluation_point.canonical_coordinates(),
                );
                assert_eq!(
                    cached_lagrange_weights.weights.len(),
                    PAIR_CHARACTER_PROFILE_LAGRANGE_WEIGHT_COUNT,
                );
                if let Some(allocation) = retained_cache_allocation {
                    assert_eq!(cached_lagrange_weights.weights.as_ptr(), allocation);
                } else {
                    retained_cache_allocation = Some(cached_lagrange_weights.weights.as_ptr());
                }
            }
        }
        assert_eq!(
            evaluator
                .cached_column
                .as_ref()
                .expect("authenticated coefficient cache remains separate")
                .column_ordinal,
            column_ordinal,
            "virtual encoder evaluation must not materialize a full trace column",
        );
        let subgroup_point = ProofChallengeExtensionElement::from_base(
            trace_domain.point(17).expect("subgroup evaluation point"),
        );
        assert_eq!(
            evaluator
                .evaluate_at_extension_point(profile_columns_and_coefficients[0].0, subgroup_point,),
            None,
            "the sparse evaluator must reject a zero subgroup denominator",
        );
        assert_eq!(
            evaluator
                .cached_pair_character_lagrange_weights
                .as_ref()
                .expect("prior valid compact cache")
                .point_coordinates,
            second_point.canonical_coordinates(),
            "a rejected subgroup point must not replace the valid cache",
        );
        assert_eq!(
            evaluator.evaluate_at_extension_point(column_ordinal, point),
            Some(expected),
            "switching back must derive only the requested authenticated column"
        );
        let evaluator_accounting = evaluator.memory_accounting().expect("memory accounting");
        let trace_column_byte_length = u64::try_from(TEST_RING_DEGREE as usize)
            .expect("ring degree")
            * u64::try_from(size_of::<ProofBaseFieldElement>()).expect("field width");
        let pair_character_lagrange_cache_byte_length =
            u64::try_from(PAIR_CHARACTER_PROFILE_LAGRANGE_WEIGHT_COUNT)
                .expect("profile weight count")
                * u64::try_from(size_of::<ProofChallengeExtensionElement>())
                    .expect("extension width");
        assert_eq!(
            evaluator_accounting.maximum_cached_column_resident_byte_length(),
            trace_column_byte_length + pair_character_lagrange_cache_byte_length,
        );
        assert_eq!(
            evaluator_accounting.maximum_evaluation_transient_byte_length(),
            trace_column_byte_length.max(2 * pair_character_lagrange_cache_byte_length),
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
