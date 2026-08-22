//! Exact CDHZ Appendix A.1 adaptive-soundness arithmetic for the selected
//! compact proof.
//!
//! This module maps an emitted-byte census into the theorem coordinates used
//! by the selected implicit-instance-free construction. The census is not a
//! proof-acceptance capability: the caller must also provide independently
//! owned semantic, masking-correspondence, emitted-byte,
//! Merkle-privacy-correspondence, and fixed-tape premises. The masking,
//! emitted-byte, and Merkle premises remain conditional; the fixed-tape owner
//! now has a source-verified ideal-QRO domain-extension constructor. Concrete
//! shared Keccak instantiation remains outside this arithmetic.

use std::cmp::Ordering;

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::compact_emitted_cdhz::CompactEmittedCdhzMeasurement;
use super::compact_factor_one_semantics::CompactFactorOneSemanticErrorTheorem;
use super::compact_fixed_tape_uniformity::CompactFixedTapeUniformityPremise;
use super::compact_proof_contract::CompactPublicKeyProofContract;
use super::compact_response_merkle::{
    COMPACT_RESPONSE_LEAF_HASH_DOMAIN, COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
    CompactResponseQuerySelection,
};
use super::compact_transcript::COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN;
use super::fixed_uniform_verifier_message::FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN;
use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE,
};
use crate::foundation::{DECLARED_ADVERSARIAL_QUERY_BUDGET, Hash512};

const STATE_RESTORATION_MULTIPLIER: u64 = 80;
const APPENDIX_A_ONE_STATE_RESTORATION_MULTIPLIER: u64 = 4;
const MERKLE_OFFLINE_MASS_MULTIPLIER: u64 = 160;
const MERKLE_OFFLINE_FIXED_MULTIPLIER: u64 = 16;
const APPENDIX_A_ONE_OFFLINE_MULTIPLIER: u64 = 4;
const MERKLE_ONLINE_MULTIPLIER: u64 = 240;
const APPENDIX_A_ONE_ONLINE_MULTIPLIER: u64 = 4;
const MERKLE_COMMUTATIVITY_MULTIPLIER: u64 = 240;
const APPENDIX_A_ONE_COMMUTATIVITY_MULTIPLIER: u64 = 2;
const TARGET_ADAPTIVE_SOUNDNESS_DENOMINATOR_EXPONENT: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCdhzAppendixAOneError {
    MissingEmittedMeasurement,
    MissingSemanticPremise,
    MissingMaskingPremise,
    MissingEmittedBytePremise,
    MissingMerklePrivacyPremise,
    MissingFixedTapeUniformityPremise,
    PremiseBindingMismatch,
    FixedTapeUniformityPremiseMismatch,
    UnexpectedEmittedCoordinates,
    InvalidRelaxedRoundByRoundKnowledgeBound,
    AdaptiveSoundnessTargetExceeded,
    ArithmeticOverflow,
}

/// A canonical exact nonnegative rational. Values above one are permitted
/// because theorem upper bounds are not truncated probabilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzExactRational {
    numerator: BigUint,
    denominator: BigUint,
}

impl CompactCdhzExactRational {
    fn try_new(
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, CompactCdhzAppendixAOneError> {
        if denominator.is_zero() {
            return Err(CompactCdhzAppendixAOneError::InvalidRelaxedRoundByRoundKnowledgeBound);
        }
        Ok(Self::from_nonzero_parts(numerator, denominator))
    }

    fn from_nonzero_parts(numerator: BigUint, denominator: BigUint) -> Self {
        debug_assert!(!denominator.is_zero());
        let greatest_common_divisor =
            greatest_common_divisor(numerator.clone(), denominator.clone());
        Self {
            numerator: numerator / &greatest_common_divisor,
            denominator: denominator / greatest_common_divisor,
        }
    }

    fn zero() -> Self {
        Self {
            numerator: BigUint::zero(),
            denominator: BigUint::one(),
        }
    }

    fn add(&self, right: &Self) -> Self {
        let common_divisor =
            greatest_common_divisor(self.denominator.clone(), right.denominator.clone());
        let left_scale = &right.denominator / &common_divisor;
        let right_scale = &self.denominator / &common_divisor;
        Self::from_nonzero_parts(
            &self.numerator * &left_scale + &right.numerator * &right_scale,
            &self.denominator * left_scale,
        )
    }

    fn scale(&self, multiplier: &BigUint) -> Self {
        Self::from_nonzero_parts(&self.numerator * multiplier, self.denominator.clone())
    }

    fn checked_subtract(&self, right: &Self) -> Option<Self> {
        let common_divisor =
            greatest_common_divisor(self.denominator.clone(), right.denominator.clone());
        let left_scale = &right.denominator / &common_divisor;
        let right_scale = &self.denominator / &common_divisor;
        let left_numerator = &self.numerator * &left_scale;
        let right_numerator = &right.numerator * &right_scale;
        (left_numerator >= right_numerator).then(|| {
            Self::from_nonzero_parts(
                left_numerator - right_numerator,
                &self.denominator * left_scale,
            )
        })
    }

    fn divide_by_positive_integer(&self, divisor: &BigUint) -> Option<Self> {
        (!divisor.is_zero())
            .then(|| Self::from_nonzero_parts(self.numerator.clone(), &self.denominator * divisor))
    }
}

impl PartialOrd for CompactCdhzExactRational {
    fn partial_cmp(&self, right: &Self) -> Option<Ordering> {
        Some(self.cmp(right))
    }
}

impl Ord for CompactCdhzExactRational {
    fn cmp(&self, right: &Self) -> Ordering {
        (&self.numerator * &right.denominator).cmp(&(&right.numerator * &self.denominator))
    }
}

/// Semantic maximum of the production relaxed round-by-round knowledge-error
/// bounds. Its production constructor consumes the opaque theorem minted by
/// the executable semantic adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactRelaxedRoundByRoundKnowledgeBound {
    maximum_error: CompactCdhzExactRational,
}

impl CompactRelaxedRoundByRoundKnowledgeBound {
    pub(super) fn from_factor_one_semantic_theorem(
        theorem: CompactFactorOneSemanticErrorTheorem,
    ) -> Result<Self, CompactCdhzAppendixAOneError> {
        let (numerator, denominator) = theorem.into_maximum_error_parts();
        let maximum_error = CompactCdhzExactRational::try_new(numerator, denominator)?;
        if maximum_error.numerator > maximum_error.denominator {
            return Err(CompactCdhzAppendixAOneError::InvalidRelaxedRoundByRoundKnowledgeBound);
        }
        Ok(Self { maximum_error })
    }

    #[cfg(test)]
    pub(crate) fn from_ratio_for_test(
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, CompactCdhzAppendixAOneError> {
        let maximum_error = CompactCdhzExactRational::try_new(numerator, denominator)?;
        if maximum_error.numerator > maximum_error.denominator {
            return Err(CompactCdhzAppendixAOneError::InvalidRelaxedRoundByRoundKnowledgeBound);
        }
        Ok(Self { maximum_error })
    }

    pub(crate) const fn maximum_error(&self) -> &CompactCdhzExactRational {
        &self.maximum_error
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactCdhzEmittedByteBinding {
    canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
}

impl CompactCdhzEmittedByteBinding {
    fn from_measurement(measurement: &CompactEmittedCdhzMeasurement) -> Self {
        let census = &measurement.decoded_actual_byte_census;
        Self {
            canonical_proof_binding: census.canonical_proof_binding,
            canonical_public_input_binding: census.canonical_public_input_binding,
        }
    }

    fn matches_measurement(&self, measurement: &CompactEmittedCdhzMeasurement) -> bool {
        self == &Self::from_measurement(measurement)
    }
}

/// Conditional bridge from the construction-level masking theorem to one
/// exact emitted byte pair. No production constructor exists before the live
/// algebraic chain supplies that correspondence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzMaskingPremise {
    emitted_byte_binding: CompactCdhzEmittedByteBinding,
}

/// Conditional correspondence between the executable relation owners and one
/// exact emitted byte pair. Strict transport validation alone cannot mint it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzEmittedBytePremise {
    emitted_byte_binding: CompactCdhzEmittedByteBinding,
}

/// Conditional bridge from the salted-Merkle privacy theorem to every opening
/// in one exact emitted byte pair. The geometry certificate alone cannot mint
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzMerklePrivacyPremise {
    emitted_byte_binding: CompactCdhzEmittedByteBinding,
}

/// Complete prerequisite bundle for the conditional Appendix A.1 calculator.
/// Every field is optional so absence has a typed refusal, but an arithmetic
/// certificate requires all five independently owned premises.
pub(crate) struct CompactCdhzAppendixAOnePremises<'premise> {
    semantic: Option<&'premise CompactRelaxedRoundByRoundKnowledgeBound>,
    masking: Option<CompactCdhzMaskingPremise>,
    emitted_byte: Option<CompactCdhzEmittedBytePremise>,
    merkle_privacy: Option<CompactCdhzMerklePrivacyPremise>,
    fixed_tape_uniformity: Option<&'premise CompactFixedTapeUniformityPremise>,
}

impl CompactCdhzMaskingPremise {
    #[cfg(test)]
    fn assume_for_appendix_arithmetic_test(measurement: &CompactEmittedCdhzMeasurement) -> Self {
        Self {
            emitted_byte_binding: CompactCdhzEmittedByteBinding::from_measurement(measurement),
        }
    }
}

impl CompactCdhzEmittedBytePremise {
    #[cfg(test)]
    fn assume_for_appendix_arithmetic_test(measurement: &CompactEmittedCdhzMeasurement) -> Self {
        Self {
            emitted_byte_binding: CompactCdhzEmittedByteBinding::from_measurement(measurement),
        }
    }
}

impl CompactCdhzMerklePrivacyPremise {
    #[cfg(test)]
    fn assume_for_appendix_arithmetic_test(measurement: &CompactEmittedCdhzMeasurement) -> Self {
        Self {
            emitted_byte_binding: CompactCdhzEmittedByteBinding::from_measurement(measurement),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzAppendixAOneCoordinates {
    adversarial_query_bound: BigUint,
    response_vector_commitment_count: u64,
    proof_query_bound: u64,
    verifier_random_oracle_query_bound: u64,
    maximum_proof_vector_symbol_length: u64,
    minimum_verifier_randomness_bit_length: u64,
    random_oracle_output_bit_length: u16,
    input_implicit_instance_tuple_size: u64,
    output_implicit_instance_tuple_size: u64,
}

impl CompactCdhzAppendixAOneCoordinates {
    fn try_from_measurement(
        measurement: &CompactEmittedCdhzMeasurement,
    ) -> Result<Self, CompactCdhzAppendixAOneError> {
        measurement
            .validate_internal_consistency()
            .map_err(|_| CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)?;
        let selected_contract = CompactPublicKeyProofContract::decode_selected()
            .map_err(|_| CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)?;
        let selected_verifier_inputs = selected_contract.verifier_inputs();
        let expected_distinct_query_group_count = selected_verifier_inputs
            .verifier_moves
            .iter()
            .try_fold(0_u64, |count, verifier_move| {
                count
                    .checked_add(
                        u64::try_from(verifier_move.message_geometry.distinct_query_groups().len())
                            .map_err(|_| CompactCdhzAppendixAOneError::ArithmeticOverflow)?,
                    )
                    .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)
            })?;
        let expected_distinct_query_group_element_count = selected_verifier_inputs
            .verifier_moves
            .iter()
            .flat_map(|verifier_move| verifier_move.message_geometry.distinct_query_groups())
            .try_fold(0_u64, |count, group| {
                count
                    .checked_add(group.query_count())
                    .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)
            })?;
        let expected_internal_relation_commitment_count = selected_verifier_inputs
            .verifier_moves
            .iter()
            .map(|verifier_move| u64::from(verifier_move.preceding_commitment_count))
            .max()
            .ok_or(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)?;
        let expected_query_group_consumer_edge_count = selected_verifier_inputs
            .response_merkle_geometries
            .iter()
            .flat_map(|geometry| geometry.components())
            .try_fold(0_u64, |count, component| {
                count
                    .checked_add(match component.query_selection() {
                        CompactResponseQuerySelection::Unqueried
                        | CompactResponseQuerySelection::EveryLeaf => 0,
                        CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. } => 1,
                        CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                            ..
                        } => 2,
                    })
                    .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)
            })?;
        let actual_byte_census = &measurement.decoded_actual_byte_census;
        if actual_byte_census.distinct_query_group_count != expected_distinct_query_group_count
            || actual_byte_census.distinct_query_group_element_count
                != expected_distinct_query_group_element_count
            || actual_byte_census.internal_relation_commitment_count
                != expected_internal_relation_commitment_count
            || actual_byte_census.verifier_query_group_consumer_edge_count
                != expected_query_group_consumer_edge_count
        {
            return Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates);
        }
        let mut minimum_verifier_randomness_bit_length = None;
        let mut concrete_fiat_shamir_query_count = 0_u64;
        let mut maximum_round_vector_symbol_length = 0_u64;
        let mut observed_proof_query_count = 0_u64;
        let mut theorem_proof_query_bound = 0_u64;
        let mut observed_vector_commitment_check_query_count = 0_u64;
        let mut geometry_vector_commitment_check_query_bound = 0_u64;
        for round in &measurement.rounds {
            let randomness_bit_length = round
                .fiat_shamir_message_byte_length
                .checked_mul(8)
                .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
            minimum_verifier_randomness_bit_length = Some(
                minimum_verifier_randomness_bit_length
                    .map_or(randomness_bit_length, |minimum: u64| {
                        minimum.min(randomness_bit_length)
                    }),
            );
            concrete_fiat_shamir_query_count = concrete_fiat_shamir_query_count
                .checked_add(round.concrete_fiat_shamir_hash_query_count)
                .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
            observed_proof_query_count = observed_proof_query_count
                .checked_add(round.observed_query_count)
                .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
            theorem_proof_query_bound = theorem_proof_query_bound
                .checked_add(round.geometry_query_count_bound)
                .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
            observed_vector_commitment_check_query_count =
                observed_vector_commitment_check_query_count
                    .checked_add(round.observed_query_count)
                    .and_then(|sum| sum.checked_add(round.observed_parent_hash_query_count))
                    .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
            geometry_vector_commitment_check_query_bound =
                geometry_vector_commitment_check_query_bound
                    .checked_add(round.geometry_query_count_bound)
                    .and_then(|sum| sum.checked_add(round.geometry_parent_hash_query_bound))
                    .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
            maximum_round_vector_symbol_length =
                maximum_round_vector_symbol_length.max(round.proof_vector_symbol_length);
        }
        let minimum_verifier_randomness_bit_length = minimum_verifier_randomness_bit_length
            .ok_or(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)?;
        let concrete_shared_qro_query_bound = concrete_fiat_shamir_query_count
            .checked_add(
                measurement
                    .merkle_multi_extraction
                    .geometry_check_oracle_query_bound,
            )
            .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
        let observed_shared_qro_query_count = concrete_fiat_shamir_query_count
            .checked_add(
                measurement
                    .merkle_multi_extraction
                    .observed_check_oracle_query_count,
            )
            .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
        if measurement.maximum_proof_vector_symbol_length == 0
            || !measurement
                .maximum_proof_vector_symbol_length
                .is_power_of_two()
        {
            return Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates);
        }
        // Theorem 8.3 bounds the fixed part of kappa_offline by
        // `16 * qPi * log2(lpmax) / 2^sigma`. Its q2 coordinate appears only
        // in kappa_extract, which Appendix A.1 does not include.
        let expected_offline_check_query_bound = measurement
            .merkle_multi_extraction
            .theorem_offline_query_set_bound
            .checked_mul(u64::from(
                measurement.maximum_proof_vector_symbol_length.ilog2(),
            ))
            .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
        let expected_response_count = u64::try_from(measurement.rounds.len())
            .map_err(|_| CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
        let domains = measurement.random_oracle_domains;

        let expected_random_oracle_output_bit_length = u16::try_from(Hash512::BYTE_LENGTH * 8)
            .map_err(|_| CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
        let expected_secret_leaf_salt_bit_length =
            u16::try_from(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH * 8)
                .map_err(|_| CompactCdhzAppendixAOneError::ArithmeticOverflow)?;

        if expected_response_count == 0
            || measurement.response_vector_commitment_count != expected_response_count
            || measurement.maximum_proof_vector_symbol_length != maximum_round_vector_symbol_length
            || measurement.observed_proof_query_count != observed_proof_query_count
            || measurement.theorem_proof_query_bound != theorem_proof_query_bound
            || concrete_shared_qro_query_bound != measurement.nrdx_verifier_q_v_bound
            || measurement.observed_nrdx_verifier_q_v != observed_shared_qro_query_count
            || measurement.observed_proof_query_count > measurement.theorem_proof_query_bound
            || measurement.observed_nrdx_verifier_q_v > measurement.nrdx_verifier_q_v_bound
            || measurement.merkle_multi_extraction.output_bit_length
                != expected_random_oracle_output_bit_length
            || measurement.merkle_multi_extraction.leaf_salt_bit_length
                != expected_secret_leaf_salt_bit_length
            || measurement
                .merkle_multi_extraction
                .vector_commitment_tuple_size
                != expected_response_count
            || measurement
                .merkle_multi_extraction
                .input_implicit_instance_tuple_size
                != 0
            || measurement
                .merkle_multi_extraction
                .output_implicit_instance_tuple_size
                != 0
            || measurement
                .merkle_multi_extraction
                .observed_check_oracle_query_count
                != observed_vector_commitment_check_query_count
            || measurement
                .merkle_multi_extraction
                .geometry_check_oracle_query_bound
                != geometry_vector_commitment_check_query_bound
            || measurement
                .merkle_multi_extraction
                .observed_check_oracle_query_count
                > measurement
                    .merkle_multi_extraction
                    .geometry_check_oracle_query_bound
            || measurement
                .merkle_multi_extraction
                .theorem_offline_query_set_bound
                != measurement.theorem_proof_query_bound
            || measurement.merkle_multi_extraction.theorem_q1_bound
                != expected_offline_check_query_bound
            || measurement.oracle_family_census.fiat_shamir_oracle_count != expected_response_count
            || measurement
                .oracle_family_census
                .vector_commitment_oracle_count
                != expected_response_count
            || measurement.oracle_family_census.multi_extract_oracle_count != 1
            || domains.fiat_shamir_prefix != COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN
            || domains.verifier_message_block != FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN
            || domains.merkle_leaf != COMPACT_RESPONSE_LEAF_HASH_DOMAIN
            || domains.merkle_parent != COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN
        {
            return Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates);
        }

        Ok(Self {
            adversarial_query_bound: BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET),
            response_vector_commitment_count: measurement.response_vector_commitment_count,
            proof_query_bound: measurement.theorem_proof_query_bound,
            verifier_random_oracle_query_bound: measurement.nrdx_verifier_q_v_bound,
            maximum_proof_vector_symbol_length: measurement.maximum_proof_vector_symbol_length,
            minimum_verifier_randomness_bit_length,
            random_oracle_output_bit_length: measurement.merkle_multi_extraction.output_bit_length,
            input_implicit_instance_tuple_size: measurement
                .merkle_multi_extraction
                .input_implicit_instance_tuple_size,
            output_implicit_instance_tuple_size: measurement
                .merkle_multi_extraction
                .output_implicit_instance_tuple_size,
        })
    }

    pub(crate) const fn adversarial_query_bound(&self) -> &BigUint {
        &self.adversarial_query_bound
    }

    pub(crate) const fn response_vector_commitment_count(&self) -> u64 {
        self.response_vector_commitment_count
    }

    pub(crate) const fn proof_query_bound(&self) -> u64 {
        self.proof_query_bound
    }

    pub(crate) const fn verifier_random_oracle_query_bound(&self) -> u64 {
        self.verifier_random_oracle_query_bound
    }

    pub(crate) const fn maximum_proof_vector_symbol_length(&self) -> u64 {
        self.maximum_proof_vector_symbol_length
    }

    pub(crate) const fn minimum_verifier_randomness_bit_length(&self) -> u64 {
        self.minimum_verifier_randomness_bit_length
    }

    pub(crate) const fn random_oracle_output_bit_length(&self) -> u16 {
        self.random_oracle_output_bit_length
    }

    pub(crate) const fn input_implicit_instance_tuple_size(&self) -> u64 {
        self.input_implicit_instance_tuple_size
    }

    pub(crate) const fn output_implicit_instance_tuple_size(&self) -> u64 {
        self.output_implicit_instance_tuple_size
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCdhzOracleMassVertex {
    NoAdversarialQueries,
    FiatShamirOracle,
    StandardVectorCommitmentOracle,
    MultiExtractOracle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzOracleMassCoefficients {
    fiat_shamir_oracle: CompactCdhzExactRational,
    standard_vector_commitment_oracle: CompactCdhzExactRational,
    multi_extract_oracle: CompactCdhzExactRational,
}

impl CompactCdhzOracleMassCoefficients {
    pub(crate) const fn fiat_shamir_oracle(&self) -> &CompactCdhzExactRational {
        &self.fiat_shamir_oracle
    }

    pub(crate) const fn standard_vector_commitment_oracle(&self) -> &CompactCdhzExactRational {
        &self.standard_vector_commitment_oracle
    }

    pub(crate) const fn multi_extract_oracle(&self) -> &CompactCdhzExactRational {
        &self.multi_extract_oracle
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzSimplexVertexBounds {
    no_adversarial_queries: CompactCdhzExactRational,
    fiat_shamir_oracle: CompactCdhzExactRational,
    standard_vector_commitment_oracle: CompactCdhzExactRational,
    multi_extract_oracle: CompactCdhzExactRational,
}

impl CompactCdhzSimplexVertexBounds {
    pub(crate) const fn no_adversarial_queries(&self) -> &CompactCdhzExactRational {
        &self.no_adversarial_queries
    }

    pub(crate) const fn fiat_shamir_oracle(&self) -> &CompactCdhzExactRational {
        &self.fiat_shamir_oracle
    }

    pub(crate) const fn standard_vector_commitment_oracle(&self) -> &CompactCdhzExactRational {
        &self.standard_vector_commitment_oracle
    }

    pub(crate) const fn multi_extract_oracle(&self) -> &CompactCdhzExactRational {
        &self.multi_extract_oracle
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzAdaptiveSoundnessTerms {
    state_restoration_soundness: CompactCdhzExactRational,
    offline_extraction: CompactCdhzExactRational,
    online_indistinguishability: CompactCdhzExactRational,
    merkle_commutativity: CompactCdhzExactRational,
    fixed_tape_domain_extension: CompactCdhzExactRational,
    fixed_tape_sampler_exhaustion: CompactCdhzExactRational,
    total_adaptive_soundness: CompactCdhzExactRational,
}

impl CompactCdhzAdaptiveSoundnessTerms {
    pub(crate) const fn state_restoration_soundness(&self) -> &CompactCdhzExactRational {
        &self.state_restoration_soundness
    }

    pub(crate) const fn offline_extraction(&self) -> &CompactCdhzExactRational {
        &self.offline_extraction
    }

    pub(crate) const fn online_indistinguishability(&self) -> &CompactCdhzExactRational {
        &self.online_indistinguishability
    }

    pub(crate) const fn merkle_commutativity(&self) -> &CompactCdhzExactRational {
        &self.merkle_commutativity
    }

    pub(crate) const fn fixed_tape_domain_extension(&self) -> &CompactCdhzExactRational {
        &self.fixed_tape_domain_extension
    }

    pub(crate) const fn fixed_tape_sampler_exhaustion(&self) -> &CompactCdhzExactRational {
        &self.fixed_tape_sampler_exhaustion
    }

    pub(crate) const fn total_adaptive_soundness(&self) -> &CompactCdhzExactRational {
        &self.total_adaptive_soundness
    }
}

/// Exact remaining relaxed-RBR allowance under the complete `2^-80`
/// Appendix A.1 partition. The limiting vertex and its state coefficient are
/// derived together; no standalone reserve constant is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzKappaHeadroom {
    target_adaptive_soundness: CompactCdhzExactRational,
    limiting_vertex: CompactCdhzOracleMassVertex,
    limiting_state_term_coefficient: BigUint,
    limiting_nonsemantic_partition: CompactCdhzExactRational,
    maximum_relaxed_round_by_round_knowledge_bound: CompactCdhzExactRational,
}

impl CompactCdhzKappaHeadroom {
    pub(crate) const fn target_adaptive_soundness(&self) -> &CompactCdhzExactRational {
        &self.target_adaptive_soundness
    }

    pub(crate) const fn limiting_vertex(&self) -> CompactCdhzOracleMassVertex {
        self.limiting_vertex
    }

    pub(crate) const fn limiting_state_term_coefficient(&self) -> &BigUint {
        &self.limiting_state_term_coefficient
    }

    pub(crate) const fn limiting_nonsemantic_partition(&self) -> &CompactCdhzExactRational {
        &self.limiting_nonsemantic_partition
    }

    pub(crate) const fn maximum_relaxed_round_by_round_knowledge_bound(
        &self,
    ) -> &CompactCdhzExactRational {
        &self.maximum_relaxed_round_by_round_knowledge_bound
    }
}

/// Exact Appendix A.1 specialization for adaptive soundness with zero input
/// and output implicit-instance tuple sizes. It certifies arithmetic only;
/// proof acceptance still belongs to the production verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzAppendixAOneCertificate {
    coordinates: CompactCdhzAppendixAOneCoordinates,
    direct_initial_transition_bound: CompactCdhzExactRational,
    maximum_relaxed_round_by_round_knowledge_bound: CompactCdhzExactRational,
    oracle_mass_coefficients: CompactCdhzOracleMassCoefficients,
    simplex_vertex_bounds: CompactCdhzSimplexVertexBounds,
    maximizing_vertices: Vec<CompactCdhzOracleMassVertex>,
    selected_maximizing_vertex: CompactCdhzOracleMassVertex,
    adaptive_soundness_terms: CompactCdhzAdaptiveSoundnessTerms,
    kappa_headroom: CompactCdhzKappaHeadroom,
}

impl CompactCdhzAppendixAOneCertificate {
    pub(crate) const fn coordinates(&self) -> &CompactCdhzAppendixAOneCoordinates {
        &self.coordinates
    }

    pub(crate) const fn direct_initial_transition_bound(&self) -> &CompactCdhzExactRational {
        &self.direct_initial_transition_bound
    }

    pub(crate) const fn maximum_relaxed_round_by_round_knowledge_bound(
        &self,
    ) -> &CompactCdhzExactRational {
        &self.maximum_relaxed_round_by_round_knowledge_bound
    }

    pub(crate) const fn oracle_mass_coefficients(&self) -> &CompactCdhzOracleMassCoefficients {
        &self.oracle_mass_coefficients
    }

    pub(crate) const fn simplex_vertex_bounds(&self) -> &CompactCdhzSimplexVertexBounds {
        &self.simplex_vertex_bounds
    }

    pub(crate) fn maximizing_vertices(&self) -> &[CompactCdhzOracleMassVertex] {
        &self.maximizing_vertices
    }

    pub(crate) const fn selected_maximizing_vertex(&self) -> CompactCdhzOracleMassVertex {
        self.selected_maximizing_vertex
    }

    pub(crate) const fn adaptive_soundness_terms(&self) -> &CompactCdhzAdaptiveSoundnessTerms {
        &self.adaptive_soundness_terms
    }

    pub(crate) const fn kappa_headroom(&self) -> &CompactCdhzKappaHeadroom {
        &self.kappa_headroom
    }
}

/// Instantiates Appendix A.1 for one selected emitted census after every
/// independently owned prerequisite is byte-bound. The semantic relaxed
/// round-by-round knowledge bound upper-bounds the state-restoration premise;
/// the remaining losses are the exact Theorem 8.3 Merkle bounds and positive
/// fixed-tape terms in the Appendix A.1 argument positions.
pub(crate) fn derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(
    measurement: Option<&CompactEmittedCdhzMeasurement>,
    premises: &CompactCdhzAppendixAOnePremises<'_>,
) -> Result<CompactCdhzAppendixAOneCertificate, CompactCdhzAppendixAOneError> {
    let measurement = measurement.ok_or(CompactCdhzAppendixAOneError::MissingEmittedMeasurement)?;
    let relaxed_round_by_round_knowledge_bound = premises
        .semantic
        .ok_or(CompactCdhzAppendixAOneError::MissingSemanticPremise)?;
    let masking_premise = premises
        .masking
        .as_ref()
        .ok_or(CompactCdhzAppendixAOneError::MissingMaskingPremise)?;
    let emitted_byte_premise = premises
        .emitted_byte
        .as_ref()
        .ok_or(CompactCdhzAppendixAOneError::MissingEmittedBytePremise)?;
    let merkle_privacy_premise = premises
        .merkle_privacy
        .as_ref()
        .ok_or(CompactCdhzAppendixAOneError::MissingMerklePrivacyPremise)?;
    let fixed_tape_uniformity_premise = premises
        .fixed_tape_uniformity
        .ok_or(CompactCdhzAppendixAOneError::MissingFixedTapeUniformityPremise)?;
    if !masking_premise
        .emitted_byte_binding
        .matches_measurement(measurement)
        || !emitted_byte_premise
            .emitted_byte_binding
            .matches_measurement(measurement)
        || !merkle_privacy_premise
            .emitted_byte_binding
            .matches_measurement(measurement)
    {
        return Err(CompactCdhzAppendixAOneError::PremiseBindingMismatch);
    }
    fixed_tape_uniformity_premise
        .validate_measurement(measurement)
        .map_err(|_| CompactCdhzAppendixAOneError::FixedTapeUniformityPremiseMismatch)?;
    let coordinates = CompactCdhzAppendixAOneCoordinates::try_from_measurement(measurement)?;
    if fixed_tape_uniformity_premise.round_count()
        != usize::try_from(coordinates.response_vector_commitment_count())
            .map_err(|_| CompactCdhzAppendixAOneError::ArithmeticOverflow)?
        || fixed_tape_uniformity_premise.minimum_uniform_message_bit_length()
            != coordinates.minimum_verifier_randomness_bit_length()
    {
        return Err(CompactCdhzAppendixAOneError::FixedTapeUniformityPremiseMismatch);
    }
    let direct_initial_transition_bound = compact_cfw_direct_initial_transition_bound();
    if relaxed_round_by_round_knowledge_bound.maximum_error() < &direct_initial_transition_bound {
        return Err(CompactCdhzAppendixAOneError::InvalidRelaxedRoundByRoundKnowledgeBound);
    }

    let adversarial_query_bound = coordinates.adversarial_query_bound();
    let round_count = BigUint::from(coordinates.response_vector_commitment_count());
    let proof_query_bound = BigUint::from(coordinates.proof_query_bound());
    let maximum_proof_vector_depth =
        BigUint::from(coordinates.maximum_proof_vector_symbol_length().ilog2());
    let verifier_random_oracle_query_bound =
        BigUint::from(coordinates.verifier_random_oracle_query_bound());
    let one = BigUint::one();
    let state_query_factor = adversarial_query_bound + &round_count + &one;
    let offline_query_factor = adversarial_query_bound * BigUint::from(2_u8) + &one;
    let online_query_factor =
        adversarial_query_bound + &one + &verifier_random_oracle_query_bound + &round_count;
    // Appendix A.1 passes `t + 1 + k + qV` as the commutativity query
    // argument. Theorem 8.3 contributes the final `+ 1`.
    let commutativity_query_factor = &online_query_factor + &one;
    let random_oracle_denominator =
        BigUint::one() << usize::from(coordinates.random_oracle_output_bit_length());

    let fiat_shamir_oracle_coefficient = relaxed_round_by_round_knowledge_bound
        .maximum_error()
        .scale(
            &(BigUint::from(
                APPENDIX_A_ONE_STATE_RESTORATION_MULTIPLIER * STATE_RESTORATION_MULTIPLIER,
            ) * &state_query_factor),
        );
    // For mass coordinates `(x, y, z) = (wFS, wVC, wMultiExtract)`, Appendix
    // A.1 passes `(2t + 1, y, z + 2x + 1, sigma, lpmax, qPi)` to
    // kappa_offline. Theorem 8.3 is independent of its MultiExtract-mass
    // argument, leaving only the `y` coefficient and fixed qPi term below.
    let standard_vector_commitment_oracle_coefficient =
        CompactCdhzExactRational::from_nonzero_parts(
            BigUint::from(APPENDIX_A_ONE_OFFLINE_MULTIPLIER * MERKLE_OFFLINE_MASS_MULTIPLIER)
                * &offline_query_factor
                * &offline_query_factor,
            random_oracle_denominator.clone(),
        );
    // Definition 7.3 orders the online mass arguments as standard VC,
    // MultiExtract, and Record. Appendix A.1 passes `(z + 1, y, x + k)`, so
    // Theorem 8.3's online bound is affine in MultiExtract mass `z` and is
    // independent of the latter two positions.
    let multi_extract_oracle_coefficient = CompactCdhzExactRational::from_nonzero_parts(
        BigUint::from(APPENDIX_A_ONE_ONLINE_MULTIPLIER * MERKLE_ONLINE_MULTIPLIER)
            * &online_query_factor
            * &online_query_factor,
        random_oracle_denominator.clone(),
    );
    let oracle_mass_coefficients = CompactCdhzOracleMassCoefficients {
        fiat_shamir_oracle: fiat_shamir_oracle_coefficient,
        standard_vector_commitment_oracle: standard_vector_commitment_oracle_coefficient,
        multi_extract_oracle: multi_extract_oracle_coefficient,
    };

    let fixed_state_restoration_semantic_error = oracle_mass_coefficients
        .fiat_shamir_oracle()
        .scale(&round_count);
    let fixed_verifier_randomness = CompactCdhzExactRational::from_nonzero_parts(
        BigUint::from(APPENDIX_A_ONE_STATE_RESTORATION_MULTIPLIER)
            * &state_query_factor
            * &round_count,
        BigUint::one()
            << usize::try_from(coordinates.minimum_verifier_randomness_bit_length())
                .map_err(|_| CompactCdhzAppendixAOneError::ArithmeticOverflow)?,
    );
    let fixed_offline_extraction = CompactCdhzExactRational::from_nonzero_parts(
        BigUint::from(APPENDIX_A_ONE_OFFLINE_MULTIPLIER * MERKLE_OFFLINE_FIXED_MULTIPLIER)
            * &proof_query_bound
            * &maximum_proof_vector_depth,
        random_oracle_denominator.clone(),
    );
    let fixed_online_indistinguishability = oracle_mass_coefficients.multi_extract_oracle().clone();
    let merkle_commutativity = CompactCdhzExactRational::from_nonzero_parts(
        BigUint::from(APPENDIX_A_ONE_COMMUTATIVITY_MULTIPLIER * MERKLE_COMMUTATIVITY_MULTIPLIER)
            * &verifier_random_oracle_query_bound
            * &verifier_random_oracle_query_bound
            * &commutativity_query_factor,
        random_oracle_denominator,
    );
    let (domain_extension_numerator, domain_extension_denominator) =
        fixed_tape_uniformity_premise.domain_extension_loss_parts();
    let fixed_tape_domain_extension = fixed_tape_loss(
        domain_extension_numerator.clone(),
        domain_extension_denominator.clone(),
    )?;
    let (sampler_exhaustion_numerator, sampler_exhaustion_denominator) =
        fixed_tape_uniformity_premise.sampler_exhaustion_loss_parts();
    let fixed_tape_sampler_exhaustion = fixed_tape_loss(
        sampler_exhaustion_numerator.clone(),
        sampler_exhaustion_denominator.clone(),
    )?;
    let fixed_nonsemantic_terms = fixed_verifier_randomness
        .add(&fixed_offline_extraction)
        .add(&fixed_online_indistinguishability)
        .add(&merkle_commutativity)
        .add(&fixed_tape_domain_extension)
        .add(&fixed_tape_sampler_exhaustion);
    let target_adaptive_soundness = CompactCdhzExactRational::from_nonzero_parts(
        BigUint::one(),
        BigUint::one() << TARGET_ADAPTIVE_SOUNDNESS_DENOMINATOR_EXPONENT,
    );
    let state_term_coefficient_per_mass =
        BigUint::from(APPENDIX_A_ONE_STATE_RESTORATION_MULTIPLIER * STATE_RESTORATION_MULTIPLIER)
            * &state_query_factor;
    let kappa_headroom_candidates = [
        (
            CompactCdhzOracleMassVertex::NoAdversarialQueries,
            &state_term_coefficient_per_mass * &round_count,
            fixed_nonsemantic_terms.clone(),
        ),
        (
            CompactCdhzOracleMassVertex::FiatShamirOracle,
            &state_term_coefficient_per_mass * (adversarial_query_bound + &round_count),
            fixed_nonsemantic_terms.clone(),
        ),
        (
            CompactCdhzOracleMassVertex::StandardVectorCommitmentOracle,
            &state_term_coefficient_per_mass * &round_count,
            fixed_nonsemantic_terms.add(
                &oracle_mass_coefficients
                    .standard_vector_commitment_oracle()
                    .scale(adversarial_query_bound),
            ),
        ),
        (
            CompactCdhzOracleMassVertex::MultiExtractOracle,
            &state_term_coefficient_per_mass * &round_count,
            fixed_nonsemantic_terms.add(
                &oracle_mass_coefficients
                    .multi_extract_oracle()
                    .scale(adversarial_query_bound),
            ),
        ),
    ];
    let mut kappa_headroom = None;
    for (vertex, state_term_coefficient, nonsemantic_partition) in kappa_headroom_candidates {
        let residual = target_adaptive_soundness
            .checked_subtract(&nonsemantic_partition)
            .ok_or(CompactCdhzAppendixAOneError::AdaptiveSoundnessTargetExceeded)?;
        let maximum_knowledge_bound = residual
            .divide_by_positive_integer(&state_term_coefficient)
            .ok_or(CompactCdhzAppendixAOneError::ArithmeticOverflow)?;
        if kappa_headroom
            .as_ref()
            .is_none_or(|current: &CompactCdhzKappaHeadroom| {
                maximum_knowledge_bound < current.maximum_relaxed_round_by_round_knowledge_bound
            })
        {
            kappa_headroom = Some(CompactCdhzKappaHeadroom {
                target_adaptive_soundness: target_adaptive_soundness.clone(),
                limiting_vertex: vertex,
                limiting_state_term_coefficient: state_term_coefficient,
                limiting_nonsemantic_partition: nonsemantic_partition,
                maximum_relaxed_round_by_round_knowledge_bound: maximum_knowledge_bound,
            });
        }
    }
    let kappa_headroom =
        kappa_headroom.ok_or(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)?;
    if relaxed_round_by_round_knowledge_bound.maximum_error()
        > kappa_headroom.maximum_relaxed_round_by_round_knowledge_bound()
    {
        return Err(CompactCdhzAppendixAOneError::AdaptiveSoundnessTargetExceeded);
    }
    let fixed_terms = fixed_state_restoration_semantic_error.add(&fixed_nonsemantic_terms);

    let simplex_vertex_bounds = CompactCdhzSimplexVertexBounds {
        no_adversarial_queries: fixed_terms.clone(),
        fiat_shamir_oracle: fixed_terms.add(
            &oracle_mass_coefficients
                .fiat_shamir_oracle()
                .scale(adversarial_query_bound),
        ),
        standard_vector_commitment_oracle: fixed_terms.add(
            &oracle_mass_coefficients
                .standard_vector_commitment_oracle()
                .scale(adversarial_query_bound),
        ),
        multi_extract_oracle: fixed_terms.add(
            &oracle_mass_coefficients
                .multi_extract_oracle()
                .scale(adversarial_query_bound),
        ),
    };
    let maximizing_vertices = maximizing_vertices(&simplex_vertex_bounds);
    let selected_maximizing_vertex = *maximizing_vertices
        .first()
        .ok_or(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)?;
    let fiat_shamir_mass = match selected_maximizing_vertex {
        CompactCdhzOracleMassVertex::FiatShamirOracle => adversarial_query_bound.clone(),
        _ => BigUint::zero(),
    };
    let standard_vector_commitment_mass = match selected_maximizing_vertex {
        CompactCdhzOracleMassVertex::StandardVectorCommitmentOracle => {
            adversarial_query_bound.clone()
        }
        _ => BigUint::zero(),
    };
    let multi_extract_mass = match selected_maximizing_vertex {
        CompactCdhzOracleMassVertex::MultiExtractOracle => adversarial_query_bound.clone(),
        _ => BigUint::zero(),
    };
    let state_restoration_soundness = oracle_mass_coefficients
        .fiat_shamir_oracle()
        .scale(&(&fiat_shamir_mass + &round_count))
        .add(&fixed_verifier_randomness);
    let offline_extraction = fixed_offline_extraction.add(
        &oracle_mass_coefficients
            .standard_vector_commitment_oracle()
            .scale(&standard_vector_commitment_mass),
    );
    let online_indistinguishability = fixed_online_indistinguishability.add(
        &oracle_mass_coefficients
            .multi_extract_oracle()
            .scale(&multi_extract_mass),
    );
    let total_adaptive_soundness = state_restoration_soundness
        .add(&offline_extraction)
        .add(&online_indistinguishability)
        .add(&merkle_commutativity)
        .add(&fixed_tape_domain_extension)
        .add(&fixed_tape_sampler_exhaustion);
    if &total_adaptive_soundness
        != simplex_vertex_bound(&simplex_vertex_bounds, selected_maximizing_vertex)
    {
        return Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates);
    }
    if total_adaptive_soundness > target_adaptive_soundness {
        return Err(CompactCdhzAppendixAOneError::AdaptiveSoundnessTargetExceeded);
    }

    Ok(CompactCdhzAppendixAOneCertificate {
        coordinates,
        direct_initial_transition_bound,
        maximum_relaxed_round_by_round_knowledge_bound: relaxed_round_by_round_knowledge_bound
            .maximum_error()
            .clone(),
        oracle_mass_coefficients,
        simplex_vertex_bounds,
        maximizing_vertices,
        selected_maximizing_vertex,
        adaptive_soundness_terms: CompactCdhzAdaptiveSoundnessTerms {
            state_restoration_soundness,
            offline_extraction,
            online_indistinguishability,
            merkle_commutativity,
            fixed_tape_domain_extension,
            fixed_tape_sampler_exhaustion,
            total_adaptive_soundness,
        },
        kappa_headroom,
    })
}

/// Direct `24 / |F|` initial-transition argument. It is deliberately separate
/// from the maximum relaxed round-by-round knowledge bound and is not an
/// instantiation of the incompatible printed CFW formula.
pub(crate) fn compact_cfw_direct_initial_transition_bound() -> CompactCdhzExactRational {
    let lemma = super::compact_cfw_initial_transition::derive_selected_compact_cfw_initial_transition_lemma()
        .expect("the selected initial CFW transition lemma derives from the checked contract");
    CompactCdhzExactRational::from_nonzero_parts(
        BigUint::from(lemma.soundness_numerator),
        lemma.challenge_field_cardinality,
    )
}

fn selected_challenge_field_cardinality() -> BigUint {
    BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(
        u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .expect("challenge extension degree fits in u32"),
    )
}

fn fixed_tape_loss(
    numerator: BigUint,
    denominator: BigUint,
) -> Result<CompactCdhzExactRational, CompactCdhzAppendixAOneError> {
    if numerator.is_zero() || denominator.is_zero() || numerator > denominator {
        return Err(CompactCdhzAppendixAOneError::FixedTapeUniformityPremiseMismatch);
    }
    Ok(CompactCdhzExactRational::from_nonzero_parts(
        numerator,
        denominator,
    ))
}

fn maximizing_vertices(
    bounds: &CompactCdhzSimplexVertexBounds,
) -> Vec<CompactCdhzOracleMassVertex> {
    let candidates = [
        (
            CompactCdhzOracleMassVertex::NoAdversarialQueries,
            bounds.no_adversarial_queries(),
        ),
        (
            CompactCdhzOracleMassVertex::FiatShamirOracle,
            bounds.fiat_shamir_oracle(),
        ),
        (
            CompactCdhzOracleMassVertex::StandardVectorCommitmentOracle,
            bounds.standard_vector_commitment_oracle(),
        ),
        (
            CompactCdhzOracleMassVertex::MultiExtractOracle,
            bounds.multi_extract_oracle(),
        ),
    ];
    let Some(maximum) = candidates.iter().map(|(_, bound)| *bound).max() else {
        return Vec::new();
    };
    candidates
        .into_iter()
        .filter(|(_, bound)| *bound == maximum)
        .map(|(vertex, _)| vertex)
        .collect()
}

fn simplex_vertex_bound(
    bounds: &CompactCdhzSimplexVertexBounds,
    vertex: CompactCdhzOracleMassVertex,
) -> &CompactCdhzExactRational {
    match vertex {
        CompactCdhzOracleMassVertex::NoAdversarialQueries => bounds.no_adversarial_queries(),
        CompactCdhzOracleMassVertex::FiatShamirOracle => bounds.fiat_shamir_oracle(),
        CompactCdhzOracleMassVertex::StandardVectorCommitmentOracle => {
            bounds.standard_vector_commitment_oracle()
        }
        CompactCdhzOracleMassVertex::MultiExtractOracle => bounds.multi_extract_oracle(),
    }
}

fn greatest_common_divisor(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_emitted_cdhz::{
        CompactCdhzMerkleMultiExtractionTerms, CompactCdhzOracleFamilyCensus,
        CompactCdhzRandomOracleDomains, CompactDecodedActualByteCensus, CompactEmittedCdhzRound,
        CompactSharedHashGraphCensus,
    };
    use crate::bgv::proof_suite::compact_proof_contract::CompactPublicKeyProofContract;

    const TEST_RESPONSE_VECTOR_COMMITMENT_COUNT: u64 = 82;
    const TEST_PROOF_QUERY_BOUND: u64 = 79_310;
    const TEST_CONCRETE_FIAT_SHAMIR_QUERY_COUNT: u64 = 181_522;
    const TEST_VECTOR_COMMITMENT_CHECK_QUERY_BOUND: u64 = 248_467;
    const TEST_VERIFIER_RANDOM_ORACLE_QUERY_BOUND: u64 = 429_989;
    const TEST_MAXIMUM_PROOF_VECTOR_SYMBOL_LENGTH: u64 = 262_144;
    const TEST_MAXIMUM_LEAF_VALUE_BYTE_LENGTH: u64 = 5_120;

    fn distinct_semantic_knowledge_bound() -> CompactRelaxedRoundByRoundKnowledgeBound {
        CompactRelaxedRoundByRoundKnowledgeBound::from_ratio_for_test(
            BigUint::from(25_u8),
            selected_challenge_field_cardinality(),
        )
        .expect("valid semantic test bound")
    }

    fn assumed_fixed_tape_uniformity_premise() -> CompactFixedTapeUniformityPremise {
        CompactFixedTapeUniformityPremise::assume_for_appendix_arithmetic_test()
            .expect("selected conditional fixed-tape arithmetic fixture")
    }

    fn assumed_complete_premises<'premise>(
        measurement: &CompactEmittedCdhzMeasurement,
        semantic: &'premise CompactRelaxedRoundByRoundKnowledgeBound,
        fixed_tape_uniformity: &'premise CompactFixedTapeUniformityPremise,
    ) -> CompactCdhzAppendixAOnePremises<'premise> {
        CompactCdhzAppendixAOnePremises {
            semantic: Some(semantic),
            masking: Some(
                CompactCdhzMaskingPremise::assume_for_appendix_arithmetic_test(measurement),
            ),
            emitted_byte: Some(
                CompactCdhzEmittedBytePremise::assume_for_appendix_arithmetic_test(measurement),
            ),
            merkle_privacy: Some(
                CompactCdhzMerklePrivacyPremise::assume_for_appendix_arithmetic_test(measurement),
            ),
            fixed_tape_uniformity: Some(fixed_tape_uniformity),
        }
    }

    fn derive_with_assumed_complete_premises(
        measurement: Option<&CompactEmittedCdhzMeasurement>,
        semantic: &CompactRelaxedRoundByRoundKnowledgeBound,
    ) -> Result<CompactCdhzAppendixAOneCertificate, CompactCdhzAppendixAOneError> {
        let fixed_tape_uniformity = assumed_fixed_tape_uniformity_premise();
        let premise_measurement = measurement
            .expect("the complete conditional arithmetic fixture needs measurement bytes");
        let premises =
            assumed_complete_premises(premise_measurement, semantic, &fixed_tape_uniformity);
        derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(measurement, &premises)
    }

    fn selected_coordinate_measurement_for_test() -> CompactEmittedCdhzMeasurement {
        let first_geometry_query_bound =
            TEST_PROOF_QUERY_BOUND - (TEST_RESPONSE_VECTOR_COMMITMENT_COUNT - 1);
        let parent_hash_query_bound =
            TEST_VECTOR_COMMITMENT_CHECK_QUERY_BOUND - TEST_PROOF_QUERY_BOUND;
        let first_parent_hash_query_bound =
            parent_hash_query_bound - (TEST_RESPONSE_VECTOR_COMMITMENT_COUNT - 1);
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("selected compact proof contract");
        let verifier_message_coordinates = contract
            .verifier_inputs()
            .proof_wire_geometry
            .responses()
            .iter()
            .map(|response| {
                let geometry = response.verifier_message_geometry();
                (
                    geometry
                        .exact_message_byte_length_u64()
                        .expect("selected message byte length"),
                    geometry
                        .concrete_hash_query_count()
                        .expect("selected fixed-tape hash count")
                        .checked_add(1)
                        .expect("round prefix hash count"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            verifier_message_coordinates.len(),
            usize::try_from(TEST_RESPONSE_VECTOR_COMMITMENT_COUNT)
                .expect("test response count fits usize")
        );
        let rounds = (0..TEST_RESPONSE_VECTOR_COMMITMENT_COUNT)
            .zip(verifier_message_coordinates)
            .map(
                |(ordinal, (message_byte_length, hash_query_count))| CompactEmittedCdhzRound {
                    ordinal: u32::try_from(ordinal).expect("test ordinal"),
                    proof_vector_symbol_length: if ordinal == 0 {
                        TEST_MAXIMUM_PROOF_VECTOR_SYMBOL_LENGTH
                    } else {
                        2
                    },
                    observed_query_count: 1,
                    geometry_query_count_bound: if ordinal == 0 {
                        first_geometry_query_bound
                    } else {
                        1
                    },
                    observed_frontier_node_count: 1,
                    observed_frontier_dictionary_entry_count: 1,
                    observed_parent_hash_query_count: 1,
                    geometry_parent_hash_query_bound: if ordinal == 0 {
                        first_parent_hash_query_bound
                    } else {
                        1
                    },
                    emitted_response_byte_length: 1,
                    emitted_answer_byte_length: 1,
                    emitted_merkle_opening_byte_length: 1,
                    fiat_shamir_message_byte_length: message_byte_length,
                    concrete_fiat_shamir_hash_query_count: hash_query_count,
                },
            )
            .collect();
        let verifier_inputs = contract.verifier_inputs();
        let distinct_query_group_count = verifier_inputs
            .verifier_moves
            .iter()
            .map(|verifier_move| verifier_move.message_geometry.distinct_query_groups().len())
            .sum::<usize>();
        let distinct_query_group_element_count = verifier_inputs
            .verifier_moves
            .iter()
            .flat_map(|verifier_move| verifier_move.message_geometry.distinct_query_groups())
            .map(|group| group.query_count())
            .sum::<u64>();
        let verifier_query_group_consumer_edge_count = verifier_inputs
            .response_merkle_geometries
            .iter()
            .flat_map(|geometry| geometry.components())
            .map(|component| match component.query_selection() {
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf => 0_u64,
                CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. } => 1,
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion { .. } => 2,
            })
            .sum::<u64>();
        let transcript_commitment_absorption_count =
            TEST_RESPONSE_VECTOR_COMMITMENT_COUNT * (TEST_RESPONSE_VECTOR_COMMITMENT_COUNT + 1) / 2;
        CompactEmittedCdhzMeasurement {
            canonical_proof_byte_length: 1,
            canonical_public_input_byte_length: 1,
            explicit_public_input_field_element_count: 0,
            response_vector_commitment_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
            observed_proof_query_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
            theorem_proof_query_bound: TEST_PROOF_QUERY_BOUND,
            input_implicit_query_bound: 0,
            observed_logical_verifier_oracle_call_count: 0,
            logical_verifier_oracle_call_bound: 0,
            observed_nrdx_verifier_q_v: TEST_CONCRETE_FIAT_SHAMIR_QUERY_COUNT
                + 2 * TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
            nrdx_verifier_q_v_bound: TEST_VERIFIER_RANDOM_ORACLE_QUERY_BOUND,
            maximum_proof_vector_symbol_length: TEST_MAXIMUM_PROOF_VECTOR_SYMBOL_LENGTH,
            emitted_answer_byte_length: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
            emitted_merkle_opening_byte_length: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
            decoded_actual_byte_census: CompactDecodedActualByteCensus {
                canonical_proof_binding: [0x11; Hash512::BYTE_LENGTH],
                canonical_public_input_binding: [0x22; Hash512::BYTE_LENGTH],
                prover_response_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                verifier_message_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                distinct_query_group_count: u64::try_from(distinct_query_group_count)
                    .expect("selected group count fits u64"),
                distinct_query_group_element_count,
                response_opening_tuple_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                response_commitment_root_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                internal_relation_commitment_count: 45,
                opened_leaf_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                secret_leaf_salt_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                round_salt_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                frontier_node_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                frontier_dictionary_entry_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                verifier_response_consumer_edge_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                verifier_query_group_consumer_edge_count,
                transcript_public_input_length_absorption_count:
                    TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                transcript_public_input_absorption_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                transcript_commitment_identifier_absorption_count:
                    transcript_commitment_absorption_count,
                transcript_commitment_root_absorption_count: transcript_commitment_absorption_count,
                transcript_round_salt_absorption_count: transcript_commitment_absorption_count,
                shared_hash_graph: CompactSharedHashGraphCensus {
                    fiat_shamir_prefix_hash_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                    fixed_message_block_hash_count: TEST_CONCRETE_FIAT_SHAMIR_QUERY_COUNT
                        - TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                    opened_leaf_hash_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                    merkle_parent_hash_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                    total_hash_count: TEST_CONCRETE_FIAT_SHAMIR_QUERY_COUNT
                        + 2 * TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                },
            },
            merkle_multi_extraction: CompactCdhzMerkleMultiExtractionTerms {
                output_bit_length: u16::try_from(Hash512::BYTE_LENGTH * 8)
                    .expect("test output width"),
                leaf_salt_bit_length: u16::try_from(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH * 8)
                    .expect("test salt width"),
                vector_commitment_tuple_size: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                input_implicit_instance_tuple_size: 0,
                output_implicit_instance_tuple_size: 0,
                observed_check_oracle_query_count: 2 * TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                geometry_check_oracle_query_bound: TEST_VECTOR_COMMITMENT_CHECK_QUERY_BOUND,
                theorem_offline_query_set_bound: TEST_PROOF_QUERY_BOUND,
                theorem_q1_bound: 1_427_580,
                theorem_q2_bound: TEST_MAXIMUM_PROOF_VECTOR_SYMBOL_LENGTH,
                maximum_leaf_value_byte_length: TEST_MAXIMUM_LEAF_VALUE_BYTE_LENGTH,
            },
            oracle_family_census: CompactCdhzOracleFamilyCensus {
                fiat_shamir_oracle_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                vector_commitment_oracle_count: TEST_RESPONSE_VECTOR_COMMITMENT_COUNT,
                multi_extract_oracle_count: 1,
            },
            random_oracle_domains: CompactCdhzRandomOracleDomains {
                fiat_shamir_prefix: COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
                verifier_message_block: FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN,
                merkle_leaf: COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
                merkle_parent: COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
            },
            rounds,
        }
    }

    #[test]
    fn selected_appendix_a_one_coordinates_are_exact() {
        let measurement = selected_coordinate_measurement_for_test();
        let certificate = derive_with_assumed_complete_premises(
            Some(&measurement),
            &distinct_semantic_knowledge_bound(),
        )
        .expect("selected Appendix A.1 certificate");
        let coordinates = certificate.coordinates();

        assert_eq!(
            coordinates.adversarial_query_bound(),
            &BigUint::parse_bytes(b"1208925819614629174706175", 10).expect("valid query bound")
        );
        assert_eq!(coordinates.response_vector_commitment_count(), 82);
        assert_eq!(coordinates.proof_query_bound(), 79_310);
        assert_eq!(coordinates.input_implicit_instance_tuple_size(), 0);
        assert_eq!(coordinates.output_implicit_instance_tuple_size(), 0);
        assert_eq!(coordinates.verifier_random_oracle_query_bound(), 429_989);
        assert_eq!(coordinates.maximum_proof_vector_symbol_length(), 262_144);
        assert_eq!(coordinates.minimum_verifier_randomness_bit_length(), 65_536);
        assert_eq!(coordinates.random_oracle_output_bit_length(), 512);
    }

    #[test]
    fn every_missing_conditional_premise_keeps_the_terminal_unavailable() {
        let measurement = selected_coordinate_measurement_for_test();
        let semantic = distinct_semantic_knowledge_bound();
        let fixed_tape_uniformity = assumed_fixed_tape_uniformity_premise();
        let mut premises =
            assumed_complete_premises(&measurement, &semantic, &fixed_tape_uniformity);
        premises.semantic = None;
        assert_eq!(
            derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(
                Some(&measurement),
                &premises,
            ),
            Err(CompactCdhzAppendixAOneError::MissingSemanticPremise)
        );
        let mut premises =
            assumed_complete_premises(&measurement, &semantic, &fixed_tape_uniformity);
        premises.masking = None;
        assert_eq!(
            derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(
                Some(&measurement),
                &premises,
            ),
            Err(CompactCdhzAppendixAOneError::MissingMaskingPremise)
        );
        let mut premises =
            assumed_complete_premises(&measurement, &semantic, &fixed_tape_uniformity);
        premises.emitted_byte = None;
        assert_eq!(
            derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(
                Some(&measurement),
                &premises,
            ),
            Err(CompactCdhzAppendixAOneError::MissingEmittedBytePremise)
        );
        let mut premises =
            assumed_complete_premises(&measurement, &semantic, &fixed_tape_uniformity);
        premises.merkle_privacy = None;
        assert_eq!(
            derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(
                Some(&measurement),
                &premises,
            ),
            Err(CompactCdhzAppendixAOneError::MissingMerklePrivacyPremise)
        );
        let mut premises =
            assumed_complete_premises(&measurement, &semantic, &fixed_tape_uniformity);
        premises.fixed_tape_uniformity = None;
        assert_eq!(
            derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(
                Some(&measurement),
                &premises,
            ),
            Err(CompactCdhzAppendixAOneError::MissingFixedTapeUniformityPremise)
        );
    }

    #[test]
    fn appendix_a_one_requires_both_implicit_instance_tuples_to_be_empty() {
        let mut measurement = selected_coordinate_measurement_for_test();
        let knowledge_bound = distinct_semantic_knowledge_bound();

        measurement
            .merkle_multi_extraction
            .input_implicit_instance_tuple_size = 1;
        assert_eq!(
            derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound,),
            Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)
        );
        measurement
            .merkle_multi_extraction
            .input_implicit_instance_tuple_size = 0;
        measurement
            .merkle_multi_extraction
            .output_implicit_instance_tuple_size = 1;
        assert_eq!(
            derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound,),
            Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)
        );
    }

    #[test]
    fn theorem_eight_three_coefficients_use_appendix_a_one_argument_positions() {
        let measurement = selected_coordinate_measurement_for_test();
        let knowledge_bound = distinct_semantic_knowledge_bound();
        let certificate =
            derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound)
                .expect("selected Appendix A.1 certificate");
        let coefficients = certificate.oracle_mass_coefficients();
        let t = certificate.coordinates().adversarial_query_bound();
        let k = BigUint::from(TEST_RESPONSE_VECTOR_COMMITMENT_COUNT);
        let q_v = BigUint::from(TEST_VERIFIER_RANDOM_ORACLE_QUERY_BOUND);
        let state_query_factor = t + &k + BigUint::one();
        let offline_query_factor = t * BigUint::from(2_u8) + BigUint::one();
        let online_query_factor = t + BigUint::one() + q_v + k;
        let denominator = BigUint::one() << 512_usize;

        assert_eq!(
            coefficients.fiat_shamir_oracle(),
            &knowledge_bound
                .maximum_error()
                .scale(&(BigUint::from(320_u16) * state_query_factor))
        );
        assert_eq!(
            coefficients.standard_vector_commitment_oracle(),
            &CompactCdhzExactRational::from_nonzero_parts(
                BigUint::from(640_u16) * &offline_query_factor * offline_query_factor,
                denominator.clone(),
            )
        );
        assert_eq!(
            coefficients.multi_extract_oracle(),
            &CompactCdhzExactRational::from_nonzero_parts(
                BigUint::from(960_u16) * &online_query_factor * online_query_factor,
                denominator,
            )
        );
    }

    #[test]
    fn full_affine_objective_selects_fiat_shamir_mass() {
        let measurement = selected_coordinate_measurement_for_test();
        let certificate = derive_with_assumed_complete_premises(
            Some(&measurement),
            &distinct_semantic_knowledge_bound(),
        )
        .expect("selected Appendix A.1 certificate");
        let coefficients = certificate.oracle_mass_coefficients();
        let bounds = certificate.simplex_vertex_bounds();

        assert!(
            coefficients.fiat_shamir_oracle() > coefficients.standard_vector_commitment_oracle()
        );
        assert!(
            coefficients.standard_vector_commitment_oracle() > coefficients.multi_extract_oracle()
        );
        assert_eq!(
            certificate.selected_maximizing_vertex(),
            CompactCdhzOracleMassVertex::FiatShamirOracle
        );
        assert_eq!(
            certificate.maximizing_vertices(),
            &[CompactCdhzOracleMassVertex::FiatShamirOracle]
        );
        assert_eq!(
            certificate
                .adaptive_soundness_terms()
                .total_adaptive_soundness(),
            bounds.fiat_shamir_oracle()
        );
        assert!(
            certificate.adaptive_soundness_terms().offline_extraction()
                > &CompactCdhzExactRational::zero()
        );
        assert!(
            certificate
                .adaptive_soundness_terms()
                .online_indistinguishability()
                > &CompactCdhzExactRational::zero()
        );
    }

    #[test]
    fn relaxed_rbr_headroom_is_derived_from_the_complete_target_partition() {
        let measurement = selected_coordinate_measurement_for_test();
        let knowledge_bound = distinct_semantic_knowledge_bound();
        let certificate =
            derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound)
                .expect("selected Appendix A.1 certificate");
        let headroom = certificate.kappa_headroom();

        assert_eq!(
            headroom.limiting_vertex(),
            CompactCdhzOracleMassVertex::FiatShamirOracle
        );
        let recomposed_target = headroom
            .maximum_relaxed_round_by_round_knowledge_bound()
            .scale(headroom.limiting_state_term_coefficient())
            .add(headroom.limiting_nonsemantic_partition());
        assert_eq!(&recomposed_target, headroom.target_adaptive_soundness());
        assert!(
            knowledge_bound.maximum_error()
                <= headroom.maximum_relaxed_round_by_round_knowledge_bound()
        );
        assert!(
            certificate
                .adaptive_soundness_terms()
                .total_adaptive_soundness()
                <= headroom.target_adaptive_soundness()
        );

        let excessive_bound = CompactRelaxedRoundByRoundKnowledgeBound::from_ratio_for_test(
            BigUint::one(),
            BigUint::one(),
        )
        .expect("unit semantic bound is structurally valid");
        assert_eq!(
            derive_with_assumed_complete_premises(Some(&measurement), &excessive_bound),
            Err(CompactCdhzAppendixAOneError::AdaptiveSoundnessTargetExceeded)
        );
    }

    #[test]
    fn premise_bindings_and_decoded_census_coordinates_are_load_bearing() {
        let measurement = selected_coordinate_measurement_for_test();
        let semantic = distinct_semantic_knowledge_bound();
        let fixed_tape_uniformity = assumed_fixed_tape_uniformity_premise();
        let premises = assumed_complete_premises(&measurement, &semantic, &fixed_tape_uniformity);
        let mut substituted_binding = measurement.clone();
        substituted_binding
            .decoded_actual_byte_census
            .canonical_proof_binding[0] ^= 1;
        assert_eq!(
            derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(
                Some(&substituted_binding),
                &premises,
            ),
            Err(CompactCdhzAppendixAOneError::PremiseBindingMismatch)
        );

        let census_mutations: [fn(&mut CompactDecodedActualByteCensus); 5] = [
            |census| census.distinct_query_group_count += 1,
            |census| census.opened_leaf_count += 1,
            |census| census.internal_relation_commitment_count += 1,
            |census| census.verifier_query_group_consumer_edge_count += 1,
            |census| census.shared_hash_graph.total_hash_count += 1,
        ];
        for mutate in census_mutations {
            let mut mutated = measurement.clone();
            mutate(&mut mutated.decoded_actual_byte_census);
            assert_eq!(
                derive_with_assumed_complete_premises(Some(&mutated), &semantic),
                Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)
            );
        }
    }

    #[test]
    fn a_fixed_tape_premise_cannot_contribute_zero_distinguishing_loss() {
        assert_eq!(
            fixed_tape_loss(BigUint::zero(), BigUint::one()),
            Err(CompactCdhzAppendixAOneError::FixedTapeUniformityPremiseMismatch)
        );
    }

    #[test]
    fn every_simplex_vertex_is_the_fixed_loss_plus_its_exact_mass_coefficient() {
        let measurement = selected_coordinate_measurement_for_test();
        let certificate = derive_with_assumed_complete_premises(
            Some(&measurement),
            &distinct_semantic_knowledge_bound(),
        )
        .expect("selected Appendix A.1 certificate");
        let coefficients = certificate.oracle_mass_coefficients();
        let bounds = certificate.simplex_vertex_bounds();
        let t = certificate.coordinates().adversarial_query_bound();

        assert_eq!(
            bounds.fiat_shamir_oracle(),
            &bounds
                .no_adversarial_queries()
                .add(&coefficients.fiat_shamir_oracle().scale(t))
        );
        assert_eq!(
            bounds.standard_vector_commitment_oracle(),
            &bounds
                .no_adversarial_queries()
                .add(&coefficients.standard_vector_commitment_oracle().scale(t),)
        );
        assert_eq!(
            bounds.multi_extract_oracle(),
            &bounds
                .no_adversarial_queries()
                .add(&coefficients.multi_extract_oracle().scale(t))
        );
    }

    #[test]
    fn selected_terms_match_the_exact_appendix_a_one_instantiation() {
        let measurement = selected_coordinate_measurement_for_test();
        let knowledge_bound = distinct_semantic_knowledge_bound();
        let certificate =
            derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound)
                .expect("selected Appendix A.1 certificate");
        let terms = certificate.adaptive_soundness_terms();
        let t = certificate.coordinates().adversarial_query_bound();
        let k = BigUint::from(TEST_RESPONSE_VECTOR_COMMITMENT_COUNT);
        let q_pi = BigUint::from(TEST_PROOF_QUERY_BOUND);
        let q_v = BigUint::from(TEST_VERIFIER_RANDOM_ORACLE_QUERY_BOUND);
        let state_query_factor = t + &k + BigUint::one();
        let online_query_factor = t + BigUint::one() + &q_v + &k;
        let commutativity_query_factor = &online_query_factor + BigUint::one();
        let merkle_denominator = BigUint::one() << 512_usize;
        let state_restoration_soundness = knowledge_bound
            .maximum_error()
            .scale(&(BigUint::from(320_u16) * &state_query_factor * (t + &k)))
            .add(&CompactCdhzExactRational::from_nonzero_parts(
                BigUint::from(4_u8) * &state_query_factor * &k,
                BigUint::one() << 65_536_usize,
            ));
        let offline_extraction = CompactCdhzExactRational::from_nonzero_parts(
            BigUint::from(64_u8)
                * q_pi
                * BigUint::from(TEST_MAXIMUM_PROOF_VECTOR_SYMBOL_LENGTH.ilog2()),
            merkle_denominator.clone(),
        );
        let online_indistinguishability = CompactCdhzExactRational::from_nonzero_parts(
            BigUint::from(960_u16) * &online_query_factor * &online_query_factor,
            merkle_denominator.clone(),
        );
        let merkle_commutativity = CompactCdhzExactRational::from_nonzero_parts(
            BigUint::from(480_u16) * &q_v * &q_v * commutativity_query_factor,
            merkle_denominator,
        );
        let premise = assumed_fixed_tape_uniformity_premise();
        let (domain_extension_numerator, domain_extension_denominator) =
            premise.domain_extension_loss_parts();
        let fixed_tape_domain_extension = CompactCdhzExactRational::try_new(
            domain_extension_numerator.clone(),
            domain_extension_denominator.clone(),
        )
        .expect("source-shaped domain-extension loss");
        let (sampler_exhaustion_numerator, sampler_exhaustion_denominator) =
            premise.sampler_exhaustion_loss_parts();
        let fixed_tape_sampler_exhaustion = CompactCdhzExactRational::try_new(
            sampler_exhaustion_numerator.clone(),
            sampler_exhaustion_denominator.clone(),
        )
        .expect("conditional sampler-exhaustion loss");

        assert_eq!(
            terms.state_restoration_soundness(),
            &state_restoration_soundness
        );
        assert_eq!(terms.offline_extraction(), &offline_extraction);
        assert_eq!(
            terms.online_indistinguishability(),
            &online_indistinguishability
        );
        assert_eq!(terms.merkle_commutativity(), &merkle_commutativity);
        assert_eq!(
            terms.fixed_tape_domain_extension(),
            &fixed_tape_domain_extension
        );
        assert_eq!(
            terms.fixed_tape_sampler_exhaustion(),
            &fixed_tape_sampler_exhaustion
        );
        assert_eq!(
            terms.total_adaptive_soundness(),
            &state_restoration_soundness
                .add(&offline_extraction)
                .add(&online_indistinguishability)
                .add(&merkle_commutativity)
                .add(&fixed_tape_domain_extension)
                .add(&fixed_tape_sampler_exhaustion)
        );
    }

    #[test]
    fn direct_initial_transition_is_separate_from_the_semantic_maximum() {
        let measurement = selected_coordinate_measurement_for_test();
        let certificate = derive_with_assumed_complete_premises(
            Some(&measurement),
            &distinct_semantic_knowledge_bound(),
        )
        .expect("selected Appendix A.1 certificate");
        let field_cardinality = selected_challenge_field_cardinality();

        assert_eq!(
            certificate.direct_initial_transition_bound(),
            &CompactCdhzExactRational::try_new(BigUint::from(24_u8), field_cardinality)
                .expect("nonzero field cardinality")
        );
        assert_ne!(
            certificate.direct_initial_transition_bound(),
            certificate.maximum_relaxed_round_by_round_knowledge_bound()
        );

        let invalid_semantic_maximum =
            CompactRelaxedRoundByRoundKnowledgeBound::from_ratio_for_test(
                BigUint::from(23_u8),
                selected_challenge_field_cardinality(),
            )
            .expect("well-formed but incomplete semantic maximum");
        assert_eq!(
            derive_with_assumed_complete_premises(Some(&measurement), &invalid_semantic_maximum,),
            Err(CompactCdhzAppendixAOneError::InvalidRelaxedRoundByRoundKnowledgeBound)
        );
    }

    #[test]
    fn emitted_q_v_is_the_concrete_shared_qro_bound() {
        let mut measurement = selected_coordinate_measurement_for_test();
        let knowledge_bound = distinct_semantic_knowledge_bound();
        let certificate =
            derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound)
                .expect("selected Appendix A.1 certificate");

        assert_eq!(
            certificate
                .coordinates()
                .verifier_random_oracle_query_bound(),
            429_989
        );
        measurement.nrdx_verifier_q_v_bound = 248_549;
        assert_eq!(
            derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound,),
            Err(CompactCdhzAppendixAOneError::UnexpectedEmittedCoordinates)
        );
    }

    #[test]
    fn equal_vertex_totals_retain_all_co_maximizers_in_enum_order() {
        let zero = CompactCdhzExactRational::zero();
        let bounds = CompactCdhzSimplexVertexBounds {
            no_adversarial_queries: zero.clone(),
            fiat_shamir_oracle: zero.clone(),
            standard_vector_commitment_oracle: zero.clone(),
            multi_extract_oracle: zero,
        };

        assert_eq!(
            maximizing_vertices(&bounds),
            vec![
                CompactCdhzOracleMassVertex::NoAdversarialQueries,
                CompactCdhzOracleMassVertex::FiatShamirOracle,
                CompactCdhzOracleMassVertex::StandardVectorCommitmentOracle,
                CompactCdhzOracleMassVertex::MultiExtractOracle,
            ]
        );
    }

    #[test]
    fn every_random_oracle_domain_is_load_bearing() {
        let knowledge_bound = distinct_semantic_knowledge_bound();
        let mutations: [fn(&mut CompactCdhzRandomOracleDomains); 4] = [
            |domains: &mut CompactCdhzRandomOracleDomains| domains.fiat_shamir_prefix = "wrong",
            |domains: &mut CompactCdhzRandomOracleDomains| domains.verifier_message_block = "wrong",
            |domains: &mut CompactCdhzRandomOracleDomains| domains.merkle_leaf = "wrong",
            |domains: &mut CompactCdhzRandomOracleDomains| domains.merkle_parent = "wrong",
        ];
        for mutate in mutations {
            let mut measurement = selected_coordinate_measurement_for_test();
            mutate(&mut measurement.random_oracle_domains);
            assert_eq!(
                derive_with_assumed_complete_premises(Some(&measurement), &knowledge_bound,),
                Err(CompactCdhzAppendixAOneError::FixedTapeUniformityPremiseMismatch)
            );
        }
    }

    #[test]
    fn absent_measurement_cannot_mint_adaptive_soundness_arithmetic() {
        let binding_measurement = selected_coordinate_measurement_for_test();
        let semantic = distinct_semantic_knowledge_bound();
        let fixed_tape_uniformity = assumed_fixed_tape_uniformity_premise();
        let premises =
            assumed_complete_premises(&binding_measurement, &semantic, &fixed_tape_uniformity);
        assert_eq!(
            derive_selected_compact_cdhz_appendix_a_one_adaptive_soundness(None, &premises,),
            Err(CompactCdhzAppendixAOneError::MissingEmittedMeasurement)
        );
    }
}
