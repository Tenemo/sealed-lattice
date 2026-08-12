//! Static CDHZ/BCS completion ledger for the compact public-key slice.
//!
//! This owner applies the arithmetic of CDHZ Theorems 6.10, 8.3, and 11.3
//! only where the current source supplies every argument. In particular, the
//! state-restoration row below consumes the maximum error from the checked
//! relaxed round-by-round extractor theorem rather than the numerical event
//! union directly.
//! The fixed-bit layout, bounded-rejection decoder, and complete SHAKE256
//! schedule are production-owned and independently reconciled with the
//! canonical proof and public-input byte map before this ledger is derived.
//! Fixed SHAKE256 is still an explicit ideal quantum-random-oracle assumption;
//! this arithmetic does not claim to prove that assumption. Construction-level
//! masking is owned and checked separately. The arithmetic instantiates the
//! Appendix A trivial implicit-input/output composition directly; there is no
//! selectable composition variant.

use num_bigint::BigUint;
use num_traits::One;

use super::CompactStaticCatalogError;
use super::lifecycle::ExactProbability;
use super::relaxed_round_by_round::RelaxedRoundByRoundCatalog;
use super::response_commitment::PackingResponseCommitmentCatalog;
use super::transcript_binding::PackingTranscriptBindingLedger;
use super::transcript_chronology::PackingTranscriptChronology;
use super::uniform_verifier_randomness::PackingUniformVerifierRandomness;
use crate::bgv::proof_suite::selected_accounting::derive_selected_proof_family_application_inventory;
use crate::foundation::{DECLARED_ADVERSARIAL_QUERY_BUDGET, ProofApplicationSlotCeilings};

const CDHZ_STATE_RESTORATION_MULTIPLIER: u64 = 80;
const CDHZ_COMPOSITION_STATE_MULTIPLIER: u64 = 4;
const CDHZ_MERKLE_COMMITMENT_MULTIPLIER: u64 = 240;
const CDHZ_MERKLE_OFFLINE_WORK_MULTIPLIER: u64 = 160;
const CDHZ_MERKLE_OFFLINE_QUERY_MULTIPLIER: u64 = 16;
const CDHZ_MERKLE_ONLINE_WORK_MULTIPLIER: u64 = 240;
const MERKLE_RANDOM_ORACLE_OUTPUT_BIT_LENGTH: u64 = 512;
const FIAT_SHAMIR_ROUND_SALT_BIT_LENGTH: u64 = 512;
const REQUIRED_PER_PROOF_SOUNDNESS_SECURITY_LEVEL: usize = 96;
const REQUIRED_PUBLIC_KEY_SHARE_SOUNDNESS_SECURITY_LEVEL: usize = 96;
const REQUIRED_COMPLETE_ACTION_SOUNDNESS_SECURITY_LEVEL: usize = 80;
const EXPECTED_PUBLIC_KEY_SHARE_PHYSICAL_PROOF_COUNT: u32 = 10;
const EXPECTED_SELECTED_INVENTORY_PHYSICAL_PROOF_COUNT: u32 = 103;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConditionalWorkAllocation {
    FiatShamirStateRestoration,
    VectorCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConditionalCdhzStateRestorationArithmetic {
    adversarial_query_bound: BigUint,
    logical_round_count: u64,
    candidate_minimum_challenge_space_bit_length: u64,
    candidate_relaxed_round_by_round_error: ExactProbability,
    round_by_round_multiplier: BigUint,
    round_by_round_term: ExactProbability,
    verifier_randomness_term: ExactProbability,
    conditional_composed_round_by_round_term: ExactProbability,
    conditional_composed_verifier_randomness_term: ExactProbability,
    extraction_operation_scale_without_theorem_hidden_constant: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConditionalCdhzMerkleArithmetic {
    adversarial_query_bound: BigUint,
    logical_round_count: u64,
    proof_oracle_query_count: u64,
    maximum_proof_oracle_length: u64,
    maximum_proof_oracle_logarithm: u32,
    maximum_leaf_value_byte_length: u64,
    maximum_verifier_merkle_hash_query_count: u64,
    concrete_challenge_stream_hash_query_count: u64,
    abstract_bcs_verifier_oracle_query_count: u64,
    offline_oracle_query_argument: BigUint,
    online_oracle_query_argument: BigUint,
    commitment_oracle_query_argument: BigUint,
    fiat_shamir_work_coefficient: ExactProbability,
    vector_commitment_work_coefficient: ExactProbability,
    maximizing_work_allocation: ConditionalWorkAllocation,
    fixed_round_by_round_state_term: ExactProbability,
    fixed_verifier_randomness_state_term: ExactProbability,
    maximum_work_term: ExactProbability,
    fixed_merkle_offline_term: ExactProbability,
    merkle_commutativity_term: ExactProbability,
    extraction_work_scale_without_hidden_constant: BigUint,
}

impl ConditionalCdhzMerkleArithmetic {
    fn derive(
        chronology: &PackingTranscriptChronology,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
        response_commitments: &PackingResponseCommitmentCatalog,
        transcript_binding: &PackingTranscriptBindingLedger,
        relaxed_round_by_round: &RelaxedRoundByRoundCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let adversarial_query_bound = BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET);
        let logical_round_count = chronology.logical_verifier_move_count()?;
        let logical_round_count_big = BigUint::from(logical_round_count);
        let proof_oracle_query_count = response_commitments.proof_oracle_query_count();
        let maximum_proof_oracle_length = response_commitments.maximum_proof_oracle_length();
        if !maximum_proof_oracle_length.is_power_of_two() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let maximum_proof_oracle_logarithm = maximum_proof_oracle_length.ilog2();
        let maximum_leaf_value_byte_length = response_commitments.maximum_leaf_value_byte_length();
        let maximum_verifier_merkle_hash_query_count =
            response_commitments.maximum_verifier_merkle_hash_query_count()?;
        let concrete_challenge_stream_hash_query_count =
            transcript_binding.total_concrete_fiat_shamir_hash_query_count();
        if transcript_binding.fixed_message_seed_and_block_hash_query_count()
            != uniform_verifier_randomness.concrete_challenge_stream_hash_query_count()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let abstract_bcs_verifier_oracle_query_count = checked_u64_add(
            logical_round_count,
            maximum_verifier_merkle_hash_query_count,
        )?;
        let abstract_bcs_verifier_oracle_query_count_big =
            BigUint::from(abstract_bcs_verifier_oracle_query_count);

        let offline_oracle_query_argument = (&adversarial_query_bound << 1_usize) + BigUint::one();
        let online_oracle_query_argument = &adversarial_query_bound
            + BigUint::one()
            + &abstract_bcs_verifier_oracle_query_count_big
            + &logical_round_count_big;
        let commitment_oracle_query_argument = online_oracle_query_argument.clone();
        let merkle_denominator = power_of_two(MERKLE_RANDOM_ORACLE_OUTPUT_BIT_LENGTH)?;

        let state_restoration_common_factor =
            BigUint::from(CDHZ_COMPOSITION_STATE_MULTIPLIER * CDHZ_STATE_RESTORATION_MULTIPLIER)
                * (&adversarial_query_bound + &logical_round_count_big + BigUint::one());
        let fiat_shamir_work_coefficient = relaxed_round_by_round
            .maximum_per_move_extraction_error()
            .scale(&state_restoration_common_factor)?;

        let vector_commitment_work_numerator =
            BigUint::from(CDHZ_COMPOSITION_STATE_MULTIPLIER * CDHZ_MERKLE_OFFLINE_WORK_MULTIPLIER)
                * &offline_oracle_query_argument
                * &offline_oracle_query_argument
                + BigUint::from(
                    CDHZ_COMPOSITION_STATE_MULTIPLIER * CDHZ_MERKLE_ONLINE_WORK_MULTIPLIER,
                ) * &online_oracle_query_argument
                    * &online_oracle_query_argument;
        let vector_commitment_work_coefficient =
            ExactProbability::new(vector_commitment_work_numerator, merkle_denominator.clone())?;
        let (maximizing_work_allocation, maximum_work_coefficient) =
            if vector_commitment_work_coefficient.is_greater_than(&fiat_shamir_work_coefficient) {
                (
                    ConditionalWorkAllocation::VectorCommitment,
                    vector_commitment_work_coefficient.clone(),
                )
            } else {
                (
                    ConditionalWorkAllocation::FiatShamirStateRestoration,
                    fiat_shamir_work_coefficient.clone(),
                )
            };
        let maximum_work_term = maximum_work_coefficient.scale(&adversarial_query_bound)?;

        let fixed_round_by_round_state_term = relaxed_round_by_round
            .maximum_per_move_extraction_error()
            .scale(&(state_restoration_common_factor * &logical_round_count_big))?;
        let fixed_verifier_randomness_state_term = ExactProbability::new(
            BigUint::from(CDHZ_COMPOSITION_STATE_MULTIPLIER)
                * (&adversarial_query_bound + &logical_round_count_big + BigUint::one())
                * &logical_round_count_big,
            power_of_two(
                uniform_verifier_randomness.minimum_uniform_verifier_message_bit_length(),
            )?,
        )?;
        let fixed_merkle_offline_term = ExactProbability::new(
            BigUint::from(CDHZ_COMPOSITION_STATE_MULTIPLIER * CDHZ_MERKLE_OFFLINE_QUERY_MULTIPLIER)
                * BigUint::from(proof_oracle_query_count)
                * BigUint::from(maximum_proof_oracle_logarithm),
            merkle_denominator.clone(),
        )?;
        let merkle_commutativity_term = ExactProbability::new(
            BigUint::from(2_u8)
                * &abstract_bcs_verifier_oracle_query_count_big
                * &abstract_bcs_verifier_oracle_query_count_big
                * BigUint::from(CDHZ_MERKLE_COMMITMENT_MULTIPLIER)
                * (&commitment_oracle_query_argument + BigUint::one()),
            merkle_denominator,
        )?;
        let extraction_work_scale_without_hidden_constant = BigUint::from(logical_round_count)
            * &offline_oracle_query_argument
            * BigUint::from(maximum_proof_oracle_length)
            * BigUint::from(
                maximum_leaf_value_byte_length
                    .checked_mul(8)
                    .and_then(|bit_length| {
                        bit_length.checked_add(super::PRIVATE_LEAF_SALT_BYTE_LENGTH * 8)
                    })
                    .and_then(|bit_length| {
                        bit_length.checked_add(MERKLE_RANDOM_ORACLE_OUTPUT_BIT_LENGTH)
                    })
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            );

        Ok(Self {
            adversarial_query_bound,
            logical_round_count,
            proof_oracle_query_count,
            maximum_proof_oracle_length,
            maximum_proof_oracle_logarithm,
            maximum_leaf_value_byte_length,
            maximum_verifier_merkle_hash_query_count,
            concrete_challenge_stream_hash_query_count,
            abstract_bcs_verifier_oracle_query_count,
            offline_oracle_query_argument,
            online_oracle_query_argument,
            commitment_oracle_query_argument,
            fiat_shamir_work_coefficient,
            vector_commitment_work_coefficient,
            maximizing_work_allocation,
            fixed_round_by_round_state_term,
            fixed_verifier_randomness_state_term,
            maximum_work_term,
            fixed_merkle_offline_term,
            merkle_commutativity_term,
            extraction_work_scale_without_hidden_constant,
        })
    }
}

impl ConditionalCdhzStateRestorationArithmetic {
    fn derive(
        chronology: &PackingTranscriptChronology,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
        relaxed_round_by_round: &RelaxedRoundByRoundCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let adversarial_query_bound = BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET);
        let logical_round_count = chronology.logical_verifier_move_count()?;
        let logical_round_count_big = BigUint::from(logical_round_count);
        let candidate_minimum_challenge_space_bit_length =
            uniform_verifier_randomness.minimum_uniform_verifier_message_bit_length();
        let query_plus_round_and_one =
            &adversarial_query_bound + &logical_round_count_big + BigUint::one();
        let work_plus_round = &adversarial_query_bound + &logical_round_count_big;
        let round_by_round_multiplier = BigUint::from(CDHZ_STATE_RESTORATION_MULTIPLIER)
            * &query_plus_round_and_one
            * work_plus_round;
        let candidate_relaxed_round_by_round_error = relaxed_round_by_round
            .maximum_per_move_extraction_error()
            .clone();
        let round_by_round_term =
            candidate_relaxed_round_by_round_error.scale(&round_by_round_multiplier)?;
        let verifier_randomness_term = ExactProbability::new(
            &query_plus_round_and_one * &logical_round_count_big,
            BigUint::one()
                << usize::try_from(candidate_minimum_challenge_space_bit_length)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        )?;
        let conditional_composed_round_by_round_term =
            round_by_round_term.scale(&BigUint::from(CDHZ_COMPOSITION_STATE_MULTIPLIER))?;
        let conditional_composed_verifier_randomness_term =
            verifier_randomness_term.scale(&BigUint::from(CDHZ_COMPOSITION_STATE_MULTIPLIER))?;
        let extraction_operation_scale_without_theorem_hidden_constant =
            BigUint::from(logical_round_count)
                * BigUint::from(relaxed_round_by_round.maximum_extraction_operation_bound())
                + BigUint::from(FIAT_SHAMIR_ROUND_SALT_BIT_LENGTH);

        Ok(Self {
            adversarial_query_bound,
            logical_round_count,
            candidate_minimum_challenge_space_bit_length,
            candidate_relaxed_round_by_round_error,
            round_by_round_multiplier,
            round_by_round_term,
            verifier_randomness_term,
            conditional_composed_round_by_round_term,
            conditional_composed_verifier_randomness_term,
            extraction_operation_scale_without_theorem_hidden_constant,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingNonInteractiveSoundness {
    conditional_state_restoration: ConditionalCdhzStateRestorationArithmetic,
    conditional_cdhz_merkle: ConditionalCdhzMerkleArithmetic,
    per_proof_adaptive_qrom_soundness_bound: ExactProbability,
    public_key_share_physical_proof_count: u32,
    public_key_share_qrom_union_bound: ExactProbability,
    selected_inventory_physical_proof_count: u32,
    selected_inventory_conditional_qrom_union_bound: ExactProbability,
    total_extraction_work_scale_without_hidden_constant: BigUint,
}

impl PackingNonInteractiveSoundness {
    pub(super) fn derive(
        chronology: &PackingTranscriptChronology,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
        response_commitments: &PackingResponseCommitmentCatalog,
        transcript_binding: &PackingTranscriptBindingLedger,
        relaxed_round_by_round: &RelaxedRoundByRoundCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let conditional_state_restoration = ConditionalCdhzStateRestorationArithmetic::derive(
            chronology,
            uniform_verifier_randomness,
            relaxed_round_by_round,
        )?;
        let conditional_cdhz_merkle = ConditionalCdhzMerkleArithmetic::derive(
            chronology,
            uniform_verifier_randomness,
            response_commitments,
            transcript_binding,
            relaxed_round_by_round,
        )?;
        if response_commitments.bcs_response_root_count()
            != chronology.logical_verifier_move_count()?
            || response_commitments.proof_oracle_query_count() == 0
            || response_commitments.maximum_proof_oracle_length() == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        if conditional_cdhz_merkle
            .fixed_round_by_round_state_term
            .add(&conditional_cdhz_merkle.maximum_work_term)?
            != conditional_state_restoration.conditional_composed_round_by_round_term
            || conditional_cdhz_merkle.fixed_verifier_randomness_state_term
                != conditional_state_restoration.conditional_composed_verifier_randomness_term
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let per_proof_adaptive_qrom_soundness_bound = sum_probabilities(&[
            &conditional_cdhz_merkle.fixed_round_by_round_state_term,
            &conditional_cdhz_merkle.fixed_verifier_randomness_state_term,
            &conditional_cdhz_merkle.maximum_work_term,
            &conditional_cdhz_merkle.fixed_merkle_offline_term,
            &conditional_cdhz_merkle.merkle_commutativity_term,
        ])?;
        let inventory = derive_selected_proof_family_application_inventory()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let public_key_share_physical_proof_count = inventory
            .family_entry(
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?
            .physical_proof_application_count();
        let selected_inventory_physical_proof_count = inventory
            .total_physical_proof_application_count()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        if public_key_share_physical_proof_count != EXPECTED_PUBLIC_KEY_SHARE_PHYSICAL_PROOF_COUNT
            || selected_inventory_physical_proof_count
                != EXPECTED_SELECTED_INVENTORY_PHYSICAL_PROOF_COUNT
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let public_key_share_qrom_union_bound = per_proof_adaptive_qrom_soundness_bound
            .scale(&BigUint::from(public_key_share_physical_proof_count))?;
        let selected_inventory_conditional_qrom_union_bound =
            per_proof_adaptive_qrom_soundness_bound
                .scale(&BigUint::from(selected_inventory_physical_proof_count))?;
        let total_extraction_work_scale_without_hidden_constant = &conditional_state_restoration
            .extraction_operation_scale_without_theorem_hidden_constant
            + &conditional_cdhz_merkle.extraction_work_scale_without_hidden_constant;
        if !per_proof_adaptive_qrom_soundness_bound
            .is_at_most_inverse_power_of_two(REQUIRED_PER_PROOF_SOUNDNESS_SECURITY_LEVEL)
            || !public_key_share_qrom_union_bound
                .is_at_most_inverse_power_of_two(REQUIRED_PUBLIC_KEY_SHARE_SOUNDNESS_SECURITY_LEVEL)
            || !selected_inventory_conditional_qrom_union_bound
                .is_at_most_inverse_power_of_two(REQUIRED_COMPLETE_ACTION_SOUNDNESS_SECURITY_LEVEL)
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(Self {
            conditional_state_restoration,
            conditional_cdhz_merkle,
            per_proof_adaptive_qrom_soundness_bound,
            public_key_share_physical_proof_count,
            public_key_share_qrom_union_bound,
            selected_inventory_physical_proof_count,
            selected_inventory_conditional_qrom_union_bound,
            total_extraction_work_scale_without_hidden_constant,
        })
    }
}

fn power_of_two(bit_length: u64) -> Result<BigUint, CompactStaticCatalogError> {
    Ok(BigUint::one()
        << usize::try_from(bit_length)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?)
}

fn checked_u64_add(left: u64, right: u64) -> Result<u64, CompactStaticCatalogError> {
    left.checked_add(right)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
}

fn sum_probabilities(
    terms: &[&ExactProbability],
) -> Result<ExactProbability, CompactStaticCatalogError> {
    let mut terms = terms.iter();
    let first = terms
        .next()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    terms.try_fold((*first).clone(), |sum, term| sum.add(term))
}

#[cfg(test)]
fn factored_probability_sum_is_at_most_inverse_power_of_two(
    terms: &[&ExactProbability],
    exponent: usize,
) -> bool {
    if terms.is_empty() {
        return true;
    }
    let Some(precision) = exponent.checked_add(128) else {
        return false;
    };
    let Some(target_unit_exponent) = precision.checked_sub(exponent) else {
        return false;
    };
    let Some(total_units) = terms.iter().try_fold(BigUint::default(), |sum, term| {
        term.ceiling_units_at_binary_precision(precision)
            .ok()
            .map(|units| sum + units)
    }) else {
        return false;
    };
    total_units <= (BigUint::one() << target_unit_exponent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[test]
    fn factor_one_closes_the_exact_cdhz_arithmetic_and_inventory_multiplicities() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        let ledger = &selected.non_interactive_soundness;
        assert!(
            ledger
                .per_proof_adaptive_qrom_soundness_bound
                .is_at_most_inverse_power_of_two(REQUIRED_PER_PROOF_SOUNDNESS_SECURITY_LEVEL)
        );
        assert!(
            ledger
                .public_key_share_qrom_union_bound
                .is_at_most_inverse_power_of_two(
                    REQUIRED_PUBLIC_KEY_SHARE_SOUNDNESS_SECURITY_LEVEL,
                )
        );
        assert!(
            ledger
                .selected_inventory_conditional_qrom_union_bound
                .is_at_most_inverse_power_of_two(
                    REQUIRED_COMPLETE_ACTION_SOUNDNESS_SECURITY_LEVEL,
                )
        );
        assert_eq!(
            selected
                .relaxed_round_by_round
                .maximum_extraction_field_operation_bound(),
            432_349_246_225_014_321
        );
        assert_eq!(ledger.conditional_cdhz_merkle.logical_round_count, 82);
        assert_eq!(
            ledger.conditional_cdhz_merkle.proof_oracle_query_count,
            79_310
        );
        assert_eq!(
            ledger.conditional_cdhz_merkle.maximum_proof_oracle_length,
            262_144
        );
        assert_eq!(
            ledger
                .conditional_cdhz_merkle
                .maximum_verifier_merkle_hash_query_count,
            248_467
        );
        assert_eq!(
            ledger
                .conditional_cdhz_merkle
                .abstract_bcs_verifier_oracle_query_count,
            248_549
        );
        assert_eq!(
            ledger
                .conditional_cdhz_merkle
                .maximum_leaf_value_byte_length,
            5_120
        );
        assert_eq!(
            ledger
                .conditional_cdhz_merkle
                .concrete_challenge_stream_hash_query_count,
            selected
                .transcript_binding
                .total_concrete_fiat_shamir_hash_query_count()
        );
        assert_eq!(
            ledger.conditional_cdhz_merkle.maximizing_work_allocation,
            ConditionalWorkAllocation::FiatShamirStateRestoration
        );
        assert_eq!(
            ledger
                .conditional_cdhz_merkle
                .fixed_round_by_round_state_term
                .add(&ledger.conditional_cdhz_merkle.maximum_work_term)
                .expect("full Fiat-Shamir state-restoration term"),
            ledger
                .conditional_state_restoration
                .conditional_composed_round_by_round_term
        );
        assert_eq!(
            ledger
                .conditional_cdhz_merkle
                .fixed_verifier_randomness_state_term,
            ledger
                .conditional_state_restoration
                .conditional_composed_verifier_randomness_term
        );
        assert!(factored_probability_sum_is_at_most_inverse_power_of_two(
            &[
                &ledger
                    .conditional_cdhz_merkle
                    .fixed_round_by_round_state_term,
                &ledger
                    .conditional_cdhz_merkle
                    .fixed_verifier_randomness_state_term,
                &ledger.conditional_cdhz_merkle.maximum_work_term,
                &ledger.conditional_cdhz_merkle.fixed_merkle_offline_term,
                &ledger.conditional_cdhz_merkle.merkle_commutativity_term,
            ],
            96,
        ));
        assert_eq!(
            ledger.per_proof_adaptive_qrom_soundness_bound,
            sum_probabilities(&[
                &ledger
                    .conditional_cdhz_merkle
                    .fixed_round_by_round_state_term,
                &ledger
                    .conditional_cdhz_merkle
                    .fixed_verifier_randomness_state_term,
                &ledger.conditional_cdhz_merkle.maximum_work_term,
                &ledger.conditional_cdhz_merkle.fixed_merkle_offline_term,
                &ledger.conditional_cdhz_merkle.merkle_commutativity_term,
            ])
            .expect("exact five-term CDHZ sum")
        );
        assert_eq!(ledger.public_key_share_physical_proof_count, 10);
        assert_eq!(ledger.selected_inventory_physical_proof_count, 103);
        assert_eq!(
            ledger.public_key_share_qrom_union_bound,
            ledger
                .per_proof_adaptive_qrom_soundness_bound
                .scale(&BigUint::from(10_u8))
                .expect("public-key-share proof union")
        );
        assert_eq!(
            ledger.selected_inventory_conditional_qrom_union_bound,
            ledger
                .per_proof_adaptive_qrom_soundness_bound
                .scale(&BigUint::from(103_u8))
                .expect("conditional selected-inventory union")
        );
        assert!(
            ledger
                .conditional_cdhz_merkle
                .extraction_work_scale_without_hidden_constant
                > BigUint::one()
        );
        assert!(
            ledger
                .conditional_state_restoration
                .extraction_operation_scale_without_theorem_hidden_constant
                > BigUint::one()
        );
        assert_eq!(
            ledger
                .conditional_state_restoration
                .extraction_operation_scale_without_theorem_hidden_constant,
            BigUint::from(82_u8)
                * BigUint::from(
                    selected
                        .relaxed_round_by_round
                        .maximum_extraction_operation_bound(),
                )
                + BigUint::from(FIAT_SHAMIR_ROUND_SALT_BIT_LENGTH)
        );
        assert_eq!(
            ledger.total_extraction_work_scale_without_hidden_constant,
            &ledger
                .conditional_state_restoration
                .extraction_operation_scale_without_theorem_hidden_constant
                + &ledger
                    .conditional_cdhz_merkle
                    .extraction_work_scale_without_hidden_constant
        );
        assert_eq!(
            ledger
                .conditional_state_restoration
                .candidate_minimum_challenge_space_bit_length,
            65_536
        );
        assert_eq!(
            ledger.conditional_state_restoration.adversarial_query_bound,
            BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
        );
        assert!(factored_probability_sum_is_at_most_inverse_power_of_two(
            &[
                &ledger
                    .conditional_state_restoration
                    .conditional_composed_round_by_round_term,
                &ledger
                    .conditional_state_restoration
                    .conditional_composed_verifier_randomness_term,
            ],
            96,
        ));
    }
}
