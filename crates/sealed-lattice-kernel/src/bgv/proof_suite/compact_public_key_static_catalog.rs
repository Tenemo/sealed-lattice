//! Static packing ledger for the compact public-key-share development slice.
//!
//! This pre-prover owner derives the two oracle epochs, the CFW masks, both
//! zero-knowledge WHIR executions, the logical transcript chronology, one
//! response commitment per logical response, exact interactive and conditional
//! non-interactive soundness arithmetic, bounded query sampling, and the
//! factor-one through factor-eight comparisons. It feeds the independently
//! derived response geometry into the canonical wire codec and accounts for
//! the production transcript's complete prefixes. Emitted-proof integration
//! and the concrete QROM correspondence remain open, so this ledger cannot
//! select a packing or authorize proof generation. It contains
//! no producer-supplied acceptance field; [`CompactPublicKeyStaticCatalog::check`]
//! independently reconstructs every value from the checked relation owner.

use num_bigint::BigUint;
use num_traits::One;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, ZkParameters, ZkWhirConfig};

use super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
use super::compact_generation_checkpoint::CompactResponseCheckpointSchedule;
use super::compact_proof_wire::{
    CompactProofWireAssemblerHeapGeometry, CompactProofWireError, CompactProofWireGeometry,
    CompactPublicInputWireGeometry,
};
use super::compact_response_merkle::{
    CompactResponseFrontierScannerHeapGeometry, CompactResponsePostorderWriterHeapGeometry,
};
use super::compact_response_tree_external::CompactResponseTreeExternalMemoryGeometry;
use super::merkle::maximum_minimal_frontier_node_count;
use super::relation_plan::{
    CompactPublicKeyRelationCatalog, selected_compact_public_key_relation_catalog,
};

mod canonical_reed_solomon;
mod cfw_lifecycle;
mod cfw_reduction;
mod cfw_to_whir_handoff;
mod emitted_byte_correspondence;
#[cfg(test)]
mod external_mask_integration;
mod lifecycle;
mod masking_leakage;
mod non_interactive_soundness;
mod relaxed_round_by_round;
mod resource_overlap;
mod response_commitment;
mod response_commitment_lifecycle;
mod row_source_lifecycle;
mod soundness;
mod transcript_binding;
mod transcript_chronology;
mod uniform_verifier_randomness;
mod witness_covector;

const GOLDILOCKS_BASE_FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;
const QUINTIC_EXTENSION_DEGREE: u64 = 5;
const BASE_FIELD_ELEMENT_BYTE_LENGTH: u64 = 8;
const EXTENSION_FIELD_ELEMENT_BYTE_LENGTH: u64 =
    BASE_FIELD_ELEMENT_BYTE_LENGTH * QUINTIC_EXTENSION_DEGREE;
const MERKLE_DIGEST_BYTE_LENGTH: u64 = 64;
const MERKLE_FRONTIER_COUNT_BYTE_LENGTH: u64 = 4;
const PRIVATE_LEAF_SALT_BYTE_LENGTH: u64 = 128;
const SHAKE256_STATE_BYTE_LENGTH: u64 = 200;
const INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL: u32 = 266;
const WHIR_PROTOCOL_SECURITY_LEVEL: u32 = INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL + 1;
const MAIN_CODE_LOG_INVERSE_RATE: u32 = 2;
const MASK_CODE_LOG_INVERSE_RATE: u32 = 2;
const WHIR_REPEATED_FOLDING_FACTOR: u32 = 4;
const WHIR_ROUND_COUNT: usize = 3;
const WHIR_FOLD_BATCH_COUNT: usize = WHIR_ROUND_COUNT + 1;
const SUMCHECK_MASK_MESSAGE_LENGTH: u64 = 3;
const PRE_CHALLENGE_RING_VECTOR_COUNT: u64 = 33;
const PRE_CHALLENGE_PADDED_RING_VECTOR_COUNT: u64 = 64;
const PRE_CHALLENGE_MESSAGE_ELEMENT_COUNT: u64 = 2_097_152;
const CROSS_EPOCH_POINT_COORDINATE_COUNT: u32 = 21;
const CROSS_EPOCH_EXPLICIT_OPENING_COUNT: u64 = 2;
const CROSS_EPOCH_DISCLOSED_VALUE_COUNT: u64 = 3;
const CROSS_EPOCH_MASK_WIDTH: u64 = 2;
const CROSS_EPOCH_MASK_MESSAGE_LENGTH: u64 = 1;
const CANONICAL_WHIR_PROOF_FRAME_BYTE_LENGTH: u64 = 32;
const TRANSPORT_CHUNK_BYTE_LENGTH: u64 = 1_048_576;
const WASM_HARD_BOUND_BYTE_LENGTH: u64 = 671_088_640;
const PROOF_ALLOCATION_BOUND_BYTE_LENGTH: u64 = 268_435_456;
const SCRATCH_BOUND_BYTE_LENGTH: u64 = 1_073_741_824;

type ChallengeField = BinomialExtensionField<Goldilocks, 5>;

#[derive(Clone, Copy, Debug)]
struct ConfigurationOnlyChallenger<F>(core::marker::PhantomData<F>);

impl<F> CanObserve<F> for ConfigurationOnlyChallenger<F> {
    fn observe(&mut self, _value: F) {}
}

impl<F: Field> CanSample<F> for ConfigurationOnlyChallenger<F> {
    fn sample(&mut self) -> F {
        F::ZERO
    }
}

impl<F> CanSampleBits<usize> for ConfigurationOnlyChallenger<F> {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        0
    }
}

impl<F: Field> FieldChallenger<F> for ConfigurationOnlyChallenger<F> {}

impl<F: Field> GrindingChallenger for ConfigurationOnlyChallenger<F> {
    type Witness = F;

    fn grind(&mut self, _bits: usize) -> Self::Witness {
        F::ZERO
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactStaticCatalogError {
    ArithmeticOverflow,
    InvalidGeometry,
    IncompleteLifecycle,
    HardBoundExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaskGroupRole {
    CrossEpochOpening,
    CfwInner,
    CfwOuter,
    WhirSumcheck { batch_ordinal: u8 },
    WhirCodeSwitch { round_ordinal: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MaskGroupStaticLedger {
    role: MaskGroupRole,
    width: u64,
    message_length: u64,
    randomness_length: u64,
    domain_size: u64,
    committed_encoding_source: MaskCommittedEncodingSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaskCommittedEncodingSource {
    OwnedByThisEpoch,
    ReusedFromPreChallenge,
}

impl MaskCommittedEncodingSource {
    const fn is_owned_by_this_epoch(self) -> bool {
        matches!(self, Self::OwnedByThisEpoch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaskEncodingRandomnessLength {
    LocalMaskQueryCount,
    Fixed(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MaskGroupStaticSpecification {
    role: MaskGroupRole,
    width: u64,
    message_length: u64,
    encoding_randomness_length: MaskEncodingRandomnessLength,
    committed_encoding_source: MaskCommittedEncodingSource,
}

impl MaskGroupStaticLedger {
    fn derive(
        role: MaskGroupRole,
        width: u64,
        message_length: u64,
        randomness_length: u64,
        committed_encoding_source: MaskCommittedEncodingSource,
    ) -> Result<Self, CompactStaticCatalogError> {
        if width == 0
            || message_length == 0
            || randomness_length == 0
            || (committed_encoding_source == MaskCommittedEncodingSource::ReusedFromPreChallenge
                && role != MaskGroupRole::CrossEpochOpening)
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let populated_message_length = message_length
            .checked_add(randomness_length)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let domain_size = populated_message_length
            .checked_next_power_of_two()
            .and_then(|value| value.checked_shl(MASK_CODE_LOG_INVERSE_RATE))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        Ok(Self {
            role,
            width,
            message_length,
            randomness_length,
            domain_size,
            committed_encoding_source,
        })
    }

    fn encoded_extension_element_count(self) -> Result<u64, CompactStaticCatalogError> {
        self.width
            .checked_mul(self.domain_size)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
    }

    fn butterfly_count(self) -> Result<u64, CompactStaticCatalogError> {
        self.width
            .checked_mul(self.domain_size / 2)
            .and_then(|count| count.checked_mul(u64::from(self.domain_size.ilog2())))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WhirStaticLedger {
    polynomial_variable_count: u32,
    first_folding_factor: u32,
    folding_schedule: [u32; WHIR_FOLD_BATCH_COUNT],
    final_variable_count: u32,
    round_log_inverse_rates: [u32; WHIR_ROUND_COUNT],
    query_counts: [u64; WHIR_FOLD_BATCH_COUNT],
    mask_query_count: u64,
    oracle_widths: [u64; WHIR_FOLD_BATCH_COUNT],
    oracle_heights: [u64; WHIR_FOLD_BATCH_COUNT],
    source_message_lengths: [u64; WHIR_FOLD_BATCH_COUNT],
    internal_mask_groups: Vec<MaskGroupStaticLedger>,
    external_mask_groups: Vec<MaskGroupStaticLedger>,
    external_generalized_relation_claim_count: u64,
    external_carried_mask_message_randomness_element_count: u64,
    mask_query_union_branch_count: u64,
    opening_evaluation_count: u64,
    opening_batching_claim_count: u64,
    initial_oracle_value_byte_length: u64,
    proof_byte_length: u64,
    merkle_root_count_in_proof: u64,
    merkle_opening_count: u64,
    query_value_byte_length: u64,
    authentication_frontier_byte_length: u64,
    transported_salt_byte_length: u64,
    merkle_parent_hash_count: u64,
    non_oracle_extension_element_count: u64,
    encoded_base_field_element_count: u64,
    encoded_extension_element_count: u64,
    base_coordinate_butterfly_count: u64,
    committed_leaf_count: u64,
    commitment_leaf_hash_query_count: u64,
    commitment_parent_hash_query_count: u64,
    verifier_opened_leaf_hash_query_count: u64,
    source_oracle_encoding_randomness_element_count: u64,
    carried_mask_message_randomness_element_count: u64,
    carried_mask_encoding_randomness_element_count: u64,
    fresh_mirror_message_randomness_element_count: u64,
    fresh_mirror_encoding_randomness_element_count: u64,
    fresh_source_message_randomness_element_count: u64,
    fresh_source_encoding_randomness_element_count: u64,
    private_extension_randomness_element_count: u64,
}

impl WhirStaticLedger {
    fn mask_groups_in_commitment_order(&self) -> impl Iterator<Item = &MaskGroupStaticLedger> {
        self.external_mask_groups
            .iter()
            .chain(self.internal_mask_groups.iter())
    }

    fn derive(
        polynomial_variable_count: u32,
        first_folding_factor: u32,
        round_log_inverse_rates: [u32; WHIR_ROUND_COUNT],
        opening_evaluation_count: u64,
        initial_oracle_value_byte_length: u64,
        external_mask_group_specifications: Vec<MaskGroupStaticSpecification>,
        external_generalized_relation_claim_count: u64,
        external_carried_mask_message_randomness_element_count: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        if external_mask_group_specifications.is_empty()
            && (external_generalized_relation_claim_count != 0
                || external_carried_mask_message_randomness_element_count != 0)
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let folding_schedule = [
            first_folding_factor,
            WHIR_REPEATED_FOLDING_FACTOR,
            WHIR_REPEATED_FOLDING_FACTOR,
            WHIR_REPEATED_FOLDING_FACTOR,
        ];
        let folded_variable_count = folding_schedule.iter().try_fold(0_u32, |sum, value| {
            sum.checked_add(*value)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
        })?;
        let final_variable_count = polynomial_variable_count
            .checked_sub(folded_variable_count)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        if final_variable_count == 0 || final_variable_count > 6 {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let rates = [
            MAIN_CODE_LOG_INVERSE_RATE,
            round_log_inverse_rates[0],
            round_log_inverse_rates[1],
            round_log_inverse_rates[2],
        ];
        let internal_mask_group_count = 2_u64
            .checked_mul(
                u64::try_from(WHIR_ROUND_COUNT)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_add(1))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let mask_group_count = internal_mask_group_count
            .checked_add(
                u64::try_from(external_mask_group_specifications.len())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let mask_query_union_branch_count = mask_group_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let mut remaining_variables = polynomial_variable_count;
        let mut oracle_widths = [0_u64; WHIR_FOLD_BATCH_COUNT];
        let mut oracle_heights = [0_u64; WHIR_FOLD_BATCH_COUNT];
        let mut source_message_lengths = [0_u64; WHIR_FOLD_BATCH_COUNT];
        let mut query_counts = [0_u64; WHIR_FOLD_BATCH_COUNT];
        for (batch_ordinal, folding_factor) in folding_schedule.iter().copied().enumerate() {
            remaining_variables = remaining_variables
                .checked_sub(folding_factor)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
            oracle_widths[batch_ordinal] = 1_u64
                .checked_shl(folding_factor)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            let message_rows = 1_u64
                .checked_shl(remaining_variables)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            source_message_lengths[batch_ordinal] = message_rows;
            oracle_heights[batch_ordinal] = message_rows
                .checked_shl(rates[batch_ordinal])
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            query_counts[batch_ordinal] = exact_full_dimension_unique_decoding_query_count(
                WHIR_PROTOCOL_SECURITY_LEVEL,
                message_rows,
                oracle_heights[batch_ordinal],
            )?;
            let randomness_slack = oracle_heights[batch_ordinal]
                .checked_sub(message_rows)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
            if query_counts[batch_ordinal] > randomness_slack {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
        }
        let vendored_mask_query_security_level = WHIR_PROTOCOL_SECURITY_LEVEL
            .checked_add(ceil_log2(
                internal_mask_group_count
                    .checked_add(1)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )?)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let vendored_mask_query_count = u64::from(exact_query_count(
            vendored_mask_query_security_level,
            MASK_CODE_LOG_INVERSE_RATE,
        ));
        let mut mask_message_lengths = Vec::with_capacity(
            usize::try_from(mask_group_count)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        );
        mask_message_lengths.push(SUMCHECK_MASK_MESSAGE_LENGTH);
        for round_ordinal in 0..WHIR_ROUND_COUNT {
            mask_message_lengths.push(query_counts[round_ordinal]);
            mask_message_lengths.push(SUMCHECK_MASK_MESSAGE_LENGTH);
        }
        mask_message_lengths.extend(
            external_mask_group_specifications
                .iter()
                .map(|specification| specification.message_length),
        );
        if mask_message_lengths.len()
            != usize::try_from(mask_group_count)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let minimum_complete_mask_query_count = exact_mask_query_count_for_final_verifier_move(
            source_message_lengths[WHIR_ROUND_COUNT],
            oracle_heights[WHIR_ROUND_COUNT],
            query_counts[WHIR_ROUND_COUNT],
            &mask_message_lengths,
            vendored_mask_query_count,
            INTERACTIVE_VERIFIER_MOVE_SECURITY_LEVEL,
        )?;
        let mask_query_count = minimum_complete_mask_query_count;

        let mut internal_mask_groups = Vec::with_capacity(7);
        internal_mask_groups.push(MaskGroupStaticLedger::derive(
            MaskGroupRole::WhirSumcheck { batch_ordinal: 0 },
            u64::from(folding_schedule[0]),
            SUMCHECK_MASK_MESSAGE_LENGTH,
            mask_query_count,
            MaskCommittedEncodingSource::OwnedByThisEpoch,
        )?);
        for round_ordinal in 0..WHIR_ROUND_COUNT {
            internal_mask_groups.push(MaskGroupStaticLedger::derive(
                MaskGroupRole::WhirCodeSwitch {
                    round_ordinal: u8::try_from(round_ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                },
                1,
                query_counts[round_ordinal],
                mask_query_count,
                MaskCommittedEncodingSource::OwnedByThisEpoch,
            )?);
            internal_mask_groups.push(MaskGroupStaticLedger::derive(
                MaskGroupRole::WhirSumcheck {
                    batch_ordinal: u8::try_from(round_ordinal + 1)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                },
                u64::from(folding_schedule[round_ordinal + 1]),
                SUMCHECK_MASK_MESSAGE_LENGTH,
                mask_query_count,
                MaskCommittedEncodingSource::OwnedByThisEpoch,
            )?);
        }
        let external_mask_groups = external_mask_group_specifications
            .iter()
            .map(|specification| {
                let randomness_length = match specification.encoding_randomness_length {
                    MaskEncodingRandomnessLength::LocalMaskQueryCount => mask_query_count,
                    MaskEncodingRandomnessLength::Fixed(randomness_length) => randomness_length,
                };
                MaskGroupStaticLedger::derive(
                    specification.role,
                    specification.width,
                    specification.message_length,
                    randomness_length,
                    specification.committed_encoding_source,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let external_mask_message_element_capacity =
            external_mask_groups
                .iter()
                .try_fold(0_u64, |count, group| {
                    checked_add(
                        count,
                        checked_product(&[group.width, group.message_length])?,
                    )
                })?;
        if external_carried_mask_message_randomness_element_count
            > external_mask_message_element_capacity
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let opening_batching_claim_count = opening_evaluation_count
            .checked_add(external_generalized_relation_claim_count)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;

        let mut query_value_byte_length = 0_u64;
        let mut authentication_frontier_byte_length = 0_u64;
        let mut transported_salt_byte_length = 0_u64;
        let mut merkle_opening_count = 0_u64;
        let mut merkle_parent_hash_count = 0_u64;
        for round_ordinal in 0..WHIR_ROUND_COUNT {
            let value_byte_length = if round_ordinal == 0 {
                initial_oracle_value_byte_length
            } else {
                EXTENSION_FIELD_ELEMENT_BYTE_LENGTH
            };
            let opening_count = query_counts[round_ordinal];
            query_value_byte_length = checked_add(
                query_value_byte_length,
                checked_product(&[
                    opening_count,
                    oracle_widths[round_ordinal],
                    value_byte_length,
                ])?,
            )?;
            authentication_frontier_byte_length = checked_add(
                authentication_frontier_byte_length,
                maximum_frontier_byte_length(oracle_heights[round_ordinal], opening_count)?,
            )?;
            transported_salt_byte_length = checked_add(
                transported_salt_byte_length,
                checked_product(&[opening_count, PRIVATE_LEAF_SALT_BYTE_LENGTH])?,
            )?;
            merkle_opening_count = checked_add(merkle_opening_count, opening_count)?;
            merkle_parent_hash_count = checked_add(
                merkle_parent_hash_count,
                maximum_frontier_parent_hash_count(oracle_heights[round_ordinal], opening_count)?,
            )?;
        }

        let final_query_count = query_counts[WHIR_ROUND_COUNT];
        let final_height = oracle_heights[WHIR_ROUND_COUNT];
        let final_source_width = oracle_widths[WHIR_ROUND_COUNT];
        query_value_byte_length = checked_add(
            query_value_byte_length,
            checked_product(&[
                final_query_count,
                final_source_width + 1,
                EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
            ])?,
        )?;
        authentication_frontier_byte_length = checked_add(
            authentication_frontier_byte_length,
            checked_product(&[
                2,
                maximum_frontier_byte_length(final_height, final_query_count)?,
            ])?,
        )?;
        transported_salt_byte_length = checked_add(
            transported_salt_byte_length,
            checked_product(&[2 * final_query_count, PRIVATE_LEAF_SALT_BYTE_LENGTH])?,
        )?;
        merkle_opening_count = checked_add(merkle_opening_count, 2 * final_query_count)?;
        merkle_parent_hash_count = checked_add(
            merkle_parent_hash_count,
            checked_product(&[
                2,
                maximum_frontier_parent_hash_count(final_height, final_query_count)?,
            ])?,
        )?;

        // CFW inner and outer groups are committed by the outer reduction
        // before WHIR creates any sumcheck or code-switch group. Construction
        // 7.2 carries every mask in that commitment order.
        let all_mask_groups = external_mask_groups
            .iter()
            .chain(internal_mask_groups.iter())
            .copied()
            .collect::<Vec<_>>();
        for group in &all_mask_groups {
            let paired_opening_count = 2 * mask_query_count;
            query_value_byte_length = checked_add(
                query_value_byte_length,
                checked_product(&[
                    paired_opening_count,
                    group.width,
                    EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
                ])?,
            )?;
            authentication_frontier_byte_length = checked_add(
                authentication_frontier_byte_length,
                checked_product(&[
                    2,
                    maximum_frontier_byte_length(group.domain_size, mask_query_count)?,
                ])?,
            )?;
            transported_salt_byte_length = checked_add(
                transported_salt_byte_length,
                checked_product(&[paired_opening_count, PRIVATE_LEAF_SALT_BYTE_LENGTH])?,
            )?;
            merkle_opening_count = checked_add(merkle_opening_count, paired_opening_count)?;
            merkle_parent_hash_count = checked_add(
                merkle_parent_hash_count,
                checked_product(&[
                    2,
                    maximum_frontier_parent_hash_count(group.domain_size, mask_query_count)?,
                ])?,
            )?;
        }

        let folded_variable_count = u64::from(polynomial_variable_count - final_variable_count);
        let zk_sumcheck_extension_element_count = u64::try_from(WHIR_FOLD_BATCH_COUNT)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            .checked_add(2 * folded_variable_count)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let source_blinding_extension_element_count = checked_add(
            1_u64
                .checked_shl(final_variable_count)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            final_query_count,
        )?;
        let mask_blinding_extension_element_count =
            all_mask_groups.iter().try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[
                        group.width,
                        group.message_length + group.randomness_length,
                    ])?,
                )
            })?;
        let non_oracle_extension_element_count = opening_evaluation_count
            .checked_add(zk_sumcheck_extension_element_count)
            .and_then(|count| count.checked_add(1))
            .and_then(|count| count.checked_add(source_blinding_extension_element_count))
            .and_then(|count| count.checked_add(mask_blinding_extension_element_count))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;

        let merkle_root_count_in_proof = u64::try_from(WHIR_FOLD_BATCH_COUNT)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            .checked_add(
                2 * u64::try_from(WHIR_ROUND_COUNT)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_add(1))
            .and_then(|count| count.checked_add(u64::try_from(all_mask_groups.len()).ok()?))
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let proof_byte_length = [
            CANONICAL_WHIR_PROOF_FRAME_BYTE_LENGTH,
            merkle_root_count_in_proof * MERKLE_DIGEST_BYTE_LENGTH,
            non_oracle_extension_element_count * EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
            query_value_byte_length,
            authentication_frontier_byte_length,
            transported_salt_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        let initial_encoded_element_count =
            checked_product(&[oracle_widths[0], oracle_heights[0]])?;
        let mut encoded_base_field_element_count = 0_u64;
        let mut encoded_extension_element_count = 0_u64;
        if initial_oracle_value_byte_length == BASE_FIELD_ELEMENT_BYTE_LENGTH {
            encoded_base_field_element_count = initial_encoded_element_count;
        } else if initial_oracle_value_byte_length == EXTENSION_FIELD_ELEMENT_BYTE_LENGTH {
            encoded_extension_element_count = initial_encoded_element_count;
        } else {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        for oracle_ordinal in 1..WHIR_FOLD_BATCH_COUNT {
            encoded_extension_element_count = checked_add(
                encoded_extension_element_count,
                checked_product(&[
                    oracle_widths[oracle_ordinal],
                    oracle_heights[oracle_ordinal],
                ])?,
            )?;
        }
        encoded_extension_element_count =
            checked_add(encoded_extension_element_count, final_height)?;
        for group in &internal_mask_groups {
            encoded_extension_element_count = checked_add(
                encoded_extension_element_count,
                2 * group.encoded_extension_element_count()?,
            )?;
        }
        for group in &external_mask_groups {
            let encoding_count = if group.committed_encoding_source.is_owned_by_this_epoch() {
                2
            } else {
                1
            };
            encoded_extension_element_count = checked_add(
                encoded_extension_element_count,
                checked_product(&[encoding_count, group.encoded_extension_element_count()?])?,
            )?;
        }

        // Every committed row is hashed through the production bounded-memory
        // shape: one salted initial call, one predecessor-linked call per
        // column, and one final call. The source commitment is outside the
        // serialized WHIR proof; carried external CFW masks are outside the
        // main WHIR proof as well, but all of those trees remain prover work.
        let mut commitment_tree_shapes = oracle_widths
            .into_iter()
            .zip(oracle_heights)
            .collect::<Vec<_>>();
        commitment_tree_shapes.push((1, final_height));
        for group in &all_mask_groups {
            if group.committed_encoding_source.is_owned_by_this_epoch() {
                commitment_tree_shapes.push((group.width, group.domain_size));
            }
            commitment_tree_shapes.push((group.width, group.domain_size));
        }
        let committed_leaf_count = commitment_tree_shapes
            .iter()
            .try_fold(0_u64, |count, (_, height)| checked_add(count, *height))?;
        let commitment_leaf_hash_query_count =
            commitment_tree_shapes
                .iter()
                .try_fold(0_u64, |count, (width, height)| {
                    checked_add(count, checked_product(&[*height, checked_add(*width, 2)?])?)
                })?;
        let commitment_parent_hash_query_count =
            commitment_tree_shapes
                .iter()
                .try_fold(0_u64, |count, (_, height)| {
                    checked_add(
                        count,
                        height
                            .checked_sub(1)
                            .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
                    )
                })?;
        let owned_external_commitment_count = external_mask_groups
            .iter()
            .filter(|group| group.committed_encoding_source.is_owned_by_this_epoch())
            .count();
        let expected_total_commitment_count = merkle_root_count_in_proof
            .checked_add(1)
            .and_then(|count| {
                count.checked_add(u64::try_from(owned_external_commitment_count).ok()?)
            })
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        if u64::try_from(commitment_tree_shapes.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            != expected_total_commitment_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let mut verifier_opened_leaf_hash_query_count = 0_u64;
        for round_ordinal in 0..WHIR_ROUND_COUNT {
            verifier_opened_leaf_hash_query_count = checked_add(
                verifier_opened_leaf_hash_query_count,
                checked_product(&[
                    query_counts[round_ordinal],
                    checked_add(oracle_widths[round_ordinal], 2)?,
                ])?,
            )?;
        }
        verifier_opened_leaf_hash_query_count = checked_add(
            verifier_opened_leaf_hash_query_count,
            checked_product(&[final_query_count, checked_add(final_source_width, 2)?])?,
        )?;
        verifier_opened_leaf_hash_query_count = checked_add(
            verifier_opened_leaf_hash_query_count,
            checked_product(&[final_query_count, 3])?,
        )?;
        for group in &all_mask_groups {
            verifier_opened_leaf_hash_query_count = checked_add(
                verifier_opened_leaf_hash_query_count,
                checked_product(&[2, mask_query_count, checked_add(group.width, 2)?])?,
            )?;
        }

        let mut base_coordinate_butterfly_count = checked_product(&[
            oracle_widths[0],
            oracle_heights[0] / 2,
            u64::from(oracle_heights[0].ilog2()),
            initial_oracle_value_byte_length / BASE_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        for oracle_ordinal in 1..WHIR_FOLD_BATCH_COUNT {
            base_coordinate_butterfly_count = checked_add(
                base_coordinate_butterfly_count,
                checked_product(&[
                    oracle_widths[oracle_ordinal],
                    oracle_heights[oracle_ordinal] / 2,
                    u64::from(oracle_heights[oracle_ordinal].ilog2()),
                    QUINTIC_EXTENSION_DEGREE,
                ])?,
            )?;
        }
        base_coordinate_butterfly_count = checked_add(
            base_coordinate_butterfly_count,
            checked_product(&[
                final_height / 2,
                u64::from(final_height.ilog2()),
                QUINTIC_EXTENSION_DEGREE,
            ])?,
        )?;
        for group in &internal_mask_groups {
            base_coordinate_butterfly_count = checked_add(
                base_coordinate_butterfly_count,
                2 * group.butterfly_count()? * QUINTIC_EXTENSION_DEGREE,
            )?;
        }
        for group in &external_mask_groups {
            let encoding_count = if group.committed_encoding_source.is_owned_by_this_epoch() {
                2
            } else {
                1
            };
            base_coordinate_butterfly_count = checked_add(
                base_coordinate_butterfly_count,
                checked_product(&[
                    encoding_count,
                    group.butterfly_count()?,
                    QUINTIC_EXTENSION_DEGREE,
                ])?,
            )?;
        }

        let initial_oracle_encoding_randomness_element_count =
            checked_product(&[oracle_widths[0], query_counts[0]])?;
        let subsequent_oracle_encoding_randomness_element_count = (1..WHIR_FOLD_BATCH_COUNT)
            .try_fold(0_u64, |count, oracle_ordinal| {
                checked_add(
                    count,
                    checked_product(&[
                        oracle_widths[oracle_ordinal],
                        query_counts[oracle_ordinal],
                    ])?,
                )
            })?;
        let source_oracle_encoding_randomness_element_count = checked_add(
            initial_oracle_encoding_randomness_element_count,
            subsequent_oracle_encoding_randomness_element_count,
        )?;
        let internal_carried_mask_message_randomness_element_count = internal_mask_groups
            .iter()
            .try_fold(0_u64, |count, group| {
                let group_randomness = match group.role {
                    MaskGroupRole::WhirSumcheck { .. } => {
                        checked_product(&[group.width, group.message_length])?
                    }
                    MaskGroupRole::WhirCodeSwitch { .. } => 0,
                    MaskGroupRole::CrossEpochOpening
                    | MaskGroupRole::CfwInner
                    | MaskGroupRole::CfwOuter => {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                };
                checked_add(count, group_randomness)
            })?;
        let carried_mask_message_randomness_element_count = checked_add(
            internal_carried_mask_message_randomness_element_count,
            external_carried_mask_message_randomness_element_count,
        )?;
        let carried_mask_encoding_randomness_element_count = all_mask_groups
            .iter()
            .filter(|group| group.committed_encoding_source.is_owned_by_this_epoch())
            .try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.randomness_length])?,
                )
            })?;
        let fresh_mirror_message_randomness_element_count =
            all_mask_groups.iter().try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.message_length])?,
                )
            })?;
        let fresh_mirror_encoding_randomness_element_count =
            all_mask_groups.iter().try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.randomness_length])?,
                )
            })?;
        let fresh_source_message_randomness_element_count = 1_u64
            .checked_shl(final_variable_count)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let fresh_source_encoding_randomness_element_count = final_query_count;
        let private_extension_randomness_element_count = [
            source_oracle_encoding_randomness_element_count,
            carried_mask_message_randomness_element_count,
            carried_mask_encoding_randomness_element_count,
            fresh_mirror_message_randomness_element_count,
            fresh_mirror_encoding_randomness_element_count,
            fresh_source_message_randomness_element_count,
            fresh_source_encoding_randomness_element_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        let ledger = Self {
            polynomial_variable_count,
            first_folding_factor,
            folding_schedule,
            final_variable_count,
            round_log_inverse_rates,
            query_counts,
            mask_query_count,
            oracle_widths,
            oracle_heights,
            source_message_lengths,
            internal_mask_groups,
            external_mask_groups,
            external_generalized_relation_claim_count,
            external_carried_mask_message_randomness_element_count,
            mask_query_union_branch_count,
            opening_evaluation_count,
            opening_batching_claim_count,
            initial_oracle_value_byte_length,
            proof_byte_length,
            merkle_root_count_in_proof,
            merkle_opening_count,
            query_value_byte_length,
            authentication_frontier_byte_length,
            transported_salt_byte_length,
            merkle_parent_hash_count,
            non_oracle_extension_element_count,
            encoded_base_field_element_count,
            encoded_extension_element_count,
            base_coordinate_butterfly_count,
            committed_leaf_count,
            commitment_leaf_hash_query_count,
            commitment_parent_hash_query_count,
            verifier_opened_leaf_hash_query_count,
            source_oracle_encoding_randomness_element_count,
            carried_mask_message_randomness_element_count,
            carried_mask_encoding_randomness_element_count,
            fresh_mirror_message_randomness_element_count,
            fresh_mirror_encoding_randomness_element_count,
            fresh_source_message_randomness_element_count,
            fresh_source_encoding_randomness_element_count,
            private_extension_randomness_element_count,
        };
        ledger.check_vendored_configuration_correspondence()?;
        ledger.check_randomness_ledger()?;
        Ok(ledger)
    }

    fn check_randomness_ledger(&self) -> Result<(), CompactStaticCatalogError> {
        let expected_source_oracle_encoding_randomness_element_count = self
            .oracle_widths
            .into_iter()
            .zip(self.query_counts)
            .try_fold(0_u64, |count, (width, query_count)| {
                checked_add(count, checked_product(&[width, query_count])?)
            })?;
        let expected_internal_carried_message_randomness_element_count = self
            .internal_mask_groups
            .iter()
            .try_fold(0_u64, |count, group| {
                let group_randomness = match group.role {
                    MaskGroupRole::WhirSumcheck { .. } => {
                        checked_product(&[group.width, group.message_length])?
                    }
                    MaskGroupRole::WhirCodeSwitch { .. } => 0,
                    MaskGroupRole::CrossEpochOpening
                    | MaskGroupRole::CfwInner
                    | MaskGroupRole::CfwOuter => {
                        return Err(CompactStaticCatalogError::InvalidGeometry);
                    }
                };
                checked_add(count, group_randomness)
            })?;
        let expected_carried_mask_message_randomness_element_count = checked_add(
            expected_internal_carried_message_randomness_element_count,
            self.external_carried_mask_message_randomness_element_count,
        )?;
        let expected_carried_mask_encoding_randomness_element_count = self
            .mask_groups_in_commitment_order()
            .filter(|group| group.committed_encoding_source.is_owned_by_this_epoch())
            .try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.randomness_length])?,
                )
            })?;
        let expected_fresh_mirror_encoding_randomness_element_count = self
            .mask_groups_in_commitment_order()
            .try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.randomness_length])?,
                )
            })?;
        let expected_fresh_mirror_message_randomness_element_count = self
            .mask_groups_in_commitment_order()
            .try_fold(0_u64, |count, group| {
                checked_add(
                    count,
                    checked_product(&[group.width, group.message_length])?,
                )
            })?;
        let expected_fresh_source_message_randomness_element_count = 1_u64
            .checked_shl(self.final_variable_count)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        let expected_fresh_source_encoding_randomness_element_count =
            self.query_counts[WHIR_ROUND_COUNT];
        let expected_total = [
            expected_source_oracle_encoding_randomness_element_count,
            expected_carried_mask_message_randomness_element_count,
            expected_carried_mask_encoding_randomness_element_count,
            expected_fresh_mirror_message_randomness_element_count,
            expected_fresh_mirror_encoding_randomness_element_count,
            expected_fresh_source_message_randomness_element_count,
            expected_fresh_source_encoding_randomness_element_count,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;

        if self.source_oracle_encoding_randomness_element_count
            != expected_source_oracle_encoding_randomness_element_count
            || self.carried_mask_message_randomness_element_count
                != expected_carried_mask_message_randomness_element_count
            || self.carried_mask_encoding_randomness_element_count
                != expected_carried_mask_encoding_randomness_element_count
            || self.fresh_mirror_message_randomness_element_count
                != expected_fresh_mirror_message_randomness_element_count
            || self.fresh_mirror_encoding_randomness_element_count
                != expected_fresh_mirror_encoding_randomness_element_count
            || self.fresh_source_message_randomness_element_count
                != expected_fresh_source_message_randomness_element_count
            || self.fresh_source_encoding_randomness_element_count
                != expected_fresh_source_encoding_randomness_element_count
            || self.private_extension_randomness_element_count != expected_total
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    fn check_vendored_configuration_correspondence(&self) -> Result<(), CompactStaticCatalogError> {
        match self.initial_oracle_value_byte_length {
            BASE_FIELD_ELEMENT_BYTE_LENGTH => {
                self.check_vendored_configuration_for_base_field::<Goldilocks>()
            }
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH => {
                self.check_vendored_configuration_for_base_field::<ChallengeField>()
            }
            _ => Err(CompactStaticCatalogError::InvalidGeometry),
        }
    }

    fn check_vendored_configuration_for_base_field<F>(
        &self,
    ) -> Result<(), CompactStaticCatalogError>
    where
        F: TwoAdicField,
        ChallengeField: ExtensionField<F> + TwoAdicField,
    {
        let folding_schedule = self
            .folding_schedule
            .into_iter()
            .map(|factor| {
                usize::try_from(factor).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let round_log_inverse_rates = self
            .round_log_inverse_rates
            .into_iter()
            .map(|rate| {
                usize::try_from(rate).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let configuration = ZkWhirConfig::<ChallengeField, F, ConfigurationOnlyChallenger<F>>::new(
            usize::try_from(self.polynomial_variable_count)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            ProtocolParameters {
                starting_log_inv_rate: usize::try_from(MAIN_CODE_LOG_INVERSE_RATE)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                round_log_inv_rates: round_log_inverse_rates.clone(),
                folding_factor: FoldingFactor::PerRound(folding_schedule.clone()),
                soundness_type: SecurityAssumption::UniqueDecoding,
                security_level: usize::try_from(WHIR_PROTOCOL_SECURITY_LEVEL)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                pow_bits: 0,
            },
            ZkParameters {
                ell_zk: usize::try_from(SUMCHECK_MASK_MESSAGE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                mask_log_inv_rate: usize::try_from(MASK_CODE_LOG_INVERSE_RATE)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
        )
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;

        let query_counts = configuration
            .round_parameters
            .iter()
            .map(|round| u64::try_from(round.num_queries))
            .chain(core::iter::once(u64::try_from(configuration.final_queries)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let source_code_shapes = configuration
            .source_code_shapes
            .iter()
            .map(|shape| {
                Ok((
                    u64::try_from(shape.message_len)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    u64::try_from(shape.randomness_len)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    u64::try_from(shape.domain_size)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                ))
            })
            .collect::<Result<Vec<_>, CompactStaticCatalogError>>()?;
        let expected_source_code_shapes = self
            .source_message_lengths
            .into_iter()
            .zip(self.query_counts)
            .zip(self.oracle_heights)
            .map(|((message_length, randomness_length), domain_size)| {
                (message_length, randomness_length, domain_size)
            })
            .collect::<Vec<_>>();
        let oracle_widths = (0..WHIR_FOLD_BATCH_COUNT)
            .map(|ordinal| {
                1_u64
                    .checked_shl(
                        u32::try_from(configuration.round_folding_factor(ordinal))
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    )
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut oracle_heights = configuration
            .round_parameters
            .iter()
            .map(|round| {
                u64::try_from(round.domain_size >> round.folding_factor)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let final_round = configuration.final_round_config();
        oracle_heights.push(
            u64::try_from(final_round.domain_size >> final_round.folding_factor)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        );
        let internal_mask_groups = configuration
            .mask_groups()
            .into_iter()
            .enumerate()
            .map(|(group_ordinal, group)| {
                let role = if group_ordinal % 2 == 0 {
                    MaskGroupRole::WhirSumcheck {
                        batch_ordinal: u8::try_from(group_ordinal / 2)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    }
                } else {
                    MaskGroupRole::WhirCodeSwitch {
                        round_ordinal: u8::try_from(group_ordinal / 2)
                            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    }
                };
                Ok(MaskGroupStaticLedger {
                    role,
                    width: u64::try_from(group.width)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    message_length: u64::try_from(group.shape.message_len)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    randomness_length: u64::try_from(group.shape.randomness_len)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    domain_size: u64::try_from(group.shape.domain_size)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                    committed_encoding_source: MaskCommittedEncodingSource::OwnedByThisEpoch,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let vendored_mask_query_count = u64::try_from(configuration.mask_queries)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let internal_mask_groups_match = vendored_mask_query_count == self.mask_query_count
            && internal_mask_groups == self.internal_mask_groups;
        let opening_batching_claim_count_matches = self.opening_batching_claim_count
            == self
                .opening_evaluation_count
                .checked_add(self.external_generalized_relation_claim_count)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;

        if configuration.folding_schedule != folding_schedule
            || configuration.params.round_log_inv_rates != round_log_inverse_rates
            || configuration.final_sumcheck_rounds
                != usize::try_from(self.final_variable_count)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || configuration.commitment_ood_samples != 0
            || configuration.starting_folding_pow_bits != 0
            || configuration.final_pow_bits != 0
            || configuration.final_folding_pow_bits != 0
            || configuration.round_parameters.iter().any(|round| {
                round.ood_samples != 0 || round.pow_bits != 0 || round.folding_pow_bits != 0
            })
            || !configuration.check_pow_bits()
            || query_counts.as_slice() != self.query_counts
            || source_code_shapes != expected_source_code_shapes
            || oracle_widths.as_slice() != self.oracle_widths
            || oracle_heights.as_slice() != self.oracle_heights
            || !internal_mask_groups_match
            || !opening_batching_claim_count_matches
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PackingStaticCatalog {
    packing_factor: u64,
    pre_challenge_whir: WhirStaticLedger,
    main_whir: WhirStaticLedger,
    transcript_chronology: transcript_chronology::PackingTranscriptChronology,
    uniform_verifier_randomness: uniform_verifier_randomness::PackingUniformVerifierRandomness,
    response_commitments: response_commitment::PackingResponseCommitmentCatalog,
    response_commitment_lifecycle:
        response_commitment_lifecycle::PackingResponseCommitmentLifecycle,
    query_sampling_lifecycle: lifecycle::PackingQuerySamplingLifecycle,
    masking_leakage: masking_leakage::PackingMaskingLeakageCorrespondence,
    interactive_soundness: soundness::PackingInteractiveSoundness,
    relaxed_round_by_round: relaxed_round_by_round::RelaxedRoundByRoundCatalog,
    emitted_byte_correspondence: emitted_byte_correspondence::PackingEmittedByteCorrespondence,
    non_interactive_soundness: non_interactive_soundness::PackingNonInteractiveSoundness,
    proof_wire_geometry: CompactProofWireGeometry,
    response_checkpoint_schedule: CompactResponseCheckpointSchedule,
    proof_assembler_heap_geometry: CompactProofWireAssemblerHeapGeometry,
    response_postorder_writer_heap_geometry: CompactResponsePostorderWriterHeapGeometry,
    response_frontier_scanner_heap_geometry: CompactResponseFrontierScannerHeapGeometry,
    response_external_memory_geometry: CompactResponseTreeExternalMemoryGeometry,
    maximum_response_query_schedule_heap_byte_length: u64,
    maximum_response_input_heap_payload_byte_length: u64,
    maximum_response_tree_kernel_heap_byte_length: u64,
    public_input_wire_geometry: CompactPublicInputWireGeometry,
    transcript_binding: transcript_binding::PackingTranscriptBindingLedger,
    maximum_proof_byte_length: u64,
    public_input_byte_length: u64,
    transport_byte_length: u64,
    transport_chunk_count: u64,
    commitment_peak_byte_length: u64,
    cfw_to_whir_retained_payload_byte_length: u64,
    wasm_peak_byte_length: u64,
    scratch_byte_length: u64,
    proof_allocation_byte_length: u64,
    base_coordinate_butterfly_count: u64,
    committed_leaf_count: u64,
    commitment_leaf_hash_query_count: u64,
    commitment_parent_hash_query_count: u64,
    verifier_opened_leaf_hash_query_count: u64,
    maximum_uninterrupted_butterfly_count: u64,
    maximum_uninterrupted_leaf_hash_count: u64,
    deterministic_checkpoint_count: u64,
    maximum_phase_recomputation_count: u64,
}

impl PackingStaticCatalog {
    fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        cfw_reduction: &cfw_reduction::CfwReductionCatalog,
        cfw_to_whir_handoff: &cfw_to_whir_handoff::CfwToWhirHandoffCatalog,
        cfw_lifecycle: &cfw_lifecycle::CfwLifecycleCatalog,
        row_source_lifecycle: &row_source_lifecycle::RowSourceLifecycleCatalog,
        resource_overlap: &resource_overlap::CompactPublicKeyResourceOverlapCatalog,
        witness_covector: &witness_covector::WitnessCovectorCatalog,
        packing_factor: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        if !matches!(packing_factor, 1 | 2 | 4 | 8) {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let packing_logarithm = packing_factor.ilog2();
        let main_component_count = relation
            .padded_witness_element_count()
            .checked_div(
                relation
                    .ring_degree()
                    .checked_mul(packing_factor)
                    .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
            )
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        if !main_component_count.is_power_of_two() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let main_first_folding_factor = main_component_count.ilog2();
        let pre_challenge_component_count = PRE_CHALLENGE_PADDED_RING_VECTOR_COUNT
            .checked_div(packing_factor)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let pre_challenge_first_folding_factor = pre_challenge_component_count.ilog2();
        let round_log_inverse_rates = [
            2,
            match packing_factor {
                1 => 4,
                2 | 4 => 3,
                8 => 2,
                _ => return Err(CompactStaticCatalogError::InvalidGeometry),
            },
            8_u32
                .checked_sub(packing_logarithm)
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?,
        ];
        cfw_reduction.check(relation)?;
        cfw_lifecycle.check(relation, cfw_reduction)?;
        row_source_lifecycle.check(relation)?;
        resource_overlap.check(relation, row_source_lifecycle)?;
        witness_covector.check(relation)?;
        if row_source_lifecycle.deterministic_preparation_poll_count() == 0
            || row_source_lifecycle.maximum_uninterrupted_elementwise_work_unit_count() == 0
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }
        let cfw_mask_group_specifications = cfw_reduction.mask_group_specifications().to_vec();
        let preliminary_cross_epoch_mask_specification = MaskGroupStaticSpecification {
            role: MaskGroupRole::CrossEpochOpening,
            width: CROSS_EPOCH_MASK_WIDTH,
            message_length: CROSS_EPOCH_MASK_MESSAGE_LENGTH,
            encoding_randomness_length: MaskEncodingRandomnessLength::LocalMaskQueryCount,
            committed_encoding_source: MaskCommittedEncodingSource::OwnedByThisEpoch,
        };
        let preliminary_pre_challenge_whir = WhirStaticLedger::derive(
            PRE_CHALLENGE_MESSAGE_ELEMENT_COUNT.ilog2(),
            pre_challenge_first_folding_factor,
            round_log_inverse_rates,
            1,
            BASE_FIELD_ELEMENT_BYTE_LENGTH,
            vec![preliminary_cross_epoch_mask_specification],
            0,
            CROSS_EPOCH_MASK_WIDTH * CROSS_EPOCH_MASK_MESSAGE_LENGTH,
        )?;
        let mut preliminary_main_mask_group_specifications = cfw_mask_group_specifications.clone();
        preliminary_main_mask_group_specifications.push(MaskGroupStaticSpecification {
            committed_encoding_source: MaskCommittedEncodingSource::ReusedFromPreChallenge,
            ..preliminary_cross_epoch_mask_specification
        });
        let preliminary_main_whir = WhirStaticLedger::derive(
            relation.padded_witness_element_count().ilog2(),
            main_first_folding_factor,
            round_log_inverse_rates,
            2,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
            preliminary_main_mask_group_specifications,
            cfw_reduction.generalized_committed_relation_claim_count(),
            cfw_reduction.fresh_mask_randomness_element_count(),
        )?;
        let shared_cross_epoch_encoding_randomness_length = checked_add(
            preliminary_pre_challenge_whir.mask_query_count,
            preliminary_main_whir.mask_query_count,
        )?;
        let cross_epoch_mask_specification = MaskGroupStaticSpecification {
            encoding_randomness_length: MaskEncodingRandomnessLength::Fixed(
                shared_cross_epoch_encoding_randomness_length,
            ),
            ..preliminary_cross_epoch_mask_specification
        };
        let pre_challenge_whir = WhirStaticLedger::derive(
            PRE_CHALLENGE_MESSAGE_ELEMENT_COUNT.ilog2(),
            pre_challenge_first_folding_factor,
            round_log_inverse_rates,
            1,
            BASE_FIELD_ELEMENT_BYTE_LENGTH,
            vec![cross_epoch_mask_specification],
            0,
            CROSS_EPOCH_MASK_WIDTH * CROSS_EPOCH_MASK_MESSAGE_LENGTH,
        )?;
        let mut main_mask_group_specifications = cfw_mask_group_specifications;
        main_mask_group_specifications.push(MaskGroupStaticSpecification {
            committed_encoding_source: MaskCommittedEncodingSource::ReusedFromPreChallenge,
            ..cross_epoch_mask_specification
        });
        let main_whir = WhirStaticLedger::derive(
            relation.padded_witness_element_count().ilog2(),
            main_first_folding_factor,
            round_log_inverse_rates,
            2,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
            main_mask_group_specifications,
            cfw_reduction.generalized_committed_relation_claim_count(),
            cfw_reduction.fresh_mask_randomness_element_count(),
        )?;
        if pre_challenge_whir.mask_query_union_branch_count != 9
            || main_whir.mask_query_union_branch_count != 11
            || pre_challenge_whir.mask_query_count == 0
            || main_whir.mask_query_count == 0
            || pre_challenge_whir.mask_query_count
                != preliminary_pre_challenge_whir.mask_query_count
            || main_whir.mask_query_count != preliminary_main_whir.mask_query_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let transcript_chronology = transcript_chronology::PackingTranscriptChronology::derive(
            &pre_challenge_whir,
            &main_whir,
            cfw_reduction,
        )?;
        let uniform_verifier_randomness =
            uniform_verifier_randomness::PackingUniformVerifierRandomness::derive(
                &transcript_chronology,
            )?;
        let response_commitments = response_commitment::PackingResponseCommitmentCatalog::derive(
            &transcript_chronology,
            &pre_challenge_whir,
            &main_whir,
            cfw_reduction,
        )?;
        let response_commitment_lifecycle =
            response_commitment_lifecycle::PackingResponseCommitmentLifecycle::derive(
                &response_commitments,
            )?;
        let response_postorder_writer_heap_geometry =
            response_commitments.maximum_postorder_writer_heap_geometry()?;
        let response_frontier_scanner_heap_geometry =
            response_commitments.maximum_frontier_scanner_heap_geometry()?;
        let response_external_memory_geometry =
            response_commitments.maximum_external_memory_geometry()?;
        let maximum_response_query_schedule_heap_byte_length =
            response_commitments.maximum_response_query_schedule_heap_byte_length()?;
        let maximum_response_input_heap_payload_byte_length =
            response_commitments.maximum_response_input_heap_payload_byte_length()?;
        let maximum_response_tree_kernel_heap_byte_length =
            response_commitments.maximum_response_tree_kernel_heap_byte_length()?;
        let query_sampling_lifecycle =
            lifecycle::PackingQuerySamplingLifecycle::derive(&pre_challenge_whir, &main_whir)?;
        let masking_leakage = masking_leakage::PackingMaskingLeakageCorrespondence::derive(
            &pre_challenge_whir,
            &main_whir,
            &transcript_chronology,
            &query_sampling_lifecycle,
            cfw_reduction,
        )?;
        let interactive_soundness = soundness::PackingInteractiveSoundness::derive(
            relation,
            &pre_challenge_whir,
            &main_whir,
            &transcript_chronology,
            cfw_reduction,
        )?;
        let relaxed_round_by_round = relaxed_round_by_round::RelaxedRoundByRoundCatalog::derive(
            relation,
            cfw_reduction,
            cfw_to_whir_handoff,
            &pre_challenge_whir,
            &main_whir,
            &transcript_chronology,
            &interactive_soundness,
        )?;
        if transcript_chronology.distinct_query_group_count
            != query_sampling_lifecycle.query_group_count
            || transcript_chronology.fixed_query_candidate_slot_count
                != query_sampling_lifecycle.fixed_candidate_slot_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let packing_factor_u16 = u16::try_from(packing_factor)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let proof_wire_geometry = CompactProofWireGeometry::new(
            packing_factor_u16,
            response_commitments.production_wire_geometries(&uniform_verifier_randomness)?,
        )
        .map_err(map_production_wire_error)?;
        let response_checkpoint_schedule = CompactResponseCheckpointSchedule::derive(
            &proof_wire_geometry,
            &response_commitments.production_merkle_geometries()?,
        )
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let public_input_wire_geometry = CompactPublicInputWireGeometry::new(
            packing_factor_u16,
            relation.public_input_ring_vector_count(),
            relation.ring_degree(),
        )
        .map_err(map_production_wire_error)?;
        let proof_assembler_heap_geometry =
            CompactProofWireAssemblerHeapGeometry::derive(&proof_wire_geometry)
                .map_err(map_production_wire_error)?;
        if proof_wire_geometry.packing_factor() != packing_factor_u16
            || u64::try_from(proof_wire_geometry.responses().len())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
                != response_commitments.bcs_response_root_count()
            || response_checkpoint_schedule.total_response_count()
                != proof_wire_geometry.responses().len()
            || response_checkpoint_schedule.lagging_checkpoint_count() == 0
            || response_checkpoint_schedule.maximum_pending_proof_response_count() == 0
            || response_checkpoint_schedule
                .completed_proof_response_count(response_checkpoint_schedule.total_response_count())
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?
                != response_checkpoint_schedule.total_response_count()
            || u64::from(public_input_wire_geometry.field_element_count())
                != checked_product(&[
                    relation.public_input_ring_vector_count(),
                    relation.ring_degree(),
                ])?
            || proof_assembler_heap_geometry.maximum_canonical_proof_byte_length()
                != u64::try_from(proof_wire_geometry.maximum_canonical_byte_length())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let transcript_binding = transcript_binding::PackingTranscriptBindingLedger::derive(
            &proof_wire_geometry,
            public_input_wire_geometry,
            &uniform_verifier_randomness,
        )?;
        let emitted_byte_correspondence =
            emitted_byte_correspondence::PackingEmittedByteCorrespondence::derive(
                &transcript_chronology,
                &uniform_verifier_randomness,
                &response_commitments,
                &proof_wire_geometry,
                public_input_wire_geometry,
                &transcript_binding,
                cfw_reduction,
            )?;
        let non_interactive_soundness =
            non_interactive_soundness::PackingNonInteractiveSoundness::derive(
                &transcript_chronology,
                &uniform_verifier_randomness,
                &response_commitments,
                &transcript_binding,
                &relaxed_round_by_round,
                &emitted_byte_correspondence,
            )?;
        let maximum_proof_byte_length =
            u64::try_from(proof_wire_geometry.maximum_canonical_byte_length())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let public_input_byte_length =
            u64::try_from(public_input_wire_geometry.exact_canonical_byte_length())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let transport_byte_length =
            checked_add(maximum_proof_byte_length, public_input_byte_length)?;
        let transport_chunk_count = transport_byte_length.div_ceil(TRANSPORT_CHUNK_BYTE_LENGTH);

        let encoded_row_count = relation
            .ring_degree()
            .checked_mul(packing_factor)
            .and_then(|message_length| message_length.checked_add(main_whir.query_counts[0]))
            .and_then(|populated| populated.checked_mul(2))
            .and_then(u64::checked_next_power_of_two)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        if encoded_row_count != main_whir.oracle_heights[0] {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let transform_batch_component_count = (8 / packing_factor).max(1);
        let transform_batch_matrix_byte_length = checked_product(&[
            transform_batch_component_count,
            encoded_row_count,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let replay_column_byte_length =
            checked_product(&[encoded_row_count, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH])?;
        let hash_state_byte_length =
            checked_product(&[encoded_row_count, SHAKE256_STATE_BYTE_LENGTH])?;
        let twiddle_byte_length =
            checked_product(&[encoded_row_count - 1, 2, BASE_FIELD_ELEMENT_BYTE_LENGTH])?;
        let commitment_peak_byte_length = [
            transform_batch_matrix_byte_length,
            replay_column_byte_length,
            hash_state_byte_length,
            twiddle_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let whir_wasm_peak_byte_length = [
            commitment_peak_byte_length,
            resource_overlap.ready_row_source_peak_byte_length(),
            cfw_to_whir_handoff.retained_combined_relation_payload_byte_length(),
            proof_assembler_heap_geometry.maximum_owned_heap_byte_length(),
            maximum_response_tree_kernel_heap_byte_length,
            public_input_byte_length,
            TRANSPORT_CHUNK_BYTE_LENGTH,
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let cfw_transcript_handoff_byte_length = checked_product(&[
            checked_add(
                cfw_reduction.non_oracle_extension_element_count(),
                u64::from(cfw_reduction.joint_constraint_randomness_element_count()),
            )?,
            EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
        ])?;
        let cfw_wasm_peak_byte_length = cfw_lifecycle.maximum_wasm_live_byte_length(
            resource_overlap.ready_row_source_peak_byte_length(),
            proof_assembler_heap_geometry.maximum_owned_heap_byte_length(),
            maximum_response_tree_kernel_heap_byte_length,
            public_input_byte_length,
            TRANSPORT_CHUNK_BYTE_LENGTH,
            checked_add(
                cfw_transcript_handoff_byte_length,
                checked_add(
                    cfw_to_whir_handoff.transition_payload_byte_length(),
                    witness_covector.maximum_transient_field_payload_byte_length(),
                )?,
            )?,
        )?;
        let wasm_peak_byte_length = whir_wasm_peak_byte_length
            .max(cfw_wasm_peak_byte_length)
            .max(resource_overlap.maximum_preproof_peak_byte_length());
        let checkpoint_staging_byte_length = checked_add(
            maximum_proof_byte_length,
            checked_add(public_input_byte_length, 2 * TRANSPORT_CHUNK_BYTE_LENGTH)?,
        )?;
        let whir_scratch_byte_length =
            checked_add(whir_wasm_peak_byte_length, checkpoint_staging_byte_length).and_then(
                |byte_length| {
                    checked_add(
                        byte_length,
                        response_commitment_lifecycle.maximum_tree_storage_byte_length(),
                    )
                },
            )?;
        let cfw_scratch_byte_length = checked_add(
            cfw_lifecycle.maximum_scratch_byte_length()?,
            response_commitment_lifecycle.maximum_tree_storage_byte_length(),
        )?;
        let scratch_byte_length = whir_scratch_byte_length.max(cfw_scratch_byte_length);
        let proof_allocation_byte_length = maximum_proof_byte_length;

        let base_coordinate_butterfly_count = [
            pre_challenge_whir.base_coordinate_butterfly_count,
            main_whir.base_coordinate_butterfly_count,
            witness_covector.transform_butterfly_count(),
        ]
        .into_iter()
        .try_fold(0_u64, checked_add)?;
        let committed_leaf_count = checked_add(
            checked_add(
                pre_challenge_whir.committed_leaf_count,
                main_whir.committed_leaf_count,
            )?,
            response_commitments.committed_leaf_count(),
        )?;
        let commitment_leaf_hash_query_count = checked_add(
            checked_add(
                pre_challenge_whir.commitment_leaf_hash_query_count,
                main_whir.commitment_leaf_hash_query_count,
            )?,
            response_commitments.committed_leaf_count(),
        )?;
        let commitment_parent_hash_query_count = checked_add(
            checked_add(
                pre_challenge_whir.commitment_parent_hash_query_count,
                main_whir.commitment_parent_hash_query_count,
            )?,
            response_commitments.commitment_parent_hash_count(),
        )?;
        let verifier_opened_leaf_hash_query_count = checked_add(
            checked_add(
                pre_challenge_whir.verifier_opened_leaf_hash_query_count,
                main_whir.verifier_opened_leaf_hash_query_count,
            )?,
            checked_add(
                response_commitments.proof_oracle_query_count(),
                response_commitments.maximum_opening_parent_hash_count(),
            )?,
        )?;
        let maximum_uninterrupted_butterfly_count = checked_product(&[
            transform_batch_component_count,
            encoded_row_count / 2,
            u64::from(encoded_row_count.ilog2()),
            QUINTIC_EXTENSION_DEGREE,
        ])?
        .max(row_source_lifecycle.maximum_uninterrupted_transform_butterfly_count());
        let maximum_uninterrupted_leaf_hash_count = encoded_row_count;
        let whir_deterministic_checkpoint_count = 4
            + 2 * u64::try_from(WHIR_FOLD_BATCH_COUNT)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            + 2 * u64::try_from(WHIR_ROUND_COUNT)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            + 2;
        let deterministic_checkpoint_count = checked_add(
            whir_deterministic_checkpoint_count,
            cfw_lifecycle.deterministic_safe_boundary_count(),
        )?;
        let maximum_phase_recomputation_count =
            1_u64.max(cfw_lifecycle.maximum_phase_recomputation_count());

        let catalog = Self {
            packing_factor,
            pre_challenge_whir,
            main_whir,
            transcript_chronology,
            uniform_verifier_randomness,
            response_commitments,
            response_commitment_lifecycle,
            query_sampling_lifecycle,
            masking_leakage,
            interactive_soundness,
            relaxed_round_by_round,
            emitted_byte_correspondence,
            non_interactive_soundness,
            proof_wire_geometry,
            response_checkpoint_schedule,
            proof_assembler_heap_geometry,
            response_postorder_writer_heap_geometry,
            response_frontier_scanner_heap_geometry,
            response_external_memory_geometry,
            maximum_response_query_schedule_heap_byte_length,
            maximum_response_input_heap_payload_byte_length,
            maximum_response_tree_kernel_heap_byte_length,
            public_input_wire_geometry,
            transcript_binding,
            maximum_proof_byte_length,
            public_input_byte_length,
            transport_byte_length,
            transport_chunk_count,
            commitment_peak_byte_length,
            cfw_to_whir_retained_payload_byte_length: cfw_to_whir_handoff
                .retained_combined_relation_payload_byte_length(),
            wasm_peak_byte_length,
            scratch_byte_length,
            proof_allocation_byte_length,
            base_coordinate_butterfly_count,
            committed_leaf_count,
            commitment_leaf_hash_query_count,
            commitment_parent_hash_query_count,
            verifier_opened_leaf_hash_query_count,
            maximum_uninterrupted_butterfly_count,
            maximum_uninterrupted_leaf_hash_count,
            deterministic_checkpoint_count,
            maximum_phase_recomputation_count,
        };
        catalog.check_static_lifecycle()?;
        Ok(catalog)
    }

    fn check_static_lifecycle(&self) -> Result<(), CompactStaticCatalogError> {
        if self.deterministic_checkpoint_count == 0
            || self.maximum_phase_recomputation_count != 1
            || self.transport_chunk_count == 0
            || self.maximum_uninterrupted_butterfly_count == 0
            || self.maximum_uninterrupted_leaf_hash_count == 0
        {
            return Err(CompactStaticCatalogError::IncompleteLifecycle);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactPublicKeyStaticCatalog {
    relation_plan_hash: [u8; 64],
    relation_padded_witness_element_count: u64,
    relation_operative_constraint_count: u64,
    pre_challenge_ring_vector_count: u64,
    cross_epoch_point_coordinate_count: u32,
    cross_epoch_binding_error_numerator: u64,
    cross_epoch_explicit_opening_count: u64,
    lookup_challenge_field_order: BigUint,
    lookup_challenge_excluded_subfield_order: BigUint,
    maximum_fiat_shamir_candidate_draws: u32,
    cfw_reduction: cfw_reduction::CfwReductionCatalog,
    cfw_to_whir_handoff: cfw_to_whir_handoff::CfwToWhirHandoffCatalog,
    cfw_lifecycle: cfw_lifecycle::CfwLifecycleCatalog,
    row_source_lifecycle: row_source_lifecycle::RowSourceLifecycleCatalog,
    resource_overlap: resource_overlap::CompactPublicKeyResourceOverlapCatalog,
    witness_covector: witness_covector::WitnessCovectorCatalog,
    factor_catalogs: Vec<PackingStaticCatalog>,
    selected_packing_factor: Option<u64>,
}

impl CompactPublicKeyStaticCatalog {
    fn derive() -> Result<Self, CompactStaticCatalogError> {
        let relation = selected_compact_public_key_relation_catalog()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let cfw_reduction = cfw_reduction::CfwReductionCatalog::derive(&relation)?;
        let cfw_to_whir_handoff = cfw_to_whir_handoff::CfwToWhirHandoffCatalog::derive(
            &relation,
            &cfw_reduction,
            CROSS_EPOCH_EXPLICIT_OPENING_COUNT,
        )?;
        let cfw_lifecycle = cfw_lifecycle::CfwLifecycleCatalog::derive(&relation, &cfw_reduction)?;
        let row_source_lifecycle =
            row_source_lifecycle::RowSourceLifecycleCatalog::derive(&relation)?;
        let resource_overlap = resource_overlap::CompactPublicKeyResourceOverlapCatalog::derive(
            &relation,
            &row_source_lifecycle,
        )?;
        let witness_covector = witness_covector::WitnessCovectorCatalog::derive(&relation)?;
        let factor_catalogs = [1_u64, 2, 4, 8]
            .into_iter()
            .map(|factor| {
                PackingStaticCatalog::derive(
                    &relation,
                    &cfw_reduction,
                    &cfw_to_whir_handoff,
                    &cfw_lifecycle,
                    &row_source_lifecycle,
                    &resource_overlap,
                    &witness_covector,
                    factor,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let field_order = BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(
            u32::try_from(QUINTIC_EXTENSION_DEGREE)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        );
        let catalog = Self {
            relation_plan_hash: relation.relation_plan_hash(),
            relation_padded_witness_element_count: relation.padded_witness_element_count(),
            relation_operative_constraint_count: relation.operative_constraint_count(),
            pre_challenge_ring_vector_count: PRE_CHALLENGE_RING_VECTOR_COUNT,
            cross_epoch_point_coordinate_count: CROSS_EPOCH_POINT_COORDINATE_COUNT,
            cross_epoch_binding_error_numerator: u64::from(CROSS_EPOCH_POINT_COORDINATE_COUNT),
            cross_epoch_explicit_opening_count: CROSS_EPOCH_EXPLICIT_OPENING_COUNT,
            lookup_challenge_field_order: field_order,
            lookup_challenge_excluded_subfield_order: BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS),
            maximum_fiat_shamir_candidate_draws:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            cfw_reduction,
            cfw_to_whir_handoff,
            cfw_lifecycle,
            row_source_lifecycle,
            resource_overlap,
            witness_covector,
            factor_catalogs,
            selected_packing_factor: None,
        };
        catalog.check()?;
        Ok(catalog)
    }

    fn check(&self) -> Result<(), CompactStaticCatalogError> {
        let expected = Self::derive_without_recursive_check()?;
        if self != &expected {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    fn derive_without_recursive_check() -> Result<Self, CompactStaticCatalogError> {
        let relation = selected_compact_public_key_relation_catalog()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let cfw_reduction = cfw_reduction::CfwReductionCatalog::derive(&relation)?;
        let cfw_to_whir_handoff = cfw_to_whir_handoff::CfwToWhirHandoffCatalog::derive(
            &relation,
            &cfw_reduction,
            CROSS_EPOCH_EXPLICIT_OPENING_COUNT,
        )?;
        let cfw_lifecycle = cfw_lifecycle::CfwLifecycleCatalog::derive(&relation, &cfw_reduction)?;
        let row_source_lifecycle =
            row_source_lifecycle::RowSourceLifecycleCatalog::derive(&relation)?;
        let resource_overlap = resource_overlap::CompactPublicKeyResourceOverlapCatalog::derive(
            &relation,
            &row_source_lifecycle,
        )?;
        let witness_covector = witness_covector::WitnessCovectorCatalog::derive(&relation)?;
        let factor_catalogs = [1_u64, 2, 4, 8]
            .into_iter()
            .map(|factor| {
                PackingStaticCatalog::derive(
                    &relation,
                    &cfw_reduction,
                    &cfw_to_whir_handoff,
                    &cfw_lifecycle,
                    &row_source_lifecycle,
                    &resource_overlap,
                    &witness_covector,
                    factor,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            relation_plan_hash: relation.relation_plan_hash(),
            relation_padded_witness_element_count: relation.padded_witness_element_count(),
            relation_operative_constraint_count: relation.operative_constraint_count(),
            pre_challenge_ring_vector_count: PRE_CHALLENGE_RING_VECTOR_COUNT,
            cross_epoch_point_coordinate_count: CROSS_EPOCH_POINT_COORDINATE_COUNT,
            cross_epoch_binding_error_numerator: u64::from(CROSS_EPOCH_POINT_COORDINATE_COUNT),
            cross_epoch_explicit_opening_count: CROSS_EPOCH_EXPLICIT_OPENING_COUNT,
            lookup_challenge_field_order: BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(
                u32::try_from(QUINTIC_EXTENSION_DEGREE)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            ),
            lookup_challenge_excluded_subfield_order: BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS),
            maximum_fiat_shamir_candidate_draws:
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            cfw_reduction,
            cfw_to_whir_handoff,
            cfw_lifecycle,
            row_source_lifecycle,
            resource_overlap,
            witness_covector,
            factor_catalogs,
            selected_packing_factor: None,
        })
    }
}

fn exact_query_count(security_level: u32, log_inverse_rate: u32) -> u32 {
    let numerator = BigUint::from((1_u64 << log_inverse_rate) + 1);
    let denominator = BigUint::from(1_u64 << (log_inverse_rate + 1));
    let target_multiplier = BigUint::one() << security_level;
    let mut numerator_power = BigUint::one();
    let mut denominator_power = BigUint::one();
    for query_count in 1..=u32::MAX {
        numerator_power *= &numerator;
        denominator_power *= &denominator;
        if &numerator_power * &target_multiplier <= denominator_power {
            return query_count;
        }
    }
    unreachable!("the fixed redundant code reaches the finite security target")
}

fn exact_full_dimension_unique_decoding_query_count(
    security_level: u32,
    message_length: u64,
    domain_size: u64,
) -> Result<u64, CompactStaticCatalogError> {
    if message_length == 0
        || domain_size <= message_length
        || domain_size % message_length != 0
        || !(domain_size / message_length).is_power_of_two()
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let log_inverse_rate = (domain_size / message_length).ilog2();
    let mut query_count = u64::from(exact_query_count(security_level, log_inverse_rate));
    loop {
        let dimension = message_length
            .checked_add(query_count)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        if dimension >= domain_size {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        if exact_full_dimension_query_failure_is_at_most_target(
            security_level,
            message_length,
            domain_size,
            query_count,
        )? {
            return Ok(query_count);
        }
        query_count = query_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    }
}

fn exact_full_dimension_query_failure_is_at_most_target(
    security_level: u32,
    message_length: u64,
    domain_size: u64,
    query_count: u64,
) -> Result<bool, CompactStaticCatalogError> {
    let dimension = message_length
        .checked_add(query_count)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    if query_count == 0 || dimension >= domain_size {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let exponent =
        u32::try_from(query_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let selected_decoding_error_count = domain_size
        .checked_sub(dimension)
        .and_then(|slack| slack.checked_sub(1))
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
        / 2;
    let minimum_agreement_count = domain_size
        .checked_sub(selected_decoding_error_count)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    Ok(
        BigUint::from(minimum_agreement_count).pow(exponent) * (BigUint::one() << security_level)
            <= BigUint::from(domain_size).pow(exponent),
    )
}

fn exact_mask_query_count_for_final_verifier_move(
    source_message_length: u64,
    source_domain_size: u64,
    source_query_count: u64,
    mask_message_lengths: &[u64],
    minimum_mask_query_count: u64,
    verifier_move_security_level: u32,
) -> Result<u64, CompactStaticCatalogError> {
    if source_query_count == 0 || mask_message_lengths.is_empty() || minimum_mask_query_count == 0 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let source_failure = exact_full_dimension_query_failure_probability(
        source_message_length,
        source_domain_size,
        source_query_count,
    )?;
    let mut candidate_mask_query_count = minimum_mask_query_count;
    loop {
        let mut grouped_move_failure = source_failure.clone();
        for message_length in mask_message_lengths {
            let populated_message_length = message_length
                .checked_add(candidate_mask_query_count)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            let domain_size = populated_message_length
                .checked_next_power_of_two()
                .and_then(|value| value.checked_shl(MASK_CODE_LOG_INVERSE_RATE))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            grouped_move_failure =
                grouped_move_failure.add(&exact_full_dimension_query_failure_probability(
                    *message_length,
                    domain_size,
                    candidate_mask_query_count,
                )?)?;
        }
        if grouped_move_failure
            .is_at_most_inverse_power_of_two(verifier_move_security_level as usize)
        {
            return Ok(candidate_mask_query_count);
        }
        candidate_mask_query_count = candidate_mask_query_count
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    }
}

fn exact_full_dimension_query_failure_probability(
    message_length: u64,
    domain_size: u64,
    query_count: u64,
) -> Result<lifecycle::ExactProbability, CompactStaticCatalogError> {
    let dimension = message_length
        .checked_add(query_count)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    if query_count == 0 || dimension >= domain_size {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let selected_decoding_error_count = domain_size
        .checked_sub(dimension)
        .and_then(|slack| slack.checked_sub(1))
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
        / 2;
    let minimum_agreement_count = domain_size
        .checked_sub(selected_decoding_error_count)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let exponent =
        u32::try_from(query_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    lifecycle::ExactProbability::new(
        BigUint::from(minimum_agreement_count).pow(exponent),
        BigUint::from(domain_size).pow(exponent),
    )
}

fn ceil_log2(value: u64) -> Result<u32, CompactStaticCatalogError> {
    if value == 0 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(u64::BITS - (value - 1).leading_zeros())
}

fn checked_add(left: u64, right: u64) -> Result<u64, CompactStaticCatalogError> {
    left.checked_add(right)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
}

fn checked_product(values: &[u64]) -> Result<u64, CompactStaticCatalogError> {
    values.iter().try_fold(1_u64, |product, value| {
        product
            .checked_mul(*value)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
    })
}

fn map_production_wire_error(error: CompactProofWireError) -> CompactStaticCatalogError {
    match error {
        CompactProofWireError::LengthOverflow => CompactStaticCatalogError::ArithmeticOverflow,
        CompactProofWireError::ProofByteCeilingExceeded => {
            CompactStaticCatalogError::HardBoundExceeded
        }
        _ => CompactStaticCatalogError::InvalidGeometry,
    }
}

fn maximum_frontier_byte_length(
    leaf_count: u64,
    query_count: u64,
) -> Result<u64, CompactStaticCatalogError> {
    let frontier_node_count = maximum_minimal_frontier_node_count(
        usize::try_from(leaf_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        usize::try_from(query_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    checked_add(
        MERKLE_FRONTIER_COUNT_BYTE_LENGTH,
        checked_product(&[
            u64::try_from(frontier_node_count)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            MERKLE_DIGEST_BYTE_LENGTH,
        ])?,
    )
}

fn maximum_frontier_parent_hash_count(
    leaf_count: u64,
    query_count: u64,
) -> Result<u64, CompactStaticCatalogError> {
    let frontier_node_count = maximum_minimal_frontier_node_count(
        usize::try_from(leaf_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        usize::try_from(query_count).map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    query_count
        .checked_add(
            u64::try_from(frontier_node_count)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        )
        .and_then(|leaf_and_frontier_count| leaf_and_frontier_count.checked_sub(1))
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct PackingResourceCeilingSnapshot {
        packing_factor: u64,
        pre_challenge_proof_byte_length: u64,
        main_proof_byte_length: u64,
        maximum_proof_byte_length: u64,
        public_input_byte_length: u64,
        transport_byte_length: u64,
        transport_chunk_count: u64,
        commitment_peak_byte_length: u64,
        cfw_to_whir_retained_payload_byte_length: u64,
        wasm_peak_byte_length: u64,
        scratch_byte_length: u64,
        base_coordinate_butterfly_count: u64,
        committed_leaf_count: u64,
        commitment_leaf_hash_query_count: u64,
        commitment_parent_hash_query_count: u64,
        verifier_opened_leaf_hash_query_count: u64,
        maximum_uninterrupted_butterfly_count: u64,
        maximum_uninterrupted_leaf_hash_count: u64,
        deterministic_checkpoint_count: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct WhirPrivateRandomnessSnapshot {
        source_oracle_encoding: u64,
        carried_mask_messages: u64,
        carried_mask_encoding: u64,
        fresh_mirror_messages: u64,
        fresh_mirror_encoding: u64,
        fresh_source_message: u64,
        fresh_source_encoding: u64,
        total: u64,
    }

    impl From<&WhirStaticLedger> for WhirPrivateRandomnessSnapshot {
        fn from(ledger: &WhirStaticLedger) -> Self {
            Self {
                source_oracle_encoding: ledger.source_oracle_encoding_randomness_element_count,
                carried_mask_messages: ledger.carried_mask_message_randomness_element_count,
                carried_mask_encoding: ledger.carried_mask_encoding_randomness_element_count,
                fresh_mirror_messages: ledger.fresh_mirror_message_randomness_element_count,
                fresh_mirror_encoding: ledger.fresh_mirror_encoding_randomness_element_count,
                fresh_source_message: ledger.fresh_source_message_randomness_element_count,
                fresh_source_encoding: ledger.fresh_source_encoding_randomness_element_count,
                total: ledger.private_extension_randomness_element_count,
            }
        }
    }

    impl From<&PackingStaticCatalog> for PackingResourceCeilingSnapshot {
        fn from(factor: &PackingStaticCatalog) -> Self {
            Self {
                packing_factor: factor.packing_factor,
                pre_challenge_proof_byte_length: factor.pre_challenge_whir.proof_byte_length,
                main_proof_byte_length: factor.main_whir.proof_byte_length,
                maximum_proof_byte_length: factor.maximum_proof_byte_length,
                public_input_byte_length: factor.public_input_byte_length,
                transport_byte_length: factor.transport_byte_length,
                transport_chunk_count: factor.transport_chunk_count,
                commitment_peak_byte_length: factor.commitment_peak_byte_length,
                cfw_to_whir_retained_payload_byte_length: factor
                    .cfw_to_whir_retained_payload_byte_length,
                wasm_peak_byte_length: factor.wasm_peak_byte_length,
                scratch_byte_length: factor.scratch_byte_length,
                base_coordinate_butterfly_count: factor.base_coordinate_butterfly_count,
                committed_leaf_count: factor.committed_leaf_count,
                commitment_leaf_hash_query_count: factor.commitment_leaf_hash_query_count,
                commitment_parent_hash_query_count: factor.commitment_parent_hash_query_count,
                verifier_opened_leaf_hash_query_count: factor.verifier_opened_leaf_hash_query_count,
                maximum_uninterrupted_butterfly_count: factor.maximum_uninterrupted_butterfly_count,
                maximum_uninterrupted_leaf_hash_count: factor.maximum_uninterrupted_leaf_hash_count,
                deterministic_checkpoint_count: factor.deterministic_checkpoint_count,
            }
        }
    }

    #[test]
    fn public_key_static_packing_ledger_derives_every_factor_without_selecting_one() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        assert_eq!(catalog.relation_padded_witness_element_count, 4_194_304);
        assert_eq!(catalog.relation_operative_constraint_count, 2_686_977);
        assert_eq!(catalog.pre_challenge_ring_vector_count, 33);
        assert_eq!(catalog.cross_epoch_point_coordinate_count, 21);
        assert_eq!(catalog.cross_epoch_binding_error_numerator, 21);
        assert_eq!(catalog.cross_epoch_explicit_opening_count, 2);
        assert_eq!(catalog.lookup_challenge_field_order.bits(), 320);
        assert_eq!(catalog.factor_catalogs.len(), 4);
        assert_eq!(
            catalog
                .factor_catalogs
                .iter()
                .map(|factor| factor.packing_factor)
                .collect::<Vec<_>>(),
            vec![1, 2, 4, 8]
        );
        assert_eq!(catalog.selected_packing_factor, None);
        assert!(catalog.factor_catalogs.iter().all(|factor| {
            factor.maximum_proof_byte_length < PROOF_ALLOCATION_BOUND_BYTE_LENGTH
                && factor.wasm_peak_byte_length < WASM_HARD_BOUND_BYTE_LENGTH
        }));
        assert!(
            catalog
                .factor_catalogs
                .iter()
                .any(|factor| factor.scratch_byte_length >= SCRATCH_BOUND_BYTE_LENGTH)
        );
    }

    #[test]
    fn mask_group_catalog_preserves_cfw_then_whir_commitment_order() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_whir_roles = vec![
            MaskGroupRole::WhirSumcheck { batch_ordinal: 0 },
            MaskGroupRole::WhirCodeSwitch { round_ordinal: 0 },
            MaskGroupRole::WhirSumcheck { batch_ordinal: 1 },
            MaskGroupRole::WhirCodeSwitch { round_ordinal: 1 },
            MaskGroupRole::WhirSumcheck { batch_ordinal: 2 },
            MaskGroupRole::WhirCodeSwitch { round_ordinal: 2 },
            MaskGroupRole::WhirSumcheck { batch_ordinal: 3 },
        ];
        let expected_pre_challenge_roles = [MaskGroupRole::CrossEpochOpening]
            .into_iter()
            .chain(expected_whir_roles.iter().copied())
            .collect::<Vec<_>>();
        let expected_main_roles = [
            MaskGroupRole::CfwInner,
            MaskGroupRole::CfwOuter,
            MaskGroupRole::CrossEpochOpening,
        ]
        .into_iter()
        .chain(expected_whir_roles.iter().copied())
        .collect::<Vec<_>>();

        for factor in &catalog.factor_catalogs {
            assert_eq!(
                factor
                    .pre_challenge_whir
                    .mask_groups_in_commitment_order()
                    .map(|group| group.role)
                    .collect::<Vec<_>>(),
                expected_pre_challenge_roles
            );
            assert_eq!(
                factor
                    .main_whir
                    .mask_groups_in_commitment_order()
                    .map(|group| group.role)
                    .collect::<Vec<_>>(),
                expected_main_roles
            );

            let cfw_inner_group = factor
                .main_whir
                .external_mask_groups
                .first()
                .expect("CFW inner mask group");
            assert_eq!(cfw_inner_group.role, MaskGroupRole::CfwInner);
            assert_eq!(cfw_inner_group.width, 69);
            assert_eq!(cfw_inner_group.message_length, 4);
            assert_eq!(cfw_inner_group.randomness_length, 399);
            assert_eq!(
                cfw_inner_group.committed_encoding_source,
                MaskCommittedEncodingSource::OwnedByThisEpoch
            );

            let cfw_outer_group = factor
                .main_whir
                .external_mask_groups
                .get(1)
                .expect("CFW outer mask group");
            assert_eq!(cfw_outer_group.role, MaskGroupRole::CfwOuter);
            assert_eq!(cfw_outer_group.width, 23);
            assert_eq!(cfw_outer_group.message_length, 8);
            assert_eq!(cfw_outer_group.randomness_length, 399);
            assert_eq!(
                cfw_outer_group.committed_encoding_source,
                MaskCommittedEncodingSource::OwnedByThisEpoch
            );

            let pre_challenge_cross_epoch_group = factor
                .pre_challenge_whir
                .external_mask_groups
                .first()
                .expect("pre-challenge cross-epoch mask group");
            let main_cross_epoch_group = factor
                .main_whir
                .external_mask_groups
                .get(2)
                .expect("main cross-epoch mask group");
            assert_eq!(
                pre_challenge_cross_epoch_group.role,
                MaskGroupRole::CrossEpochOpening
            );
            assert_eq!(pre_challenge_cross_epoch_group.width, 2);
            assert_eq!(pre_challenge_cross_epoch_group.message_length, 1);
            assert_eq!(pre_challenge_cross_epoch_group.randomness_length, 798);
            assert_eq!(
                pre_challenge_cross_epoch_group.committed_encoding_source,
                MaskCommittedEncodingSource::OwnedByThisEpoch
            );
            assert_eq!(
                main_cross_epoch_group,
                &MaskGroupStaticLedger {
                    committed_encoding_source: MaskCommittedEncodingSource::ReusedFromPreChallenge,
                    ..*pre_challenge_cross_epoch_group
                }
            );

            // Definition 11.1 has one global claim, two claims per inner
            // mask, and one per outer mask. The two explicit cross-epoch
            // openings join those 162 CFW claims under the same batching
            // challenge.
            assert_eq!(factor.pre_challenge_whir.opening_evaluation_count, 1);
            assert_eq!(factor.pre_challenge_whir.opening_batching_claim_count, 1);
            assert_eq!(factor.main_whir.opening_evaluation_count, 2);
            assert_eq!(factor.main_whir.opening_batching_claim_count, 164);
        }

        let mut wrong_role = catalog.clone();
        wrong_role.factor_catalogs[0].main_whir.external_mask_groups[0].role =
            MaskGroupRole::CfwOuter;
        assert_eq!(
            wrong_role.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut wrong_order = catalog.clone();
        wrong_order.factor_catalogs[0]
            .main_whir
            .external_mask_groups
            .swap(0, 1);
        assert_eq!(
            wrong_order.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }

    #[test]
    fn private_randomness_ledgers_count_every_independent_mask_coin_once() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let pre_challenge_snapshots = catalog
            .factor_catalogs
            .iter()
            .map(|factor| WhirPrivateRandomnessSnapshot::from(&factor.pre_challenge_whir))
            .collect::<Vec<_>>();
        let main_snapshots = catalog
            .factor_catalogs
            .iter()
            .map(|factor| WhirPrivateRandomnessSnapshot::from(&factor.main_whir))
            .collect::<Vec<_>>();

        assert_eq!(
            pre_challenge_snapshots,
            vec![
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 44_224,
                    carried_mask_messages: 56,
                    carried_mask_encoding: 9_975,
                    fresh_mirror_messages: 1_284,
                    fresh_mirror_encoding: 9_975,
                    fresh_source_message: 8,
                    fresh_source_encoding: 348,
                    total: 65_870,
                },
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 32_544,
                    carried_mask_messages: 53,
                    carried_mask_encoding: 9_576,
                    fresh_mirror_messages: 1_341,
                    fresh_mirror_encoding: 9_576,
                    fresh_source_message: 16,
                    fresh_source_encoding: 351,
                    total: 53_457,
                },
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 24_448,
                    carried_mask_messages: 50,
                    carried_mask_encoding: 9_177,
                    fresh_mirror_messages: 1_221,
                    fresh_mirror_encoding: 9_177,
                    fresh_source_message: 32,
                    fresh_source_encoding: 357,
                    total: 44_462,
                },
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 23_288,
                    carried_mask_messages: 47,
                    carried_mask_encoding: 8_778,
                    fresh_mirror_messages: 1_329,
                    fresh_mirror_encoding: 8_778,
                    fresh_source_message: 64,
                    fresh_source_encoding: 371,
                    total: 42_655,
                },
            ]
        );
        assert_eq!(
            main_snapshots,
            vec![
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 69_568,
                    carried_mask_messages: 379,
                    carried_mask_encoding: 45_486,
                    fresh_mirror_messages: 1_747,
                    fresh_mirror_encoding: 47_082,
                    fresh_source_message: 8,
                    fresh_source_encoding: 348,
                    total: 164_618,
                },
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 45_184,
                    carried_mask_messages: 376,
                    carried_mask_encoding: 45_087,
                    fresh_mirror_messages: 1_804,
                    fresh_mirror_encoding: 46_683,
                    fresh_source_message: 16,
                    fresh_source_encoding: 351,
                    total: 139_501,
                },
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 30_768,
                    carried_mask_messages: 373,
                    carried_mask_encoding: 44_688,
                    fresh_mirror_messages: 1_684,
                    fresh_mirror_encoding: 46_284,
                    fresh_source_message: 32,
                    fresh_source_encoding: 357,
                    total: 124_186,
                },
                WhirPrivateRandomnessSnapshot {
                    source_oracle_encoding: 26_448,
                    carried_mask_messages: 370,
                    carried_mask_encoding: 44_289,
                    fresh_mirror_messages: 1_792,
                    fresh_mirror_encoding: 45_885,
                    fresh_source_message: 64,
                    fresh_source_encoding: 371,
                    total: 119_219,
                },
            ]
        );

        assert_eq!(
            catalog.cfw_reduction.fresh_mask_randomness_element_count(),
            322
        );
        assert!(catalog.factor_catalogs.iter().all(|factor| {
            factor
                .pre_challenge_whir
                .external_carried_mask_message_randomness_element_count
                == 2
                && factor
                    .main_whir
                    .external_carried_mask_message_randomness_element_count
                    == 322
        }));
    }

    #[test]
    fn canonical_wire_resource_ceiling_vectors_are_exact_and_cannot_select_a_factor() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let snapshots = catalog
            .factor_catalogs
            .iter()
            .map(PackingResourceCeilingSnapshot::from)
            .collect::<Vec<_>>();
        assert_eq!(
            snapshots,
            vec![
                PackingResourceCeilingSnapshot {
                    packing_factor: 1,
                    pre_challenge_proof_byte_length: 4_868_556,
                    main_proof_byte_length: 11_602_452,
                    maximum_proof_byte_length: 26_927_670,
                    public_input_byte_length: 15_991_062,
                    transport_byte_length: 42_918_732,
                    transport_chunk_count: 41,
                    commitment_peak_byte_length: 75_497_456,
                    cfw_to_whir_retained_payload_byte_length: 167_790_680,
                    wasm_peak_byte_length: 385_505_540,
                    scratch_byte_length: 640_811_508,
                    base_coordinate_butterfly_count: 916_598_784,
                    committed_leaf_count: 1_032_486,
                    commitment_leaf_hash_query_count: 27_590_950,
                    commitment_parent_hash_query_count: 1_032_359,
                    verifier_opened_leaf_hash_query_count: 510_301,
                    maximum_uninterrupted_butterfly_count: 44_564_480,
                    maximum_uninterrupted_leaf_hash_count: 131_072,
                    deterministic_checkpoint_count: 2_677,
                },
                PackingResourceCeilingSnapshot {
                    packing_factor: 2,
                    pre_challenge_proof_byte_length: 4_824_140,
                    main_proof_byte_length: 10_643_348,
                    maximum_proof_byte_length: 26_064_742,
                    public_input_byte_length: 15_991_062,
                    transport_byte_length: 42_055_804,
                    transport_chunk_count: 41,
                    commitment_peak_byte_length: 109_051_888,
                    cfw_to_whir_retained_payload_byte_length: 167_790_680,
                    wasm_peak_byte_length: 418_112_804,
                    scratch_byte_length: 693_240_308,
                    base_coordinate_butterfly_count: 972_341_248,
                    committed_leaf_count: 1_736_994,
                    commitment_leaf_hash_query_count: 28_827_938,
                    commitment_parent_hash_query_count: 1_736_869,
                    verifier_opened_leaf_hash_query_count: 476_727,
                    maximum_uninterrupted_butterfly_count: 47_185_920,
                    maximum_uninterrupted_leaf_hash_count: 262_144,
                    deterministic_checkpoint_count: 2_677,
                },
                PackingResourceCeilingSnapshot {
                    packing_factor: 4,
                    pre_challenge_proof_byte_length: 4_703_956,
                    main_proof_byte_length: 10_068_124,
                    maximum_proof_byte_length: 25_415_814,
                    public_input_byte_length: 15_991_062,
                    transport_byte_length: 41_406_876,
                    transport_chunk_count: 40,
                    commitment_peak_byte_length: 176_160_752,
                    cfw_to_whir_retained_payload_byte_length: 167_790_680,
                    wasm_peak_byte_length: 484_445_268,
                    scratch_byte_length: 798_097_908,
                    base_coordinate_butterfly_count: 1_041_354_752,
                    committed_leaf_count: 3_150_110,
                    commitment_leaf_hash_query_count: 31_383_838,
                    commitment_parent_hash_query_count: 3_149_987,
                    verifier_opened_leaf_hash_query_count: 454_319,
                    maximum_uninterrupted_butterfly_count: 49_807_360,
                    maximum_uninterrupted_leaf_hash_count: 524_288,
                    deterministic_checkpoint_count: 2_677,
                },
                PackingResourceCeilingSnapshot {
                    packing_factor: 8,
                    pre_challenge_proof_byte_length: 4_801_020,
                    main_proof_byte_length: 9_937_668,
                    maximum_proof_byte_length: 25_526_102,
                    public_input_byte_length: 15_991_062,
                    transport_byte_length: 41_517_164,
                    transport_chunk_count: 40,
                    commitment_peak_byte_length: 310_378_480,
                    cfw_to_whir_retained_payload_byte_length: 167_790_680,
                    wasm_peak_byte_length: 618_845_620,
                    scratch_byte_length: 1_082_414_368,
                    base_coordinate_butterfly_count: 1_131_831_296,
                    committed_leaf_count: 5_968_154,
                    commitment_leaf_hash_query_count: 36_356_378,
                    commitment_parent_hash_query_count: 5_968_033,
                    verifier_opened_leaf_hash_query_count: 452_379,
                    maximum_uninterrupted_butterfly_count: 52_428_800,
                    maximum_uninterrupted_leaf_hash_count: 1_048_576,
                    deterministic_checkpoint_count: 2_677,
                },
            ]
        );
        assert_eq!(catalog.selected_packing_factor, None);
        assert_eq!(
            catalog
                .factor_catalogs
                .iter()
                .map(|factor| {
                    (
                        factor.packing_factor,
                        factor.proof_allocation_byte_length < PROOF_ALLOCATION_BOUND_BYTE_LENGTH,
                        factor.wasm_peak_byte_length < WASM_HARD_BOUND_BYTE_LENGTH,
                        factor.scratch_byte_length < SCRATCH_BOUND_BYTE_LENGTH,
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (1, true, true, true),
                (2, true, true, true),
                (4, true, true, true),
                (8, true, true, false),
            ]
        );
    }

    #[test]
    fn incremental_proof_assembly_heap_is_exact_for_every_factor() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let heap_snapshots = catalog
            .factor_catalogs
            .iter()
            .map(|factor| {
                let heap = factor.proof_assembler_heap_geometry;
                (
                    factor.packing_factor,
                    heap.maximum_canonical_proof_byte_length(),
                    heap.leaf_salt_registry_byte_length(),
                    heap.maximum_frontier_dictionary_byte_length(),
                    heap.maximum_owned_heap_byte_length(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            heap_snapshots,
            vec![
                (1, 26_927_670, 10_151_680, 1_046_464, 38_125_814),
                (2, 26_064_742, 10_083_328, 1_067_648, 37_215_718),
                (4, 25_415_814, 9_928_704, 1_150_464, 36_494_982),
                (8, 25_526_102, 9_901_056, 1_277_888, 36_705_046),
            ]
        );
    }

    #[test]
    fn production_response_checkpoint_schedule_preserves_canonical_section_order() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let snapshots = catalog
            .factor_catalogs
            .iter()
            .map(|factor| {
                (
                    factor.packing_factor,
                    factor.response_checkpoint_schedule.total_response_count(),
                    factor
                        .response_checkpoint_schedule
                        .lagging_checkpoint_count(),
                    factor
                        .response_checkpoint_schedule
                        .maximum_pending_proof_response_count(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            snapshots,
            vec![
                (1, 82, 81, 80),
                (2, 80, 79, 78),
                (4, 78, 77, 76),
                (8, 76, 75, 74)
            ]
        );
    }

    #[test]
    fn response_tree_kernel_heap_is_exact_for_every_factor() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let heap_snapshots = catalog
            .factor_catalogs
            .iter()
            .map(|factor| {
                (
                    factor.packing_factor,
                    factor
                        .response_postorder_writer_heap_geometry
                        .maximum_owned_heap_byte_length(),
                    factor
                        .response_frontier_scanner_heap_geometry
                        .maximum_owned_heap_byte_length(),
                    factor
                        .response_external_memory_geometry
                        .driver_inline_byte_length(),
                    factor
                        .response_external_memory_geometry
                        .executor_owned_heap_byte_length(),
                    factor.maximum_response_query_schedule_heap_byte_length,
                    factor.maximum_response_input_heap_payload_byte_length,
                    factor.maximum_response_tree_kernel_heap_byte_length,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            heap_snapshots,
            vec![
                (
                    1, 1_050_944, 1_308_080, 368, 64, 393_480, 9_703_024, 9_703_024
                ),
                (
                    2, 1_051_072, 1_334_560, 368, 64, 390_832, 9_665_952, 9_665_952
                ),
                (
                    4, 1_051_200, 1_438_080, 368, 64, 386_856, 9_610_288, 9_610_288
                ),
                (
                    8, 1_051_328, 1_597_360, 368, 64, 384_896, 9_582_848, 9_582_848
                ),
            ]
        );
    }

    #[test]
    fn whir_query_counts_and_rate_changes_are_exact_integers() {
        assert_eq!(exact_query_count(266, 2), 393);
        assert_eq!(exact_query_count(269, 2), 397);
        assert_eq!(exact_query_count(266, 3), 321);
        assert_eq!(exact_query_count(266, 4), 292);
        assert_eq!(exact_query_count(266, 5), 279);
        assert_eq!(exact_query_count(266, 6), 273);
        assert_eq!(exact_query_count(WHIR_PROTOCOL_SECURITY_LEVEL, 2), 394);
        assert_eq!(exact_query_count(WHIR_PROTOCOL_SECURITY_LEVEL, 3), 322);
        assert_eq!(exact_query_count(WHIR_PROTOCOL_SECURITY_LEVEL, 4), 293);
        assert_eq!(exact_query_count(WHIR_PROTOCOL_SECURITY_LEVEL, 5), 280);
        assert_eq!(exact_query_count(WHIR_PROTOCOL_SECURITY_LEVEL, 6), 274);

        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_round_rates = [[2, 4, 8], [2, 3, 7], [2, 3, 6], [2, 2, 5]];
        let expected_full_dimension_query_counts = [
            [396, 432, 400, 348],
            [395, 412, 481, 351],
            [395, 403, 373, 357],
            [395, 398, 489, 371],
        ];
        for ((factor, expected_rates), expected_query_counts) in catalog
            .factor_catalogs
            .iter()
            .zip(expected_round_rates)
            .zip(expected_full_dimension_query_counts)
        {
            assert_eq!(factor.main_whir.round_log_inverse_rates, expected_rates);
            assert_eq!(
                factor.pre_challenge_whir.round_log_inverse_rates,
                expected_rates
            );
            assert_eq!(factor.main_whir.query_counts, expected_query_counts);
            assert_eq!(
                factor.pre_challenge_whir.query_counts,
                expected_query_counts
            );
            assert_eq!(factor.pre_challenge_whir.mask_query_count, 399);
            assert_eq!(factor.main_whir.mask_query_count, 399);
            assert_eq!(factor.pre_challenge_whir.mask_query_union_branch_count, 9);
            assert_eq!(factor.main_whir.mask_query_union_branch_count, 11);
        }
    }

    #[test]
    fn whir_proof_accounting_uses_coordinate_derived_compact_frontiers() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        for factor in &catalog.factor_catalogs {
            for whir in [&factor.pre_challenge_whir, &factor.main_whir] {
                let mut literal_path_byte_length = 0_u64;
                for round_ordinal in 0..WHIR_ROUND_COUNT {
                    literal_path_byte_length = checked_add(
                        literal_path_byte_length,
                        checked_add(
                            MERKLE_FRONTIER_COUNT_BYTE_LENGTH,
                            checked_product(&[
                                whir.query_counts[round_ordinal],
                                u64::from(whir.oracle_heights[round_ordinal].ilog2()),
                                MERKLE_DIGEST_BYTE_LENGTH,
                            ])
                            .expect("literal path bytes"),
                        )
                        .expect("framed literal path bytes"),
                    )
                    .expect("accumulated literal path bytes");
                }

                let final_query_count = whir.query_counts[WHIR_ROUND_COUNT];
                literal_path_byte_length = checked_add(
                    literal_path_byte_length,
                    checked_product(&[
                        2,
                        checked_add(
                            MERKLE_FRONTIER_COUNT_BYTE_LENGTH,
                            checked_product(&[
                                final_query_count,
                                u64::from(whir.oracle_heights[WHIR_ROUND_COUNT].ilog2()),
                                MERKLE_DIGEST_BYTE_LENGTH,
                            ])
                            .expect("final literal path bytes"),
                        )
                        .expect("framed final literal path bytes"),
                    ])
                    .expect("both final literal path batches"),
                )
                .expect("accumulated final literal path bytes");

                for group in whir.mask_groups_in_commitment_order() {
                    literal_path_byte_length = checked_add(
                        literal_path_byte_length,
                        checked_product(&[
                            2,
                            checked_add(
                                MERKLE_FRONTIER_COUNT_BYTE_LENGTH,
                                checked_product(&[
                                    whir.mask_query_count,
                                    u64::from(group.domain_size.ilog2()),
                                    MERKLE_DIGEST_BYTE_LENGTH,
                                ])
                                .expect("mask literal path bytes"),
                            )
                            .expect("framed mask literal path bytes"),
                        ])
                        .expect("paired mask literal path batches"),
                    )
                    .expect("accumulated mask literal path bytes");
                }

                assert!(whir.authentication_frontier_byte_length > 0);
                assert!(whir.authentication_frontier_byte_length < literal_path_byte_length);
                assert!(whir.merkle_parent_hash_count > 0);
                assert!(whir.merkle_parent_hash_count < whir.committed_leaf_count);
                assert!(whir.commitment_parent_hash_query_count < whir.committed_leaf_count);
                assert!(whir.commitment_leaf_hash_query_count > whir.committed_leaf_count);
                assert!(whir.verifier_opened_leaf_hash_query_count > whir.merkle_opening_count);
            }
        }
    }

    #[test]
    fn static_catalog_rejects_mutated_packing_and_lifecycle_values() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        let mut wrong_relation = catalog.clone();
        wrong_relation.relation_plan_hash[0] ^= 1;
        assert_eq!(
            wrong_relation.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut wrong_proof_length = catalog.clone();
        wrong_proof_length.factor_catalogs[0].maximum_proof_byte_length += 1;
        assert_eq!(
            wrong_proof_length.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut missing_checkpoint = catalog.clone();
        missing_checkpoint.factor_catalogs[0].deterministic_checkpoint_count = 0;
        assert_eq!(
            missing_checkpoint.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut missing_cfw_batching_claim = catalog.clone();
        missing_cfw_batching_claim.factor_catalogs[0]
            .main_whir
            .opening_batching_claim_count -= 1;
        assert_eq!(
            missing_cfw_batching_claim.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );

        let mut wrong_selection = catalog.clone();
        wrong_selection.selected_packing_factor = Some(8);
        assert_eq!(
            wrong_selection.check(),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
