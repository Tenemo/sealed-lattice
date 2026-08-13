//! Static packing and transport-geometry ledger for the compact public-key-share
//! development slice.
//!
//! This pre-prover owner derives the two oracle epochs, the CFW masks, both
//! zero-knowledge WHIR executions, the logical transcript chronology, one
//! response commitment per logical response, bounded query sampling, and the
//! selected factor-one packing. It feeds the independently derived response
//! geometry into the canonical wire codec and accounts for the production
//! transcript's complete prefixes. Semantic execution, masking reductions, and
//! adaptive soundness belong to their dedicated owners; this catalog does not
//! authorize proof generation or verification.

use num_bigint::BigUint;
use num_traits::One;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, ZkParameters, ZkWhirConfig};

use super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
use super::compact_generation_checkpoint::CompactResponseCheckpointSchedule;
use super::compact_proof_contract::{
    CompactProofContractGenerationInput, CompactResponseComponentRoleContract,
    CompactVerifierMoveContractInput, CompactVerifierRoleCoordinate, CompactWhirEpochContractInput,
    CompactWhirFoldContractInput, CompactWhirMaskGroupContractInput,
    encode_generated_contract_source,
};
use super::compact_proof_wire::{
    CompactProofWireError, CompactProofWireGeometry, CompactPublicInputWireGeometry,
};
use super::merkle::maximum_minimal_frontier_node_count;
use super::relation_plan::{
    CompactPublicKeyRelationCatalog, compact_structured_witness_covector_geometry,
    selected_compact_public_key_relation_catalog,
};

mod cfw_lifecycle;
mod cfw_reduction;
mod cfw_to_whir_handoff;
mod emitted_byte_correspondence;
#[cfg(test)]
mod external_mask_integration;
#[cfg(test)]
pub(super) use external_mask_integration::assert_selected_masking_producer_differentials;
mod lifecycle;
mod response_commitment;
mod row_source_lifecycle;
mod transcript_chronology;
mod uniform_verifier_randomness;

const GOLDILOCKS_BASE_FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;
const QUINTIC_EXTENSION_DEGREE: u64 = 5;
const BASE_FIELD_ELEMENT_BYTE_LENGTH: u64 = 8;
const EXTENSION_FIELD_ELEMENT_BYTE_LENGTH: u64 =
    BASE_FIELD_ELEMENT_BYTE_LENGTH * QUINTIC_EXTENSION_DEGREE;
const MERKLE_DIGEST_BYTE_LENGTH: u64 = 64;
const MERKLE_FRONTIER_COUNT_BYTE_LENGTH: u64 = 4;
const PRIVATE_LEAF_SALT_BYTE_LENGTH: u64 = 128;
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
const PROOF_ALLOCATION_BOUND_BYTE_LENGTH: u64 = 268_435_456;

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
        external_mask_input: WhirExternalMaskInput,
    ) -> Result<Self, CompactStaticCatalogError> {
        let WhirExternalMaskInput {
            group_specifications: external_mask_group_specifications,
            generalized_relation_claim_count: external_generalized_relation_claim_count,
            carried_message_randomness_element_count:
                external_carried_mask_message_randomness_element_count,
        } = external_mask_input;
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
            query_counts[batch_ordinal] = conservative_full_dimension_unique_decoding_query_count(
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
        let mut mask_code_shapes = Vec::with_capacity(
            usize::try_from(mask_group_count)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        );
        mask_code_shapes.push((
            SUMCHECK_MASK_MESSAGE_LENGTH,
            MaskEncodingRandomnessLength::LocalMaskQueryCount,
        ));
        for query_count in query_counts.iter().copied().take(WHIR_ROUND_COUNT) {
            mask_code_shapes.push((
                query_count,
                MaskEncodingRandomnessLength::LocalMaskQueryCount,
            ));
            mask_code_shapes.push((
                SUMCHECK_MASK_MESSAGE_LENGTH,
                MaskEncodingRandomnessLength::LocalMaskQueryCount,
            ));
        }
        mask_code_shapes.extend(
            external_mask_group_specifications
                .iter()
                .map(|specification| {
                    (
                        specification.message_length,
                        specification.encoding_randomness_length,
                    )
                }),
        );
        if mask_code_shapes.len()
            != usize::try_from(mask_group_count)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let minimum_complete_mask_query_count = exact_mask_query_count_for_final_verifier_move(
            source_message_lengths[WHIR_ROUND_COUNT],
            oracle_heights[WHIR_ROUND_COUNT],
            query_counts[WHIR_ROUND_COUNT],
            &mask_code_shapes,
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

struct WhirExternalMaskInput {
    group_specifications: Vec<MaskGroupStaticSpecification>,
    generalized_relation_claim_count: u64,
    carried_message_randomness_element_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedStaticCatalog {
    pre_challenge_whir: WhirStaticLedger,
    main_whir: WhirStaticLedger,
    transcript_chronology: transcript_chronology::PackingTranscriptChronology,
    uniform_verifier_randomness: uniform_verifier_randomness::PackingUniformVerifierRandomness,
    response_commitments: response_commitment::PackingResponseCommitmentCatalog,
    query_sampling_lifecycle: lifecycle::PackingQuerySamplingLifecycle,
    decoded_challenge_consumers: emitted_byte_correspondence::DecodedChallengeConsumers,
    proof_wire_geometry: CompactProofWireGeometry,
    response_checkpoint_schedule: CompactResponseCheckpointSchedule,
    public_input_wire_geometry: CompactPublicInputWireGeometry,
    maximum_proof_byte_length: u64,
    public_input_byte_length: u64,
    transport_byte_length: u64,
    transport_chunk_count: u64,
    cfw_to_whir_retained_payload_byte_length: u64,
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

#[derive(Clone, Copy)]
struct SelectedStaticCatalogInput<'catalog> {
    relation: &'catalog CompactPublicKeyRelationCatalog,
    cfw_reduction: &'catalog cfw_reduction::CfwReductionCatalog,
    cfw_to_whir_handoff: &'catalog cfw_to_whir_handoff::CfwToWhirHandoffCatalog,
    cfw_lifecycle: &'catalog cfw_lifecycle::CfwLifecycleCatalog,
    row_source_lifecycle: &'catalog row_source_lifecycle::RowSourceLifecycleCatalog,
}

impl SelectedStaticCatalog {
    fn derive(input: SelectedStaticCatalogInput<'_>) -> Result<Self, CompactStaticCatalogError> {
        let SelectedStaticCatalogInput {
            relation,
            cfw_reduction,
            cfw_to_whir_handoff,
            cfw_lifecycle,
            row_source_lifecycle,
        } = input;
        let main_component_count = relation
            .padded_witness_element_count()
            .checked_div(relation.ring_degree())
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        if !main_component_count.is_power_of_two() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let main_first_folding_factor = main_component_count.ilog2();
        let pre_challenge_component_count = PRE_CHALLENGE_PADDED_RING_VECTOR_COUNT;
        let pre_challenge_first_folding_factor = pre_challenge_component_count.ilog2();
        let round_log_inverse_rates = [2, 4, 8];
        cfw_reduction.check(relation)?;
        let witness_covector_geometry = compact_structured_witness_covector_geometry(relation)
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
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
            WhirExternalMaskInput {
                group_specifications: vec![preliminary_cross_epoch_mask_specification],
                generalized_relation_claim_count: 0,
                carried_message_randomness_element_count: CROSS_EPOCH_MASK_WIDTH
                    * CROSS_EPOCH_MASK_MESSAGE_LENGTH,
            },
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
            WhirExternalMaskInput {
                group_specifications: preliminary_main_mask_group_specifications,
                generalized_relation_claim_count: cfw_reduction
                    .generalized_committed_relation_claim_count(),
                carried_message_randomness_element_count: cfw_reduction
                    .fresh_mask_randomness_element_count(),
            },
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
            WhirExternalMaskInput {
                group_specifications: vec![cross_epoch_mask_specification],
                generalized_relation_claim_count: 0,
                carried_message_randomness_element_count: CROSS_EPOCH_MASK_WIDTH
                    * CROSS_EPOCH_MASK_MESSAGE_LENGTH,
            },
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
            WhirExternalMaskInput {
                group_specifications: main_mask_group_specifications,
                generalized_relation_claim_count: cfw_reduction
                    .generalized_committed_relation_claim_count(),
                carried_message_randomness_element_count: cfw_reduction
                    .fresh_mask_randomness_element_count(),
            },
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
        let query_sampling_lifecycle =
            lifecycle::PackingQuerySamplingLifecycle::derive(&pre_challenge_whir, &main_whir)?;
        if transcript_chronology.distinct_query_group_count
            != query_sampling_lifecycle.query_group_count
            || transcript_chronology.fixed_query_candidate_slot_count
                != query_sampling_lifecycle.fixed_candidate_slot_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let proof_wire_geometry = CompactProofWireGeometry::new(
            response_commitments.production_wire_geometries(&uniform_verifier_randomness)?,
        )
        .map_err(map_production_wire_error)?;
        let response_checkpoint_schedule = CompactResponseCheckpointSchedule::derive(
            &proof_wire_geometry,
            &response_commitments.production_merkle_geometries()?,
        )
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        let public_input_wire_geometry = CompactPublicInputWireGeometry::new(
            relation.public_input_ring_vector_count(),
            relation.ring_degree(),
        )
        .map_err(map_production_wire_error)?;
        if u64::try_from(proof_wire_geometry.responses().len())
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
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let decoded_challenge_consumers =
            emitted_byte_correspondence::DecodedChallengeConsumers::derive(
                &transcript_chronology,
                &uniform_verifier_randomness,
                cfw_reduction,
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
            .checked_add(main_whir.query_counts[0])
            .and_then(|populated| populated.checked_mul(2))
            .and_then(u64::checked_next_power_of_two)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        if encoded_row_count != main_whir.oracle_heights[0] {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let transform_batch_component_count = 8;
        let base_coordinate_butterfly_count = [
            pre_challenge_whir.base_coordinate_butterfly_count,
            main_whir.base_coordinate_butterfly_count,
            witness_covector_geometry.transform_butterfly_count(),
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
            pre_challenge_whir,
            main_whir,
            transcript_chronology,
            uniform_verifier_randomness,
            response_commitments,
            query_sampling_lifecycle,
            decoded_challenge_consumers,
            proof_wire_geometry,
            response_checkpoint_schedule,
            public_input_wire_geometry,
            maximum_proof_byte_length,
            public_input_byte_length,
            transport_byte_length,
            transport_chunk_count,
            cfw_to_whir_retained_payload_byte_length: cfw_to_whir_handoff
                .retained_combined_relation_payload_byte_length(),
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
    selected: SelectedStaticCatalog,
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
        let selected_input = SelectedStaticCatalogInput {
            relation: &relation,
            cfw_reduction: &cfw_reduction,
            cfw_to_whir_handoff: &cfw_to_whir_handoff,
            cfw_lifecycle: &cfw_lifecycle,
            row_source_lifecycle: &row_source_lifecycle,
        };
        let selected = SelectedStaticCatalog::derive(selected_input)?;
        let field_order = BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(
            u32::try_from(QUINTIC_EXTENSION_DEGREE)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        );
        Ok(Self {
            relation_plan_hash: relation.relation_plan_variant_hash(),
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
            selected,
        })
    }
}

pub(super) fn generated_factor_one_contract_source_bytes() -> Vec<u8> {
    let catalog = CompactPublicKeyStaticCatalog::derive()
        .expect("factor-one contract source geometry derives");
    let selected = &catalog.selected;
    let relation = selected_compact_public_key_relation_catalog()
        .expect("factor-one contract relation derives");
    let response_merkle_geometries = selected
        .response_commitments
        .production_merkle_geometries()
        .expect("factor-one response Merkle geometries derive");
    let response_component_roles = selected
        .response_commitments
        .responses()
        .iter()
        .map(|response| {
            response
                .components
                .iter()
                .map(|component| {
                    let (role_tag, epoch, batch_ordinal, round_ordinal) =
                        component.role.contract_coordinates();
                    CompactResponseComponentRoleContract::new(
                        role_tag,
                        epoch,
                        batch_ordinal,
                        round_ordinal,
                    )
                })
                .collect()
        })
        .collect();
    let verifier_moves = selected
        .transcript_chronology
        .verifier_moves()
        .iter()
        .enumerate()
        .map(|(move_index, verifier_move)| {
            let decoded_consumers = selected
                .decoded_challenge_consumers
                .for_move(move_index)
                .expect("factor-one decoded challenge consumers derive");
            assert_eq!(decoded_consumers.len(), verifier_move.roles().len());
            CompactVerifierMoveContractInput {
                ordinal: verifier_move.ordinal(),
                preceding_prover_response_ordinal: verifier_move
                    .preceding_prover_response_ordinal(),
                preceding_commitment_count: u32::try_from(
                    verifier_move.preceding_commitment_count(),
                )
                .expect("commitment count fits u32"),
                role_coordinates: verifier_move
                    .roles()
                    .iter()
                    .copied()
                    .zip(decoded_consumers)
                    .map(|(role, consumer)| {
                        assert_eq!(consumer.role, role);
                        contract_role_coordinate(
                            role,
                            [
                                [
                                    consumer.extension_output_range.start,
                                    consumer.extension_output_range.end,
                                ],
                                [
                                    consumer.base_field_output_range.start,
                                    consumer.base_field_output_range.end,
                                ],
                                [
                                    consumer.distinct_query_group_range.start,
                                    consumer.distinct_query_group_range.end,
                                ],
                            ],
                        )
                    })
                    .collect(),
                message_geometry: selected
                    .uniform_verifier_randomness
                    .fixed_message_geometry(move_index)
                    .expect("factor-one verifier-message geometry derives"),
            }
        })
        .collect();
    let whir_ledgers = [
        (1_u8, &selected.pre_challenge_whir),
        (2_u8, &selected.main_whir),
    ];
    let whir_epochs = whir_ledgers
        .into_iter()
        .map(|(epoch, whir)| CompactWhirEpochContractInput {
            epoch,
            polynomial_variable_count: whir.polynomial_variable_count,
            folding_schedule: whir.folding_schedule,
            final_variable_count: whir.final_variable_count,
            round_log_inverse_rates: whir.round_log_inverse_rates,
            mask_query_count: whir.mask_query_count,
            internal_mask_groups: whir
                .internal_mask_groups
                .iter()
                .copied()
                .map(contract_whir_mask_group)
                .collect(),
            external_mask_groups: whir
                .external_mask_groups
                .iter()
                .copied()
                .map(contract_whir_mask_group)
                .collect(),
        })
        .collect();
    let whir_folds = whir_ledgers
        .into_iter()
        .flat_map(|(epoch, whir)| {
            (0..WHIR_FOLD_BATCH_COUNT).map(move |batch_ordinal| CompactWhirFoldContractInput {
                epoch,
                batch_ordinal: u8::try_from(batch_ordinal).expect("fold ordinal fits u8"),
                message_length: whir.source_message_lengths[batch_ordinal],
                hiding_randomness_length: whir.query_counts[batch_ordinal],
                block_length: whir.oracle_heights[batch_ordinal],
                oracle_width: whir.oracle_widths[batch_ordinal],
                query_count: whir.query_counts[batch_ordinal],
            })
        })
        .collect();
    encode_generated_contract_source(CompactProofContractGenerationInput {
        relation_schema_digest: relation
            .canonical_schema_digest()
            .expect("factor-one relation schema digest derives"),
        commitment_count: u32::try_from(selected.transcript_chronology.commitment_count())
            .expect("commitment count fits u32"),
        distinct_query_group_count: u32::try_from(
            selected.transcript_chronology.distinct_query_group_count,
        )
        .expect("query-group count fits u32"),
        public_input_wire_geometry: selected.public_input_wire_geometry,
        proof_wire_geometry: selected.proof_wire_geometry.clone(),
        response_merkle_geometries,
        response_component_roles,
        checkpoint_schedule: selected.response_checkpoint_schedule.clone(),
        verifier_moves,
        whir_epochs,
        whir_folds,
    })
    .expect("factor-one contract source bytes encode and decode")
}

fn contract_whir_mask_group(group: MaskGroupStaticLedger) -> CompactWhirMaskGroupContractInput {
    let (role_tag, coordinate) = match group.role {
        MaskGroupRole::CrossEpochOpening => (1, 0),
        MaskGroupRole::CfwInner => (2, 0),
        MaskGroupRole::CfwOuter => (3, 0),
        MaskGroupRole::WhirSumcheck { batch_ordinal } => (4, batch_ordinal),
        MaskGroupRole::WhirCodeSwitch { round_ordinal } => (5, round_ordinal),
    };
    let committed_encoding_source = match group.committed_encoding_source {
        MaskCommittedEncodingSource::OwnedByThisEpoch => 1,
        MaskCommittedEncodingSource::ReusedFromPreChallenge => 2,
    };
    CompactWhirMaskGroupContractInput {
        role_tag,
        coordinate,
        width: group.width,
        message_length: group.message_length,
        randomness_length: group.randomness_length,
        domain_size: group.domain_size,
        committed_encoding_source,
    }
}

fn contract_role_coordinate(
    role: transcript_chronology::VerifierMoveRole,
    ranges: [[u64; 2]; 3],
) -> CompactVerifierRoleCoordinate {
    use transcript_chronology::VerifierMoveRole;

    match role {
        VerifierMoveRole::LookupChallenge => CompactVerifierRoleCoordinate::non_epoch(1, 0, ranges),
        VerifierMoveRole::CrossEpochPoint => CompactVerifierRoleCoordinate::non_epoch(2, 0, ranges),
        VerifierMoveRole::CfwInitialRandomness => {
            CompactVerifierRoleCoordinate::non_epoch(3, 0, ranges)
        }
        VerifierMoveRole::CfwSumcheckRound { round_ordinal } => {
            CompactVerifierRoleCoordinate::non_epoch(4, round_ordinal, ranges)
        }
        VerifierMoveRole::CfwJointConstraint => {
            CompactVerifierRoleCoordinate::non_epoch(5, 0, ranges)
        }
        VerifierMoveRole::WhirOpeningBatching { epoch } => {
            CompactVerifierRoleCoordinate::epoch(6, contract_epoch(epoch), 0, 0, ranges)
        }
        VerifierMoveRole::WhirMaskedSumcheckCombination {
            epoch,
            batch_ordinal,
        } => {
            CompactVerifierRoleCoordinate::epoch(7, contract_epoch(epoch), batch_ordinal, 0, ranges)
        }
        VerifierMoveRole::WhirFolding {
            epoch,
            batch_ordinal,
            round_ordinal,
        } => CompactVerifierRoleCoordinate::epoch(
            8,
            contract_epoch(epoch),
            batch_ordinal,
            u32::from(round_ordinal),
            ranges,
        ),
        VerifierMoveRole::WhirRoundQueryAndCombination {
            epoch,
            round_ordinal,
        } => CompactVerifierRoleCoordinate::epoch(
            9,
            contract_epoch(epoch),
            0,
            u32::from(round_ordinal),
            ranges,
        ),
        VerifierMoveRole::WhirBaseCombination { epoch } => {
            CompactVerifierRoleCoordinate::epoch(10, contract_epoch(epoch), 0, 0, ranges)
        }
        VerifierMoveRole::WhirFinalQueries { epoch } => {
            CompactVerifierRoleCoordinate::epoch(11, contract_epoch(epoch), 0, 0, ranges)
        }
    }
}

const fn contract_epoch(epoch: transcript_chronology::TranscriptEpoch) -> u8 {
    match epoch {
        transcript_chronology::TranscriptEpoch::PreChallenge => 1,
        transcript_chronology::TranscriptEpoch::Main => 2,
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

fn conservative_full_dimension_unique_decoding_query_count(
    security_level: u32,
    message_length: u64,
    domain_size: u64,
) -> Result<u64, CompactStaticCatalogError> {
    if message_length == 0
        || domain_size <= message_length
        || !domain_size.is_multiple_of(message_length)
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
        // Retain the accepted source geometry selected by the independent-
        // query upper bound. The transcript samples ordered distinct queries;
        // its tighter exact probability is checked by the soundness and
        // relaxed-extraction owners against these fixed counts.
        if independent_full_dimension_query_failure_is_at_most_target(
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

fn independent_full_dimension_query_failure_is_at_most_target(
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
    // Query-count selection intentionally keeps the one-location looser
    // `n - t` upper bound. The exact theorem and soundness ledgers use the
    // strict bad-word maximum `n - t - 1`; retaining this conservative bound
    // cannot underselect queries and preserves stable production geometry.
    let conservative_bad_agreement_upper_bound = domain_size
        .checked_sub(selected_decoding_error_count)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    Ok(
        BigUint::from(conservative_bad_agreement_upper_bound).pow(exponent)
            * (BigUint::one() << security_level)
            <= BigUint::from(domain_size).pow(exponent),
    )
}

fn exact_mask_query_count_for_final_verifier_move(
    source_message_length: u64,
    source_domain_size: u64,
    source_query_count: u64,
    mask_code_shapes: &[(u64, MaskEncodingRandomnessLength)],
    minimum_mask_query_count: u64,
    verifier_move_security_level: u32,
) -> Result<u64, CompactStaticCatalogError> {
    if source_query_count == 0 || mask_code_shapes.is_empty() || minimum_mask_query_count == 0 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let source_failure = exact_full_dimension_query_failure_probability(
        source_message_length,
        source_query_count,
        source_domain_size,
        source_query_count,
    )?;
    let mut candidate_mask_query_count = minimum_mask_query_count;
    loop {
        let mut grouped_move_failure = source_failure.clone();
        for (message_length, encoding_randomness_length) in mask_code_shapes {
            let encoding_randomness_length = match encoding_randomness_length {
                MaskEncodingRandomnessLength::LocalMaskQueryCount => candidate_mask_query_count,
                MaskEncodingRandomnessLength::Fixed(randomness_length) => *randomness_length,
            };
            let populated_message_length = message_length
                .checked_add(encoding_randomness_length)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            let domain_size = populated_message_length
                .checked_next_power_of_two()
                .and_then(|value| value.checked_shl(MASK_CODE_LOG_INVERSE_RATE))
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
            grouped_move_failure =
                grouped_move_failure.add(&exact_full_dimension_query_failure_probability(
                    *message_length,
                    encoding_randomness_length,
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
    encoding_randomness_length: u64,
    domain_size: u64,
    query_count: u64,
) -> Result<lifecycle::ExactProbability, CompactStaticCatalogError> {
    let dimension = message_length
        .checked_add(encoding_randomness_length)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
    if query_count == 0 || dimension >= domain_size {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let selected_decoding_error_count = domain_size
        .checked_sub(dimension)
        .and_then(|slack| slack.checked_sub(1))
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
        / 2;
    let conservative_bad_agreement_upper_bound = domain_size
        .checked_sub(selected_decoding_error_count)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    lifecycle::ExactProbability::new(
        exact_query_falling_factorial(conservative_bad_agreement_upper_bound, query_count)?,
        exact_query_falling_factorial(domain_size, query_count)?,
    )
}

fn exact_query_falling_factorial(
    population_size: u64,
    selection_count: u64,
) -> Result<BigUint, CompactStaticCatalogError> {
    if selection_count == 0 || selection_count > population_size {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    (0..selection_count).try_fold(BigUint::one(), |product, selected_count| {
        Ok(product * (population_size - selected_count))
    })
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
    struct SelectedResourceCeilingSnapshot {
        pre_challenge_proof_byte_length: u64,
        main_proof_byte_length: u64,
        maximum_proof_byte_length: u64,
        public_input_byte_length: u64,
        transport_byte_length: u64,
        transport_chunk_count: u64,
        cfw_to_whir_retained_payload_byte_length: u64,
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

    impl From<&SelectedStaticCatalog> for SelectedResourceCeilingSnapshot {
        fn from(selected: &SelectedStaticCatalog) -> Self {
            Self {
                pre_challenge_proof_byte_length: selected.pre_challenge_whir.proof_byte_length,
                main_proof_byte_length: selected.main_whir.proof_byte_length,
                maximum_proof_byte_length: selected.maximum_proof_byte_length,
                public_input_byte_length: selected.public_input_byte_length,
                transport_byte_length: selected.transport_byte_length,
                transport_chunk_count: selected.transport_chunk_count,
                cfw_to_whir_retained_payload_byte_length: selected
                    .cfw_to_whir_retained_payload_byte_length,
                base_coordinate_butterfly_count: selected.base_coordinate_butterfly_count,
                committed_leaf_count: selected.committed_leaf_count,
                commitment_leaf_hash_query_count: selected.commitment_leaf_hash_query_count,
                commitment_parent_hash_query_count: selected.commitment_parent_hash_query_count,
                verifier_opened_leaf_hash_query_count: selected
                    .verifier_opened_leaf_hash_query_count,
                maximum_uninterrupted_butterfly_count: selected
                    .maximum_uninterrupted_butterfly_count,
                maximum_uninterrupted_leaf_hash_count: selected
                    .maximum_uninterrupted_leaf_hash_count,
                deterministic_checkpoint_count: selected.deterministic_checkpoint_count,
            }
        }
    }

    #[test]
    fn public_key_static_catalog_derives_the_factor_one_production_contract() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;

        assert_eq!(catalog.relation_padded_witness_element_count, 4_194_304);
        assert_eq!(catalog.relation_operative_constraint_count, 2_686_977);
        assert_eq!(catalog.pre_challenge_ring_vector_count, 33);
        assert_eq!(catalog.cross_epoch_point_coordinate_count, 21);
        assert_eq!(catalog.cross_epoch_binding_error_numerator, 21);
        assert_eq!(catalog.cross_epoch_explicit_opening_count, 2);
        assert_eq!(catalog.lookup_challenge_field_order.bits(), 320);
        assert!(selected.maximum_proof_byte_length < PROOF_ALLOCATION_BOUND_BYTE_LENGTH);
    }

    #[test]
    fn mask_group_catalog_preserves_cfw_then_whir_commitment_order() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_whir_roles = [
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

        let selected = &catalog.selected;
        assert_eq!(
            selected
                .pre_challenge_whir
                .mask_groups_in_commitment_order()
                .map(|group| group.role)
                .collect::<Vec<_>>(),
            expected_pre_challenge_roles
        );
        assert_eq!(
            selected
                .main_whir
                .mask_groups_in_commitment_order()
                .map(|group| group.role)
                .collect::<Vec<_>>(),
            expected_main_roles
        );

        let cfw_inner_group = selected
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

        let cfw_outer_group = selected
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

        let pre_challenge_cross_epoch_group = selected
            .pre_challenge_whir
            .external_mask_groups
            .first()
            .expect("pre-challenge cross-epoch mask group");
        let main_cross_epoch_group = selected
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
        assert_eq!(selected.pre_challenge_whir.opening_evaluation_count, 1);
        assert_eq!(selected.pre_challenge_whir.opening_batching_claim_count, 1);
        assert_eq!(selected.main_whir.opening_evaluation_count, 2);
        assert_eq!(selected.main_whir.opening_batching_claim_count, 164);
    }

    #[test]
    fn private_randomness_ledgers_count_every_independent_mask_coin_once() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        let pre_challenge_snapshot =
            WhirPrivateRandomnessSnapshot::from(&selected.pre_challenge_whir);
        let main_snapshot = WhirPrivateRandomnessSnapshot::from(&selected.main_whir);

        assert_eq!(
            pre_challenge_snapshot,
            WhirPrivateRandomnessSnapshot {
                source_oracle_encoding: 44_224,
                carried_mask_messages: 56,
                carried_mask_encoding: 9_975,
                fresh_mirror_messages: 1_284,
                fresh_mirror_encoding: 9_975,
                fresh_source_message: 8,
                fresh_source_encoding: 348,
                total: 65_870,
            }
        );
        assert_eq!(
            main_snapshot,
            WhirPrivateRandomnessSnapshot {
                source_oracle_encoding: 69_568,
                carried_mask_messages: 379,
                carried_mask_encoding: 45_486,
                fresh_mirror_messages: 1_747,
                fresh_mirror_encoding: 47_082,
                fresh_source_message: 8,
                fresh_source_encoding: 348,
                total: 164_618,
            }
        );

        assert_eq!(
            catalog.cfw_reduction.fresh_mask_randomness_element_count(),
            322
        );
        assert_eq!(
            selected
                .pre_challenge_whir
                .external_carried_mask_message_randomness_element_count,
            2
        );
        assert_eq!(
            selected
                .main_whir
                .external_carried_mask_message_randomness_element_count,
            322
        );
    }

    #[test]
    fn canonical_wire_resource_ceiling_is_exact_for_factor_one() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        assert_eq!(
            SelectedResourceCeilingSnapshot::from(selected),
            SelectedResourceCeilingSnapshot {
                pre_challenge_proof_byte_length: 4_868_556,
                main_proof_byte_length: 11_602_452,
                maximum_proof_byte_length: 26_927_670,
                public_input_byte_length: 15_991_062,
                transport_byte_length: 42_918_732,
                transport_chunk_count: 41,
                cfw_to_whir_retained_payload_byte_length: 167_790_680,
                base_coordinate_butterfly_count: 916_598_784,
                committed_leaf_count: 1_032_486,
                commitment_leaf_hash_query_count: 27_590_950,
                commitment_parent_hash_query_count: 1_032_359,
                verifier_opened_leaf_hash_query_count: 510_301,
                maximum_uninterrupted_butterfly_count: 44_564_480,
                maximum_uninterrupted_leaf_hash_count: 131_072,
                deterministic_checkpoint_count: 2_677,
            }
        );
    }

    #[test]
    fn production_response_checkpoint_schedule_preserves_canonical_section_order() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        assert_eq!(
            (
                selected.response_checkpoint_schedule.total_response_count(),
                selected
                    .response_checkpoint_schedule
                    .lagging_checkpoint_count(),
                selected
                    .response_checkpoint_schedule
                    .maximum_pending_proof_response_count(),
            ),
            (82, 81, 80)
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
        let selected = &catalog.selected;
        assert_eq!(selected.main_whir.round_log_inverse_rates, [2, 4, 8]);
        assert_eq!(
            selected.pre_challenge_whir.round_log_inverse_rates,
            [2, 4, 8]
        );
        assert_eq!(selected.main_whir.query_counts, [396, 432, 400, 348]);
        assert_eq!(
            selected.pre_challenge_whir.query_counts,
            [396, 432, 400, 348]
        );
        assert_eq!(selected.pre_challenge_whir.mask_query_count, 399);
        assert_eq!(selected.main_whir.mask_query_count, 399);
        assert_eq!(selected.pre_challenge_whir.mask_query_union_branch_count, 9);
        assert_eq!(selected.main_whir.mask_query_union_branch_count, 11);
    }

    #[test]
    fn whir_proof_accounting_uses_coordinate_derived_compact_frontiers() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");

        let selected = &catalog.selected;
        for whir in [&selected.pre_challenge_whir, &selected.main_whir] {
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
