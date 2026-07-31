//! Construction-derived liveness for aggregate-wide oracle commitments.

use core::mem::size_of;

use super::{
    ChallengeField, ColumnStreamableLeafState, MERKLE_DIGEST_WORD_LENGTH,
    construction_plan::RowCodeWhirConstructionPlan,
    recomputable_oracle::{
        AGGREGATE_ORACLE_LEAF_STATE_STRIPE_ROW_COUNT, aggregate_oracle_leaf_state_stripe_count,
    },
};
use crate::bgv::proof_suite::MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH;

const ROOT_AND_OPENING_PASS_COUNT: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AggregateCommitmentEpochLiveness {
    leaf_count: usize,
    leaf_width: usize,
    query_count: usize,
    stripe_count: usize,
}

impl AggregateCommitmentEpochLiveness {
    #[cfg(test)]
    pub(super) const fn leaf_count(self) -> usize {
        self.leaf_count
    }

    #[cfg(test)]
    pub(super) const fn leaf_width(self) -> usize {
        self.leaf_width
    }

    #[cfg(test)]
    pub(super) const fn query_count(self) -> usize {
        self.query_count
    }

    #[cfg(test)]
    pub(super) const fn stripe_count(self) -> usize {
        self.stripe_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateCommitmentLiveness {
    epochs: Vec<AggregateCommitmentEpochLiveness>,
    maximum_dft_buffer_byte_length: u64,
    maximum_leaf_state_stripe_byte_length: u64,
    maximum_algorithm_live_set_byte_length: u64,
    full_column_dft_count: u64,
    cached_initial_hash_query_count: u64,
    transition_hash_query_count: u64,
    final_hash_query_count: u64,
    merkle_parent_hash_query_count: u64,
}

impl AggregateCommitmentLiveness {
    #[cfg(test)]
    pub(super) fn epochs(&self) -> &[AggregateCommitmentEpochLiveness] {
        &self.epochs
    }

    #[cfg(test)]
    pub(super) const fn maximum_dft_buffer_byte_length(&self) -> u64 {
        self.maximum_dft_buffer_byte_length
    }

    #[cfg(test)]
    pub(super) const fn maximum_leaf_state_stripe_byte_length(&self) -> u64 {
        self.maximum_leaf_state_stripe_byte_length
    }

    pub(super) const fn maximum_algorithm_live_set_byte_length(&self) -> u64 {
        self.maximum_algorithm_live_set_byte_length
    }

    #[cfg(test)]
    pub(super) const fn full_column_dft_count(&self) -> u64 {
        self.full_column_dft_count
    }

    #[cfg(test)]
    pub(super) const fn cached_initial_hash_query_count(&self) -> u64 {
        self.cached_initial_hash_query_count
    }

    #[cfg(test)]
    pub(super) const fn transition_hash_query_count(&self) -> u64 {
        self.transition_hash_query_count
    }

    #[cfg(test)]
    pub(super) const fn final_hash_query_count(&self) -> u64 {
        self.final_hash_query_count
    }

    #[cfg(test)]
    pub(super) const fn merkle_parent_hash_query_count(&self) -> u64 {
        self.merkle_parent_hash_query_count
    }

    #[cfg(test)]
    pub(super) fn aggregate_hash_query_count(&self) -> Result<u64, String> {
        self.cached_initial_hash_query_count
            .checked_add(self.transition_hash_query_count)
            .and_then(|count| count.checked_add(self.final_hash_query_count))
            .and_then(|count| count.checked_add(self.merkle_parent_hash_query_count))
            .ok_or_else(|| "aggregate commitment hash count overflowed".to_owned())
    }
}

pub(super) fn derive_aggregate_commitment_liveness(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<AggregateCommitmentLiveness, String> {
    if size_of::<ColumnStreamableLeafState>() != MERKLE_DIGEST_WORD_LENGTH * size_of::<u64>() {
        return Err("aggregate leaf state is not one 512-bit digest".to_owned());
    }
    let whir_plan = construction_plan.whir_plan();
    let mut epochs = whir_plan
        .rounds
        .iter()
        .map(|round| (round.encoded_oracle, round.query_epoch))
        .collect::<Vec<_>>();
    epochs.push((
        whir_plan.final_round.encoded_oracle,
        whir_plan.final_round.query_epoch,
    ));
    if epochs.is_empty() {
        return Err("aggregate commitment has no WHIR epochs".to_owned());
    }

    let mut accounting_rows = Vec::with_capacity(epochs.len());
    let mut maximum_leaf_count = 0_usize;
    let mut stripe_count_sum = 0_u64;
    let mut transition_hash_query_count = 0_u64;
    let mut final_hash_query_count = 0_u64;
    let mut merkle_parent_hash_query_count = 0_u64;
    for (encoded_oracle, query_epoch) in epochs {
        if encoded_oracle.leaf_count == 0
            || !encoded_oracle.leaf_count.is_power_of_two()
            || encoded_oracle.leaf_width != 8
            || encoded_oracle.evaluation_count
                != encoded_oracle
                    .leaf_count
                    .checked_mul(encoded_oracle.leaf_width)
                    .ok_or_else(|| "aggregate encoded-oracle size overflowed".to_owned())?
            || query_epoch.domain_size != encoded_oracle.leaf_count
            || query_epoch.query_count == 0
            || query_epoch.query_count > encoded_oracle.leaf_count
        {
            return Err("aggregate commitment epoch geometry is invalid".to_owned());
        }
        let stripe_count = aggregate_oracle_leaf_state_stripe_count(encoded_oracle.leaf_count)?;
        let leaf_count = u64::try_from(encoded_oracle.leaf_count)
            .map_err(|_| "aggregate leaf count exceeds u64".to_owned())?;
        let leaf_width = u64::try_from(encoded_oracle.leaf_width)
            .map_err(|_| "aggregate leaf width exceeds u64".to_owned())?;
        let pass_leaf_count = leaf_count
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            .ok_or_else(|| "aggregate pass leaf count overflowed".to_owned())?;
        transition_hash_query_count = transition_hash_query_count
            .checked_add(
                pass_leaf_count
                    .checked_mul(leaf_width)
                    .ok_or_else(|| "aggregate transition count overflowed".to_owned())?,
            )
            .ok_or_else(|| "aggregate transition count overflowed".to_owned())?;
        final_hash_query_count = final_hash_query_count
            .checked_add(pass_leaf_count)
            .ok_or_else(|| "aggregate final count overflowed".to_owned())?;
        merkle_parent_hash_query_count = merkle_parent_hash_query_count
            .checked_add(
                leaf_count
                    .checked_sub(1)
                    .and_then(|count| count.checked_mul(ROOT_AND_OPENING_PASS_COUNT))
                    .ok_or_else(|| "aggregate parent count overflowed".to_owned())?,
            )
            .ok_or_else(|| "aggregate parent count overflowed".to_owned())?;
        stripe_count_sum = stripe_count_sum
            .checked_add(
                u64::try_from(stripe_count)
                    .map_err(|_| "aggregate stripe count exceeds u64".to_owned())?,
            )
            .ok_or_else(|| "aggregate stripe count overflowed".to_owned())?;
        maximum_leaf_count = maximum_leaf_count.max(encoded_oracle.leaf_count);
        accounting_rows.push(AggregateCommitmentEpochLiveness {
            leaf_count: encoded_oracle.leaf_count,
            leaf_width: encoded_oracle.leaf_width,
            query_count: query_epoch.query_count,
            stripe_count,
        });
    }

    let maximum_dft_buffer_byte_length = u64::try_from(maximum_leaf_count)
        .ok()
        .and_then(|count| count.checked_mul(size_of::<ChallengeField>() as u64))
        .ok_or_else(|| "aggregate DFT liveness overflowed".to_owned())?;
    let maximum_leaf_state_stripe_byte_length =
        u64::try_from(maximum_leaf_count.min(AGGREGATE_ORACLE_LEAF_STATE_STRIPE_ROW_COUNT))
            .ok()
            .and_then(|count| count.checked_mul(size_of::<ColumnStreamableLeafState>() as u64))
            .ok_or_else(|| "aggregate leaf-state liveness overflowed".to_owned())?;
    let maximum_algorithm_live_set_byte_length = maximum_dft_buffer_byte_length
        .checked_add(maximum_leaf_state_stripe_byte_length)
        .ok_or_else(|| "aggregate algorithm liveness overflowed".to_owned())?;
    if maximum_algorithm_live_set_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
        return Err("aggregate algorithm live set exceeds the hard WASM bound".to_owned());
    }
    let epoch_count = u64::try_from(accounting_rows.len())
        .map_err(|_| "aggregate epoch count exceeds u64".to_owned())?;
    let cached_initial_hash_query_count = epoch_count
        .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
        .ok_or_else(|| "aggregate initial hash count overflowed".to_owned())?;
    let full_column_dft_count = stripe_count_sum
        .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
        .and_then(|count| count.checked_mul(8))
        .ok_or_else(|| "aggregate DFT count overflowed".to_owned())?;

    Ok(AggregateCommitmentLiveness {
        epochs: accounting_rows,
        maximum_dft_buffer_byte_length,
        maximum_leaf_state_stripe_byte_length,
        maximum_algorithm_live_set_byte_length,
        full_column_dft_count,
        cached_initial_hash_query_count,
        transition_hash_query_count,
        final_hash_query_count,
        merkle_parent_hash_query_count,
    })
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::One;

    use super::super::canonical_row_code_whir_family_body_byte_length_ceiling;
    use super::*;
    use crate::bgv::proof_suite::{
        AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, ValidatedRelationPlanArtifact,
        build_relation_bound_public_tree_catalog_entries,
        canonical_selected_application_statement_for_ceiling, compile_same_secret_relation_plan,
        external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        merkle::maximum_minimal_frontier_node_count,
        selected_accounting::resource_accounting::selected_relation_tree_inputs,
        selected_relation_plan_check_context, selected_same_secret_relation_plan_input,
    };
    use crate::foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings,
        ProofObjectHeader,
    };

    const MERKLE_DIGEST_BYTE_LENGTH: u64 = 64;
    const CANONICAL_COUNT_BYTE_LENGTH: u64 = 4;
    const DIRECT_SINGLE_COLUMN_COMMITMENT_HASH_QUERY_COUNT: u64 = 1_114_109;

    fn selected_same_secret_construction()
    -> (RowCodeWhirConstructionPlan, ValidatedRelationPlanArtifact) {
        let schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let context =
            selected_relation_plan_check_context(schema_identifier).expect("the context exists");
        let compiled = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input().expect("the relation input derives"),
            &context,
        )
        .expect("the relation compiles");
        let validated = ValidatedRelationPlanArtifact::from_owned_compiled_plan(compiled, &context)
            .expect("the relation validates");
        let construction_plan =
            RowCodeWhirConstructionPlan::for_selected_variant(&validated, None, None)
                .expect("the construction plan derives");
        (construction_plan, validated)
    }

    fn selected_same_secret_proof_byte_length(
        construction_plan: &RowCodeWhirConstructionPlan,
        validated: &ValidatedRelationPlanArtifact,
    ) -> u64 {
        let variant = validated
            .compiled_plan()
            .variants()
            .first()
            .expect("the same-secret variant exists");
        let relation_trees =
            selected_relation_tree_inputs(variant).expect("the relation tree inputs derive");
        let bound_tree_entries = build_relation_bound_public_tree_catalog_entries(&relation_trees)
            .expect("the bound-tree entries derive");
        let family_body_byte_length = canonical_row_code_whir_family_body_byte_length_ceiling(
            construction_plan,
            variant,
            &bound_tree_entries,
        )
        .expect("the canonical same-secret family body derives");
        let statement = canonical_selected_application_statement_for_ceiling(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            crate::bgv::proof_suite::SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0_u8; Hash512::BYTE_LENGTH],
                None,
                None,
            ),
        )
        .expect("the canonical same-secret statement derives");
        let header_byte_length = ProofObjectHeader::from_canonical_application_statement(
            statement,
            &CanonicalDecodeLimits::default(),
        )
        .expect("the canonical proof header derives")
        .encode()
        .expect("the canonical proof header encodes")
        .len();
        u64::try_from(header_byte_length + family_body_byte_length)
            .expect("the same-secret proof length fits u64")
    }

    #[test]
    fn aligned_internal_leaf_state_stripes_close_the_selected_aggregate_core() {
        let (plan, validated) = selected_same_secret_construction();
        let accounting =
            derive_aggregate_commitment_liveness(&plan).expect("the liveness accounting derives");

        assert_eq!(
            accounting
                .epochs()
                .iter()
                .map(|epoch| epoch.leaf_count())
                .collect::<Vec<_>>(),
            [8_388_608, 4_194_304, 2_097_152, 1_048_576, 524_288, 262_144],
        );
        assert_eq!(
            accounting
                .epochs()
                .iter()
                .map(|epoch| epoch.leaf_width())
                .collect::<Vec<_>>(),
            [8; 6],
        );
        assert_eq!(
            accounting
                .epochs()
                .iter()
                .map(|epoch| epoch.query_count())
                .collect::<Vec<_>>(),
            [387, 288, 268, 264, 263, 263],
        );
        assert_eq!(
            accounting
                .epochs()
                .iter()
                .map(|epoch| epoch.stripe_count())
                .collect::<Vec<_>>(),
            [8, 4, 2, 1, 1, 1],
        );
        assert_eq!(size_of::<ChallengeField>(), 40);
        assert_eq!(size_of::<ColumnStreamableLeafState>(), 64);
        assert_eq!(accounting.maximum_dft_buffer_byte_length(), 335_544_320);
        assert_eq!(
            accounting.maximum_leaf_state_stripe_byte_length(),
            67_108_864
        );
        assert_eq!(
            accounting.maximum_algorithm_live_set_byte_length(),
            NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
        );
        assert!(
            accounting.maximum_algorithm_live_set_byte_length()
                <= AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        );
        assert_eq!(accounting.full_column_dft_count(), 272);
        assert_eq!(accounting.cached_initial_hash_query_count(), 12);
        assert_eq!(accounting.transition_hash_query_count(), 264_241_152);
        assert_eq!(accounting.final_hash_query_count(), 33_030_144);
        assert_eq!(accounting.merkle_parent_hash_query_count(), 33_030_132);
        assert_eq!(
            accounting
                .aggregate_hash_query_count()
                .expect("the hash count adds"),
            330_301_440,
        );
        assert_eq!(
            accounting
                .aggregate_hash_query_count()
                .expect("the hash count adds")
                + DIRECT_SINGLE_COLUMN_COMMITMENT_HASH_QUERY_COUNT,
            331_415_549,
        );
        assert_eq!(
            selected_same_secret_proof_byte_length(&plan, &validated),
            5_309_850
        );
    }

    #[test]
    fn column_separation_is_larger_and_external_leaf_states_exceed_scratch() {
        let (plan, validated) = selected_same_secret_construction();
        let accounting =
            derive_aggregate_commitment_liveness(&plan).expect("the liveness accounting derives");
        let frontier_node_count = accounting
            .epochs()
            .iter()
            .map(|epoch| {
                maximum_minimal_frontier_node_count(epoch.leaf_count(), epoch.query_count())
                    .expect("the compact frontier derives")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            frontier_node_count,
            [5_543, 3_968, 3_460, 3_152, 2_879, 2_616]
        );
        let extra_frontier_node_count = frontier_node_count
            .iter()
            .try_fold(0_u64, |total, count| {
                u64::try_from(*count)
                    .ok()
                    .and_then(|count| count.checked_mul(7))
                    .and_then(|count| total.checked_add(count))
            })
            .expect("the separated frontier count adds");
        let epoch_count =
            u64::try_from(accounting.epochs().len()).expect("the epoch count fits u64");
        let column_separated_proof_byte_length =
            selected_same_secret_proof_byte_length(&plan, &validated)
                + extra_frontier_node_count * MERKLE_DIGEST_BYTE_LENGTH
                + epoch_count * 7 * MERKLE_DIGEST_BYTE_LENGTH
                + epoch_count * 7 * CANONICAL_COUNT_BYTE_LENGTH;
        assert_eq!(extra_frontier_node_count, 151_326);
        assert_eq!(column_separated_proof_byte_length, 14_997_570);

        let leaf_count_sum = accounting
            .epochs()
            .iter()
            .map(|epoch| u64::try_from(epoch.leaf_count()).expect("the leaf count fits u64"))
            .sum::<u64>();
        let column_separated_aggregate_hash_query_count = leaf_count_sum * 2 * 24 + 12;
        assert_eq!(
            column_separated_aggregate_hash_query_count
                + DIRECT_SINGLE_COLUMN_COMMITMENT_HASH_QUERY_COUNT,
            793_837_577,
        );

        let maximum_external_leaf_state_byte_length =
            u64::try_from(accounting.epochs()[0].leaf_count())
                .expect("the widest leaf count fits u64")
                * MERKLE_DIGEST_BYTE_LENGTH;
        let initial_source_table_byte_length =
            4_u64 * (1 << 22) * size_of::<ChallengeField>() as u64;
        let external_leaf_state_scratch_lower_bound =
            maximum_external_leaf_state_byte_length + initial_source_table_byte_length;
        let external_leaf_state_bytes_each_direction =
            leaf_count_sum * 2 * 9 * MERKLE_DIGEST_BYTE_LENGTH;
        assert_eq!(maximum_external_leaf_state_byte_length, 536_870_912);
        assert_eq!(initial_source_table_byte_length, 671_088_640);
        assert_eq!(external_leaf_state_scratch_lower_bound, 1_207_959_552);
        assert!(
            external_leaf_state_scratch_lower_bound
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        );
        assert_eq!(external_leaf_state_bytes_each_direction, 19_025_362_944);

        let adversarial_query_bound = (BigUint::one() << 80_usize) - BigUint::one();
        let qrom_numerator = BigUint::from(48_u8)
            * &adversarial_query_bound
            * &adversarial_query_bound
            * &adversarial_query_bound;
        assert!((qrom_numerator << 128_usize) < (BigUint::one() << 512_usize));
    }
}
