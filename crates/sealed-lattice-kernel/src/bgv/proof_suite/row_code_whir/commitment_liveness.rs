//! Construction-derived liveness for aggregate-wide oracle commitments.

use core::mem::size_of;

use super::{
    ChallengeField, ColumnStreamableLeafState, MERKLE_DIGEST_WORD_LENGTH,
    aggregate_wide_hiding::{AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE, AggregateWidePadLayout},
    column_commitment::{
        StreamingColumnHasher, maximum_interleaved_commitment_metadata_byte_length,
    },
    construction_plan::RowCodeWhirConstructionPlan,
    coordinate_derived_hiding_mmcs::{
        aggregate_private_leaf_salt_resident_state_byte_length,
        aggregate_private_leaf_salt_row_workspace_byte_length,
        materialized_single_column_commitment_payload_byte_length,
        transported_private_leaf_salt_uniqueness_set_byte_length,
    },
    private_leaf_salt::{
        PRIVATE_LEAF_SALT_BYTE_LENGTH, private_leaf_salt_derivation_workspace_byte_length,
    },
    recomputable_oracle::{
        AGGREGATE_ORACLE_LEAF_STATE_STRIPE_ROW_COUNT, aggregate_oracle_leaf_state_stripe_count,
    },
    row_encoding::RowEncodingGeometry,
};
use crate::bgv::proof_suite::relation_plan::{
    BoundTreeConstructionKind, ProofPrivacyMode, RelationColumnValueType,
};
use crate::bgv::proof_suite::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    ProofBaseFieldElement, ProofTreeValue,
    external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH,
    merkle::maximum_minimal_frontier_node_count, prover::CommonProofSourceProviderMemoryAccounting,
};

pub(super) const ROOT_AND_OPENING_PASS_COUNT: u64 = 2;
pub(super) const BOUND_TREE_AUTHENTICATION_STRIPE_LEAF_COUNT: usize = 1 << 20;

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
    initial_hash_query_count: u64,
    private_leaf_salt_derivation_count: u64,
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

    #[cfg(test)]
    pub(super) const fn maximum_algorithm_live_set_byte_length(&self) -> u64 {
        self.maximum_algorithm_live_set_byte_length
    }

    #[cfg(test)]
    pub(super) const fn full_column_dft_count(&self) -> u64 {
        self.full_column_dft_count
    }

    #[cfg(test)]
    pub(super) const fn initial_hash_query_count(&self) -> u64 {
        self.initial_hash_query_count
    }

    #[cfg(test)]
    pub(super) const fn private_leaf_salt_derivation_count(&self) -> u64 {
        self.private_leaf_salt_derivation_count
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
        self.initial_hash_query_count
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
    let mut initial_hash_query_count = 0_u64;
    let mut private_leaf_salt_derivation_count = 0_u64;
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
        let epoch_initial_hash_query_count = match construction_plan.proof_privacy_mode {
            ProofPrivacyMode::SecretBearing => pass_leaf_count,
            ProofPrivacyMode::PublicOnly => ROOT_AND_OPENING_PASS_COUNT,
        };
        initial_hash_query_count = initial_hash_query_count
            .checked_add(epoch_initial_hash_query_count)
            .ok_or_else(|| "aggregate initial count overflowed".to_owned())?;
        if construction_plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing {
            private_leaf_salt_derivation_count = private_leaf_salt_derivation_count
                .checked_add(pass_leaf_count)
                .ok_or_else(|| "aggregate private salt count overflowed".to_owned())?;
        }
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
    let private_leaf_salt_workspace_byte_length = match construction_plan.proof_privacy_mode {
        ProofPrivacyMode::PublicOnly => 0,
        ProofPrivacyMode::SecretBearing => u64::try_from(
            aggregate_private_leaf_salt_resident_state_byte_length()?
                .checked_add(private_leaf_salt_derivation_workspace_byte_length())
                .and_then(|byte_length| {
                    byte_length.checked_add(aggregate_private_leaf_salt_row_workspace_byte_length())
                })
                .ok_or_else(|| "aggregate private salt workspace overflowed".to_owned())?,
        )
        .map_err(|_| "aggregate private salt workspace exceeds u64".to_owned())?,
    };
    let maximum_algorithm_live_set_byte_length = maximum_dft_buffer_byte_length
        .checked_add(maximum_leaf_state_stripe_byte_length)
        .and_then(|byte_length| byte_length.checked_add(private_leaf_salt_workspace_byte_length))
        .ok_or_else(|| "aggregate algorithm liveness overflowed".to_owned())?;
    if maximum_algorithm_live_set_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
        return Err("aggregate algorithm live set exceeds the hard WASM bound".to_owned());
    }
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
        initial_hash_query_count,
        private_leaf_salt_derivation_count,
        transition_hash_query_count,
        final_hash_query_count,
        merkle_parent_hash_query_count,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PrivateLeafSaltLiveness {
    phase_opening_salt_count: u64,
    bound_opening_salt_count: u64,
    aggregate_opening_salt_count: u64,
    transported_salt_byte_length: u64,
    aggregate_resident_state_byte_length: u64,
    derivation_workspace_byte_length: u64,
    aggregate_row_workspace_byte_length: u64,
    canonical_uniqueness_set_byte_length: u64,
    retained_pad_commitment_payload_byte_length: u64,
    base_case_commitment_payload_byte_length: u64,
}

fn derive_private_leaf_salt_liveness(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<PrivateLeafSaltLiveness, String> {
    let bound_opening_salt_count = construction_plan
        .bound_trees
        .iter()
        .filter(|tree| tree.construction_kind == BoundTreeConstructionKind::CommittedMaterial)
        .try_fold(0_u64, |total, tree| {
            u64::try_from(tree.query_count)
                .ok()
                .and_then(|query_count| total.checked_add(query_count))
                .ok_or_else(|| "bound private leaf-salt count overflowed".to_owned())
        })?;
    if construction_plan.proof_privacy_mode == ProofPrivacyMode::PublicOnly {
        let transported_salt_byte_length = bound_opening_salt_count
            .checked_mul(
                u64::try_from(PRIVATE_LEAF_SALT_BYTE_LENGTH)
                    .map_err(|_| "private leaf-salt width exceeds u64".to_owned())?,
            )
            .ok_or_else(|| "transported private leaf-salt bytes overflowed".to_owned())?;
        return Ok(PrivateLeafSaltLiveness {
            phase_opening_salt_count: 0,
            bound_opening_salt_count,
            aggregate_opening_salt_count: 0,
            transported_salt_byte_length,
            aggregate_resident_state_byte_length: 0,
            derivation_workspace_byte_length: 0,
            aggregate_row_workspace_byte_length: 0,
            canonical_uniqueness_set_byte_length: u64::try_from(
                transported_private_leaf_salt_uniqueness_set_byte_length(
                    usize::try_from(bound_opening_salt_count)
                        .map_err(|_| "private leaf-salt count exceeds usize".to_owned())?,
                )?,
            )
            .map_err(|_| "private leaf-salt uniqueness set exceeds u64".to_owned())?,
            retained_pad_commitment_payload_byte_length: 0,
            base_case_commitment_payload_byte_length: 0,
        });
    }
    let aggregate = derive_aggregate_commitment_liveness(construction_plan)?;
    let hiding_configuration =
        super::hiding_whir::selected_hiding_whir_config(construction_plan.parameters)
            .map_err(|error| format!("derive private leaf-salt configuration: {error}"))?;
    let pad_layout = AggregateWidePadLayout::derive(&hiding_configuration)?;
    let pad_domain_size = p3_whir::MaskCodeShape::new(
        pad_layout.message_length(),
        hiding_configuration.sumcheck_mask.randomness_len,
        AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
    )
    .domain_size;
    let phase_opening_salt_count = u64::try_from(construction_plan.phase_order.len())
        .ok()
        .and_then(|phase_count| {
            u64::try_from(construction_plan.parameters.outer_query_count)
                .ok()
                .and_then(|query_count| phase_count.checked_mul(query_count))
        })
        .ok_or_else(|| "phase private leaf-salt count overflowed".to_owned())?;
    let aggregate_opening_salt_count = aggregate
        .epochs
        .iter()
        .try_fold(0_u64, |total, epoch| {
            u64::try_from(epoch.query_count)
                .ok()
                .and_then(|query_count| total.checked_add(query_count))
                .ok_or_else(|| "aggregate private leaf-salt count overflowed".to_owned())
        })?
        .checked_add(
            u64::try_from(hiding_configuration.mask_queries)
                .ok()
                .and_then(|query_count| query_count.checked_mul(2))
                .ok_or_else(|| "aggregate pad salt count overflowed".to_owned())?,
        )
        .and_then(|total| {
            u64::try_from(construction_plan.whir.final_round.query_epoch.query_count)
                .ok()
                .and_then(|query_count| total.checked_add(query_count))
        })
        .ok_or_else(|| "aggregate private leaf-salt count overflowed".to_owned())?;
    let total_salt_count = phase_opening_salt_count
        .checked_add(bound_opening_salt_count)
        .and_then(|total| total.checked_add(aggregate_opening_salt_count))
        .ok_or_else(|| "transported private leaf-salt count overflowed".to_owned())?;
    let transported_salt_byte_length = total_salt_count
        .checked_mul(
            u64::try_from(PRIVATE_LEAF_SALT_BYTE_LENGTH)
                .map_err(|_| "private leaf-salt width exceeds u64".to_owned())?,
        )
        .ok_or_else(|| "transported private leaf-salt bytes overflowed".to_owned())?;
    let retained_pad_commitment_payload_byte_length =
        materialized_single_column_commitment_payload_byte_length(pad_domain_size)?;
    let fresh_source_commitment_payload_byte_length =
        materialized_single_column_commitment_payload_byte_length(
            construction_plan.whir.final_round.encoded_oracle.leaf_count,
        )?;
    let fresh_pad_commitment_payload_byte_length =
        materialized_single_column_commitment_payload_byte_length(pad_domain_size)?;
    let base_case_commitment_payload_byte_length = retained_pad_commitment_payload_byte_length
        .checked_add(fresh_source_commitment_payload_byte_length)
        .and_then(|total| total.checked_add(fresh_pad_commitment_payload_byte_length))
        .ok_or_else(|| "base-case commitment liveness overflowed".to_owned())?;
    Ok(PrivateLeafSaltLiveness {
        phase_opening_salt_count,
        bound_opening_salt_count,
        aggregate_opening_salt_count,
        transported_salt_byte_length,
        aggregate_resident_state_byte_length: u64::try_from(
            aggregate_private_leaf_salt_resident_state_byte_length()?,
        )
        .map_err(|_| "aggregate private leaf-salt state exceeds u64".to_owned())?,
        derivation_workspace_byte_length: u64::try_from(
            private_leaf_salt_derivation_workspace_byte_length(),
        )
        .map_err(|_| "private leaf-salt workspace exceeds u64".to_owned())?,
        aggregate_row_workspace_byte_length: u64::try_from(
            aggregate_private_leaf_salt_row_workspace_byte_length(),
        )
        .map_err(|_| "aggregate private leaf-salt row workspace exceeds u64".to_owned())?,
        canonical_uniqueness_set_byte_length: u64::try_from(
            transported_private_leaf_salt_uniqueness_set_byte_length(
                usize::try_from(total_salt_count)
                    .map_err(|_| "private leaf-salt count exceeds usize".to_owned())?,
            )?,
        )
        .map_err(|_| "private leaf-salt uniqueness set exceeds u64".to_owned())?,
        retained_pad_commitment_payload_byte_length: u64::try_from(
            retained_pad_commitment_payload_byte_length,
        )
        .map_err(|_| "retained pad commitment payload exceeds u64".to_owned())?,
        base_case_commitment_payload_byte_length: u64::try_from(
            base_case_commitment_payload_byte_length,
        )
        .map_err(|_| "base-case commitment payload exceeds u64".to_owned())?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BoundTreeAuthenticationLiveness {
    tree_count: u64,
    committed_material_tree_count: u64,
    maximum_leaf_count: u64,
    maximum_row_width: u64,
    maximum_stripe_count: u64,
    maximum_dft_buffer_byte_length: u64,
    maximum_evaluated_stripe_byte_length: u64,
    maximum_leaf_workspace_byte_length: u64,
    maximum_algorithm_live_set_byte_length: u64,
    full_column_dft_count: u64,
    leaf_hash_query_count: u64,
    merkle_parent_hash_query_count: u64,
    logical_salt_delivery_count: u64,
}

impl BoundTreeAuthenticationLiveness {
    #[cfg(test)]
    pub(super) const fn tree_count(self) -> u64 {
        self.tree_count
    }

    #[cfg(test)]
    pub(super) const fn committed_material_tree_count(self) -> u64 {
        self.committed_material_tree_count
    }

    #[cfg(test)]
    pub(super) const fn maximum_leaf_count(self) -> u64 {
        self.maximum_leaf_count
    }

    #[cfg(test)]
    pub(super) const fn maximum_row_width(self) -> u64 {
        self.maximum_row_width
    }

    #[cfg(test)]
    pub(super) const fn maximum_stripe_count(self) -> u64 {
        self.maximum_stripe_count
    }

    #[cfg(test)]
    pub(super) const fn maximum_dft_buffer_byte_length(self) -> u64 {
        self.maximum_dft_buffer_byte_length
    }

    #[cfg(test)]
    pub(super) const fn maximum_evaluated_stripe_byte_length(self) -> u64 {
        self.maximum_evaluated_stripe_byte_length
    }

    #[cfg(test)]
    pub(super) const fn maximum_leaf_workspace_byte_length(self) -> u64 {
        self.maximum_leaf_workspace_byte_length
    }

    #[cfg(test)]
    pub(super) const fn maximum_algorithm_live_set_byte_length(self) -> u64 {
        self.maximum_algorithm_live_set_byte_length
    }

    #[cfg(test)]
    pub(super) const fn full_column_dft_count(self) -> u64 {
        self.full_column_dft_count
    }

    #[cfg(test)]
    pub(super) const fn leaf_hash_query_count(self) -> u64 {
        self.leaf_hash_query_count
    }

    #[cfg(test)]
    pub(super) const fn merkle_parent_hash_query_count(self) -> u64 {
        self.merkle_parent_hash_query_count
    }

    #[cfg(test)]
    pub(super) const fn logical_salt_delivery_count(self) -> u64 {
        self.logical_salt_delivery_count
    }

    #[cfg(test)]
    pub(super) const fn total_hash_query_count(self) -> Option<u64> {
        self.leaf_hash_query_count
            .checked_add(self.merkle_parent_hash_query_count)
    }
}

pub(super) fn derive_bound_tree_authentication_liveness(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<BoundTreeAuthenticationLiveness, String> {
    if construction_plan.bound_trees.is_empty() {
        return Err("bound-tree authentication has no trees".to_owned());
    }
    let mut committed_material_tree_count = 0_u64;
    let mut maximum_leaf_count = 0_u64;
    let mut maximum_row_width = 0_u64;
    let mut maximum_stripe_count = 0_u64;
    let mut maximum_dft_buffer_byte_length = 0_u64;
    let mut maximum_evaluated_stripe_byte_length = 0_u64;
    let mut maximum_leaf_workspace_byte_length = 0_u64;
    let mut maximum_algorithm_live_set_byte_length = 0_u64;
    let mut full_column_dft_count = 0_u64;
    let mut leaf_hash_query_count = 0_u64;
    let mut merkle_parent_hash_query_count = 0_u64;
    let mut logical_salt_delivery_count = 0_u64;
    for tree in &construction_plan.bound_trees {
        if tree.leaf_count == 0
            || !tree.leaf_count.is_power_of_two()
            || tree.evaluation_domain_size
                != u64::try_from(tree.leaf_count)
                    .ok()
                    .and_then(|count| count.checked_mul(2))
                    .ok_or_else(|| "bound-tree evaluation domain overflows".to_owned())?
            || tree.ordered_columns.is_empty()
            || tree
                .ordered_columns
                .iter()
                .any(|column| column.value_type != RelationColumnValueType::BaseField)
        {
            return Err("bound-tree authentication geometry is invalid".to_owned());
        }
        let leaf_count = u64::try_from(tree.leaf_count)
            .map_err(|_| "bound-tree leaf count exceeds u64".to_owned())?;
        let row_width = u64::try_from(tree.ordered_columns.len())
            .map_err(|_| "bound-tree row width exceeds u64".to_owned())?;
        let stripe_count = u64::try_from(
            tree.leaf_count
                .div_ceil(BOUND_TREE_AUTHENTICATION_STRIPE_LEAF_COUNT),
        )
        .map_err(|_| "bound-tree stripe count exceeds u64".to_owned())?;
        let evaluation_byte_length = tree
            .evaluation_domain_size
            .checked_mul(size_of::<crate::bgv::proof_suite::ProofBaseFieldElement>() as u64)
            .ok_or_else(|| "bound-tree DFT byte length overflows".to_owned())?;
        let stripe_leaf_count = u64::try_from(
            tree.leaf_count
                .min(BOUND_TREE_AUTHENTICATION_STRIPE_LEAF_COUNT),
        )
        .map_err(|_| "bound-tree stripe leaf count exceeds u64".to_owned())?;
        let stripe_byte_length = stripe_leaf_count
            .checked_mul(2)
            .and_then(|count| count.checked_mul(row_width))
            .and_then(|count| {
                count
                    .checked_mul(size_of::<crate::bgv::proof_suite::ProofBaseFieldElement>() as u64)
            })
            .ok_or_else(|| "bound-tree stripe byte length overflows".to_owned())?;
        let leaf_workspace_byte_length = row_width
            .checked_mul(2)
            .and_then(|value_count| {
                value_count.checked_mul(
                    u64::try_from(size_of::<ProofBaseFieldElement>()).ok()?
                        + u64::try_from(size_of::<ProofTreeValue>()).ok()?,
                )
            })
            .and_then(|byte_length| {
                byte_length.checked_add(
                    4_u64.checked_mul(u64::try_from(size_of::<Vec<ProofTreeValue>>()).ok()?)?,
                )
            })
            .and_then(|byte_length| {
                byte_length.checked_add(
                    if tree.construction_kind == BoundTreeConstructionKind::CommittedMaterial {
                        u64::try_from(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)
                            .ok()?
                            .checked_mul(2)?
                    } else {
                        0
                    },
                )
            })
            .and_then(|byte_length| byte_length.checked_add(MERKLE_DIGEST_BYTE_LENGTH))
            .ok_or_else(|| "bound-tree leaf workspace overflows".to_owned())?;
        let algorithm_live_byte_length = evaluation_byte_length
            .checked_add(stripe_byte_length)
            .and_then(|byte_length| byte_length.checked_add(leaf_workspace_byte_length))
            .ok_or_else(|| "bound-tree algorithm live set overflows".to_owned())?;
        if algorithm_live_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
            return Err("bound-tree algorithm live set exceeds the hard WASM bound".to_owned());
        }
        maximum_leaf_count = maximum_leaf_count.max(leaf_count);
        maximum_row_width = maximum_row_width.max(row_width);
        maximum_stripe_count = maximum_stripe_count.max(stripe_count);
        maximum_dft_buffer_byte_length = maximum_dft_buffer_byte_length.max(evaluation_byte_length);
        maximum_evaluated_stripe_byte_length =
            maximum_evaluated_stripe_byte_length.max(stripe_byte_length);
        maximum_leaf_workspace_byte_length =
            maximum_leaf_workspace_byte_length.max(leaf_workspace_byte_length);
        maximum_algorithm_live_set_byte_length =
            maximum_algorithm_live_set_byte_length.max(algorithm_live_byte_length);
        full_column_dft_count = full_column_dft_count
            .checked_add(
                stripe_count
                    .checked_mul(row_width)
                    .ok_or_else(|| "bound-tree DFT count overflows".to_owned())?,
            )
            .ok_or_else(|| "bound-tree DFT count overflows".to_owned())?;
        leaf_hash_query_count = leaf_hash_query_count
            .checked_add(leaf_count)
            .ok_or_else(|| "bound-tree leaf hash count overflows".to_owned())?;
        merkle_parent_hash_query_count = merkle_parent_hash_query_count
            .checked_add(
                leaf_count
                    .checked_sub(1)
                    .ok_or_else(|| "bound-tree parent count underflows".to_owned())?,
            )
            .ok_or_else(|| "bound-tree parent hash count overflows".to_owned())?;
        if tree.construction_kind == BoundTreeConstructionKind::CommittedMaterial {
            committed_material_tree_count = committed_material_tree_count
                .checked_add(1)
                .ok_or_else(|| "committed-material tree count overflows".to_owned())?;
            logical_salt_delivery_count = logical_salt_delivery_count
                .checked_add(leaf_count)
                .ok_or_else(|| "bound-tree salt delivery count overflows".to_owned())?;
        }
    }
    Ok(BoundTreeAuthenticationLiveness {
        tree_count: u64::try_from(construction_plan.bound_trees.len())
            .map_err(|_| "bound-tree count exceeds u64".to_owned())?,
        committed_material_tree_count,
        maximum_leaf_count,
        maximum_row_width,
        maximum_stripe_count,
        maximum_dft_buffer_byte_length,
        maximum_evaluated_stripe_byte_length,
        maximum_leaf_workspace_byte_length,
        maximum_algorithm_live_set_byte_length,
        full_column_dft_count,
        leaf_hash_query_count,
        merkle_parent_hash_query_count,
        logical_salt_delivery_count,
    })
}

const WASM_RUNTIME_BASELINE_RESERVE_BYTE_LENGTH: u64 = 32 * 1_024 * 1_024;
const ALLOCATOR_OVERHEAD_DENOMINATOR: u64 = 8;
const MERKLE_DIGEST_BYTE_LENGTH: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GenerationPhaseLivenessKind {
    LoadingAuthenticatedSources,
    SourceReplay,
    RelationMaterialization,
    PhaseCommitment,
    QuotientPreparation,
    AggregateSource,
    PrivateMaterialSampling,
    AggregateOpeningPreparation,
    AggregateCommitment,
    BoundTreeAuthentication,
    WhirOpening,
    BaseCaseOpening,
    CanonicalEncoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GenerationPhaseLivenessRow {
    phase: GenerationPhaseLivenessKind,
    wasm_runtime_baseline_byte_length: u64,
    engine_control_byte_length: u64,
    source_provider_byte_length: u64,
    replay_reader_byte_length: u64,
    dft_buffer_byte_length: u64,
    merkle_and_frontier_byte_length: u64,
    proof_encoder_non_salt_byte_length: u64,
    transported_private_leaf_salt_byte_length: u64,
    transcript_byte_length: u64,
    private_material_byte_length: u64,
    private_leaf_salt_state_byte_length: u64,
    private_leaf_salt_workspace_byte_length: u64,
    private_leaf_salt_uniqueness_set_byte_length: u64,
    bridge_copy_byte_length: u64,
    specialized_workspace_byte_length: u64,
    allocator_overhead_byte_length: u64,
    total_byte_length: u64,
}

impl GenerationPhaseLivenessRow {
    #[cfg(test)]
    pub(super) const fn phase(self) -> GenerationPhaseLivenessKind {
        self.phase
    }

    #[cfg(test)]
    pub(super) const fn wasm_runtime_baseline_byte_length(self) -> u64 {
        self.wasm_runtime_baseline_byte_length
    }

    #[cfg(test)]
    pub(super) const fn engine_control_byte_length(self) -> u64 {
        self.engine_control_byte_length
    }

    #[cfg(test)]
    pub(super) const fn source_provider_byte_length(self) -> u64 {
        self.source_provider_byte_length
    }

    #[cfg(test)]
    pub(super) const fn replay_reader_byte_length(self) -> u64 {
        self.replay_reader_byte_length
    }

    #[cfg(test)]
    pub(super) const fn dft_buffer_byte_length(self) -> u64 {
        self.dft_buffer_byte_length
    }

    #[cfg(test)]
    pub(super) const fn merkle_and_frontier_byte_length(self) -> u64 {
        self.merkle_and_frontier_byte_length
    }

    #[cfg(test)]
    pub(super) const fn proof_encoder_non_salt_byte_length(self) -> u64 {
        self.proof_encoder_non_salt_byte_length
    }

    #[cfg(test)]
    pub(super) const fn transported_private_leaf_salt_byte_length(self) -> u64 {
        self.transported_private_leaf_salt_byte_length
    }

    #[cfg(test)]
    pub(super) const fn transcript_byte_length(self) -> u64 {
        self.transcript_byte_length
    }

    #[cfg(test)]
    pub(super) const fn private_material_byte_length(self) -> u64 {
        self.private_material_byte_length
    }

    #[cfg(test)]
    pub(super) const fn private_leaf_salt_state_byte_length(self) -> u64 {
        self.private_leaf_salt_state_byte_length
    }

    #[cfg(test)]
    pub(super) const fn private_leaf_salt_workspace_byte_length(self) -> u64 {
        self.private_leaf_salt_workspace_byte_length
    }

    #[cfg(test)]
    pub(super) const fn private_leaf_salt_uniqueness_set_byte_length(self) -> u64 {
        self.private_leaf_salt_uniqueness_set_byte_length
    }

    #[cfg(test)]
    pub(super) const fn bridge_copy_byte_length(self) -> u64 {
        self.bridge_copy_byte_length
    }

    #[cfg(test)]
    pub(super) const fn specialized_workspace_byte_length(self) -> u64 {
        self.specialized_workspace_byte_length
    }

    #[cfg(test)]
    pub(super) const fn allocator_overhead_byte_length(self) -> u64 {
        self.allocator_overhead_byte_length
    }

    #[cfg(test)]
    pub(super) const fn total_byte_length(self) -> u64 {
        self.total_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PhaseCommitmentWorkAccounting {
    pub(super) geometry_count: u64,
    pub(super) materialization_pass_count: u64,
    pub(super) lane_dft_count: u64,
    pub(super) butterfly_count: u64,
    pub(super) coefficient_fold_count: u64,
    pub(super) coset_multiplication_count: u64,
    pub(super) column_value_delivery_count: u64,
    pub(super) leaf_hash_query_count: u64,
    pub(super) merkle_parent_hash_query_count: u64,
    pub(super) private_leaf_salt_derivation_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompleteGenerationLiveness {
    rows: Vec<GenerationPhaseLivenessRow>,
    maximum_live_set_byte_length: u64,
    phase_commitment_work: PhaseCommitmentWorkAccounting,
}

impl CompleteGenerationLiveness {
    #[cfg(test)]
    pub(super) fn rows(&self) -> &[GenerationPhaseLivenessRow] {
        &self.rows
    }

    pub(super) const fn maximum_live_set_byte_length(&self) -> u64 {
        self.maximum_live_set_byte_length
    }

    pub(super) fn phase_count(&self) -> usize {
        self.rows.len()
    }

    #[cfg(test)]
    pub(super) const fn phase_commitment_work(&self) -> &PhaseCommitmentWorkAccounting {
        &self.phase_commitment_work
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CompleteGenerationLivenessInput {
    pub(super) engine_control_byte_length: u64,
    pub(super) source_provider: CommonProofSourceProviderMemoryAccounting,
    pub(super) maximum_replay_reader_byte_length: u64,
    pub(super) auxiliary_materialization_byte_length: u64,
    pub(super) quotient_preparation_byte_length: u64,
    pub(super) aggregate_source_batch_byte_length: u64,
    pub(super) aggregate_source_row_byte_length: u64,
    pub(super) aggregate_opening_preparation_byte_length: u64,
    pub(super) proof_encoder_byte_length: u64,
    pub(super) transcript_byte_length: u64,
    pub(super) private_material_byte_length: u64,
    pub(super) private_material_partition_transition_byte_length: u64,
    pub(super) proof_transport_bridge_byte_length: u64,
}

pub(super) fn derive_complete_generation_liveness(
    construction_plan: &RowCodeWhirConstructionPlan,
    input: CompleteGenerationLivenessInput,
) -> Result<CompleteGenerationLiveness, String> {
    let liveness = derive_complete_generation_liveness_rows(construction_plan, input)?;
    if liveness.maximum_live_set_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
        return Err(format!(
            "complete proof-generation live set {} exceeds the hard WASM bound",
            liveness.maximum_live_set_byte_length
        ));
    }
    Ok(liveness)
}

fn derive_complete_generation_liveness_rows(
    construction_plan: &RowCodeWhirConstructionPlan,
    input: CompleteGenerationLivenessInput,
) -> Result<CompleteGenerationLiveness, String> {
    if input.engine_control_byte_length == 0
        || input
            .source_provider
            .loading_persistent_resident_byte_length()
            == 0
        || input
            .source_provider
            .post_source_polynomial_finish_persistent_resident_byte_length()
            == 0
        || input
            .source_provider
            .maximum_returned_source_polynomial_byte_length()
            == 0
        || input.maximum_replay_reader_byte_length == 0
        || input.proof_encoder_byte_length == 0
        || input.transcript_byte_length == 0
        || input.proof_transport_bridge_byte_length == 0
        || (construction_plan.proof_privacy_mode == ProofPrivacyMode::SecretBearing
            && (input.private_material_byte_length == 0
                || input.private_material_partition_transition_byte_length == 0))
    {
        return Err("complete proof-generation liveness omitted a required allocation".to_owned());
    }
    let aggregate = derive_aggregate_commitment_liveness(construction_plan)?;
    let bound = derive_bound_tree_authentication_liveness(construction_plan)?;
    let private_leaf_salt = derive_private_leaf_salt_liveness(construction_plan)?;
    let proof_encoder_non_salt_byte_length = input
        .proof_encoder_byte_length
        .checked_sub(private_leaf_salt.transported_salt_byte_length)
        .ok_or_else(|| "proof encoder is smaller than its transported private salts".to_owned())?;
    let (phase_dft_byte_length, phase_merkle_byte_length) =
        maximum_phase_commitment_algorithm_liveness(construction_plan)?;
    let phase_commitment_work = derive_phase_commitment_work_accounting(construction_plan)?;
    let common_bridge_byte_length =
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH
            .checked_add(input.proof_transport_bridge_byte_length)
            .ok_or_else(|| "proof bridge liveness overflowed".to_owned())?;
    let post_source_provider_byte_length = input
        .source_provider
        .post_source_polynomial_finish_persistent_resident_byte_length();
    let common = |phase,
                  source_provider_byte_length,
                  replay_reader_byte_length,
                  dft_buffer_byte_length,
                  merkle_and_frontier_byte_length,
                  include_proof_encoder,
                  private_leaf_salt_state_byte_length,
                  private_leaf_salt_workspace_byte_length,
                  private_leaf_salt_uniqueness_set_byte_length,
                  specialized_workspace_byte_length| {
        generation_phase_liveness_row(
            phase,
            input.engine_control_byte_length,
            source_provider_byte_length,
            replay_reader_byte_length,
            dft_buffer_byte_length,
            merkle_and_frontier_byte_length,
            if include_proof_encoder {
                proof_encoder_non_salt_byte_length
            } else {
                0
            },
            if include_proof_encoder {
                private_leaf_salt.transported_salt_byte_length
            } else {
                0
            },
            input.transcript_byte_length,
            input.private_material_byte_length,
            private_leaf_salt_state_byte_length,
            private_leaf_salt_workspace_byte_length,
            private_leaf_salt_uniqueness_set_byte_length,
            common_bridge_byte_length,
            specialized_workspace_byte_length,
        )
    };
    let loading_source_provider_byte_length = input
        .source_provider
        .loading_persistent_resident_byte_length()
        .checked_add(
            input
                .source_provider
                .additional_loading_transient_byte_length(),
        )
        .ok_or_else(|| "source loading liveness overflowed".to_owned())?;
    // Replay readers hand their owned coefficient vector to the next phase.
    // A phase-row or bound-tree DFT is constructed only after its reader is
    // removed from the state machine; aggregate and WHIR DFTs likewise consume
    // the external column vector. These rows therefore model source replay as
    // a distinct live snapshot instead of summing a dead reader allocation
    // with its successor DFT buffer.
    let mut rows = vec![
        common(
            GenerationPhaseLivenessKind::LoadingAuthenticatedSources,
            loading_source_provider_byte_length,
            input
                .source_provider
                .maximum_returned_source_polynomial_byte_length(),
            0,
            0,
            false,
            0,
            0,
            0,
            0,
        )?,
        common(
            GenerationPhaseLivenessKind::SourceReplay,
            post_source_provider_byte_length,
            input.maximum_replay_reader_byte_length,
            0,
            0,
            true,
            0,
            0,
            0,
            0,
        )?,
        common(
            GenerationPhaseLivenessKind::RelationMaterialization,
            post_source_provider_byte_length,
            input.maximum_replay_reader_byte_length,
            0,
            0,
            true,
            0,
            0,
            0,
            input.auxiliary_materialization_byte_length,
        )?,
        common(
            GenerationPhaseLivenessKind::PhaseCommitment,
            post_source_provider_byte_length,
            input.maximum_replay_reader_byte_length,
            phase_dft_byte_length,
            phase_merkle_byte_length,
            true,
            0,
            private_leaf_salt.derivation_workspace_byte_length,
            0,
            0,
        )?,
        common(
            GenerationPhaseLivenessKind::QuotientPreparation,
            post_source_provider_byte_length,
            input.maximum_replay_reader_byte_length,
            0,
            0,
            true,
            0,
            0,
            0,
            input.quotient_preparation_byte_length,
        )?,
        common(
            GenerationPhaseLivenessKind::AggregateSource,
            post_source_provider_byte_length,
            input.maximum_replay_reader_byte_length,
            0,
            0,
            true,
            0,
            0,
            0,
            input
                .aggregate_source_batch_byte_length
                .checked_add(input.aggregate_source_row_byte_length)
                .ok_or_else(|| "aggregate source liveness overflowed".to_owned())?,
        )?,
        common(
            GenerationPhaseLivenessKind::PrivateMaterialSampling,
            post_source_provider_byte_length,
            0,
            0,
            0,
            true,
            0,
            0,
            0,
            input.private_material_partition_transition_byte_length,
        )?,
        common(
            GenerationPhaseLivenessKind::AggregateOpeningPreparation,
            post_source_provider_byte_length,
            0,
            0,
            0,
            true,
            0,
            0,
            0,
            input.aggregate_opening_preparation_byte_length,
        )?,
        common(
            GenerationPhaseLivenessKind::AggregateCommitment,
            post_source_provider_byte_length,
            0,
            aggregate.maximum_dft_buffer_byte_length,
            aggregate.maximum_leaf_state_stripe_byte_length,
            true,
            private_leaf_salt.aggregate_resident_state_byte_length,
            private_leaf_salt
                .derivation_workspace_byte_length
                .checked_add(private_leaf_salt.aggregate_row_workspace_byte_length)
                .ok_or_else(|| "aggregate private salt workspace overflowed".to_owned())?,
            0,
            0,
        )?,
        common(
            GenerationPhaseLivenessKind::BoundTreeAuthentication,
            post_source_provider_byte_length,
            0,
            bound.maximum_dft_buffer_byte_length,
            bound
                .maximum_evaluated_stripe_byte_length
                .checked_add(bound.maximum_leaf_workspace_byte_length)
                .ok_or_else(|| "bound-tree Merkle workspace overflowed".to_owned())?,
            true,
            0,
            0,
            0,
            0,
        )?,
        common(
            GenerationPhaseLivenessKind::WhirOpening,
            0,
            0,
            aggregate.maximum_dft_buffer_byte_length,
            aggregate.maximum_leaf_state_stripe_byte_length,
            true,
            private_leaf_salt.aggregate_resident_state_byte_length,
            private_leaf_salt
                .derivation_workspace_byte_length
                .checked_add(private_leaf_salt.aggregate_row_workspace_byte_length)
                .ok_or_else(|| "WHIR private salt workspace overflowed".to_owned())?,
            0,
            private_leaf_salt.retained_pad_commitment_payload_byte_length,
        )?,
        common(
            GenerationPhaseLivenessKind::BaseCaseOpening,
            0,
            0,
            u64::try_from(
                aggregate
                    .epochs
                    .last()
                    .ok_or_else(|| "aggregate liveness has no final epoch".to_owned())?
                    .leaf_count,
            )
            .ok()
            .and_then(|leaf_count| {
                leaf_count.checked_mul(u64::try_from(size_of::<ChallengeField>()).ok()?)
            })
            .ok_or_else(|| "base-case DFT liveness overflowed".to_owned())?,
            u64::try_from(
                aggregate
                    .epochs
                    .last()
                    .ok_or_else(|| "aggregate liveness has no final epoch".to_owned())?
                    .leaf_count,
            )
            .ok()
            .and_then(|leaf_count| {
                leaf_count.checked_mul(u64::try_from(size_of::<ColumnStreamableLeafState>()).ok()?)
            })
            .ok_or_else(|| "base-case leaf-state liveness overflowed".to_owned())?,
            true,
            private_leaf_salt.aggregate_resident_state_byte_length,
            private_leaf_salt
                .derivation_workspace_byte_length
                .checked_add(private_leaf_salt.aggregate_row_workspace_byte_length)
                .ok_or_else(|| "base-case private salt workspace overflowed".to_owned())?,
            0,
            private_leaf_salt.base_case_commitment_payload_byte_length,
        )?,
        common(
            GenerationPhaseLivenessKind::CanonicalEncoding,
            0,
            0,
            0,
            0,
            true,
            0,
            0,
            private_leaf_salt.canonical_uniqueness_set_byte_length,
            0,
        )?,
    ];
    let maximum_live_set_byte_length = rows
        .iter()
        .map(|row| row.total_byte_length)
        .max()
        .ok_or_else(|| "proof generation has no liveness rows".to_owned())?;
    rows.shrink_to_fit();
    Ok(CompleteGenerationLiveness {
        rows,
        maximum_live_set_byte_length,
        phase_commitment_work,
    })
}

#[allow(clippy::too_many_arguments)]
fn generation_phase_liveness_row(
    phase: GenerationPhaseLivenessKind,
    engine_control_byte_length: u64,
    source_provider_byte_length: u64,
    replay_reader_byte_length: u64,
    dft_buffer_byte_length: u64,
    merkle_and_frontier_byte_length: u64,
    proof_encoder_non_salt_byte_length: u64,
    transported_private_leaf_salt_byte_length: u64,
    transcript_byte_length: u64,
    private_material_byte_length: u64,
    private_leaf_salt_state_byte_length: u64,
    private_leaf_salt_workspace_byte_length: u64,
    private_leaf_salt_uniqueness_set_byte_length: u64,
    bridge_copy_byte_length: u64,
    specialized_workspace_byte_length: u64,
) -> Result<GenerationPhaseLivenessRow, String> {
    let allocator_owned_byte_length = [
        engine_control_byte_length,
        source_provider_byte_length,
        replay_reader_byte_length,
        dft_buffer_byte_length,
        merkle_and_frontier_byte_length,
        proof_encoder_non_salt_byte_length,
        transported_private_leaf_salt_byte_length,
        transcript_byte_length,
        private_material_byte_length,
        private_leaf_salt_state_byte_length,
        private_leaf_salt_workspace_byte_length,
        private_leaf_salt_uniqueness_set_byte_length,
        bridge_copy_byte_length,
        specialized_workspace_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or_else(|| "proof phase liveness overflowed".to_owned())
    })?;
    let allocator_overhead_byte_length =
        allocator_owned_byte_length.div_ceil(ALLOCATOR_OVERHEAD_DENOMINATOR);
    let total_byte_length = WASM_RUNTIME_BASELINE_RESERVE_BYTE_LENGTH
        .checked_add(allocator_owned_byte_length)
        .and_then(|total| total.checked_add(allocator_overhead_byte_length))
        .ok_or_else(|| "complete proof phase liveness overflowed".to_owned())?;
    Ok(GenerationPhaseLivenessRow {
        phase,
        wasm_runtime_baseline_byte_length: WASM_RUNTIME_BASELINE_RESERVE_BYTE_LENGTH,
        engine_control_byte_length,
        source_provider_byte_length,
        replay_reader_byte_length,
        dft_buffer_byte_length,
        merkle_and_frontier_byte_length,
        proof_encoder_non_salt_byte_length,
        transported_private_leaf_salt_byte_length,
        transcript_byte_length,
        private_material_byte_length,
        private_leaf_salt_state_byte_length,
        private_leaf_salt_workspace_byte_length,
        private_leaf_salt_uniqueness_set_byte_length,
        bridge_copy_byte_length,
        specialized_workspace_byte_length,
        allocator_overhead_byte_length,
        total_byte_length,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PhaseCommitmentGeometryAccounting {
    pub(super) row_count: u64,
    pub(super) encoded_column_count: u64,
    pub(super) lane_column_count: u64,
    pub(super) lane_count: u64,
    pub(super) working_buffer_byte_length: u64,
    pub(super) hash_state_byte_length: u64,
    pub(super) digest_plane_byte_length: u64,
    pub(super) algorithm_live_set_byte_length: u64,
    pub(super) lane_dft_count_per_pass: u64,
    pub(super) butterfly_count_per_pass: u64,
    pub(super) coefficient_fold_count_per_pass: u64,
    pub(super) coset_multiplication_count_per_pass: u64,
    pub(super) column_value_delivery_count_per_pass: u64,
    pub(super) leaf_hash_query_count_per_pass: u64,
    pub(super) merkle_parent_hash_query_count_per_pass: u64,
}

pub(super) fn derive_phase_commitment_geometry_accounting(
    geometry: RowEncodingGeometry,
) -> Result<PhaseCommitmentGeometryAccounting, String> {
    let encoded_column_count = geometry.encoded_column_count;
    let lane_column_count = encoded_column_count
        .min(super::generation_state::MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT);
    if geometry.row_count == 0
        || lane_column_count < 2
        || !lane_column_count.is_power_of_two()
        || !encoded_column_count.is_multiple_of(lane_column_count)
        || geometry.padded_coefficient_count > encoded_column_count
    {
        return Err("phase commitment lane geometry is invalid".to_owned());
    }
    let lane_count = encoded_column_count / lane_column_count;
    let lane_tree_depth = u64::from(lane_count.ilog2());
    let working_capacity = geometry.padded_coefficient_count.max(lane_column_count);
    let hash_state_byte_length = u64::try_from(
        StreamingColumnHasher::exact_state_byte_length(lane_column_count)
            .ok_or_else(|| "phase hash-state liveness overflowed".to_owned())?,
    )
    .map_err(|_| "phase hash-state liveness exceeds u64".to_owned())?;
    let row_count =
        u64::try_from(geometry.row_count).map_err(|_| "phase row count exceeds u64".to_owned())?;
    let encoded_column_count = u64::try_from(encoded_column_count)
        .map_err(|_| "phase encoded column count exceeds u64".to_owned())?;
    let lane_column_count = u64::try_from(lane_column_count)
        .map_err(|_| "phase lane column count exceeds u64".to_owned())?;
    let lane_count =
        u64::try_from(lane_count).map_err(|_| "phase lane count exceeds u64".to_owned())?;
    let working_buffer_byte_length = u64::try_from(working_capacity)
        .ok()
        .and_then(|count| count.checked_mul(size_of::<ProofBaseFieldElement>() as u64))
        .ok_or_else(|| "phase working-buffer liveness overflowed".to_owned())?;
    let digest_plane_byte_length = lane_column_count
        .checked_mul(lane_tree_depth)
        .and_then(|digest_count| digest_count.checked_mul(MERKLE_DIGEST_BYTE_LENGTH))
        .ok_or_else(|| "phase digest-plane liveness overflowed".to_owned())?;
    let algorithm_live_set_byte_length = working_buffer_byte_length
        .checked_add(hash_state_byte_length)
        .and_then(|total| total.checked_add(digest_plane_byte_length))
        .ok_or_else(|| "phase algorithm live set overflowed".to_owned())?;
    let lane_dft_count_per_pass = row_count
        .checked_mul(lane_count)
        .ok_or_else(|| "phase lane DFT count overflowed".to_owned())?;
    let butterfly_count_per_dft = lane_column_count
        .checked_div(2)
        .and_then(|count| count.checked_mul(u64::from(lane_column_count.ilog2())))
        .ok_or_else(|| "phase butterfly count overflowed".to_owned())?;
    let butterfly_count_per_pass = lane_dft_count_per_pass
        .checked_mul(butterfly_count_per_dft)
        .ok_or_else(|| "phase butterfly count overflowed".to_owned())?;
    let folded_coefficient_count_per_dft = geometry.padded_coefficient_count.saturating_sub(
        usize::try_from(lane_column_count)
            .map_err(|_| "phase lane column count exceeds usize".to_owned())?,
    );
    let coefficient_fold_count_per_pass = lane_dft_count_per_pass
        .checked_mul(
            u64::try_from(folded_coefficient_count_per_dft)
                .map_err(|_| "phase coefficient-fold count exceeds u64".to_owned())?,
        )
        .ok_or_else(|| "phase coefficient-fold count overflowed".to_owned())?;
    let coset_multiplication_count_per_pass = lane_dft_count_per_pass
        .checked_mul(lane_column_count)
        .ok_or_else(|| "phase coset multiplication count overflowed".to_owned())?;
    let column_value_delivery_count_per_pass = row_count
        .checked_mul(encoded_column_count)
        .ok_or_else(|| "phase value-delivery count overflowed".to_owned())?;
    Ok(PhaseCommitmentGeometryAccounting {
        row_count,
        encoded_column_count,
        lane_column_count,
        lane_count,
        working_buffer_byte_length,
        hash_state_byte_length,
        digest_plane_byte_length,
        algorithm_live_set_byte_length,
        lane_dft_count_per_pass,
        butterfly_count_per_pass,
        coefficient_fold_count_per_pass,
        coset_multiplication_count_per_pass,
        column_value_delivery_count_per_pass,
        leaf_hash_query_count_per_pass: encoded_column_count,
        merkle_parent_hash_query_count_per_pass: encoded_column_count - 1,
    })
}

pub(super) fn derive_phase_commitment_work_accounting(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<PhaseCommitmentWorkAccounting, String> {
    let geometries = construction_plan
        .base_phase
        .iter()
        .chain(construction_plan.auxiliary_phase.iter())
        .map(|phase| phase.geometry)
        .chain(core::iter::once(construction_plan.quotient_phase.geometry));
    let mut geometry_count = 0_u64;
    let mut lane_dft_count_per_pass = 0_u64;
    let mut butterfly_count_per_pass = 0_u64;
    let mut coefficient_fold_count_per_pass = 0_u64;
    let mut coset_multiplication_count_per_pass = 0_u64;
    let mut column_value_delivery_count_per_pass = 0_u64;
    let mut leaf_hash_query_count_per_pass = 0_u64;
    let mut merkle_parent_hash_query_count_per_pass = 0_u64;
    for geometry in geometries {
        let accounting = derive_phase_commitment_geometry_accounting(geometry)?;
        if accounting.lane_dft_count_per_pass
            != accounting
                .row_count
                .checked_mul(accounting.lane_count)
                .ok_or_else(|| "phase lane DFT identity overflowed".to_owned())?
            || accounting.column_value_delivery_count_per_pass
                != accounting
                    .row_count
                    .checked_mul(accounting.encoded_column_count)
                    .ok_or_else(|| "phase value-delivery identity overflowed".to_owned())?
            || accounting.coset_multiplication_count_per_pass
                != accounting
                    .lane_dft_count_per_pass
                    .checked_mul(accounting.lane_column_count)
                    .ok_or_else(|| "phase coset-work identity overflowed".to_owned())?
        {
            return Err("phase commitment work identities are inconsistent".to_owned());
        }
        geometry_count = geometry_count
            .checked_add(1)
            .ok_or_else(|| "phase geometry count overflowed".to_owned())?;
        lane_dft_count_per_pass = lane_dft_count_per_pass
            .checked_add(accounting.lane_dft_count_per_pass)
            .ok_or_else(|| "phase lane DFT count overflowed".to_owned())?;
        butterfly_count_per_pass = butterfly_count_per_pass
            .checked_add(accounting.butterfly_count_per_pass)
            .ok_or_else(|| "phase butterfly count overflowed".to_owned())?;
        coefficient_fold_count_per_pass = coefficient_fold_count_per_pass
            .checked_add(accounting.coefficient_fold_count_per_pass)
            .ok_or_else(|| "phase coefficient-fold count overflowed".to_owned())?;
        coset_multiplication_count_per_pass = coset_multiplication_count_per_pass
            .checked_add(accounting.coset_multiplication_count_per_pass)
            .ok_or_else(|| "phase coset multiplication count overflowed".to_owned())?;
        column_value_delivery_count_per_pass = column_value_delivery_count_per_pass
            .checked_add(accounting.column_value_delivery_count_per_pass)
            .ok_or_else(|| "phase value-delivery count overflowed".to_owned())?;
        leaf_hash_query_count_per_pass = leaf_hash_query_count_per_pass
            .checked_add(accounting.leaf_hash_query_count_per_pass)
            .ok_or_else(|| "phase leaf-hash count overflowed".to_owned())?;
        merkle_parent_hash_query_count_per_pass = merkle_parent_hash_query_count_per_pass
            .checked_add(accounting.merkle_parent_hash_query_count_per_pass)
            .ok_or_else(|| "phase parent-hash count overflowed".to_owned())?;
    }
    let scale = |count: u64, role: &str| {
        count
            .checked_mul(ROOT_AND_OPENING_PASS_COUNT)
            .ok_or_else(|| format!("phase {role} count overflowed"))
    };
    let leaf_hash_query_count = scale(leaf_hash_query_count_per_pass, "leaf-hash")?;
    Ok(PhaseCommitmentWorkAccounting {
        geometry_count,
        materialization_pass_count: ROOT_AND_OPENING_PASS_COUNT,
        lane_dft_count: scale(lane_dft_count_per_pass, "lane DFT")?,
        butterfly_count: scale(butterfly_count_per_pass, "butterfly")?,
        coefficient_fold_count: scale(coefficient_fold_count_per_pass, "coefficient-fold")?,
        coset_multiplication_count: scale(
            coset_multiplication_count_per_pass,
            "coset multiplication",
        )?,
        column_value_delivery_count: scale(column_value_delivery_count_per_pass, "value-delivery")?,
        leaf_hash_query_count,
        merkle_parent_hash_query_count: scale(
            merkle_parent_hash_query_count_per_pass,
            "parent-hash",
        )?,
        private_leaf_salt_derivation_count: if construction_plan.proof_privacy_mode
            == ProofPrivacyMode::SecretBearing
        {
            leaf_hash_query_count
        } else {
            0
        },
    })
}

fn maximum_phase_commitment_algorithm_liveness(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<(u64, u64), String> {
    let trace_geometries = construction_plan
        .base_phase
        .iter()
        .chain(construction_plan.auxiliary_phase.iter())
        .map(|phase| phase.geometry);
    let geometries =
        trace_geometries.chain(core::iter::once(construction_plan.quotient_phase.geometry));
    let mut maximum_dft_byte_length = 0_u64;
    let mut maximum_merkle_byte_length = 0_u64;
    for geometry in geometries {
        let encoded_column_count = geometry.encoded_column_count;
        let accounting = derive_phase_commitment_geometry_accounting(geometry)?;
        let dft_byte_length = accounting.working_buffer_byte_length;
        let hash_state_byte_length = accounting.hash_state_byte_length;
        let digest_plane_byte_length = accounting.digest_plane_byte_length;
        if accounting.algorithm_live_set_byte_length
            != dft_byte_length
                .checked_add(hash_state_byte_length)
                .and_then(|total| total.checked_add(digest_plane_byte_length))
                .ok_or_else(|| "phase algorithm live-set identity overflowed".to_owned())?
        {
            return Err("phase algorithm live-set identity is inconsistent".to_owned());
        }
        let opening_value_byte_length = u64::try_from(
            construction_plan
                .parameters
                .outer_query_count
                .checked_mul(
                    geometry
                        .row_count
                        .checked_mul(size_of::<ProofBaseFieldElement>())
                        .and_then(|byte_length| {
                            byte_length.checked_add(
                                usize::from(
                                    construction_plan.proof_privacy_mode
                                        == ProofPrivacyMode::SecretBearing,
                                ) * PRIVATE_LEAF_SALT_BYTE_LENGTH,
                            )
                        })
                        .ok_or_else(|| "phase opening row liveness overflowed".to_owned())?,
                )
                .ok_or_else(|| "phase opening liveness overflowed".to_owned())?,
        )
        .map_err(|_| "phase opening liveness exceeds u64".to_owned())?;
        let frontier_node_count = maximum_minimal_frontier_node_count(
            encoded_column_count,
            construction_plan.parameters.outer_query_count,
        )
        .map_err(|_| "phase frontier liveness geometry is invalid".to_owned())?;
        let lane_column_count = encoded_column_count
            .min(super::generation_state::MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT);
        let upper_frontier_node_count = maximum_minimal_frontier_node_count(
            lane_column_count,
            construction_plan
                .parameters
                .outer_query_count
                .min(lane_column_count),
        )
        .map_err(|_| "phase upper-frontier liveness geometry is invalid".to_owned())?;
        let commitment_metadata_byte_length =
            u64::try_from(maximum_interleaved_commitment_metadata_byte_length(
                encoded_column_count,
                super::generation_state::MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT,
                construction_plan.parameters.outer_query_count,
                construction_plan
                    .parameters
                    .outer_query_count
                    .min(lane_column_count),
                frontier_node_count,
                upper_frontier_node_count,
            )?)
            .map_err(|_| "phase commitment metadata liveness exceeds u64".to_owned())?;
        let merkle_byte_length = hash_state_byte_length
            .checked_add(digest_plane_byte_length)
            .and_then(|count| count.checked_add(opening_value_byte_length))
            .and_then(|count| count.checked_add(commitment_metadata_byte_length))
            .ok_or_else(|| "phase Merkle liveness overflowed".to_owned())?;
        maximum_dft_byte_length = maximum_dft_byte_length.max(dft_byte_length);
        maximum_merkle_byte_length = maximum_merkle_byte_length.max(merkle_byte_length);
    }
    Ok((maximum_dft_byte_length, maximum_merkle_byte_length))
}

pub(super) fn noncompact_aggregate_opening_path_byte_length(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<u64, String> {
    construction_plan
        .whir_plan()
        .rounds
        .iter()
        .map(|round| (round.encoded_oracle, round.query_epoch))
        .chain(core::iter::once((
            construction_plan.whir_plan().final_round.encoded_oracle,
            construction_plan.whir_plan().final_round.query_epoch,
        )))
        .try_fold(0_u64, |total, (oracle, epoch)| {
            u64::try_from(epoch.query_count)
                .ok()
                .and_then(|query_count| {
                    query_count.checked_mul(u64::from(oracle.leaf_count.ilog2()))
                })
                .and_then(|node_count| node_count.checked_mul(MERKLE_DIGEST_BYTE_LENGTH))
                .and_then(|byte_length| total.checked_add(byte_length))
                .ok_or_else(|| "aggregate opening path liveness overflowed".to_owned())
        })
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::One;

    use super::super::canonical_row_code_whir_family_body_byte_length_ceiling;
    use super::*;
    use crate::bgv::proof_suite::{
        AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, ValidatedRelationPlanArtifact,
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
            402_654_216,
        );
        assert!(
            accounting.maximum_algorithm_live_set_byte_length()
                <= AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        );
        assert_eq!(accounting.full_column_dft_count(), 272);
        assert_eq!(accounting.initial_hash_query_count(), 33_030_144);
        assert_eq!(accounting.private_leaf_salt_derivation_count(), 33_030_144);
        assert_eq!(accounting.transition_hash_query_count(), 264_241_152);
        assert_eq!(accounting.final_hash_query_count(), 33_030_144);
        assert_eq!(accounting.merkle_parent_hash_query_count(), 33_030_132);
        assert_eq!(
            accounting
                .aggregate_hash_query_count()
                .expect("the hash count adds"),
            363_331_572,
        );
        assert_eq!(
            accounting
                .aggregate_hash_query_count()
                .expect("the hash count adds")
                + DIRECT_SINGLE_COLUMN_COMMITMENT_HASH_QUERY_COUNT,
            364_445_681,
        );
        assert_eq!(
            selected_same_secret_proof_byte_length(&plan, &validated),
            5_814_554
        );
    }

    #[test]
    fn selected_private_leaf_salt_liveness_covers_every_transport_and_resident_owner() {
        let (plan, _) = selected_same_secret_construction();
        let accounting =
            derive_private_leaf_salt_liveness(&plan).expect("private salt liveness derives");
        assert_eq!(accounting.phase_opening_salt_count, 1_161);
        assert_eq!(accounting.bound_opening_salt_count, 320);
        assert_eq!(accounting.aggregate_opening_salt_count, 2_782);
        assert_eq!(accounting.transported_salt_byte_length, 545_664);
        assert_eq!(accounting.aggregate_resident_state_byte_length, 56);
        assert_eq!(accounting.derivation_workspace_byte_length, 392);
        assert_eq!(accounting.aggregate_row_workspace_byte_length, 584);
        assert_eq!(accounting.canonical_uniqueness_set_byte_length, 750_312);
        assert_eq!(
            accounting.retained_pad_commitment_payload_byte_length,
            1_376_720,
        );
        assert_eq!(
            accounting.base_case_commitment_payload_byte_length,
            46_794_256,
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
        assert_eq!(column_separated_proof_byte_length, 15_502_274);

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

    #[test]
    fn selected_bound_tree_stripes_derive_the_complete_lower_bound_work() {
        let (plan, _) = selected_same_secret_construction();
        let accounting = derive_bound_tree_authentication_liveness(&plan)
            .expect("the bound-tree liveness accounting derives");

        assert_eq!(accounting.tree_count(), 11);
        assert_eq!(accounting.committed_material_tree_count(), 8);
        assert_eq!(accounting.maximum_leaf_count(), 8_388_608);
        assert_eq!(accounting.maximum_row_width(), 4);
        assert_eq!(accounting.maximum_stripe_count(), 8);
        assert_eq!(accounting.maximum_dft_buffer_byte_length(), 134_217_728);
        assert_eq!(
            accounting.maximum_evaluated_stripe_byte_length(),
            67_108_864
        );
        assert_eq!(
            accounting.maximum_algorithm_live_set_byte_length(),
            201_327_136
        );
        assert_eq!(accounting.maximum_leaf_workspace_byte_length(), 544);
        assert_eq!(accounting.full_column_dft_count(), 352);
        assert_eq!(accounting.leaf_hash_query_count(), 92_274_688);
        assert_eq!(accounting.merkle_parent_hash_query_count(), 92_274_677);
        assert_eq!(
            accounting
                .total_hash_query_count()
                .expect("the bound-tree hash count adds"),
            184_549_365,
        );
        assert_eq!(accounting.logical_salt_delivery_count(), 67_108_864);
    }

    fn minimal_complete_generation_liveness_input() -> CompleteGenerationLivenessInput {
        CompleteGenerationLivenessInput {
            engine_control_byte_length: 1,
            source_provider: CommonProofSourceProviderMemoryAccounting::new(1, 1, 0, 1),
            maximum_replay_reader_byte_length: 1,
            auxiliary_materialization_byte_length: 0,
            quotient_preparation_byte_length: 0,
            aggregate_source_batch_byte_length: 0,
            aggregate_source_row_byte_length: 0,
            aggregate_opening_preparation_byte_length: 0,
            proof_encoder_byte_length: 1_000_000,
            transcript_byte_length: 1,
            private_material_byte_length: 1,
            private_material_partition_transition_byte_length: 1,
            proof_transport_bridge_byte_length: 1,
        }
    }

    #[test]
    fn complete_generation_liveness_refuses_an_omitted_required_allocation() {
        let (plan, _) = selected_same_secret_construction();
        let mut input = minimal_complete_generation_liveness_input();
        input.engine_control_byte_length = 0;
        assert_eq!(
            derive_complete_generation_liveness(&plan, input),
            Err("complete proof-generation liveness omitted a required allocation".to_owned(),),
        );

        let mut input = minimal_complete_generation_liveness_input();
        input.source_provider = CommonProofSourceProviderMemoryAccounting::new(0, 0, 0, 0);
        assert_eq!(
            derive_complete_generation_liveness(&plan, input),
            Err("complete proof-generation liveness omitted a required allocation".to_owned(),),
        );
    }

    #[test]
    fn complete_generation_liveness_refuses_a_whole_phase_over_the_hard_bound() {
        let (plan, _) = selected_same_secret_construction();
        let mut input = minimal_complete_generation_liveness_input();
        input.engine_control_byte_length = MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH;
        assert!(
            derive_complete_generation_liveness(&plan, input)
                .is_err_and(|error| error.contains("exceeds the hard WASM bound")),
        );
    }
}
