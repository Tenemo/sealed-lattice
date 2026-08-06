//! Bounded external-tree lifecycle alternatives for response commitments.
//!
//! A response tree is committed before the verifier move with the same
//! ordinal, but its proper-subset components may be queried by later moves.
//! The complete retained-tree plan keeps every sealed postorder object through
//! its last verifier-owned query source, scans it once, and then deletes it.
//! The catalog also measures a root-only plus response-recomputation
//! alternative. That alternative is not selectable yet because the root-only
//! driver, authenticated leaf-salt replay, and response-value replay are not
//! implemented.

use super::response_commitment::{PackingResponseCommitmentCatalog, ResponseTreeGeometry};
use super::{CompactStaticCatalogError, MERKLE_DIGEST_BYTE_LENGTH, checked_add, checked_product};
use crate::bgv::proof_suite::compact_response_merkle::{
    COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH, CompactResponseMerkleGeometry,
};
use crate::bgv::proof_suite::compact_response_tree_external::CompactResponseTreeExternalMemoryGeometry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResponseTreeRetentionInterval {
    response_ordinal: u32,
    last_query_verifier_move_ordinal: u32,
    tree_byte_length: u64,
    tree_chunk_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PackingResponseRecomputationAlternative {
    response_recomputation_pass_count: u64,
    additional_leaf_hash_count: u64,
    additional_parent_hash_count: u64,
    maximum_external_tree_storage_byte_length: u64,
    root_only_commitment_driver_is_implemented: bool,
    authenticated_leaf_salt_replay_is_implemented: bool,
    response_value_replay_is_implemented: bool,
}

impl PackingResponseRecomputationAlternative {
    const fn missing_implementation_owner_count(&self) -> u64 {
        (!self.root_only_commitment_driver_is_implemented as u64)
            + (!self.authenticated_leaf_salt_replay_is_implemented as u64)
            + (!self.response_value_replay_is_implemented as u64)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingResponseCommitmentLifecycle {
    response_count: u64,
    commitment_pass_count: u64,
    frontier_scan_count: u64,
    commitment_leaf_hash_count: u64,
    commitment_parent_hash_count: u64,
    full_tree_digest_count: u64,
    total_tree_write_byte_length: u64,
    total_tree_read_byte_length: u64,
    tree_write_transaction_count: u64,
    tree_read_transaction_count: u64,
    tree_create_transaction_count: u64,
    tree_seal_transaction_count: u64,
    tree_delete_transaction_count: u64,
    total_tree_transaction_count: u64,
    maximum_tree_storage_byte_length: u64,
    maximum_tree_storage_chunk_count: u64,
    maximum_uninterrupted_tree_digest_transfer_count: u64,
    maximum_uninterrupted_tree_digest_transfer_byte_length: u64,
    maximum_simultaneously_retained_tree_count: u64,
    distinct_tree_deletion_move_count: u64,
    maximum_tree_delete_count_after_one_verifier_move: u64,
    retention_intervals: Vec<ResponseTreeRetentionInterval>,
    authenticated_restart_record_count: u64,
    maximum_full_attempt_replay_count: u64,
    recomputation_alternative: PackingResponseRecomputationAlternative,
}

impl PackingResponseCommitmentLifecycle {
    pub(super) fn derive(
        response_commitments: &PackingResponseCommitmentCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let response_geometries = response_commitments.response_tree_geometries()?;
        let merkle_geometries = response_commitments.production_merkle_geometries()?;
        let lifecycle = derive_from_response_geometries(&response_geometries, &merkle_geometries)?;
        lifecycle.check(response_commitments)?;
        Ok(lifecycle)
    }

    pub(super) const fn maximum_tree_storage_byte_length(&self) -> u64 {
        self.maximum_tree_storage_byte_length
    }

    fn check(
        &self,
        response_commitments: &PackingResponseCommitmentCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected = derive_from_response_geometries(
            &response_commitments.response_tree_geometries()?,
            &response_commitments.production_merkle_geometries()?,
        )?;
        if self != &expected
            || self.response_count != response_commitments.bcs_response_root_count()
            || self.commitment_leaf_hash_count != response_commitments.committed_leaf_count()
            || self.commitment_parent_hash_count
                != response_commitments.commitment_parent_hash_count()
            || self.commitment_pass_count != self.response_count
            || self.frontier_scan_count != self.response_count
            || self.total_tree_write_byte_length != self.total_tree_read_byte_length
            || self.tree_write_transaction_count != self.tree_read_transaction_count
            || self.tree_create_transaction_count != self.response_count
            || self.tree_seal_transaction_count != self.response_count
            || self.tree_delete_transaction_count != self.response_count
            || self.total_tree_transaction_count
                != checked_add(
                    checked_add(
                        self.tree_write_transaction_count,
                        self.tree_read_transaction_count,
                    )?,
                    checked_product(&[self.response_count, 3])?,
                )?
            || self.maximum_tree_storage_byte_length == 0
            || self.maximum_tree_storage_chunk_count == 0
            || self.maximum_uninterrupted_tree_digest_transfer_byte_length
                != u64::try_from(COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
            || self.maximum_simultaneously_retained_tree_count == 0
            || self.distinct_tree_deletion_move_count == 0
            || self.maximum_tree_delete_count_after_one_verifier_move == 0
            || u64::try_from(self.retention_intervals.len()).ok() != Some(self.response_count)
            || self.authenticated_restart_record_count != 0
            || self.maximum_full_attempt_replay_count != 1
            || self
                .recomputation_alternative
                .missing_implementation_owner_count()
                != 3
            || self
                .recomputation_alternative
                .maximum_external_tree_storage_byte_length
                != 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }
}

fn derive_from_response_geometries(
    response_geometries: &[ResponseTreeGeometry],
    merkle_geometries: &[CompactResponseMerkleGeometry],
) -> Result<PackingResponseCommitmentLifecycle, CompactStaticCatalogError> {
    if response_geometries.is_empty() || response_geometries.len() != merkle_geometries.len() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let response_count = u64::try_from(response_geometries.len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let response_tree_storage_chunk_byte_length =
        u64::try_from(COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let maximum_uninterrupted_tree_digest_transfer_count = response_tree_storage_chunk_byte_length
        .checked_div(MERKLE_DIGEST_BYTE_LENGTH)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if maximum_uninterrupted_tree_digest_transfer_count == 0
        || response_tree_storage_chunk_byte_length % MERKLE_DIGEST_BYTE_LENGTH != 0
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    let mut commitment_leaf_hash_count = 0_u64;
    let mut commitment_parent_hash_count = 0_u64;
    let mut full_tree_digest_count = 0_u64;
    let mut total_tree_write_byte_length = 0_u64;
    let mut tree_write_transaction_count = 0_u64;
    let mut retention_intervals = Vec::new();
    retention_intervals
        .try_reserve_exact(response_geometries.len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;

    let mut response_recomputation_pass_count = 0_u64;
    let mut additional_leaf_hash_count = 0_u64;
    let mut additional_parent_hash_count = 0_u64;
    for (response_index, (response, merkle_geometry)) in response_geometries
        .iter()
        .zip(merkle_geometries)
        .enumerate()
    {
        if usize::try_from(response.ordinal).ok() != Some(response_index)
            || merkle_geometry.response_ordinal() != response.ordinal
            || response.merkle_leaf_count == 0
            || !response.merkle_leaf_count.is_power_of_two()
            || response.queried_leaf_count == 0
            || response.queried_leaf_count > response.merkle_leaf_count
            || response.maximum_frontier_node_count >= response.merkle_leaf_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let last_query_verifier_move_ordinal = merkle_geometry.last_query_verifier_move_ordinal();
        if last_query_verifier_move_ordinal < response.ordinal
            || u64::from(last_query_verifier_move_ordinal) >= response_count
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let response_parent_hash_count = response
            .merkle_leaf_count
            .checked_sub(1)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        let response_tree_digest_count =
            checked_add(response.merkle_leaf_count, response_parent_hash_count)?;
        let response_tree_byte_length =
            checked_product(&[response_tree_digest_count, MERKLE_DIGEST_BYTE_LENGTH])?;
        let response_tree_chunk_count =
            response_tree_byte_length.div_ceil(response_tree_storage_chunk_byte_length);
        let external_memory_geometry =
            CompactResponseTreeExternalMemoryGeometry::derive(merkle_geometry)
                .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
        if external_memory_geometry.tree_byte_length() != response_tree_byte_length
            || external_memory_geometry.tree_chunk_count() != response_tree_chunk_count
            || external_memory_geometry.transaction_count()
                != checked_add(checked_product(&[response_tree_chunk_count, 2])?, 3)?
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        commitment_leaf_hash_count =
            checked_add(commitment_leaf_hash_count, response.merkle_leaf_count)?;
        commitment_parent_hash_count =
            checked_add(commitment_parent_hash_count, response_parent_hash_count)?;
        full_tree_digest_count = checked_add(full_tree_digest_count, response_tree_digest_count)?;
        total_tree_write_byte_length =
            checked_add(total_tree_write_byte_length, response_tree_byte_length)?;
        tree_write_transaction_count =
            checked_add(tree_write_transaction_count, response_tree_chunk_count)?;
        retention_intervals.push(ResponseTreeRetentionInterval {
            response_ordinal: response.ordinal,
            last_query_verifier_move_ordinal,
            tree_byte_length: response_tree_byte_length,
            tree_chunk_count: response_tree_chunk_count,
        });

        if merkle_geometry.has_verifier_message_queries() {
            response_recomputation_pass_count = checked_add(response_recomputation_pass_count, 1)?;
            additional_leaf_hash_count =
                checked_add(additional_leaf_hash_count, response.merkle_leaf_count)?;
            additional_parent_hash_count =
                checked_add(additional_parent_hash_count, response_parent_hash_count)?;
        }
    }

    let mut live_intervals = Vec::<ResponseTreeRetentionInterval>::new();
    let mut current_tree_storage_byte_length = 0_u64;
    let mut current_tree_storage_chunk_count = 0_u64;
    let mut maximum_tree_storage_byte_length = 0_u64;
    let mut maximum_tree_storage_chunk_count = 0_u64;
    let mut maximum_simultaneously_retained_tree_count = 0_u64;
    let mut distinct_tree_deletion_move_count = 0_u64;
    let mut maximum_tree_delete_count_after_one_verifier_move = 0_u64;

    for interval in &retention_intervals {
        current_tree_storage_byte_length =
            checked_add(current_tree_storage_byte_length, interval.tree_byte_length)?;
        current_tree_storage_chunk_count =
            checked_add(current_tree_storage_chunk_count, interval.tree_chunk_count)?;
        live_intervals.push(*interval);
        maximum_tree_storage_byte_length =
            maximum_tree_storage_byte_length.max(current_tree_storage_byte_length);
        maximum_tree_storage_chunk_count =
            maximum_tree_storage_chunk_count.max(current_tree_storage_chunk_count);
        maximum_simultaneously_retained_tree_count = maximum_simultaneously_retained_tree_count
            .max(
                u64::try_from(live_intervals.len())
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            );

        let mut retained_after_move = Vec::with_capacity(live_intervals.len());
        let mut deleted_after_move = 0_u64;
        for live_interval in live_intervals.drain(..) {
            if live_interval.last_query_verifier_move_ordinal == interval.response_ordinal {
                current_tree_storage_byte_length = current_tree_storage_byte_length
                    .checked_sub(live_interval.tree_byte_length)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                current_tree_storage_chunk_count = current_tree_storage_chunk_count
                    .checked_sub(live_interval.tree_chunk_count)
                    .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
                deleted_after_move = checked_add(deleted_after_move, 1)?;
            } else {
                retained_after_move.push(live_interval);
            }
        }
        live_intervals = retained_after_move;
        if deleted_after_move > 0 {
            distinct_tree_deletion_move_count = checked_add(distinct_tree_deletion_move_count, 1)?;
            maximum_tree_delete_count_after_one_verifier_move =
                maximum_tree_delete_count_after_one_verifier_move.max(deleted_after_move);
        }
    }
    if !live_intervals.is_empty()
        || current_tree_storage_byte_length != 0
        || current_tree_storage_chunk_count != 0
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    let total_tree_transaction_count = checked_add(
        checked_add(tree_write_transaction_count, tree_write_transaction_count)?,
        checked_product(&[response_count, 3])?,
    )?;
    Ok(PackingResponseCommitmentLifecycle {
        response_count,
        commitment_pass_count: response_count,
        frontier_scan_count: response_count,
        commitment_leaf_hash_count,
        commitment_parent_hash_count,
        full_tree_digest_count,
        total_tree_write_byte_length,
        total_tree_read_byte_length: total_tree_write_byte_length,
        tree_write_transaction_count,
        tree_read_transaction_count: tree_write_transaction_count,
        tree_create_transaction_count: response_count,
        tree_seal_transaction_count: response_count,
        tree_delete_transaction_count: response_count,
        total_tree_transaction_count,
        maximum_tree_storage_byte_length,
        maximum_tree_storage_chunk_count,
        maximum_uninterrupted_tree_digest_transfer_count,
        maximum_uninterrupted_tree_digest_transfer_byte_length:
            response_tree_storage_chunk_byte_length,
        maximum_simultaneously_retained_tree_count,
        distinct_tree_deletion_move_count,
        maximum_tree_delete_count_after_one_verifier_move,
        retention_intervals,
        authenticated_restart_record_count: 0,
        maximum_full_attempt_replay_count: 1,
        recomputation_alternative: PackingResponseRecomputationAlternative {
            response_recomputation_pass_count,
            additional_leaf_hash_count,
            additional_parent_hash_count,
            maximum_external_tree_storage_byte_length: 0,
            root_only_commitment_driver_is_implemented: false,
            authenticated_leaf_salt_replay_is_implemented: false,
            response_value_replay_is_implemented: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[test]
    fn every_factor_has_bounded_retention_and_measured_recomputation_alternatives() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_response_counts = [82, 80, 78, 76];
        let expected_leaf_counts = [639_270, 1_065_250, 1_917_214, 3_621_146];
        let expected_parent_counts = [639_188, 1_065_170, 1_917_136, 3_621_070];
        assert_eq!(
            catalog
                .factor_catalogs
                .iter()
                .map(|factor| {
                    factor
                        .response_commitment_lifecycle
                        .total_tree_transaction_count
                })
                .collect::<Vec<_>>(),
            vec![534, 628, 826, 1_232]
        );
        assert_eq!(
            catalog
                .factor_catalogs
                .iter()
                .map(|factor| {
                    let lifecycle = &factor.response_commitment_lifecycle;
                    (
                        factor.packing_factor,
                        lifecycle.maximum_tree_storage_byte_length,
                        lifecycle.maximum_tree_storage_chunk_count,
                        lifecycle.maximum_simultaneously_retained_tree_count,
                        lifecycle.distinct_tree_deletion_move_count,
                        lifecycle.maximum_tree_delete_count_after_one_verifier_move,
                        lifecycle
                            .recomputation_alternative
                            .response_recomputation_pass_count,
                        lifecycle
                            .recomputation_alternative
                            .additional_leaf_hash_count,
                        lifecycle
                            .recomputation_alternative
                            .additional_parent_hash_count,
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (1, 52_952_832, 52, 10, 65, 10, 18, 557_056, 557_038),
                (2, 105_381_632, 101, 10, 63, 10, 18, 983_040, 983_022),
                (4, 210_239_232, 201, 10, 61, 10, 18, 1_835_008, 1_834_990,),
                (8, 419_954_432, 401, 10, 59, 10, 18, 3_538_944, 3_538_926,),
            ]
        );

        for (factor_ordinal, factor) in catalog.factor_catalogs.iter().enumerate() {
            let lifecycle = &factor.response_commitment_lifecycle;
            assert_eq!(
                lifecycle.response_count,
                expected_response_counts[factor_ordinal]
            );
            assert_eq!(
                lifecycle.commitment_leaf_hash_count,
                expected_leaf_counts[factor_ordinal]
            );
            assert_eq!(
                lifecycle.commitment_parent_hash_count,
                expected_parent_counts[factor_ordinal]
            );
            assert_eq!(
                lifecycle.tree_create_transaction_count,
                lifecycle.response_count
            );
            assert_eq!(
                lifecycle.tree_seal_transaction_count,
                lifecycle.response_count
            );
            assert!(lifecycle.maximum_simultaneously_retained_tree_count > 1);
            assert!(
                lifecycle
                    .retention_intervals
                    .iter()
                    .any(|interval| interval.last_query_verifier_move_ordinal
                        > interval.response_ordinal)
            );
            assert!(
                lifecycle
                    .recomputation_alternative
                    .response_recomputation_pass_count
                    > 0
            );
            assert!(
                lifecycle
                    .recomputation_alternative
                    .additional_leaf_hash_count
                    > 0
            );
            assert_eq!(
                lifecycle
                    .recomputation_alternative
                    .missing_implementation_owner_count(),
                3
            );
            assert_eq!(lifecycle.authenticated_restart_record_count, 0);
            assert_eq!(lifecycle.maximum_full_attempt_replay_count, 1);
        }
    }
}
