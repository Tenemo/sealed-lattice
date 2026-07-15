use super::super::merkle_commitment::{
    LEAF_SALT_BYTES, MerkleContext, MerkleTree, phase_pair_leaf_hash,
};
use super::super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;

pub(super) struct SaltedTree {
    pub(super) tree: MerkleTree,
    salts: Vec<u8>,
}

impl SaltedTree {
    pub(super) fn pair_salt(&self, pair_index: usize) -> &[u8] {
        &self.salts[pair_index * LEAF_SALT_BYTES..(pair_index + 1) * LEAF_SALT_BYTES]
    }
}

pub(super) fn commit_salted_extension_row_pairs(
    merkle_context: MerkleContext,
    extension_columns: &[Vec<u64>],
    extension_size: usize,
    salt_sampler: &mut DeterministicSampler,
) -> CanonicalResult<SaltedTree> {
    if extension_size < 2 || !extension_size.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "phase tree extension size must be a power of two with paired rows",
        ));
    }
    let pair_count = extension_size / 2;
    let salts = salt_sampler.bytes(pair_count * LEAF_SALT_BYTES);
    let mut leaf_hashes = Vec::with_capacity(pair_count);
    let mut first_row = vec![0_u64; extension_columns.len()];
    let mut second_row = vec![0_u64; extension_columns.len()];
    for pair_index in 0..pair_count {
        let second_position = pair_index + pair_count;
        for (column_index, column) in extension_columns.iter().enumerate() {
            first_row[column_index] = column[pair_index];
            second_row[column_index] = column[second_position];
        }
        leaf_hashes.push(phase_pair_leaf_hash(
            merkle_context,
            pair_index,
            &salts[pair_index * LEAF_SALT_BYTES..(pair_index + 1) * LEAF_SALT_BYTES],
            &first_row,
            &second_row,
        ));
    }

    Ok(SaltedTree {
        tree: MerkleTree::from_leaf_hashes(merkle_context, leaf_hashes)?,
        salts,
    })
}
