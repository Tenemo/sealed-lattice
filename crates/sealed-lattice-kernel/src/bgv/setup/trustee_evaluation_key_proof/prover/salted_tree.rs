use super::super::merkle_commitment::{LEAF_SALT_BYTES, MerkleTree, leaf_hash};
use super::super::*;
use crate::bgv::evaluator::prg::DeterministicSampler;

pub(super) struct SaltedTree {
    pub(super) tree: MerkleTree,
    salts: Vec<u8>,
}

impl SaltedTree {
    pub(super) fn salt(&self, position: usize) -> &[u8] {
        &self.salts[position * LEAF_SALT_BYTES..(position + 1) * LEAF_SALT_BYTES]
    }
}

pub(super) fn commit_salted_extension_rows(
    extension_columns: &[Vec<u64>],
    extension_size: usize,
    salt_sampler: &mut DeterministicSampler,
) -> CanonicalResult<SaltedTree> {
    let salts = salt_sampler.bytes(extension_size * LEAF_SALT_BYTES);
    let mut leaf_hashes = Vec::with_capacity(extension_size);
    let mut row = vec![0_u64; extension_columns.len()];
    for position in 0..extension_size {
        for (column_index, column) in extension_columns.iter().enumerate() {
            row[column_index] = column[position];
        }
        leaf_hashes.push(leaf_hash(
            position,
            &salts[position * LEAF_SALT_BYTES..(position + 1) * LEAF_SALT_BYTES],
            &row,
        ));
    }

    Ok(SaltedTree {
        tree: MerkleTree::from_leaf_hashes(leaf_hashes)?,
        salts,
    })
}
