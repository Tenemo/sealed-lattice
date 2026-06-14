use super::*;
use crate::hashing::hash512;

const LEAF_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/merkle-leaf-v1";
const NODE_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/merkle-node-v1";

// Merkle commitment over a power-of-two leaf count. Leaves are rows of u64
// values (one row per evaluation position across all committed columns).
pub(super) struct MerkleTree {
    levels: Vec<Vec<[u8; 64]>>,
}

pub(super) const LEAF_SALT_BYTES: usize = 32;

// Salted leaf: the salt statistically hides unopened sibling rows so the
// commitment is hiding, not only binding.
pub(super) fn leaf_hash(index: usize, salt: &[u8], row_values: &[u64]) -> [u8; 64] {
    let mut row_bytes = Vec::with_capacity(row_values.len() * 8);
    for value in row_values {
        row_bytes.extend_from_slice(&value.to_le_bytes());
    }

    hash512(
        LEAF_DOMAIN,
        &[&(index as u64).to_le_bytes(), salt, &row_bytes],
    )
}

impl MerkleTree {
    pub(super) fn from_leaf_hashes(leaf_hashes: Vec<[u8; 64]>) -> CanonicalResult<Self> {
        if leaf_hashes.is_empty() || !leaf_hashes.len().is_power_of_two() {
            return Err(invalid_succinct_setup_proof(
                "Merkle leaf count must be a non-empty power of two",
            ));
        }
        let mut levels = vec![leaf_hashes];
        while levels.last().expect("levels are non-empty").len() > 1 {
            let previous = levels.last().expect("levels are non-empty");
            let mut next = Vec::with_capacity(previous.len() / 2);
            for pair in previous.chunks_exact(2) {
                next.push(hash512(NODE_DOMAIN, &[&pair[0], &pair[1]]));
            }
            levels.push(next);
        }

        Ok(Self { levels })
    }

    pub(super) fn root(&self) -> [u8; 64] {
        self.levels.last().expect("levels are non-empty")[0]
    }

    pub(super) fn open(&self, leaf_index: usize) -> Vec<[u8; 64]> {
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut index = leaf_index;
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[index ^ 1]);
            index >>= 1;
        }

        path
    }
}

pub(super) fn verify_merkle_opening(
    root: &[u8; 64],
    leaf_index: usize,
    leaf: &[u8; 64],
    path: &[[u8; 64]],
) -> bool {
    let mut node = *leaf;
    let mut index = leaf_index;
    for sibling in path {
        node = if index & 1 == 0 {
            hash512(NODE_DOMAIN, &[&node, sibling])
        } else {
            hash512(NODE_DOMAIN, &[sibling, &node])
        };
        index >>= 1;
    }

    node == *root && index == 0
}
