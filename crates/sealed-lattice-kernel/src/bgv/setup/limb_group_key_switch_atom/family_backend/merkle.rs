//! Salted Merkle row commitments for the atom family backend.
//!
//! Same construction and traversal discipline as the existing succinct
//! engine's `merkle_commitment` module, under atom-family domain strings.
//! Leaves are rows of u64 words (proof-field elements contribute their
//! little-endian limbs in column order), salted so unopened sibling rows
//! stay statistically hidden. The batched opening emits exactly the
//! authentication nodes that are not derivable from the opened leaves, in
//! ascending-index leaf-to-root order, and verification consumes every
//! supplied node so short and padded node lists are both rejected.

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::hash256;

const LEAF_DOMAIN: &str = "sealed-lattice/setup/key-switch-atom/merkle-leaf-v1";
const NODE_DOMAIN: &str = "sealed-lattice/setup/key-switch-atom/merkle-node-v1";

pub(super) const MERKLE_DIGEST_BYTES: usize = 32;
pub(super) type MerkleDigest = [u8; MERKLE_DIGEST_BYTES];

fn invalid_atom_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// Salted leaf over one evaluation row: the position index, the per-leaf salt,
// and every committed column's word at that position, length-framed by the
// fixed row width absorbed once into the transcript separately.
pub(super) fn leaf_hash(index: usize, salt: &[u8], row_words: &[u64]) -> MerkleDigest {
    let mut row_bytes = Vec::with_capacity(row_words.len() * 8);
    for word in row_words {
        row_bytes.extend_from_slice(&word.to_le_bytes());
    }

    merkle_digest(
        LEAF_DOMAIN,
        &[&(index as u64).to_le_bytes(), salt, &row_bytes],
    )
}

pub(super) struct MerkleTree {
    levels: Vec<Vec<MerkleDigest>>,
}

impl MerkleTree {
    pub(super) fn from_leaf_hashes(leaf_hashes: Vec<MerkleDigest>) -> CanonicalResult<Self> {
        if leaf_hashes.is_empty() || !leaf_hashes.len().is_power_of_two() {
            return Err(invalid_atom_proof(
                "Merkle leaf count must be a non-empty power of two",
            ));
        }
        let mut levels = vec![leaf_hashes];
        while levels.last().expect("levels are non-empty").len() > 1 {
            let previous = levels.last().expect("levels are non-empty");
            let mut next = Vec::with_capacity(previous.len() / 2);
            for pair in previous.chunks_exact(2) {
                next.push(merkle_digest(NODE_DOMAIN, &[&pair[0], &pair[1]]));
            }
            levels.push(next);
        }

        Ok(Self { levels })
    }

    pub(super) fn root(&self) -> MerkleDigest {
        self.levels.last().expect("levels are non-empty")[0]
    }

    // Open a sorted, unique index set at once. The emitted nodes are exactly
    // the siblings not derivable from the opened leaves, in ascending-index,
    // leaf-to-root order; `verify_merkle_batch` walks identically. Any
    // divergence between the two traversals breaks soundness.
    pub(super) fn open_batch(&self, sorted_unique_indices: &[usize]) -> BatchedMerkleOpening {
        let mut authentication_nodes = Vec::new();
        let mut current = sorted_unique_indices.to_vec();
        for level in &self.levels[..self.levels.len() - 1] {
            let mut parents = Vec::new();
            let mut index_cursor = 0;
            while index_cursor < current.len() {
                let node_index = current[index_cursor];
                if index_cursor + 1 < current.len() && current[index_cursor + 1] == (node_index ^ 1)
                {
                    index_cursor += 2;
                } else {
                    authentication_nodes.push(level[node_index ^ 1]);
                    index_cursor += 1;
                }
                let parent_index = node_index >> 1;
                if parents.last() != Some(&parent_index) {
                    parents.push(parent_index);
                }
            }
            current = parents;
        }

        BatchedMerkleOpening {
            authentication_nodes,
        }
    }
}

fn merkle_digest(domain: &str, parts: &[&[u8]]) -> MerkleDigest {
    hash256(domain, parts)
}

pub(super) struct BatchedMerkleOpening {
    pub(super) authentication_nodes: Vec<MerkleDigest>,
}

pub(super) fn sorted_unique_indices(indices: impl IntoIterator<Item = usize>) -> Vec<usize> {
    indices
        .into_iter()
        .collect::<std::collections::BTreeSet<usize>>()
        .into_iter()
        .collect()
}

// Sorted, unique (index, leaf hash) pairs, rejecting any index opened to two
// different leaf hashes across queries; without this a prover could bind only
// one of two conflicting openings to the committed root.
pub(super) fn consistent_sorted_leaves(
    leaves: impl IntoIterator<Item = (usize, MerkleDigest)>,
) -> Option<Vec<(usize, MerkleDigest)>> {
    let mut leaves_by_index = std::collections::BTreeMap::new();
    for (index, leaf) in leaves {
        match leaves_by_index.entry(index) {
            std::collections::btree_map::Entry::Occupied(existing) => {
                if *existing.get() != leaf {
                    return None;
                }
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(leaf);
            }
        }
    }

    Some(leaves_by_index.into_iter().collect())
}

// Recompute the root from a batched opening and a sorted, unique, consistent
// leaf set. True only when the recomputed root matches, every supplied node
// was consumed, and the walk terminates at the root slot.
pub(super) fn verify_merkle_batch(
    root: &MerkleDigest,
    depth: usize,
    sorted_unique_leaves: &[(usize, MerkleDigest)],
    opening: &BatchedMerkleOpening,
) -> bool {
    if sorted_unique_leaves.is_empty() {
        return false;
    }
    let mut current = sorted_unique_leaves.to_vec();
    let mut node_cursor = 0;
    for _level in 0..depth {
        let mut parents: Vec<(usize, MerkleDigest)> = Vec::new();
        let mut index_cursor = 0;
        while index_cursor < current.len() {
            let (node_index, node_hash) = current[index_cursor];
            let sibling_hash = if index_cursor + 1 < current.len()
                && current[index_cursor + 1].0 == (node_index ^ 1)
            {
                let sibling = current[index_cursor + 1].1;
                index_cursor += 2;
                sibling
            } else {
                let Some(supplied) = opening.authentication_nodes.get(node_cursor) else {
                    return false;
                };
                node_cursor += 1;
                index_cursor += 1;
                *supplied
            };
            let (left, right) = if node_index & 1 == 0 {
                (node_hash, sibling_hash)
            } else {
                (sibling_hash, node_hash)
            };
            let parent_index = node_index >> 1;
            let parent_hash = merkle_digest(NODE_DOMAIN, &[&left, &right]);
            if parents.last().map(|(index, _)| *index) != Some(parent_index) {
                parents.push((parent_index, parent_hash));
            }
        }
        current = parents;
    }

    node_cursor == opening.authentication_nodes.len()
        && current.len() == 1
        && current[0].0 == 0
        && &current[0].1 == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_leaves(count: usize) -> Vec<MerkleDigest> {
        (0..count)
            .map(|index| merkle_digest(LEAF_DOMAIN, &[&(index as u64).to_le_bytes()]))
            .collect()
    }

    fn opened_leaf_set(leaves: &[MerkleDigest], indices: &[usize]) -> Vec<(usize, MerkleDigest)> {
        consistent_sorted_leaves(indices.iter().map(|index| (*index, leaves[*index])))
            .expect("consistent leaves")
    }

    #[test]
    fn batched_opening_round_trips_and_rejects_tampering() {
        let leaf_count = 512_usize;
        let leaves = deterministic_leaves(leaf_count);
        let tree = MerkleTree::from_leaf_hashes(leaves.clone()).expect("tree");
        let depth = leaf_count.trailing_zeros() as usize;
        let indices = sorted_unique_indices([0_usize, 3, 7, 8, 100, 200, 201, 511]);
        let opening = tree.open_batch(&indices);
        let opened = opened_leaf_set(&leaves, &indices);
        assert!(verify_merkle_batch(&tree.root(), depth, &opened, &opening));

        let mut tampered_nodes = opening.authentication_nodes.clone();
        tampered_nodes[0][0] ^= 0x01;
        assert!(!verify_merkle_batch(
            &tree.root(),
            depth,
            &opened,
            &BatchedMerkleOpening {
                authentication_nodes: tampered_nodes,
            },
        ));

        let mut short_nodes = opening.authentication_nodes.clone();
        short_nodes.pop();
        assert!(!verify_merkle_batch(
            &tree.root(),
            depth,
            &opened,
            &BatchedMerkleOpening {
                authentication_nodes: short_nodes,
            },
        ));

        let mut long_nodes = opening.authentication_nodes.clone();
        long_nodes.push([0_u8; MERKLE_DIGEST_BYTES]);
        assert!(!verify_merkle_batch(
            &tree.root(),
            depth,
            &opened,
            &BatchedMerkleOpening {
                authentication_nodes: long_nodes,
            },
        ));

        let mut tampered_leaves = opened.clone();
        tampered_leaves[0].1[0] ^= 0x01;
        assert!(!verify_merkle_batch(
            &tree.root(),
            depth,
            &tampered_leaves,
            &opening
        ));

        let other_indices = sorted_unique_indices([1_usize, 3, 7, 8, 100, 200, 201, 511]);
        let other_opened = opened_leaf_set(&leaves, &other_indices);
        assert!(!verify_merkle_batch(
            &tree.root(),
            depth,
            &other_opened,
            &opening
        ));
    }

    #[test]
    fn consistent_sorted_leaves_rejects_conflicting_values() {
        let leaves = deterministic_leaves(16);
        assert!(consistent_sorted_leaves([(3_usize, leaves[3]), (3, leaves[4])]).is_none());
        let collapsed =
            consistent_sorted_leaves([(3_usize, leaves[3]), (3, leaves[3]), (1, leaves[1])])
                .expect("consistent");
        assert_eq!(collapsed, vec![(1, leaves[1]), (3, leaves[3])]);
    }
}
