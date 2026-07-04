use super::*;
use crate::hashing::hash256;

const LEAF_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/merkle-leaf-v2";
const PHASE_PAIR_LEAF_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/phase-pair-merkle-leaf-v1";
const NODE_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/merkle-node-v2";

pub(super) const MERKLE_DIGEST_BYTES: usize = 32;
pub(super) type MerkleDigest = [u8; MERKLE_DIGEST_BYTES];

// Merkle commitment over a power-of-two leaf count. Leaves are rows of u64
// values (one row per evaluation position across all committed columns).
pub(super) struct MerkleTree {
    levels: Vec<Vec<MerkleDigest>>,
}

pub(super) const LEAF_SALT_BYTES: usize = 32;

// Salted leaf: the salt statistically hides unopened sibling rows so the
// commitment is hiding, not only binding.
pub(super) fn leaf_hash(index: usize, salt: &[u8], row_values: &[u64]) -> MerkleDigest {
    let mut row_bytes = Vec::with_capacity(row_values.len() * 8);
    for value in row_values {
        row_bytes.extend_from_slice(&value.to_le_bytes());
    }

    merkle_digest(
        LEAF_DOMAIN,
        &[&(index as u64).to_le_bytes(), salt, &row_bytes],
    )
}

// Phase queries always open the ordered pair (position, position + half). A
// separate leaf domain binds both rows and their row boundary under one salt,
// while keeping low-degree folded-layer leaves in their existing domain.
pub(super) fn phase_pair_leaf_hash(
    pair_index: usize,
    salt: &[u8],
    first_row_values: &[u64],
    second_row_values: &[u64],
) -> MerkleDigest {
    let mut row_bytes = Vec::with_capacity((first_row_values.len() + second_row_values.len()) * 8);
    for value in first_row_values.iter().chain(second_row_values.iter()) {
        row_bytes.extend_from_slice(&value.to_le_bytes());
    }

    merkle_digest(
        PHASE_PAIR_LEAF_DOMAIN,
        &[
            &(pair_index as u64).to_le_bytes(),
            &(first_row_values.len() as u64).to_le_bytes(),
            &(second_row_values.len() as u64).to_le_bytes(),
            salt,
            &row_bytes,
        ],
    )
}

impl MerkleTree {
    pub(super) fn from_leaf_hashes(leaf_hashes: Vec<MerkleDigest>) -> CanonicalResult<Self> {
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
                next.push(merkle_digest(NODE_DOMAIN, &[&pair[0], &pair[1]]));
            }
            levels.push(next);
        }

        Ok(Self { levels })
    }

    pub(super) fn root(&self) -> MerkleDigest {
        self.levels.last().expect("levels are non-empty")[0]
    }

    #[cfg(test)]
    pub(super) fn open(&self, leaf_index: usize) -> Vec<MerkleDigest> {
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        let mut index = leaf_index;
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[index ^ 1]);
            index >>= 1;
        }

        path
    }
}

fn merkle_digest(domain: &str, parts: &[&[u8]]) -> MerkleDigest {
    hash256(domain, parts)
}

#[cfg(test)]
pub(super) fn verify_merkle_opening(
    root: &MerkleDigest,
    leaf_index: usize,
    leaf: &MerkleDigest,
    path: &[MerkleDigest],
) -> bool {
    let mut node = *leaf;
    let mut index = leaf_index;
    for sibling in path {
        node = if index & 1 == 0 {
            merkle_digest(NODE_DOMAIN, &[&node, sibling])
        } else {
            merkle_digest(NODE_DOMAIN, &[sibling, &node])
        };
        index >>= 1;
    }

    // index == 0 rejects an over-long leaf index (a path shorter than the tree
    // depth), and consuming exactly every authentication node rejects padded or
    // short node lists; both prevent forged short-path openings.
    node == *root && index == 0
}

// Batched Merkle opening: the deduplicated authentication nodes that, together
// with a set of opened leaves, recompute the tree root. The verifier consumes
// each required internal node once and still binds the opened leaves to the
// same salted commitment root.
pub(super) struct BatchedMerkleOpening {
    pub(super) authentication_nodes: Vec<MerkleDigest>,
}

// Sorted, unique leaf indices from a possibly unsorted, repeating index list.
// Prover and verifier both canonicalize the same way so the node order agrees.
pub(super) fn sorted_unique_indices(indices: impl IntoIterator<Item = usize>) -> Vec<usize> {
    indices
        .into_iter()
        .collect::<std::collections::BTreeSet<usize>>()
        .into_iter()
        .collect()
}

// Sorted, unique (index, leaf hash) pairs, rejecting any index that appears with
// two different leaf hashes. Without this check a prover could open one position
// to two different values across queries and have only one of them bound to the
// committed root; returning None forces the verifier to reject that.
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

impl MerkleTree {
    // Open a set of leaf indices at once. `sorted_unique_indices` must be
    // strictly ascending with no repeats and every index below the leaf count.
    // The returned nodes are exactly the siblings that are not themselves
    // derivable from the opened leaves, emitted in ascending-index, leaf-to-root
    // order, which `verify_merkle_batch` consumes in the same order.
    pub(super) fn open_batch(&self, sorted_unique_indices: &[usize]) -> BatchedMerkleOpening {
        // Node emission and consumption must walk identically: sorted-unique
        // indices make a sibling pair adjacent, so the both-children-opened
        // branch skips a node on both sides. Any divergence between these two
        // traversals breaks soundness.
        let mut authentication_nodes = Vec::new();
        let mut current = sorted_unique_indices.to_vec();
        for level in &self.levels[..self.levels.len() - 1] {
            let mut parents = Vec::new();
            let mut index_cursor = 0;
            while index_cursor < current.len() {
                let node_index = current[index_cursor];
                if index_cursor + 1 < current.len() && current[index_cursor + 1] == (node_index ^ 1)
                {
                    // Both children are opened; the parent needs no extra node.
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

// Recompute the root from a batched opening and a sorted, unique, consistent
// leaf set (as returned by `consistent_sorted_leaves`). Returns true only when
// the recomputed root matches and every supplied node was consumed, so neither a
// short nor a padded node list is accepted.
pub(super) fn verify_merkle_batch(
    root: &MerkleDigest,
    depth: usize,
    sorted_unique_leaves: &[(usize, MerkleDigest)],
    opening: &BatchedMerkleOpening,
) -> bool {
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
    fn batched_opening_round_trips_for_varied_index_sets() {
        for leaf_count in [2_usize, 4, 16, 256, 1024] {
            let leaves = deterministic_leaves(leaf_count);
            let tree = MerkleTree::from_leaf_hashes(leaves.clone()).expect("tree");
            let depth = leaf_count.trailing_zeros() as usize;
            // A spread of index sets: singletons, adjacent pairs, every leaf,
            // and a pseudo-random scatter.
            let mut index_sets: Vec<Vec<usize>> = vec![
                vec![0],
                vec![leaf_count - 1],
                vec![0, leaf_count - 1],
                (0..leaf_count).collect(),
            ];
            if leaf_count >= 16 {
                index_sets.push(vec![1, 2, 3, leaf_count / 2, leaf_count - 2]);
                let mut scattered = Vec::new();
                let mut state = 0x1234_5678_u64;
                for _ in 0..(leaf_count / 4).max(1) {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    scattered.push((state >> 33) as usize % leaf_count);
                }
                index_sets.push(scattered);
            }
            for raw_indices in index_sets {
                let indices = sorted_unique_indices(raw_indices);
                let opening = tree.open_batch(&indices);
                let opened = opened_leaf_set(&leaves, &indices);
                assert!(
                    verify_merkle_batch(&tree.root(), depth, &opened, &opening),
                    "batched opening must verify (leaf_count={leaf_count}, indices={indices:?})"
                );
                // Every opened leaf also verifies against the same root through
                // the single-leaf path, so the batched node set is consistent
                // with the per-leaf commitment.
                for &index in &indices {
                    assert!(verify_merkle_opening(
                        &tree.root(),
                        index,
                        &leaves[index],
                        &tree.open(index),
                    ));
                }
            }
        }
    }

    #[test]
    fn batched_opening_rejects_tampering() {
        let leaf_count = 256_usize;
        let leaves = deterministic_leaves(leaf_count);
        let tree = MerkleTree::from_leaf_hashes(leaves.clone()).expect("tree");
        let depth = leaf_count.trailing_zeros() as usize;
        let indices = sorted_unique_indices([3_usize, 7, 8, 100, 200, 201]);
        let opening = tree.open_batch(&indices);
        let opened = opened_leaf_set(&leaves, &indices);
        assert!(verify_merkle_batch(&tree.root(), depth, &opened, &opening));

        // A flipped authentication node is rejected.
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

        // A dropped node is rejected (root mismatch or exhausted node list).
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

        // A padded node list is rejected because not every node is consumed.
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

        // A flipped opened leaf is rejected.
        let mut tampered_leaves = opened.clone();
        tampered_leaves[0].1[0] ^= 0x01;
        assert!(!verify_merkle_batch(
            &tree.root(),
            depth,
            &tampered_leaves,
            &opening
        ));

        // The opening for one index set does not verify a different index set.
        let other_indices = sorted_unique_indices([4_usize, 7, 8, 100, 200, 201]);
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
        // Same index with two different leaf hashes must be rejected.
        assert!(consistent_sorted_leaves([(3_usize, leaves[3]), (3, leaves[4])]).is_none());
        // Same index with the same hash collapses to one entry.
        let collapsed =
            consistent_sorted_leaves([(3_usize, leaves[3]), (3, leaves[3]), (1, leaves[1])])
                .expect("consistent");
        assert_eq!(collapsed, vec![(1, leaves[1]), (3, leaves[3])]);
    }
}
