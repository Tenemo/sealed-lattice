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

use crate::bgv::setup::trustee_evaluation_key_proof::{
    SetupBatchedMerkleOpening, SetupMerkleDigest, SetupMerkleTree, consistent_setup_merkle_leaves,
    sorted_unique_setup_merkle_indices, verify_merkle_batch_with_node_domain,
};
use crate::encoding::CanonicalResult;
use crate::hashing::{StreamingHash256, hash256};

const LEAF_DOMAIN: &str = "sealed-lattice/setup/key-switch-atom/merkle-leaf";
const NODE_DOMAIN: &str = "sealed-lattice/setup/key-switch-atom/merkle-node";

pub(super) const MERKLE_DIGEST_BYTES: usize = 32;
pub(super) type MerkleDigest = SetupMerkleDigest;

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

// A streaming leaf hasher producing output byte-identical to `leaf_hash` while
// absorbing the row one committed column at a time, so the streamed prover
// never materializes all column codewords at once. The row byte length (every
// column's words at this position) is declared up front; the caller must absorb
// exactly that many word bytes before finalizing.
pub(super) struct StreamingLeafHasher {
    inner: StreamingHash256,
}

impl StreamingLeafHasher {
    pub(super) fn new(index: usize, salt: &[u8], row_byte_length: u64) -> Self {
        let mut inner = StreamingHash256::new(LEAF_DOMAIN, 3);
        inner.absorb_part(&(index as u64).to_le_bytes());
        inner.absorb_part(salt);
        inner.begin_part(row_byte_length);
        Self { inner }
    }

    pub(super) fn absorb_value_words(&mut self, words: &[u64]) {
        for word in words {
            self.inner.absorb_raw(&word.to_le_bytes());
        }
    }

    pub(super) fn finalize(self) -> MerkleDigest {
        self.inner.finalize()
    }
}

pub(super) struct MerkleTree(SetupMerkleTree);

impl MerkleTree {
    pub(super) fn from_leaf_hashes(leaf_hashes: Vec<MerkleDigest>) -> CanonicalResult<Self> {
        SetupMerkleTree::from_leaf_hashes_with_node_domain(leaf_hashes, NODE_DOMAIN).map(Self)
    }

    pub(super) fn root(&self) -> MerkleDigest {
        self.0.root()
    }

    pub(super) fn open_batch(&self, sorted_unique_indices: &[usize]) -> BatchedMerkleOpening {
        self.0.open_batch(sorted_unique_indices)
    }
}

fn merkle_digest(domain: &str, parts: &[&[u8]]) -> MerkleDigest {
    hash256(domain, parts)
}

pub(super) type BatchedMerkleOpening = SetupBatchedMerkleOpening;

pub(super) fn sorted_unique_indices(indices: impl IntoIterator<Item = usize>) -> Vec<usize> {
    sorted_unique_setup_merkle_indices(indices)
}

pub(super) fn consistent_sorted_leaves(
    leaves: impl IntoIterator<Item = (usize, MerkleDigest)>,
) -> Option<Vec<(usize, MerkleDigest)>> {
    consistent_setup_merkle_leaves(leaves)
}

pub(super) fn verify_merkle_batch(
    root: &MerkleDigest,
    depth: usize,
    sorted_unique_leaves: &[(usize, MerkleDigest)],
    opening: &BatchedMerkleOpening,
) -> bool {
    verify_merkle_batch_with_node_domain(root, depth, sorted_unique_leaves, opening, NODE_DOMAIN)
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
