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

use crate::bgv::proof_suite::canonical_merkle_leaf_hash;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    SetupBatchedMerkleOpening, SetupMerkleContext, SetupMerkleDigest,
    consistent_setup_merkle_leaves, verify_merkle_batch_with_context,
};
#[cfg(test)]
use crate::bgv::setup::trustee_evaluation_key_proof::{
    SetupMerkleTree, sorted_unique_setup_merkle_indices,
};
#[cfg(test)]
use crate::encoding::CanonicalResult;
#[cfg(test)]
use crate::hashing::StreamingHash512;

#[cfg(test)]
const LEAF_DOMAIN: &str = "sealed-lattice/proof/merkle/leaf/v1";

const APPLICATION_STATEMENT_SCHEMA_IDENTIFIER: u16 = crate::foundation::ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER;
// The trustee evaluation-key proof reserves 0x6000..=0x7fff for residual
// low-degree trees across all RNS limbs and folds.
const TREE_ORDINAL: u16 = 0x8000;
#[cfg(test)]
const STREAMING_WORD_BATCH_SIZE: usize = 16;

const fn merkle_context() -> SetupMerkleContext {
    SetupMerkleContext::new(APPLICATION_STATEMENT_SCHEMA_IDENTIFIER, TREE_ORDINAL)
}

pub(super) const MERKLE_DIGEST_BYTES: usize = 64;
pub(super) type MerkleDigest = SetupMerkleDigest;

// Salted leaf over one evaluation row: the position index, the per-leaf salt,
// and every committed column's word at that position, length-framed by the
// fixed row width absorbed once into the transcript separately.
pub(super) fn leaf_hash(index: usize, salt: &[u8], row_words: &[u64]) -> MerkleDigest {
    let mut row_bytes = Vec::with_capacity(8 + salt.len() + row_words.len() * 8);
    row_bytes.extend_from_slice(
        &u64::try_from(salt.len())
            .expect("a Merkle salt length fits u64")
            .to_le_bytes(),
    );
    row_bytes.extend_from_slice(salt);
    for word in row_words {
        row_bytes.extend_from_slice(&word.to_le_bytes());
    }

    canonical_merkle_leaf_hash(
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER,
        TREE_ORDINAL,
        index,
        &row_bytes,
    )
}

// A streaming leaf hasher producing output byte-identical to `leaf_hash` while
// absorbing the row one committed column at a time, so the streamed prover
// never materializes all column codewords at once. The row byte length (every
// column's words at this position) is declared up front; the caller must absorb
// exactly that many word bytes before finalizing.
#[cfg(test)]
pub(super) struct StreamingLeafHasher {
    inner: StreamingHash512,
    absorbed_row_byte_length: usize,
    expected_row_byte_length: usize,
}

#[cfg(test)]
impl StreamingLeafHasher {
    pub(super) fn new(index: usize, salt: &[u8], row_byte_length: u64) -> Self {
        let expected_row_byte_length =
            usize::try_from(row_byte_length).expect("a streamed Merkle row byte length fits usize");
        let framed_row_byte_length = 8_u64
            .checked_add(u64::try_from(salt.len()).expect("a Merkle salt length fits u64"))
            .and_then(|length| length.checked_add(row_byte_length))
            .expect("a streamed Merkle row length fits u64");
        let mut inner = StreamingHash512::new(LEAF_DOMAIN, 4);
        inner.absorb_part(&APPLICATION_STATEMENT_SCHEMA_IDENTIFIER.to_le_bytes());
        inner.absorb_part(&TREE_ORDINAL.to_le_bytes());
        inner.absorb_part(
            &u64::try_from(index)
                .expect("a Merkle leaf index fits u64")
                .to_le_bytes(),
        );
        inner.begin_part(framed_row_byte_length);
        inner.absorb_raw(
            &u64::try_from(salt.len())
                .expect("a Merkle salt length fits u64")
                .to_le_bytes(),
        );
        inner.absorb_raw(salt);
        Self {
            inner,
            absorbed_row_byte_length: 0,
            expected_row_byte_length,
        }
    }

    pub(super) fn absorb_value_words(&mut self, words: &[u64]) {
        let mut bytes = [0_u8; STREAMING_WORD_BATCH_SIZE * 8];
        for word_batch in words.chunks(STREAMING_WORD_BATCH_SIZE) {
            for (word_bytes, word) in bytes.chunks_exact_mut(8).zip(word_batch) {
                word_bytes.copy_from_slice(&word.to_le_bytes());
            }
            let byte_length = word_batch.len() * 8;
            self.inner.absorb_raw(&bytes[..byte_length]);
            self.absorbed_row_byte_length += byte_length;
        }
    }

    pub(super) fn finalize(self) -> MerkleDigest {
        debug_assert_eq!(self.absorbed_row_byte_length, self.expected_row_byte_length,);
        self.inner.finalize()
    }
}

#[cfg(test)]
pub(super) struct MerkleTree(SetupMerkleTree);

#[cfg(test)]
impl MerkleTree {
    pub(super) fn from_leaf_hashes(leaf_hashes: Vec<MerkleDigest>) -> CanonicalResult<Self> {
        SetupMerkleTree::from_leaf_hashes(merkle_context(), leaf_hashes).map(Self)
    }

    pub(super) fn root(&self) -> MerkleDigest {
        self.0.root()
    }

    pub(super) fn open_batch(&self, sorted_unique_indices: &[usize]) -> BatchedMerkleOpening {
        self.0.open_batch(sorted_unique_indices)
    }
}

pub(super) type BatchedMerkleOpening = SetupBatchedMerkleOpening;

#[cfg(test)]
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
    verify_merkle_batch_with_context(merkle_context(), root, depth, sorted_unique_leaves, opening)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_leaves(count: usize) -> Vec<MerkleDigest> {
        (0..count)
            .map(|index| leaf_hash(index, &[], &[index as u64]))
            .collect()
    }

    fn opened_leaf_set(leaves: &[MerkleDigest], indices: &[usize]) -> Vec<(usize, MerkleDigest)> {
        consistent_sorted_leaves(indices.iter().map(|index| (*index, leaves[*index])))
            .expect("consistent leaves")
    }

    #[test]
    fn batched_streaming_leaf_hash_matches_canonical_leaf_hash_across_batch_boundaries() {
        let salt = [0x5a_u8; 32];
        for word_count in [0_usize, 1, 13, 16, 17, 33] {
            let words = (0..word_count)
                .map(|index| {
                    (index as u64)
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407)
                })
                .collect::<Vec<_>>();
            let mut streaming =
                StreamingLeafHasher::new(7 + word_count, &salt, (word_count * 8) as u64);
            streaming.absorb_value_words(&words);
            assert_eq!(
                streaming.finalize(),
                leaf_hash(7 + word_count, &salt, &words),
                "streamed absorption must preserve bytes for {word_count} words"
            );
        }
    }

    #[test]
    fn batched_streaming_leaf_hash_is_independent_of_production_call_partitions() {
        let salt = [0xa5_u8; 32];
        let words = (0..33_u64)
            .map(|index| {
                index
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407)
            })
            .collect::<Vec<_>>();
        let expected = leaf_hash(19, &salt, &words);

        for words_per_call in [1_usize, 7, 13, 16, 17] {
            let mut streaming = StreamingLeafHasher::new(19, &salt, (words.len() * 8) as u64);
            for partition in words.chunks(words_per_call) {
                streaming.absorb_value_words(partition);
            }
            assert_eq!(
                streaming.finalize(),
                expected,
                "streamed hashing must preserve bytes with {words_per_call} words per call"
            );
        }
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
