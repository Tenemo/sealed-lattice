//! Raw-witness Merkle memory diagnostic.
//!
//! This tree commits only to Boolean-hypercube witness evaluations. It is not
//! a polynomial commitment and cannot authenticate an evaluation at the
//! non-Boolean terminal point of sumcheck. Its sole purpose is to measure the
//! memory floor of streaming leaf hashing and to catch accidental changes in
//! the deterministic witness generator.

use crate::hashing::hash_framed_parts_512;

use super::arena::{ArenaGeometry, stacked_value_at};

const LEAF_DOMAIN: &str = "sealed-lattice/backend-research/raw-witness-leaf/v1";
const NODE_DOMAIN: &str = "sealed-lattice/backend-research/raw-witness-node/v1";

#[inline]
fn leaf_hash(geometry: ArenaGeometry, stacked_index: usize) -> [u8; 64] {
    hash_framed_parts_512(
        LEAF_DOMAIN,
        &[
            &(stacked_index as u64).to_le_bytes(),
            &stacked_value_at(geometry, stacked_index).to_le_bytes(),
        ],
    )
}

#[inline]
fn node_hash(left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    hash_framed_parts_512(NODE_DOMAIN, &[left.as_slice(), right.as_slice()])
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn resident_raw_merkle_root(geometry: ArenaGeometry) -> [u8; 64] {
    let mut level: Vec<[u8; 64]> = (0..geometry.stacked_evaluation_count())
        .map(|index| leaf_hash(geometry, index))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

pub(crate) fn streaming_raw_merkle_root(geometry: ArenaGeometry) -> [u8; 64] {
    let mut frontier: Vec<Option<[u8; 64]>> =
        Vec::with_capacity(geometry.witness_variable_count() as usize + 1);
    for index in 0..geometry.stacked_evaluation_count() {
        let mut carry = leaf_hash(geometry, index);
        let mut height = 0_usize;
        loop {
            if height == frontier.len() {
                frontier.push(Some(carry));
                break;
            }
            match frontier[height].take() {
                None => {
                    frontier[height] = Some(carry);
                    break;
                }
                Some(pending) => {
                    carry = node_hash(&pending, &carry);
                    height += 1;
                }
            }
        }
    }
    frontier
        .into_iter()
        .rev()
        .flatten()
        .next()
        .expect("a non-empty diagnostic tree has a root")
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn streaming_and_resident_raw_trees_match() {
        for relation_instance_variables in 0..=4 {
            let geometry = ArenaGeometry::new(relation_instance_variables, 5);
            assert_eq!(
                streaming_raw_merkle_root(geometry),
                resident_raw_merkle_root(geometry)
            );
        }
    }
}
