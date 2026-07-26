//! Streaming column commitment and ordinary Merkle authentication.

use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet};

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
#[cfg(test)]
use tiny_keccak::keccakf;

// The project security ledger models Fiat-Shamir with 512-bit random-oracle
// outputs. Keep the outer matrix commitment at the same width: truncating it
// to 320 bits would cap generic collision work at 160 bits before the
// multi-proof compiler loss is considered.
pub(super) const COLUMN_DIGEST_WORD_LENGTH: usize = 8;
pub(super) const COLUMN_DIGEST_BYTE_LENGTH: usize = COLUMN_DIGEST_WORD_LENGTH * size_of::<u64>();
#[cfg(test)]
const SHAKE256_STATE_WORD_LENGTH: usize = 25;
#[cfg(test)]
const SHAKE256_RATE_WORD_LENGTH: usize = 17;
#[cfg(test)]
const SHAKE256_DELIMITER: u64 = 0x1f;
#[cfg(test)]
const SHAKE256_FINAL_RATE_BYTE: u64 = 0x80_u64 << 56;

pub(super) type ColumnDigest = [u64; COLUMN_DIGEST_WORD_LENGTH];

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StreamingColumnCommitment {
    pub(super) root: ColumnDigest,
    pub(super) frontier: Vec<ColumnDigest>,
}

/// One SHAKE256 state per encoded column, updated in row-major order.
///
/// All states have the same byte offset. Keeping that offset once, rather
/// than inside every hasher object, makes the exact resident state 200 bytes
/// per column.
#[cfg(test)]
pub(super) struct StreamingColumnHasher {
    states: Vec<[u64; SHAKE256_STATE_WORD_LENGTH]>,
    next_rate_word: usize,
    expected_row_count: usize,
    absorbed_row_count: usize,
}

#[cfg(test)]
impl StreamingColumnHasher {
    pub(super) fn new(
        expected_row_count: usize,
        encoded_column_count: usize,
    ) -> Result<Self, String> {
        if expected_row_count == 0 {
            return Err("column commitment requires at least one row".to_owned());
        }
        if !encoded_column_count.is_power_of_two() {
            return Err(format!(
                "encoded column count {encoded_column_count} is not a non-zero power of two"
            ));
        }

        let mut base_state = [0_u64; SHAKE256_STATE_WORD_LENGTH];
        let mut next_rate_word = 0_usize;
        for word in column_hash_preamble(expected_row_count, encoded_column_count) {
            absorb_word(&mut base_state, &mut next_rate_word, word);
        }
        Ok(Self {
            states: vec![base_state; encoded_column_count],
            next_rate_word,
            expected_row_count,
            absorbed_row_count: 0,
        })
    }

    pub(super) fn absorb_row(&mut self, encoded_row: &[Goldilocks]) -> Result<(), String> {
        if self.absorbed_row_count == self.expected_row_count {
            return Err(format!(
                "column commitment received more than {} rows",
                self.expected_row_count
            ));
        }
        if encoded_row.len() != self.states.len() {
            return Err(format!(
                "encoded row has {} columns, expected {}",
                encoded_row.len(),
                self.states.len()
            ));
        }

        let rate_word = self.next_rate_word;
        for (state, value) in self.states.iter_mut().zip(encoded_row) {
            state[rate_word] ^= value.as_canonical_u64();
        }
        self.next_rate_word += 1;
        if self.next_rate_word == SHAKE256_RATE_WORD_LENGTH {
            for state in &mut self.states {
                keccakf(state);
            }
            self.next_rate_word = 0;
        }
        self.absorbed_row_count += 1;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn finalize(mut self) -> Result<Vec<ColumnDigest>, String> {
        if self.absorbed_row_count != self.expected_row_count {
            return Err(format!(
                "column commitment received {} rows, expected {}",
                self.absorbed_row_count, self.expected_row_count
            ));
        }
        let delimiter_word = self.next_rate_word;
        Ok(self
            .states
            .drain(..)
            .map(|mut state| {
                state[delimiter_word] ^= SHAKE256_DELIMITER;
                state[SHAKE256_RATE_WORD_LENGTH - 1] ^= SHAKE256_FINAL_RATE_BYTE;
                keccakf(&mut state);
                core::array::from_fn(|word_index| state[word_index])
            })
            .collect())
    }

    pub(super) fn finalize_root(self) -> Result<ColumnDigest, String> {
        self.finalize_commitment(&[])
            .map(|commitment| commitment.root)
    }

    pub(super) fn finalize_commitment(
        mut self,
        opened_column_indices: &[usize],
    ) -> Result<StreamingColumnCommitment, String> {
        if self.absorbed_row_count != self.expected_row_count {
            return Err(format!(
                "column commitment received {} rows, expected {}",
                self.absorbed_row_count, self.expected_row_count
            ));
        }
        let opened_columns = if opened_column_indices.is_empty() {
            BTreeSet::new()
        } else {
            canonical_column_index_set(opened_column_indices, self.states.len())?
        };
        let delimiter_word = self.next_rate_word;
        let mut builder = StreamingMerkleBuilder::new(self.states.len(), opened_columns)?;
        for (column_index, mut state) in self.states.drain(..).enumerate() {
            state[delimiter_word] ^= SHAKE256_DELIMITER;
            state[SHAKE256_RATE_WORD_LENGTH - 1] ^= SHAKE256_FINAL_RATE_BYTE;
            keccakf(&mut state);
            builder.push_leaf(
                column_index,
                core::array::from_fn(|word_index| state[word_index]),
            )?;
        }
        builder.finish()
    }

    #[cfg(test)]
    pub(super) const fn exact_state_byte_length(encoded_column_count: usize) -> Option<usize> {
        encoded_column_count.checked_mul(size_of::<[u64; SHAKE256_STATE_WORD_LENGTH]>())
    }
}

#[cfg(test)]
struct StreamingMerkleNode {
    level: usize,
    index: usize,
    digest: ColumnDigest,
    contains_opened_column: bool,
}

#[cfg(test)]
struct StreamingMerkleBuilder {
    leaf_count: usize,
    opened_columns: BTreeSet<usize>,
    stack: Vec<StreamingMerkleNode>,
    frontier_by_level_and_index: Vec<(usize, usize, ColumnDigest)>,
    next_leaf_index: usize,
}

#[cfg(test)]
impl StreamingMerkleBuilder {
    fn new(leaf_count: usize, opened_columns: BTreeSet<usize>) -> Result<Self, String> {
        if !leaf_count.is_power_of_two()
            || opened_columns
                .last()
                .is_some_and(|column_index| *column_index >= leaf_count)
        {
            return Err("streaming Merkle geometry is invalid".to_owned());
        }
        Ok(Self {
            leaf_count,
            opened_columns,
            stack: Vec::with_capacity(leaf_count.ilog2() as usize + 1),
            frontier_by_level_and_index: Vec::new(),
            next_leaf_index: 0,
        })
    }

    fn push_leaf(&mut self, column_index: usize, digest: ColumnDigest) -> Result<(), String> {
        if column_index != self.next_leaf_index || column_index >= self.leaf_count {
            return Err("streaming Merkle leaves are not in canonical order".to_owned());
        }
        self.next_leaf_index += 1;
        self.stack.push(StreamingMerkleNode {
            level: 0,
            index: column_index,
            digest,
            contains_opened_column: self.opened_columns.contains(&column_index),
        });
        while self.stack.len() >= 2 {
            let right_position = self.stack.len() - 1;
            let left_position = right_position - 1;
            if self.stack[left_position].level != self.stack[right_position].level {
                break;
            }
            let right = self.stack.pop().expect("right node exists");
            let left = self.stack.pop().expect("left node exists");
            if left.index ^ 1 != right.index || left.index & 1 != 0 {
                return Err("streaming Merkle siblings are not canonical".to_owned());
            }
            if left.contains_opened_column != right.contains_opened_column {
                let frontier_node = if left.contains_opened_column {
                    &right
                } else {
                    &left
                };
                self.frontier_by_level_and_index.push((
                    frontier_node.level,
                    frontier_node.index,
                    frontier_node.digest,
                ));
            }
            self.stack.push(StreamingMerkleNode {
                level: left.level + 1,
                index: left.index >> 1,
                digest: hash_merkle_parent(&left.digest, &right.digest),
                contains_opened_column: left.contains_opened_column || right.contains_opened_column,
            });
        }
        Ok(())
    }

    fn finish(mut self) -> Result<StreamingColumnCommitment, String> {
        if self.next_leaf_index != self.leaf_count
            || self.stack.len() != 1
            || self.stack[0].level != self.leaf_count.ilog2() as usize
            || self.stack[0].index != 0
        {
            return Err("streaming Merkle tree is incomplete".to_owned());
        }
        self.frontier_by_level_and_index
            .sort_unstable_by_key(|(level, index, _)| (*level, *index));
        let frontier = self
            .frontier_by_level_and_index
            .into_iter()
            .map(|(_, _, digest)| digest)
            .collect::<Vec<_>>();
        if !self.opened_columns.is_empty()
            && frontier.len()
                != canonical_frontier_node_count_from_set(self.opened_columns, self.leaf_count)
        {
            return Err("streaming Merkle frontier has the wrong size".to_owned());
        }
        Ok(StreamingColumnCommitment {
            root: self.stack.pop().expect("root exists").digest,
            frontier,
        })
    }
}

fn column_hash_preamble(expected_row_count: usize, encoded_column_count: usize) -> [u64; 6] {
    let mut words = [0_u64; 6];
    for (word_index, chunk) in super::ROW_CODE_WHIR_PHASE_COLUMN_LEAF_DOMAIN
        .chunks_exact(8)
        .enumerate()
    {
        words[word_index] = u64::from_le_bytes(chunk.try_into().expect("eight-byte domain word"));
    }
    words[4] = expected_row_count as u64;
    words[5] = encoded_column_count as u64;
    words
}

#[cfg(test)]
fn absorb_word(
    state: &mut [u64; SHAKE256_STATE_WORD_LENGTH],
    next_rate_word: &mut usize,
    word: u64,
) {
    state[*next_rate_word] ^= word;
    *next_rate_word += 1;
    if *next_rate_word == SHAKE256_RATE_WORD_LENGTH {
        keccakf(state);
        *next_rate_word = 0;
    }
}

pub(super) fn hash_opened_column(
    values: &[Goldilocks],
    encoded_column_count: usize,
) -> ColumnDigest {
    let mut state = Shake256::default();
    for word in column_hash_preamble(values.len(), encoded_column_count) {
        state.update(&word.to_le_bytes());
    }
    for value in values {
        state.update(&value.as_canonical_u64().to_le_bytes());
    }
    finish_shake256(state)
}

fn hash_merkle_parent(left: &ColumnDigest, right: &ColumnDigest) -> ColumnDigest {
    let mut state = Shake256::default();
    state.update(&(super::ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN.len() as u64).to_le_bytes());
    state.update(super::ROW_CODE_WHIR_PHASE_COLUMN_NODE_DOMAIN);
    for word in left.iter().chain(right) {
        state.update(&word.to_le_bytes());
    }
    finish_shake256(state)
}

fn finish_shake256(state: Shake256) -> ColumnDigest {
    let mut bytes = [0_u8; COLUMN_DIGEST_BYTE_LENGTH];
    state.finalize_xof().read(&mut bytes);
    core::array::from_fn(|word_index| {
        u64::from_le_bytes(
            bytes[word_index * 8..(word_index + 1) * 8]
                .try_into()
                .expect("eight-byte digest word"),
        )
    })
}

#[cfg(test)]
pub(super) struct ColumnMerkleTree {
    levels: Vec<Vec<ColumnDigest>>,
}

#[cfg(test)]
impl ColumnMerkleTree {
    pub(super) fn new(leaves: Vec<ColumnDigest>) -> Result<Self, String> {
        if !leaves.len().is_power_of_two() {
            return Err(format!(
                "column Merkle leaf count {} is not a non-zero power of two",
                leaves.len()
            ));
        }
        let mut levels = vec![leaves];
        while levels.last().expect("at least one Merkle level").len() > 1 {
            let previous = levels.last().expect("at least one Merkle level");
            levels.push(
                previous
                    .chunks_exact(2)
                    .map(|children| hash_merkle_parent(&children[0], &children[1]))
                    .collect(),
            );
        }
        Ok(Self { levels })
    }

    pub(super) fn root(&self) -> ColumnDigest {
        self.levels.last().expect("at least one Merkle level")[0]
    }

    #[cfg(test)]
    pub(super) fn opening(&self, column_index: usize) -> Result<Vec<ColumnDigest>, String> {
        if column_index >= self.levels[0].len() {
            return Err(format!(
                "column index {column_index} is outside Merkle leaf count {}",
                self.levels[0].len()
            ));
        }
        let mut position = column_index;
        let mut path = Vec::with_capacity(self.levels.len() - 1);
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[position ^ 1]);
            position >>= 1;
        }
        Ok(path)
    }

    pub(super) fn canonical_frontier(
        &self,
        column_indices: &[usize],
    ) -> Result<Vec<ColumnDigest>, String> {
        let mut active = canonical_column_index_set(column_indices, self.levels[0].len())?;
        let mut frontier = Vec::with_capacity(canonical_frontier_node_count_from_set(
            active.clone(),
            self.levels[0].len(),
        ));
        for level in &self.levels[..self.levels.len() - 1] {
            for sibling_index in missing_sibling_indices(&active) {
                frontier.push(level[sibling_index]);
            }
            active = active.into_iter().map(|position| position >> 1).collect();
        }
        Ok(frontier)
    }

    #[cfg(test)]
    pub(super) fn exact_stored_byte_length(&self) -> usize {
        self.levels
            .iter()
            .map(|level| level.len() * size_of::<ColumnDigest>())
            .sum()
    }
}

#[cfg(test)]
pub(super) fn canonical_frontier_node_count(
    column_indices: &[usize],
    encoded_column_count: usize,
) -> Result<usize, String> {
    let active = canonical_column_index_set(column_indices, encoded_column_count)?;
    Ok(canonical_frontier_node_count_from_set(
        active,
        encoded_column_count,
    ))
}

fn canonical_frontier_node_count_from_set(
    mut active: BTreeSet<usize>,
    encoded_column_count: usize,
) -> usize {
    let mut count = 0_usize;
    for _ in 0..encoded_column_count.ilog2() {
        count += missing_sibling_indices(&active).len();
        active = active.into_iter().map(|position| position >> 1).collect();
    }
    count
}

fn canonical_column_index_set(
    column_indices: &[usize],
    encoded_column_count: usize,
) -> Result<BTreeSet<usize>, String> {
    if !encoded_column_count.is_power_of_two() || column_indices.is_empty() {
        return Err("column frontier geometry is invalid".to_owned());
    }
    let active = column_indices.iter().copied().collect::<BTreeSet<_>>();
    if active.len() != column_indices.len()
        || active
            .last()
            .is_some_and(|column_index| *column_index >= encoded_column_count)
    {
        return Err("column frontier indices are duplicated or out of range".to_owned());
    }
    Ok(active)
}

fn missing_sibling_indices(active: &BTreeSet<usize>) -> Vec<usize> {
    active
        .iter()
        .copied()
        .map(|position| position ^ 1)
        .filter(|sibling| !active.contains(sibling))
        .collect()
}

#[cfg(test)]
pub(super) fn verify_column_opening(
    root: &ColumnDigest,
    column_index: usize,
    encoded_column_count: usize,
    values: &[Goldilocks],
    path: &[ColumnDigest],
) -> Result<(), String> {
    if !encoded_column_count.is_power_of_two() || column_index >= encoded_column_count {
        return Err("column opening index or encoded column count is invalid".to_owned());
    }
    if path.len() != encoded_column_count.ilog2() as usize {
        return Err(format!(
            "column Merkle path has {} nodes, expected {}",
            path.len(),
            encoded_column_count.ilog2()
        ));
    }
    let mut position = column_index;
    let mut digest = hash_opened_column(values, encoded_column_count);
    for sibling in path {
        digest = if position & 1 == 0 {
            hash_merkle_parent(&digest, sibling)
        } else {
            hash_merkle_parent(sibling, &digest)
        };
        position >>= 1;
    }
    if &digest != root {
        return Err("column opening does not match the committed Merkle root".to_owned());
    }
    Ok(())
}

pub(super) fn verify_column_frontier(
    root: &ColumnDigest,
    encoded_column_count: usize,
    opened_columns: &[(usize, &[Goldilocks])],
    frontier: &[ColumnDigest],
) -> Result<(), String> {
    let column_indices = opened_columns
        .iter()
        .map(|(column_index, _)| *column_index)
        .collect::<Vec<_>>();
    let mut active_indices = canonical_column_index_set(&column_indices, encoded_column_count)?;
    let expected_frontier_node_count =
        canonical_frontier_node_count_from_set(active_indices.clone(), encoded_column_count);
    if frontier.len() != expected_frontier_node_count {
        return Err(format!(
            "column Merkle frontier has {} nodes, expected {expected_frontier_node_count}",
            frontier.len()
        ));
    }

    let mut active_digests = opened_columns
        .iter()
        .map(|(column_index, values)| {
            (
                *column_index,
                hash_opened_column(values, encoded_column_count),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if active_digests.len() != opened_columns.len() {
        return Err("column frontier contains a duplicated opening".to_owned());
    }
    let mut frontier_cursor = 0_usize;
    for _ in 0..encoded_column_count.ilog2() {
        for sibling_index in missing_sibling_indices(&active_indices) {
            let digest = *frontier
                .get(frontier_cursor)
                .ok_or_else(|| "column Merkle frontier ended early".to_owned())?;
            if active_digests.insert(sibling_index, digest).is_some() {
                return Err("column Merkle frontier duplicates an active node".to_owned());
            }
            frontier_cursor += 1;
        }
        let parent_indices = active_indices
            .iter()
            .map(|position| position >> 1)
            .collect::<BTreeSet<_>>();
        let mut parent_digests = BTreeMap::new();
        for parent_index in &parent_indices {
            let left_index = parent_index << 1;
            let left = active_digests
                .get(&left_index)
                .ok_or_else(|| "column Merkle frontier lacks a left child".to_owned())?;
            let right = active_digests
                .get(&(left_index | 1))
                .ok_or_else(|| "column Merkle frontier lacks a right child".to_owned())?;
            parent_digests.insert(*parent_index, hash_merkle_parent(left, right));
        }
        active_indices = parent_indices;
        active_digests = parent_digests;
    }
    if frontier_cursor != frontier.len()
        || active_digests.len() != 1
        || active_digests.get(&0) != Some(root)
    {
        return Err("column Merkle frontier does not reconstruct the committed root".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    fn sample_rows(row_count: usize, column_count: usize) -> Vec<Vec<Goldilocks>> {
        (0..row_count)
            .map(|row_index| {
                (0..column_count)
                    .map(|column_index| {
                        Goldilocks::from_u64(
                            (row_index as u64 + 5) * 131 + column_index as u64 * 17,
                        )
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn parallel_column_hashes_match_independent_shake256() {
        let rows = sample_rows(31, 16);
        let mut hasher =
            StreamingColumnHasher::new(rows.len(), rows[0].len()).expect("valid column geometry");
        for row in &rows {
            hasher.absorb_row(row).expect("valid encoded row");
        }
        let parallel = hasher.finalize().expect("complete row stream");
        for column_index in 0..rows[0].len() {
            let column = rows.iter().map(|row| row[column_index]).collect::<Vec<_>>();
            assert_eq!(
                parallel[column_index],
                hash_opened_column(&column, rows[0].len())
            );
        }
    }

    #[test]
    fn column_hash_binds_geometry_and_row_order() {
        let values = (0..19)
            .map(|value| Goldilocks::from_u64(value + 1))
            .collect::<Vec<_>>();
        let digest = hash_opened_column(&values, 32);
        let mut reordered = values.clone();
        reordered.swap(0, 18);
        assert_ne!(digest, hash_opened_column(&reordered, 32));
        assert_ne!(digest, hash_opened_column(&values, 64));
        assert_ne!(digest, hash_opened_column(&values[..values.len() - 1], 32));
    }

    #[test]
    fn merkle_openings_reject_value_index_path_and_root_mutations() {
        let rows = sample_rows(7, 16);
        let leaves = (0..16)
            .map(|column_index| {
                hash_opened_column(
                    &rows.iter().map(|row| row[column_index]).collect::<Vec<_>>(),
                    16,
                )
            })
            .collect();
        let tree = ColumnMerkleTree::new(leaves).expect("power-of-two Merkle tree");
        for column_index in 0..16 {
            let values = rows.iter().map(|row| row[column_index]).collect::<Vec<_>>();
            let path = tree.opening(column_index).expect("valid leaf index");
            verify_column_opening(&tree.root(), column_index, 16, &values, &path)
                .expect("genuine column opening");

            let mut changed_values = values.clone();
            changed_values[0] += Goldilocks::ONE;
            assert!(
                verify_column_opening(&tree.root(), column_index, 16, &changed_values, &path,)
                    .is_err()
            );
            assert!(
                verify_column_opening(&tree.root(), column_index ^ 1, 16, &values, &path,).is_err()
            );

            let mut changed_path = path.clone();
            changed_path[0][0] ^= 1;
            assert!(
                verify_column_opening(&tree.root(), column_index, 16, &values, &changed_path,)
                    .is_err()
            );
            let mut changed_root = tree.root();
            changed_root[0] ^= 1;
            assert!(
                verify_column_opening(&changed_root, column_index, 16, &values, &path,).is_err()
            );
        }
    }

    #[test]
    fn canonical_frontier_authenticates_distinct_columns_and_rejects_mutations() {
        let rows = sample_rows(9, 64);
        let leaves = (0..64)
            .map(|column_index| {
                hash_opened_column(
                    &rows.iter().map(|row| row[column_index]).collect::<Vec<_>>(),
                    64,
                )
            })
            .collect();
        let tree = ColumnMerkleTree::new(leaves).expect("power-of-two Merkle tree");
        let indices = [1, 2, 3, 17, 41, 62];
        let values = indices
            .iter()
            .map(|column_index| {
                rows.iter()
                    .map(|row| row[*column_index])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let opened = indices
            .iter()
            .copied()
            .zip(values.iter().map(Vec::as_slice))
            .collect::<Vec<_>>();
        let frontier = tree
            .canonical_frontier(&indices)
            .expect("valid canonical frontier");
        assert_eq!(
            frontier.len(),
            canonical_frontier_node_count(&indices, 64).expect("valid geometry")
        );
        assert!(frontier.len() < indices.len() * 6);
        verify_column_frontier(&tree.root(), 64, &opened, &frontier)
            .expect("genuine frontier verifies");

        let mut changed_values = values.clone();
        changed_values[3][4] += Goldilocks::ONE;
        let changed_opened = indices
            .iter()
            .copied()
            .zip(changed_values.iter().map(Vec::as_slice))
            .collect::<Vec<_>>();
        assert!(verify_column_frontier(&tree.root(), 64, &changed_opened, &frontier).is_err());

        let mut changed_frontier = frontier.clone();
        changed_frontier[0][0] ^= 1;
        assert!(verify_column_frontier(&tree.root(), 64, &opened, &changed_frontier).is_err());
        assert!(
            verify_column_frontier(&tree.root(), 64, &opened, &frontier[..frontier.len() - 1])
                .is_err()
        );
        assert!(canonical_frontier_node_count(&[1, 1], 64).is_err());
        assert!(canonical_frontier_node_count(&[64], 64).is_err());
    }

    #[test]
    fn streaming_merkle_root_and_frontier_match_the_materialized_tree() {
        for row_count in [1, 2, 17, 31] {
            for column_count in [2, 8, 64, 256] {
                let rows = sample_rows(row_count, column_count);
                let mut materialized_hasher =
                    StreamingColumnHasher::new(row_count, column_count).expect("valid geometry");
                let mut streaming_hasher =
                    StreamingColumnHasher::new(row_count, column_count).expect("valid geometry");
                for row in &rows {
                    materialized_hasher.absorb_row(row).expect("valid row");
                    streaming_hasher.absorb_row(row).expect("valid row");
                }
                let tree = ColumnMerkleTree::new(
                    materialized_hasher
                        .finalize()
                        .expect("complete materialized hashes"),
                )
                .expect("valid tree");
                let indices = (0..column_count)
                    .filter(|column_index| {
                        column_index % 5 == 1 || *column_index + 1 == column_count
                    })
                    .collect::<Vec<_>>();
                let streaming = streaming_hasher
                    .finalize_commitment(&indices)
                    .expect("complete streaming tree");
                assert_eq!(streaming.root, tree.root());
                assert_eq!(
                    streaming.frontier,
                    tree.canonical_frontier(&indices)
                        .expect("canonical frontier")
                );
                let opened_values = indices
                    .iter()
                    .map(|column_index| {
                        (
                            *column_index,
                            rows.iter()
                                .map(|row| row[*column_index])
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>();
                let opened = opened_values
                    .iter()
                    .map(|(column_index, values)| (*column_index, values.as_slice()))
                    .collect::<Vec<_>>();
                verify_column_frontier(&streaming.root, column_count, &opened, &streaming.frontier)
                    .expect("streamed frontier verifies");
            }
        }
    }

    #[test]
    fn target_state_and_tree_accounting_is_exact() {
        let encoded_column_count = 1_usize << 19;
        assert_eq!(size_of::<[u64; SHAKE256_STATE_WORD_LENGTH]>(), 200);
        assert_eq!(
            StreamingColumnHasher::exact_state_byte_length(encoded_column_count),
            Some(100 * 1_024 * 1_024)
        );

        let small_tree = ColumnMerkleTree::new(vec![[0; COLUMN_DIGEST_WORD_LENGTH]; 16])
            .expect("power-of-two Merkle tree");
        assert_eq!(
            small_tree.exact_stored_byte_length(),
            (2 * 16 - 1) * COLUMN_DIGEST_BYTE_LENGTH
        );
        assert_eq!(
            (2 * encoded_column_count - 1) * COLUMN_DIGEST_BYTE_LENGTH,
            64 * 1_024 * 1_024 - COLUMN_DIGEST_BYTE_LENGTH
        );
    }

    #[test]
    fn malformed_stream_geometry_is_rejected() {
        assert!(StreamingColumnHasher::new(0, 8).is_err());
        assert!(StreamingColumnHasher::new(3, 7).is_err());

        let mut short = StreamingColumnHasher::new(2, 8).expect("valid geometry");
        short.absorb_row(&[Goldilocks::ZERO; 8]).expect("first row");
        assert!(short.finalize().is_err());

        let mut wrong_width = StreamingColumnHasher::new(1, 8).expect("valid geometry");
        assert!(wrong_width.absorb_row(&[Goldilocks::ZERO; 7]).is_err());

        let mut excess = StreamingColumnHasher::new(1, 8).expect("valid geometry");
        excess
            .absorb_row(&[Goldilocks::ZERO; 8])
            .expect("only expected row");
        assert!(excess.absorb_row(&[Goldilocks::ZERO; 8]).is_err());
    }
}
