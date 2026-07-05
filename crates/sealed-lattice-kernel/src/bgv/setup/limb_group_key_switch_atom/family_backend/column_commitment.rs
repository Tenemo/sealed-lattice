//! A salted Merkle commitment to a set of equal-length columns (coset
//! codewords), with batched openings at shared query positions.
//!
//! Each leaf row concatenates every column's value at one coset index, so one
//! opening reveals all columns at that index. Used for the atom PIOP's base
//! (witness) columns and its quotient columns; both are opened at the same FRI
//! query positions so the algebraic identities can be checked pointwise and the
//! FRI-tested random combination bound to the opened values.

use super::super::proof_field::ProofFieldParameters;
use super::merkle::{
    BatchedMerkleOpening, MerkleDigest, MerkleTree, consistent_sorted_leaves, leaf_hash,
    sorted_unique_indices, verify_merkle_batch,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub(super) struct ColumnCommitment<const LIMB_COUNT: usize> {
    columns: Vec<Vec<[u64; LIMB_COUNT]>>,
    salts: Vec<Vec<u8>>,
    tree: MerkleTree,
}

// One opened leaf row: every column's value at a coset index, the salt, and the
// index. The batched opening for a set of these is carried alongside.
pub(super) struct ColumnRow<const LIMB_COUNT: usize> {
    pub(super) index: usize,
    pub(super) values: Vec<[u64; LIMB_COUNT]>,
    pub(super) salt: Vec<u8>,
}

pub(super) struct ColumnOpening<const LIMB_COUNT: usize> {
    pub(super) rows: Vec<ColumnRow<LIMB_COUNT>>,
    pub(super) opening: BatchedMerkleOpening,
}

fn invalid_column(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

fn row_words<const LIMB_COUNT: usize>(values: &[[u64; LIMB_COUNT]]) -> Vec<u64> {
    let mut words = Vec::with_capacity(values.len() * LIMB_COUNT);
    for value in values {
        words.extend_from_slice(value);
    }
    words
}

impl<const LIMB_COUNT: usize> ColumnCommitment<LIMB_COUNT> {
    // Commit a set of columns, each of the same power-of-two length. `salt_seed`
    // advances a deterministic per-attempt salt stream.
    pub(super) fn commit(
        columns: Vec<Vec<[u64; LIMB_COUNT]>>,
        salt_seed: &mut u64,
    ) -> CanonicalResult<Self> {
        if columns.is_empty() {
            return Err(invalid_column("column set must be non-empty"));
        }
        let domain_size = columns[0].len();
        if !domain_size.is_power_of_two()
            || columns.iter().any(|column| column.len() != domain_size)
        {
            return Err(invalid_column(
                "columns must share one power-of-two domain length",
            ));
        }
        let mut salts = Vec::with_capacity(domain_size);
        let mut leaves = Vec::with_capacity(domain_size);
        for index in 0..domain_size {
            *salt_seed = salt_seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let salt = salt_seed.to_le_bytes().to_vec();
            let row = columns
                .iter()
                .map(|column| column[index])
                .collect::<Vec<_>>();
            leaves.push(leaf_hash(index, &salt, &row_words(&row)));
            salts.push(salt);
        }
        let tree = MerkleTree::from_leaf_hashes(leaves)?;
        Ok(Self {
            columns,
            salts,
            tree,
        })
    }

    pub(super) fn root(&self) -> MerkleDigest {
        self.tree.root()
    }

    pub(super) fn column_count(&self) -> usize {
        self.columns.len()
    }

    pub(super) fn value(&self, column: usize, index: usize) -> [u64; LIMB_COUNT] {
        self.columns[column][index]
    }

    // Open a set of indices, returning each requested row and one batched
    // authentication path.
    pub(super) fn open(&self, indices: &[usize]) -> ColumnOpening<LIMB_COUNT> {
        let sorted = sorted_unique_indices(indices.iter().copied());
        let opening = self.tree.open_batch(&sorted);
        let rows = sorted
            .iter()
            .map(|&index| ColumnRow {
                index,
                values: self.columns.iter().map(|column| column[index]).collect(),
                salt: self.salts[index].clone(),
            })
            .collect();
        ColumnOpening { rows, opening }
    }
}

// Verify a column opening against a committed root: authenticate every row and
// return the opened rows indexed by coset position, or None on any failure.
pub(super) fn verify_column_opening<const LIMB_COUNT: usize>(
    root: &MerkleDigest,
    domain_size: usize,
    expected_column_count: usize,
    opening: &ColumnOpening<LIMB_COUNT>,
) -> Option<std::collections::BTreeMap<usize, Vec<[u64; LIMB_COUNT]>>> {
    if !domain_size.is_power_of_two() {
        return None;
    }
    let mut leaves = Vec::with_capacity(opening.rows.len());
    let mut by_index = std::collections::BTreeMap::new();
    for row in &opening.rows {
        if row.values.len() != expected_column_count || row.index >= domain_size {
            return None;
        }
        leaves.push((
            row.index,
            leaf_hash(row.index, &row.salt, &row_words(&row.values)),
        ));
        by_index.insert(row.index, row.values.clone());
    }
    let leaves = consistent_sorted_leaves(leaves)?;
    let depth = domain_size.trailing_zeros() as usize;
    if !verify_merkle_batch(root, depth, &leaves, &opening.opening) {
        return None;
    }
    Some(by_index)
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    fn column<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        size: usize,
        seed: u64,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut state = seed;
        (0..size)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                parameters.unsigned_word_to_element(state)
            })
            .collect()
    }

    #[test]
    fn column_opening_round_trips_and_rejects_tampering() {
        let parameters = sixteen_limb_group_field_parameters();
        let size = 256;
        let columns = vec![
            column(&parameters, size, 1),
            column(&parameters, size, 2),
            column(&parameters, size, 3),
        ];
        let mut salt_seed = 0x1;
        let commitment = ColumnCommitment::commit(columns.clone(), &mut salt_seed).expect("commit");
        let indices = [3_usize, 3, 100, 7, 200];
        let opening = commitment.open(&indices);
        let opened = verify_column_opening(&commitment.root(), size, 3, &opening)
            .expect("valid opening verifies");
        for &index in &[3_usize, 100, 7, 200] {
            let expected = columns.iter().map(|c| c[index]).collect::<Vec<_>>();
            assert_eq!(opened.get(&index), Some(&expected));
        }

        // Tampering a value breaks authentication.
        let mut tampered = commitment.open(&indices);
        tampered.rows[0].values[0] = parameters.add(&tampered.rows[0].values[0], &parameters.one());
        assert!(verify_column_opening(&commitment.root(), size, 3, &tampered).is_none());
    }
}
