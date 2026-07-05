//! A salted Merkle commitment to a set of equal-length columns (coset
//! codewords), with batched openings at shared query positions.
//!
//! Each leaf row concatenates every column's value at one coset index, so one
//! opening reveals all columns at that index. Used for the atom PIOP's base
//! (witness) columns and its quotient columns; both are opened at the same FRI
//! query positions so the algebraic identities can be checked pointwise and the
//! FRI-tested random combination bound to the opened values.

use rayon::prelude::*;

use super::super::proof_field::ProofFieldParameters;
use super::merkle::{
    BatchedMerkleOpening, MerkleDigest, MerkleTree, StreamingLeafHasher, consistent_sorted_leaves,
    leaf_hash, sorted_unique_indices, verify_merkle_batch,
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

// A streamed column commitment: byte-identical root, salts, and openings to
// `ColumnCommitment::commit` over the same columns and salt seed, but built one
// column at a time so the prover never holds every codeword at once. The
// declared column count fixes each leaf's framed row length up front; salts are
// drawn in the same per-leaf order as the in-memory path. Peak memory is one
// incremental leaf-hash state per coset position plus whatever single codeword
// the caller is currently absorbing.
pub(super) struct StreamedColumnCommitmentBuilder<const LIMB_COUNT: usize> {
    domain_size: usize,
    column_count: usize,
    absorbed_columns: usize,
    salts: Vec<[u8; 8]>,
    states: Vec<StreamingLeafHasher>,
}

pub(super) struct StreamedColumnCommitment {
    domain_size: usize,
    column_count: usize,
    salts: Vec<[u8; 8]>,
    tree: MerkleTree,
}

impl<const LIMB_COUNT: usize> StreamedColumnCommitmentBuilder<LIMB_COUNT> {
    pub(super) fn begin(
        domain_size: usize,
        column_count: usize,
        salt_seed: &mut u64,
    ) -> CanonicalResult<Self> {
        if column_count == 0 {
            return Err(invalid_column("column set must be non-empty"));
        }
        if !domain_size.is_power_of_two() {
            return Err(invalid_column(
                "columns must share one power-of-two domain length",
            ));
        }
        let row_byte_length = (column_count * LIMB_COUNT * 8) as u64;
        let mut salts = Vec::with_capacity(domain_size);
        let mut states = Vec::with_capacity(domain_size);
        for index in 0..domain_size {
            *salt_seed = salt_seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let salt = salt_seed.to_le_bytes();
            states.push(StreamingLeafHasher::new(index, &salt, row_byte_length));
            salts.push(salt);
        }
        Ok(Self {
            domain_size,
            column_count,
            absorbed_columns: 0,
            salts,
            states,
        })
    }

    pub(super) fn absorb_column(&mut self, codeword: &[[u64; LIMB_COUNT]]) -> CanonicalResult<()> {
        if codeword.len() != self.domain_size {
            return Err(invalid_column(
                "streamed column length must match the domain",
            ));
        }
        if self.absorbed_columns == self.column_count {
            return Err(invalid_column(
                "streamed commitment already absorbed every declared column",
            ));
        }
        self.states
            .par_iter_mut()
            .zip(codeword.par_iter())
            .for_each(|(state, value)| state.absorb_value_words(value));
        self.absorbed_columns += 1;
        Ok(())
    }

    pub(super) fn finalize(self) -> CanonicalResult<StreamedColumnCommitment> {
        if self.absorbed_columns != self.column_count {
            return Err(invalid_column(
                "streamed commitment finalized before every declared column",
            ));
        }
        let leaves = self
            .states
            .into_par_iter()
            .map(StreamingLeafHasher::finalize)
            .collect::<Vec<_>>();
        let tree = MerkleTree::from_leaf_hashes(leaves)?;
        Ok(StreamedColumnCommitment {
            domain_size: self.domain_size,
            column_count: self.column_count,
            salts: self.salts,
            tree,
        })
    }
}

impl StreamedColumnCommitment {
    pub(super) fn root(&self) -> MerkleDigest {
        self.tree.root()
    }

    // Open the sorted unique index set with caller-collected row values (the
    // streamed prover regenerates codewords and extracts opened positions in a
    // later pass). `values_by_row[i]` holds every column's value at
    // `sorted_indices[i]`, in column order; the assembled opening is identical
    // to `ColumnCommitment::open` over the same data.
    pub(super) fn open_rows<const LIMB_COUNT: usize>(
        &self,
        sorted_indices: &[usize],
        values_by_row: Vec<Vec<[u64; LIMB_COUNT]>>,
    ) -> CanonicalResult<ColumnOpening<LIMB_COUNT>> {
        if sorted_indices.len() != values_by_row.len() {
            return Err(invalid_column(
                "opened row values must match the opened index count",
            ));
        }
        if sorted_indices
            .iter()
            .any(|index| *index >= self.domain_size)
            || sorted_indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid_column(
                "opened indices must be sorted, unique, and inside the domain",
            ));
        }
        if values_by_row
            .iter()
            .any(|row| row.len() != self.column_count)
        {
            return Err(invalid_column(
                "opened row width must match the committed column count",
            ));
        }
        let opening = self.tree.open_batch(sorted_indices);
        let rows = sorted_indices
            .iter()
            .zip(values_by_row)
            .map(|(&index, values)| ColumnRow {
                index,
                values,
                salt: self.salts[index].to_vec(),
            })
            .collect();
        Ok(ColumnOpening { rows, opening })
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

    #[test]
    fn streamed_commitment_is_byte_identical_to_in_memory() {
        // Same columns, same salt seed: the streamed builder must produce the
        // same root, the same salts, and openings that verify identically to
        // the in-memory path. This pins the streamed leaf framing to the
        // canonical single-shot `leaf_hash`.
        let parameters = sixteen_limb_group_field_parameters();
        let size = 256;
        let columns = vec![
            column(&parameters, size, 11),
            column(&parameters, size, 22),
            column(&parameters, size, 33),
            column(&parameters, size, 44),
        ];

        let mut in_memory_seed = 0xfeed;
        let in_memory =
            ColumnCommitment::commit(columns.clone(), &mut in_memory_seed).expect("commit");

        let mut streamed_seed = 0xfeed;
        let mut builder =
            StreamedColumnCommitmentBuilder::<13>::begin(size, columns.len(), &mut streamed_seed)
                .expect("begin");
        for codeword in &columns {
            builder.absorb_column(codeword).expect("absorb");
        }
        let streamed = builder.finalize().expect("finalize");

        assert_eq!(streamed.root(), in_memory.root(), "roots must match");
        assert_eq!(
            in_memory_seed, streamed_seed,
            "both paths must advance the salt seed identically"
        );

        // Openings assembled from caller-collected values must equal the
        // in-memory openings and verify.
        let indices = [5_usize, 9, 9, 77, 200, 255];
        let sorted = sorted_unique_indices(indices.iter().copied());
        let values_by_row = sorted
            .iter()
            .map(|&index| columns.iter().map(|c| c[index]).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let streamed_opening = streamed
            .open_rows(&sorted, values_by_row)
            .expect("open rows");
        let in_memory_opening = in_memory.open(&indices);
        assert_eq!(
            streamed_opening.rows.len(),
            in_memory_opening.rows.len(),
            "row counts must match"
        );
        for (streamed_row, in_memory_row) in streamed_opening
            .rows
            .iter()
            .zip(in_memory_opening.rows.iter())
        {
            assert_eq!(streamed_row.index, in_memory_row.index);
            assert_eq!(streamed_row.values, in_memory_row.values);
            assert_eq!(streamed_row.salt, in_memory_row.salt);
        }
        assert_eq!(
            streamed_opening.opening.authentication_nodes,
            in_memory_opening.opening.authentication_nodes,
            "authentication nodes must match"
        );
        assert!(
            verify_column_opening(&streamed.root(), size, columns.len(), &streamed_opening)
                .is_some(),
            "streamed opening must verify"
        );
    }

    #[test]
    fn streamed_commitment_rejects_column_miscounts() {
        let size = 64;
        let parameters = sixteen_limb_group_field_parameters();
        let columns = [column(&parameters, size, 1), column(&parameters, size, 2)];
        let mut seed = 0x77;
        let mut builder =
            StreamedColumnCommitmentBuilder::<13>::begin(size, 2, &mut seed).expect("begin");
        builder.absorb_column(&columns[0]).expect("absorb");
        // Finalizing before every declared column is rejected.
        assert!(builder.finalize().is_err());

        let mut seed = 0x78;
        let mut builder =
            StreamedColumnCommitmentBuilder::<13>::begin(size, 1, &mut seed).expect("begin");
        builder.absorb_column(&columns[0]).expect("absorb");
        // Absorbing more columns than declared is rejected.
        assert!(builder.absorb_column(&columns[1]).is_err());
    }
}
