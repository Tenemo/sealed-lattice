use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::{
    polynomial_matrix::PolynomialMatrix, polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePolynomialMatrixEntry {
    row_index: usize,
    column_index: usize,
    coefficients: Vec<u64>,
}

impl SparsePolynomialMatrixEntry {
    pub fn new(row_index: usize, column_index: usize, coefficients: Vec<u64>) -> Self {
        Self {
            row_index,
            column_index,
            coefficients,
        }
    }

    pub fn row_index(&self) -> usize {
        self.row_index
    }

    pub fn column_index(&self) -> usize {
        self.column_index
    }

    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePolynomialMatrix {
    ring: PolynomialRing,
    rows: usize,
    columns: usize,
    entries: Vec<SparsePolynomialMatrixEntry>,
}

impl SparsePolynomialMatrix {
    pub fn new(
        ring: PolynomialRing,
        rows: usize,
        columns: usize,
        entries: Vec<SparsePolynomialMatrixEntry>,
    ) -> CanonicalResult<Self> {
        if rows == 0 || columns == 0 {
            return Err(invalid_sparse_matrix(
                "sparse matrix dimensions must be non-zero",
            ));
        }

        let mut previous_position = None;
        for entry in &entries {
            if entry.row_index >= rows || entry.column_index >= columns {
                return Err(invalid_sparse_matrix(
                    "sparse matrix entry position is out of range",
                ));
            }
            let entry_position = (entry.row_index, entry.column_index);
            if let Some(previous_position) = previous_position
                && entry_position <= previous_position
            {
                return Err(invalid_sparse_matrix(
                    "sparse matrix entries must be strictly sorted in row-major order",
                ));
            }
            ring.validate_coefficients(&entry.coefficients)?;
            if is_zero_polynomial(&entry.coefficients) {
                return Err(invalid_sparse_matrix(
                    "sparse matrix entries must not store zero polynomials",
                ));
            }
            previous_position = Some(entry_position);
        }

        Ok(Self {
            ring,
            rows,
            columns,
            entries,
        })
    }

    pub fn zero(ring: PolynomialRing, rows: usize, columns: usize) -> CanonicalResult<Self> {
        Self::new(ring, rows, columns, Vec::new())
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn columns(&self) -> usize {
        self.columns
    }

    pub fn ring(&self) -> PolynomialRing {
        self.ring
    }

    pub fn entries(&self) -> &[SparsePolynomialMatrixEntry] {
        &self.entries
    }

    pub fn is_upper_diagonal(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| entry.row_index <= entry.column_index)
    }

    pub fn to_dense(&self) -> CanonicalResult<PolynomialMatrix> {
        let mut dense_entries = vec![vec![0_u64; self.ring.degree()]; self.rows * self.columns];
        for entry in &self.entries {
            dense_entries[entry.row_index * self.columns + entry.column_index] =
                entry.coefficients.clone();
        }

        PolynomialMatrix::new(self.ring, self.rows, self.columns, dense_entries)
    }

    pub fn add(&self, other: &Self) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;

        let mut merged_entries = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut left_index = 0_usize;
        let mut right_index = 0_usize;
        while left_index < self.entries.len() || right_index < other.entries.len() {
            match (self.entries.get(left_index), other.entries.get(right_index)) {
                (Some(left_entry), Some(right_entry))
                    if entry_position(left_entry) == entry_position(right_entry) =>
                {
                    let sum = self
                        .ring
                        .add(&left_entry.coefficients, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&sum) {
                        merged_entries.push(SparsePolynomialMatrixEntry::new(
                            left_entry.row_index,
                            left_entry.column_index,
                            sum,
                        ));
                    }
                    left_index += 1;
                    right_index += 1;
                }
                (Some(left_entry), Some(right_entry))
                    if entry_position(left_entry) < entry_position(right_entry) =>
                {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (Some(_), Some(right_entry)) => {
                    merged_entries.push(right_entry.clone());
                    right_index += 1;
                }
                (Some(left_entry), None) => {
                    merged_entries.push(left_entry.clone());
                    left_index += 1;
                }
                (None, Some(right_entry)) => {
                    merged_entries.push(right_entry.clone());
                    right_index += 1;
                }
                (None, None) => break,
            }
        }

        Self::new(self.ring, self.rows, self.columns, merged_entries)
    }

    pub fn scale(&self, scalar: u64) -> CanonicalResult<Self> {
        let mut scaled_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let scaled_coefficients = self.ring.scale(scalar, &entry.coefficients)?;
            if !is_zero_polynomial(&scaled_coefficients) {
                scaled_entries.push(SparsePolynomialMatrixEntry::new(
                    entry.row_index,
                    entry.column_index,
                    scaled_coefficients,
                ));
            }
        }

        Self::new(self.ring, self.rows, self.columns, scaled_entries)
    }

    pub(crate) fn scale_by_polynomial(&self, polynomial: &[u64]) -> CanonicalResult<Self> {
        self.ring.validate_coefficients(polynomial)?;

        let mut scaled_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let scaled_coefficients = self.ring.mul_negacyclic(polynomial, &entry.coefficients)?;
            if !is_zero_polynomial(&scaled_coefficients) {
                scaled_entries.push(SparsePolynomialMatrixEntry::new(
                    entry.row_index,
                    entry.column_index,
                    scaled_coefficients,
                ));
            }
        }

        Self::new(self.ring, self.rows, self.columns, scaled_entries)
    }

    pub(crate) fn resize(
        &self,
        resized_rows: usize,
        resized_columns: usize,
    ) -> CanonicalResult<Self> {
        if resized_rows < self.rows || resized_columns < self.columns {
            return Err(invalid_sparse_matrix(
                "sparse matrix resize cannot shrink existing entries",
            ));
        }

        Self::new(
            self.ring,
            resized_rows,
            resized_columns,
            self.entries.clone(),
        )
    }

    pub fn automorphism(&self) -> CanonicalResult<Self> {
        let mut transformed_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            transformed_entries.push(SparsePolynomialMatrixEntry::new(
                entry.row_index,
                entry.column_index,
                self.ring.automorphism(&entry.coefficients)?,
            ));
        }

        Self::new(self.ring, self.rows, self.columns, transformed_entries)
    }

    pub fn left_rotate_negacyclic(&self, rotation: usize) -> CanonicalResult<Self> {
        let mut rotated_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            rotated_entries.push(SparsePolynomialMatrixEntry::new(
                entry.row_index,
                entry.column_index,
                self.ring
                    .left_rotate_negacyclic(&entry.coefficients, rotation)?,
            ));
        }

        Self::new(self.ring, self.rows, self.columns, rotated_entries)
    }

    pub fn shuffle_upper_diagonal_automorphism_by_pairs(&self) -> CanonicalResult<Self> {
        if !self.rows.is_multiple_of(2) || !self.columns.is_multiple_of(2) {
            return Err(invalid_sparse_matrix(
                "pair shuffle requires even sparse matrix dimensions",
            ));
        }
        if !self.is_upper_diagonal() {
            return Err(invalid_sparse_matrix(
                "pair shuffle requires an upper-diagonal sparse matrix",
            ));
        }

        let mut transformed_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let (transformed_row_index, transformed_column_index) =
                shuffled_upper_diagonal_pair_position(entry.row_index, entry.column_index);
            transformed_entries.push(SparsePolynomialMatrixEntry::new(
                transformed_row_index,
                transformed_column_index,
                self.ring.automorphism(&entry.coefficients)?,
            ));
        }
        transformed_entries.sort_by_key(entry_position);

        Self::new(self.ring, self.rows, self.columns, transformed_entries)
    }

    pub fn multiply_vector(&self, vector: &PolynomialVector) -> CanonicalResult<PolynomialVector> {
        if self.ring != vector.ring() {
            return Err(invalid_sparse_matrix(
                "sparse matrix and vector rings do not match",
            ));
        }
        if self.columns != vector.len() {
            return Err(invalid_sparse_matrix(
                "sparse matrix column count does not match vector length",
            ));
        }

        let mut output_entries = vec![vec![0_u64; self.ring.degree()]; self.rows];
        for entry in &self.entries {
            let vector_entry = &vector.entries()[entry.column_index];
            let product = self
                .ring
                .mul_negacyclic(&entry.coefficients, vector_entry)?;
            output_entries[entry.row_index] =
                self.ring.add(&output_entries[entry.row_index], &product)?;
        }

        PolynomialVector::new(self.ring, output_entries)
    }

    fn require_same_shape(&self, other: &Self) -> CanonicalResult<()> {
        if self.ring != other.ring {
            return Err(invalid_sparse_matrix("sparse matrix rings do not match"));
        }
        if self.rows != other.rows || self.columns != other.columns {
            return Err(invalid_sparse_matrix(
                "sparse matrix dimensions do not match",
            ));
        }

        Ok(())
    }
}

fn entry_position(entry: &SparsePolynomialMatrixEntry) -> (usize, usize) {
    (entry.row_index, entry.column_index)
}

fn shuffled_upper_diagonal_pair_position(row_index: usize, column_index: usize) -> (usize, usize) {
    match (row_index.is_multiple_of(2), column_index.is_multiple_of(2)) {
        (true, true) => (row_index + 1, column_index + 1),
        (false, false) => (row_index - 1, column_index - 1),
        (false, true) => (row_index - 1, column_index + 1),
        (true, false) if row_index + 1 > column_index - 1 => (row_index, column_index),
        (true, false) => (row_index + 1, column_index - 1),
    }
}

fn is_zero_polynomial(coefficients: &[u64]) -> bool {
    coefficients.iter().all(|coefficient| *coefficient == 0)
}

fn invalid_sparse_matrix(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        PolynomialMatrix, PolynomialRing, PolynomialVector, SparsePolynomialMatrix,
        SparsePolynomialMatrixEntry,
    };

    #[test]
    fn sparse_matrix_multiplication_matches_dense_matrix_multiplication() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            3,
            3,
            vec![
                SparsePolynomialMatrixEntry::new(0, 1, vec![1, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 0, vec![0, 1, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 2, vec![2, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(2, 2, vec![0, 0, 1, 0]),
            ],
        )
        .expect("sparse matrix should validate");
        let dense_matrix = sparse_matrix
            .to_dense()
            .expect("dense matrix conversion should succeed");
        let vector = PolynomialVector::new(
            ring,
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]],
        )
        .expect("vector should validate");

        assert_eq!(
            sparse_matrix
                .multiply_vector(&vector)
                .expect("sparse multiplication should succeed"),
            dense_matrix
                .multiply_vector(&vector)
                .expect("dense multiplication should succeed")
        );
    }

    #[test]
    fn adds_sparse_matrices_and_drops_cancelled_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let left = SparsePolynomialMatrix::new(
            ring,
            3,
            3,
            vec![
                SparsePolynomialMatrixEntry::new(0, 0, vec![1, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 2, vec![3, 4, 0, 0]),
            ],
        )
        .expect("left matrix should validate");
        let right = SparsePolynomialMatrix::new(
            ring,
            3,
            3,
            vec![
                SparsePolynomialMatrixEntry::new(1, 2, vec![14, 13, 0, 0]),
                SparsePolynomialMatrixEntry::new(2, 2, vec![5, 0, 0, 0]),
            ],
        )
        .expect("right matrix should validate");
        let sum = left.add(&right).expect("addition should succeed");

        assert_eq!(sum.entries().len(), 2);
        assert_eq!(sum.entries()[0].row_index(), 0);
        assert_eq!(sum.entries()[0].column_index(), 0);
        assert_eq!(sum.entries()[0].coefficients(), &[1, 0, 0, 0]);
        assert_eq!(sum.entries()[1].row_index(), 2);
        assert_eq!(sum.entries()[1].column_index(), 2);
        assert_eq!(sum.entries()[1].coefficients(), &[5, 0, 0, 0]);
    }

    #[test]
    fn checks_upper_diagonal_sparse_matrices() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let upper = SparsePolynomialMatrix::new(
            ring,
            3,
            3,
            vec![
                SparsePolynomialMatrixEntry::new(0, 2, vec![1, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 1, vec![1, 0, 0, 0]),
            ],
        )
        .expect("upper matrix should validate");
        let lower = SparsePolynomialMatrix::new(
            ring,
            3,
            3,
            vec![SparsePolynomialMatrixEntry::new(2, 0, vec![1, 0, 0, 0])],
        )
        .expect("lower matrix should validate");

        assert!(upper.is_upper_diagonal());
        assert!(!lower.is_upper_diagonal());
    }

    #[test]
    fn rejects_noncanonical_sparse_matrix_layouts() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");

        assert!(
            SparsePolynomialMatrix::new(
                ring,
                3,
                3,
                vec![
                    SparsePolynomialMatrixEntry::new(1, 0, vec![1, 0, 0, 0]),
                    SparsePolynomialMatrixEntry::new(0, 2, vec![1, 0, 0, 0]),
                ],
            )
            .expect_err("unsorted entries should fail")
            .message
            .contains("row-major")
        );
        assert!(
            SparsePolynomialMatrix::new(
                ring,
                3,
                3,
                vec![SparsePolynomialMatrixEntry::new(3, 0, vec![1, 0, 0, 0])],
            )
            .expect_err("out-of-range row should fail")
            .message
            .contains("out of range")
        );
        assert!(
            SparsePolynomialMatrix::new(
                ring,
                3,
                3,
                vec![SparsePolynomialMatrixEntry::new(0, 0, vec![0, 0, 0, 0])],
            )
            .expect_err("stored zero polynomial should fail")
            .message
            .contains("zero polynomials")
        );
    }

    #[test]
    fn dense_conversion_preserves_dimensions() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            2,
            3,
            vec![SparsePolynomialMatrixEntry::new(1, 2, vec![7, 0, 0, 0])],
        )
        .expect("sparse matrix should validate");
        let dense_matrix = sparse_matrix
            .to_dense()
            .expect("dense matrix conversion should succeed");
        let expected_dense_matrix = PolynomialMatrix::new(
            ring,
            2,
            3,
            vec![
                vec![0, 0, 0, 0],
                vec![0, 0, 0, 0],
                vec![0, 0, 0, 0],
                vec![0, 0, 0, 0],
                vec![0, 0, 0, 0],
                vec![7, 0, 0, 0],
            ],
        )
        .expect("expected dense matrix should validate");

        assert_eq!(dense_matrix, expected_dense_matrix);
    }

    #[test]
    fn maps_ring_operations_across_sparse_matrix_entries_without_changing_positions() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            3,
            3,
            vec![
                SparsePolynomialMatrixEntry::new(0, 1, vec![1, 2, 3, 4, 5, 6, 7, 8]),
                SparsePolynomialMatrixEntry::new(2, 2, vec![8, 7, 6, 5, 4, 3, 2, 1]),
            ],
        )
        .expect("sparse matrix should validate");

        let scaled = sparse_matrix.scale(3).expect("scaling should succeed");
        assert_eq!(scaled.entries()[0].row_index(), 0);
        assert_eq!(scaled.entries()[0].column_index(), 1);
        assert_eq!(
            scaled.entries()[0].coefficients(),
            &[3, 6, 9, 12, 15, 1, 4, 7]
        );
        assert_eq!(scaled.entries()[1].row_index(), 2);
        assert_eq!(scaled.entries()[1].column_index(), 2);
        assert_eq!(
            scaled.entries()[1].coefficients(),
            &[7, 4, 1, 15, 12, 9, 6, 3]
        );

        let transformed = sparse_matrix
            .automorphism()
            .expect("automorphism should succeed");
        assert_eq!(transformed.entries()[0].row_index(), 0);
        assert_eq!(transformed.entries()[0].column_index(), 1);
        assert_eq!(
            transformed.entries()[0].coefficients(),
            &[1, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(transformed.entries()[1].row_index(), 2);
        assert_eq!(transformed.entries()[1].column_index(), 2);
        assert_eq!(
            transformed.entries()[1].coefficients(),
            &[8, 16, 15, 14, 13, 12, 11, 10]
        );
    }

    #[test]
    fn scaling_sparse_matrix_by_zero_drops_all_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            2,
            2,
            vec![
                SparsePolynomialMatrixEntry::new(0, 0, vec![1, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 1, vec![0, 2, 0, 0]),
            ],
        )
        .expect("sparse matrix should validate");

        let scaled = sparse_matrix.scale(0).expect("scaling should succeed");

        assert!(scaled.entries().is_empty());
        assert_eq!(scaled.rows(), 2);
        assert_eq!(scaled.columns(), 2);
    }

    #[test]
    fn polynomial_scaling_multiplies_each_sparse_entry() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            2,
            2,
            vec![
                SparsePolynomialMatrixEntry::new(0, 0, vec![1, 2, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 1, vec![0, 1, 0, 0]),
            ],
        )
        .expect("sparse matrix should validate");

        let scaled = sparse_matrix
            .scale_by_polynomial(&[3, 4, 0, 0])
            .expect("polynomial scaling should succeed");

        assert_eq!(scaled.entries().len(), 2);
        assert_eq!(scaled.entries()[0].coefficients(), &[3, 10, 8, 0]);
        assert_eq!(scaled.entries()[1].coefficients(), &[0, 3, 4, 0]);
    }

    #[test]
    fn resize_expands_shape_without_moving_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            2,
            2,
            vec![SparsePolynomialMatrixEntry::new(1, 1, vec![7, 0, 0, 0])],
        )
        .expect("sparse matrix should validate");

        let resized = sparse_matrix
            .resize(4, 5)
            .expect("expanding resize should succeed");

        assert_eq!(resized.rows(), 4);
        assert_eq!(resized.columns(), 5);
        assert_eq!(resized.entries()[0].row_index(), 1);
        assert_eq!(resized.entries()[0].column_index(), 1);
        assert!(
            sparse_matrix
                .resize(1, 2)
                .expect_err("shrinking rows should fail")
                .message
                .contains("cannot shrink")
        );
    }

    #[test]
    fn left_rotates_sparse_matrix_coefficients_without_changing_positions() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            3,
            3,
            vec![
                SparsePolynomialMatrixEntry::new(0, 1, vec![1, 2, 3, 4, 5, 6, 7, 8]),
                SparsePolynomialMatrixEntry::new(2, 2, vec![8, 7, 6, 5, 4, 3, 2, 1]),
            ],
        )
        .expect("sparse matrix should validate");

        let rotated = sparse_matrix
            .left_rotate_negacyclic(3)
            .expect("rotation should succeed");

        assert_eq!(rotated.entries()[0].row_index(), 0);
        assert_eq!(rotated.entries()[0].column_index(), 1);
        assert_eq!(
            rotated.entries()[0].coefficients(),
            &[11, 10, 9, 1, 2, 3, 4, 5]
        );
        assert_eq!(rotated.entries()[1].row_index(), 2);
        assert_eq!(rotated.entries()[1].column_index(), 2);
        assert_eq!(
            rotated.entries()[1].coefficients(),
            &[14, 15, 16, 8, 7, 6, 5, 4]
        );
    }

    #[test]
    fn shuffle_automorphism_preserves_upper_diagonal_matrix_layout() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            6,
            6,
            vec![
                SparsePolynomialMatrixEntry::new(0, 0, vec![1, 2, 3, 4, 5, 6, 7, 8]),
                SparsePolynomialMatrixEntry::new(0, 1, vec![2, 0, 0, 0, 0, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 2, vec![3, 0, 0, 0, 0, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(1, 3, vec![4, 0, 0, 0, 0, 0, 0, 0]),
                SparsePolynomialMatrixEntry::new(2, 4, vec![5, 0, 0, 0, 0, 0, 0, 0]),
            ],
        )
        .expect("sparse matrix should validate");

        let transformed = sparse_matrix
            .shuffle_upper_diagonal_automorphism_by_pairs()
            .expect("shuffle automorphism should succeed");

        assert!(transformed.is_upper_diagonal());
        assert_eq!(transformed.entries()[0].row_index(), 0);
        assert_eq!(transformed.entries()[0].column_index(), 1);
        assert_eq!(
            transformed.entries()[0].coefficients(),
            &[2, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(transformed.entries()[1].row_index(), 0);
        assert_eq!(transformed.entries()[1].column_index(), 2);
        assert_eq!(
            transformed.entries()[1].coefficients(),
            &[4, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(transformed.entries()[2].row_index(), 0);
        assert_eq!(transformed.entries()[2].column_index(), 3);
        assert_eq!(
            transformed.entries()[2].coefficients(),
            &[3, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(transformed.entries()[3].row_index(), 1);
        assert_eq!(transformed.entries()[3].column_index(), 1);
        assert_eq!(
            transformed.entries()[3].coefficients(),
            &[1, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(transformed.entries()[4].row_index(), 3);
        assert_eq!(transformed.entries()[4].column_index(), 5);
        assert_eq!(
            transformed.entries()[4].coefficients(),
            &[5, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn shuffle_automorphism_rejects_non_upper_diagonal_matrix() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_matrix = SparsePolynomialMatrix::new(
            ring,
            4,
            4,
            vec![SparsePolynomialMatrixEntry::new(2, 0, vec![1, 0, 0, 0])],
        )
        .expect("sparse matrix should validate");

        let error = sparse_matrix
            .shuffle_upper_diagonal_automorphism_by_pairs()
            .expect_err("lower diagonal matrix should fail");

        assert!(error.message.contains("upper-diagonal"));
    }
}
