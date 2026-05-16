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
}
