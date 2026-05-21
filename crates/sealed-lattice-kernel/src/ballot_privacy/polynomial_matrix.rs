use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::{polynomial_ring::PolynomialRing, polynomial_vector::PolynomialVector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolynomialMatrix {
    ring: PolynomialRing,
    rows: usize,
    columns: usize,
    entries: Vec<Vec<u64>>,
}

impl PolynomialMatrix {
    pub fn new(
        ring: PolynomialRing,
        rows: usize,
        columns: usize,
        entries: Vec<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        if rows == 0 || columns == 0 {
            return Err(invalid_matrix("matrix dimensions must be non-zero"));
        }
        if entries.len() != rows * columns {
            return Err(invalid_matrix(format!(
                "matrix entry count must be {}",
                rows * columns
            )));
        }
        for entry in &entries {
            ring.validate_coefficients(entry)?;
        }

        Ok(Self {
            ring,
            rows,
            columns,
            entries,
        })
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

    pub fn entry(&self, row_index: usize, column_index: usize) -> CanonicalResult<&[u64]> {
        if row_index >= self.rows || column_index >= self.columns {
            return Err(invalid_matrix("matrix entry index is out of range"));
        }

        Ok(&self.entries[row_index * self.columns + column_index])
    }

    #[cfg(test)]
    pub fn entries_by_row(&self) -> Vec<Vec<Vec<u64>>> {
        self.entries
            .chunks_exact(self.columns)
            .map(|row| row.to_vec())
            .collect()
    }

    #[cfg(test)]
    pub fn scale(&self, scalar: u64) -> CanonicalResult<Self> {
        let entries = self
            .entries
            .iter()
            .map(|entry| self.ring.scale(scalar, entry))
            .collect::<CanonicalResult<Vec<_>>>()?;

        Self::new(self.ring, self.rows, self.columns, entries)
    }

    pub fn automorphism(&self) -> CanonicalResult<Self> {
        let entries = self
            .entries
            .iter()
            .map(|entry| self.ring.automorphism(entry))
            .collect::<CanonicalResult<Vec<_>>>()?;

        Self::new(self.ring, self.rows, self.columns, entries)
    }

    pub fn multiply_vector(&self, vector: &PolynomialVector) -> CanonicalResult<PolynomialVector> {
        if self.ring != vector.ring() {
            return Err(invalid_matrix("matrix and vector rings do not match"));
        }
        if self.columns != vector.len() {
            return Err(invalid_matrix(
                "matrix column count does not match vector length",
            ));
        }

        let mut output_entries = Vec::with_capacity(self.rows);
        for row_index in 0..self.rows {
            let mut row_sum = vec![0_u64; self.ring.degree()];
            for column_index in 0..self.columns {
                let matrix_entry = &self.entries[row_index * self.columns + column_index];
                let vector_entry = &vector.entries()[column_index];
                let product = self.ring.mul_negacyclic(matrix_entry, vector_entry)?;
                row_sum = self.ring.add(&row_sum, &product)?;
            }
            output_entries.push(row_sum);
        }

        PolynomialVector::new(self.ring, output_entries)
    }

    pub fn evaluate_linear_relation(
        &self,
        witness: &PolynomialVector,
        target: &PolynomialVector,
    ) -> CanonicalResult<PolynomialVector> {
        let product = self.multiply_vector(witness)?;

        product.add(target)
    }
}

fn invalid_matrix(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{PolynomialMatrix, PolynomialRing, PolynomialVector};

    #[test]
    fn multiplies_polynomial_matrix_by_vector() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let matrix = PolynomialMatrix::new(
            ring,
            2,
            2,
            vec![
                vec![1, 0, 0, 0],
                vec![0, 1, 0, 0],
                vec![2, 0, 0, 0],
                vec![0, 0, 1, 0],
            ],
        )
        .expect("matrix should validate");
        let vector = PolynomialVector::new(ring, vec![vec![3, 4, 5, 6], vec![7, 8, 9, 10]])
            .expect("vector should validate");
        let product = matrix
            .multiply_vector(&vector)
            .expect("multiplication should succeed");

        assert_eq!(
            product.entries(),
            &[vec![10, 11, 13, 15], vec![14, 15, 0, 3]]
        );
    }

    #[test]
    fn maps_ring_operations_across_matrix_entries() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let matrix = PolynomialMatrix::new(
            ring,
            1,
            2,
            vec![vec![1, 2, 3, 4, 5, 6, 7, 8], vec![8, 7, 6, 5, 4, 3, 2, 1]],
        )
        .expect("matrix should validate");

        let scaled = matrix.scale(3).expect("scaling should succeed");
        assert_eq!(
            scaled.entries_by_row(),
            vec![vec![
                vec![3, 6, 9, 12, 15, 1, 4, 7],
                vec![7, 4, 1, 15, 12, 9, 6, 3],
            ]]
        );

        let transformed = matrix.automorphism().expect("automorphism should succeed");
        assert_eq!(
            transformed.entries_by_row(),
            vec![vec![
                vec![1, 9, 10, 11, 12, 13, 14, 15],
                vec![8, 16, 15, 14, 13, 12, 11, 10],
            ]]
        );
    }
}
