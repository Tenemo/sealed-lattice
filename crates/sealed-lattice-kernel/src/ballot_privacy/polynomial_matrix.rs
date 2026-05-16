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
}
