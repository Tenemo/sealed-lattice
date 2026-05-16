use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::{polynomial_ring::PolynomialRing, polynomial_vector::PolynomialVector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePolynomialVectorEntry {
    position: usize,
    coefficients: Vec<u64>,
}

impl SparsePolynomialVectorEntry {
    pub fn new(position: usize, coefficients: Vec<u64>) -> Self {
        Self {
            position,
            coefficients,
        }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePolynomialVector {
    ring: PolynomialRing,
    length: usize,
    entries: Vec<SparsePolynomialVectorEntry>,
}

impl SparsePolynomialVector {
    pub fn new(
        ring: PolynomialRing,
        length: usize,
        entries: Vec<SparsePolynomialVectorEntry>,
    ) -> CanonicalResult<Self> {
        if length == 0 {
            return Err(invalid_sparse_vector(
                "sparse vector length must be non-zero",
            ));
        }

        let mut previous_position = None;
        for entry in &entries {
            if entry.position >= length {
                return Err(invalid_sparse_vector(
                    "sparse vector entry position is out of range",
                ));
            }
            if let Some(previous_position) = previous_position
                && entry.position <= previous_position
            {
                return Err(invalid_sparse_vector(
                    "sparse vector entries must be strictly sorted by position",
                ));
            }
            ring.validate_coefficients(&entry.coefficients)?;
            if is_zero_polynomial(&entry.coefficients) {
                return Err(invalid_sparse_vector(
                    "sparse vector entries must not store zero polynomials",
                ));
            }
            previous_position = Some(entry.position);
        }

        Ok(Self {
            ring,
            length,
            entries,
        })
    }

    pub fn zero(ring: PolynomialRing, length: usize) -> CanonicalResult<Self> {
        Self::new(ring, length, Vec::new())
    }

    pub fn ring(&self) -> PolynomialRing {
        self.ring
    }

    pub fn length(&self) -> usize {
        self.length
    }

    pub fn entries(&self) -> &[SparsePolynomialVectorEntry] {
        &self.entries
    }

    pub fn to_dense(&self) -> CanonicalResult<PolynomialVector> {
        let mut dense_entries = vec![vec![0_u64; self.ring.degree()]; self.length];
        for entry in &self.entries {
            dense_entries[entry.position] = entry.coefficients.clone();
        }

        PolynomialVector::new(self.ring, dense_entries)
    }

    pub fn add(&self, other: &Self) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;

        let mut merged_entries = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut left_index = 0_usize;
        let mut right_index = 0_usize;
        while left_index < self.entries.len() || right_index < other.entries.len() {
            match (self.entries.get(left_index), other.entries.get(right_index)) {
                (Some(left_entry), Some(right_entry))
                    if left_entry.position == right_entry.position =>
                {
                    let sum = self
                        .ring
                        .add(&left_entry.coefficients, &right_entry.coefficients)?;
                    if !is_zero_polynomial(&sum) {
                        merged_entries
                            .push(SparsePolynomialVectorEntry::new(left_entry.position, sum));
                    }
                    left_index += 1;
                    right_index += 1;
                }
                (Some(left_entry), Some(right_entry))
                    if left_entry.position < right_entry.position =>
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

        Self::new(self.ring, self.length, merged_entries)
    }

    fn require_same_shape(&self, other: &Self) -> CanonicalResult<()> {
        if self.ring != other.ring {
            return Err(invalid_sparse_vector("sparse vector rings do not match"));
        }
        if self.length != other.length {
            return Err(invalid_sparse_vector("sparse vector lengths do not match"));
        }

        Ok(())
    }
}

fn is_zero_polynomial(coefficients: &[u64]) -> bool {
    coefficients.iter().all(|coefficient| *coefficient == 0)
}

fn invalid_sparse_vector(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{PolynomialRing, SparsePolynomialVector, SparsePolynomialVectorEntry};

    #[test]
    fn converts_sparse_vector_to_dense_vector() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let sparse_vector = SparsePolynomialVector::new(
            ring,
            4,
            vec![
                SparsePolynomialVectorEntry::new(1, vec![2, 0, 0, 0]),
                SparsePolynomialVectorEntry::new(3, vec![0, 3, 0, 0]),
            ],
        )
        .expect("sparse vector should validate");

        assert_eq!(sparse_vector.length(), 4);
        assert_eq!(
            sparse_vector
                .to_dense()
                .expect("dense conversion should succeed")
                .entries(),
            &[
                vec![0, 0, 0, 0],
                vec![2, 0, 0, 0],
                vec![0, 0, 0, 0],
                vec![0, 3, 0, 0],
            ]
        );
    }

    #[test]
    fn adds_sparse_vectors_and_drops_cancelled_entries() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let left = SparsePolynomialVector::new(
            ring,
            5,
            vec![
                SparsePolynomialVectorEntry::new(0, vec![1, 0, 0, 0]),
                SparsePolynomialVectorEntry::new(2, vec![3, 4, 0, 0]),
            ],
        )
        .expect("left vector should validate");
        let right = SparsePolynomialVector::new(
            ring,
            5,
            vec![
                SparsePolynomialVectorEntry::new(2, vec![14, 13, 0, 0]),
                SparsePolynomialVectorEntry::new(4, vec![5, 0, 0, 0]),
            ],
        )
        .expect("right vector should validate");
        let sum = left.add(&right).expect("addition should succeed");

        assert_eq!(sum.entries().len(), 2);
        assert_eq!(sum.entries()[0].position(), 0);
        assert_eq!(sum.entries()[0].coefficients(), &[1, 0, 0, 0]);
        assert_eq!(sum.entries()[1].position(), 4);
        assert_eq!(sum.entries()[1].coefficients(), &[5, 0, 0, 0]);
    }

    #[test]
    fn rejects_noncanonical_sparse_vector_layouts() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");

        assert!(
            SparsePolynomialVector::new(
                ring,
                3,
                vec![
                    SparsePolynomialVectorEntry::new(2, vec![1, 0, 0, 0]),
                    SparsePolynomialVectorEntry::new(1, vec![1, 0, 0, 0]),
                ],
            )
            .expect_err("unsorted positions should fail")
            .message
            .contains("strictly sorted")
        );
        assert!(
            SparsePolynomialVector::new(
                ring,
                3,
                vec![SparsePolynomialVectorEntry::new(3, vec![1, 0, 0, 0])],
            )
            .expect_err("out-of-range position should fail")
            .message
            .contains("out of range")
        );
        assert!(
            SparsePolynomialVector::new(
                ring,
                3,
                vec![SparsePolynomialVectorEntry::new(1, vec![0, 0, 0, 0])],
            )
            .expect_err("stored zero polynomial should fail")
            .message
            .contains("zero polynomials")
        );
    }
}
