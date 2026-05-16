use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::polynomial_ring::PolynomialRing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolynomialVector {
    ring: PolynomialRing,
    entries: Vec<Vec<u64>>,
}

impl PolynomialVector {
    pub fn new(ring: PolynomialRing, entries: Vec<Vec<u64>>) -> CanonicalResult<Self> {
        if entries.is_empty() {
            return Err(invalid_vector(
                "polynomial vector must contain at least one entry",
            ));
        }
        for entry in &entries {
            ring.validate_coefficients(entry)?;
        }

        Ok(Self { ring, entries })
    }

    pub fn zero(ring: PolynomialRing, length: usize) -> CanonicalResult<Self> {
        if length == 0 {
            return Err(invalid_vector("zero vector length must be non-zero"));
        }

        Self::new(ring, vec![vec![0; ring.degree()]; length])
    }

    pub fn ring(&self) -> PolynomialRing {
        self.ring
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Vec<u64>] {
        &self.entries
    }

    pub fn add(&self, other: &Self) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;
        let entries = self
            .entries
            .iter()
            .zip(other.entries())
            .map(|(left, right)| self.ring.add(left, right))
            .collect::<CanonicalResult<Vec<_>>>()?;

        Self::new(self.ring, entries)
    }

    pub fn sub(&self, other: &Self) -> CanonicalResult<Self> {
        self.require_same_shape(other)?;
        let entries = self
            .entries
            .iter()
            .zip(other.entries())
            .map(|(left, right)| self.ring.sub(left, right))
            .collect::<CanonicalResult<Vec<_>>>()?;

        Self::new(self.ring, entries)
    }

    pub fn l2_norm_squared_centered(&self) -> CanonicalResult<u128> {
        let mut sum = 0_u128;
        for polynomial in &self.entries {
            for coefficient in polynomial {
                let centered_abs = u128::from(self.ring.centered_abs(*coefficient)?);
                let squared = centered_abs
                    .checked_mul(centered_abs)
                    .ok_or_else(|| invalid_vector("centered coefficient square overflowed u128"))?;
                sum = sum
                    .checked_add(squared)
                    .ok_or_else(|| invalid_vector("l2 norm overflowed u128"))?;
            }
        }

        Ok(sum)
    }

    fn require_same_shape(&self, other: &Self) -> CanonicalResult<()> {
        if self.ring != other.ring {
            return Err(invalid_vector("polynomial vector rings do not match"));
        }
        if self.len() != other.len() {
            return Err(invalid_vector("polynomial vector lengths do not match"));
        }

        Ok(())
    }
}

fn invalid_vector(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{PolynomialRing, PolynomialVector};

    #[test]
    fn computes_centered_l2_norm() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let vector =
            PolynomialVector::new(ring, vec![vec![1, 16, 8, 9]]).expect("vector should validate");

        assert_eq!(
            vector
                .l2_norm_squared_centered()
                .expect("norm should compute"),
            130
        );
    }

    #[test]
    fn subtracts_vectors_entrywise() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let left = PolynomialVector::new(ring, vec![vec![1, 2, 3, 4]])
            .expect("left vector should validate");
        let right = PolynomialVector::new(ring, vec![vec![4, 3, 2, 1]])
            .expect("right vector should validate");
        let difference = left.sub(&right).expect("subtraction should succeed");

        assert_eq!(difference.entries(), &[vec![14, 16, 1, 3]]);
    }
}
