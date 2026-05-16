use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolynomialRing {
    degree: usize,
    modulus: u64,
}

impl PolynomialRing {
    pub fn new(degree: usize, modulus: u64) -> CanonicalResult<Self> {
        if degree == 0 || !degree.is_power_of_two() {
            return Err(invalid_ring("degree must be a non-zero power of two"));
        }
        if modulus < 2 {
            return Err(invalid_ring("modulus must be at least two"));
        }

        Ok(Self { degree, modulus })
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    pub fn validate_coefficients(&self, coefficients: &[u64]) -> CanonicalResult<()> {
        if coefficients.len() != self.degree {
            return Err(invalid_ring(format!(
                "polynomial must have exactly {} coefficients",
                self.degree
            )));
        }
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= self.modulus)
        {
            return Err(invalid_ring(
                "polynomial contains a non-canonical coefficient",
            ));
        }

        Ok(())
    }

    pub fn add(&self, left: &[u64], right: &[u64]) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(left)?;
        self.validate_coefficients(right)?;

        Ok(left
            .iter()
            .zip(right)
            .map(|(left_coefficient, right_coefficient)| {
                add_mod(*left_coefficient, *right_coefficient, self.modulus)
            })
            .collect())
    }

    pub fn sub(&self, left: &[u64], right: &[u64]) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(left)?;
        self.validate_coefficients(right)?;

        Ok(left
            .iter()
            .zip(right)
            .map(|(left_coefficient, right_coefficient)| {
                sub_mod(*left_coefficient, *right_coefficient, self.modulus)
            })
            .collect())
    }

    pub fn neg(&self, value: &[u64]) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(value)?;

        Ok(value
            .iter()
            .map(|coefficient| {
                if *coefficient == 0 {
                    0
                } else {
                    self.modulus - coefficient
                }
            })
            .collect())
    }

    pub fn mul_negacyclic(&self, left: &[u64], right: &[u64]) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(left)?;
        self.validate_coefficients(right)?;

        let mut result = vec![0_u64; self.degree];
        for (left_index, left_coefficient) in left.iter().enumerate() {
            for (right_index, right_coefficient) in right.iter().enumerate() {
                let raw_index = left_index + right_index;
                let target_index = raw_index % self.degree;
                let product = mul_mod(*left_coefficient, *right_coefficient, self.modulus);
                if raw_index >= self.degree {
                    result[target_index] = sub_mod(result[target_index], product, self.modulus);
                } else {
                    result[target_index] = add_mod(result[target_index], product, self.modulus);
                }
            }
        }

        Ok(result)
    }

    pub fn centered_abs(&self, coefficient: u64) -> CanonicalResult<u64> {
        if coefficient >= self.modulus {
            return Err(invalid_ring(
                "coefficient is not canonical for this modulus",
            ));
        }

        Ok(coefficient.min(self.modulus - coefficient))
    }
}

fn add_mod(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

fn sub_mod(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        (u128::from(modulus) + u128::from(left) - u128::from(right)) as u64
    }
}

fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

fn invalid_ring(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::PolynomialRing;

    #[test]
    fn multiplies_negacyclic_polynomials() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let product = ring
            .mul_negacyclic(&[1, 2, 3, 4], &[5, 6, 7, 8])
            .expect("multiplication should succeed");

        assert_eq!(product, vec![12, 15, 2, 9]);
    }

    #[test]
    fn rejects_noncanonical_coefficients() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let error = ring
            .add(&[1, 2, 17, 4], &[0, 0, 0, 0])
            .expect_err("coefficient equal to modulus should fail");

        assert!(error.message.contains("non-canonical"));
    }
}
