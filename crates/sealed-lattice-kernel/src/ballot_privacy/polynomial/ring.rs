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
                    self.modulus - *coefficient
                }
            })
            .collect())
    }

    pub fn scale(&self, scalar: u64, value: &[u64]) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(value)?;
        if scalar >= self.modulus {
            return Err(invalid_ring("scalar is not canonical for this modulus"));
        }

        Ok(value
            .iter()
            .map(|coefficient| mul_mod(*coefficient, scalar, self.modulus))
            .collect())
    }

    pub fn left_rotate_negacyclic(
        &self,
        value: &[u64],
        rotation: usize,
    ) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(value)?;
        let cycle_length = self
            .degree
            .checked_mul(2)
            .ok_or_else(|| invalid_ring("negacyclic rotation cycle length overflowed"))?;
        let normalized_rotation = rotation % cycle_length;
        let coefficient_rotation = normalized_rotation % self.degree;
        let negate_output = normalized_rotation >= self.degree;

        let mut output = if coefficient_rotation == 0 {
            value.to_vec()
        } else {
            let mut rotated = vec![0_u64; self.degree];
            for wrapped_offset in 1..=coefficient_rotation {
                let output_index = coefficient_rotation - wrapped_offset;
                let input_index = self.degree - wrapped_offset;
                rotated[output_index] = if value[input_index] == 0 {
                    0
                } else {
                    self.modulus - value[input_index]
                };
            }
            rotated[coefficient_rotation..self.degree]
                .copy_from_slice(&value[..(self.degree - coefficient_rotation)]);
            rotated
        };

        if negate_output {
            output = self.neg(&output)?;
        }

        Ok(output)
    }

    pub fn automorphism(&self, value: &[u64]) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(value)?;

        let mut output = vec![0_u64; self.degree];
        output[0] = value[0];
        let half_degree = self.degree / 2;
        output[half_degree] = if value[half_degree] == 0 {
            0
        } else {
            self.modulus - value[half_degree]
        };
        for coefficient_index in 1..half_degree {
            let reflected_index = self.degree - coefficient_index;
            output[coefficient_index] = if value[reflected_index] == 0 {
                0
            } else {
                self.modulus - value[reflected_index]
            };
            output[reflected_index] = if value[coefficient_index] == 0 {
                0
            } else {
                self.modulus - value[coefficient_index]
            };
        }

        Ok(output)
    }

    pub fn mul_negacyclic(&self, left: &[u64], right: &[u64]) -> CanonicalResult<Vec<u64>> {
        self.validate_coefficients(left)?;
        self.validate_coefficients(right)?;

        let mut result = vec![0_u64; self.degree];
        self.mul_negacyclic_accumulate_unchecked(&mut result, left, right);

        Ok(result)
    }

    pub fn mul_negacyclic_accumulate(
        &self,
        output: &mut [u64],
        left: &[u64],
        right: &[u64],
    ) -> CanonicalResult<()> {
        self.validate_coefficients(output)?;
        self.validate_coefficients(left)?;
        self.validate_coefficients(right)?;

        self.mul_negacyclic_accumulate_unchecked(output, left, right);

        Ok(())
    }

    fn mul_negacyclic_accumulate_unchecked(&self, output: &mut [u64], left: &[u64], right: &[u64]) {
        for (left_index, left_coefficient) in left.iter().copied().enumerate() {
            if left_coefficient == 0 {
                continue;
            }
            for (right_index, right_coefficient) in right.iter().copied().enumerate() {
                if right_coefficient == 0 {
                    continue;
                }
                let raw_index = left_index + right_index;
                let target_index = raw_index & (self.degree - 1);
                let product = mul_mod(left_coefficient, right_coefficient, self.modulus);
                if raw_index >= self.degree {
                    output[target_index] = sub_mod(output[target_index], product, self.modulus);
                } else {
                    output[target_index] = add_mod(output[target_index], product, self.modulus);
                }
            }
        }
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

const GOLDILOCKS_MODULUS: u64 = 18_446_744_069_414_584_321;
const GOLDILOCKS_FOLD_FACTOR: u128 = (1_u128 << 32) - 1;

fn add_mod(left: u64, right: u64, modulus: u64) -> u64 {
    if modulus == GOLDILOCKS_MODULUS {
        return reduce_goldilocks_u128(u128::from(left) + u128::from(right));
    }
    if modulus <= u64::MAX / 2 {
        let sum = left + right;
        return if sum >= modulus { sum - modulus } else { sum };
    }

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
    if modulus == GOLDILOCKS_MODULUS {
        return reduce_goldilocks_u128(u128::from(left) * u128::from(right));
    }

    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

fn reduce_goldilocks_u128(value: u128) -> u64 {
    let first_fold =
        u128::from(value as u64) + u128::from((value >> 64) as u64) * GOLDILOCKS_FOLD_FACTOR;
    let second_fold = u128::from(first_fold as u64)
        + u128::from((first_fold >> 64) as u64) * GOLDILOCKS_FOLD_FACTOR;
    let modulus = u128::from(GOLDILOCKS_MODULUS);
    let reduced = if second_fold >= modulus {
        second_fold - modulus
    } else {
        second_fold
    };

    reduced as u64
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
    fn goldilocks_reduction_matches_generic_modular_arithmetic_edges() {
        let modulus = super::GOLDILOCKS_MODULUS;
        let ring = PolynomialRing::new(4, modulus).expect("ring should validate");
        let product = ring
            .mul_negacyclic(
                &[modulus - 1, modulus - 2, 3, 4],
                &[modulus - 3, 5, modulus - 6, 7],
            )
            .expect("multiplication should succeed");
        let expected = direct_negacyclic_product(
            &[modulus - 1, modulus - 2, 3, 4],
            &[modulus - 3, 5, modulus - 6, 7],
            modulus,
        );

        assert_eq!(product, expected);
    }

    #[test]
    fn rejects_noncanonical_coefficients() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let error = ring
            .add(&[1, 2, 17, 4], &[0, 0, 0, 0])
            .expect_err("coefficient equal to modulus should fail");

        assert!(error.message.contains("non-canonical"));
    }

    #[test]
    fn scales_polynomial_coefficients() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let scaled = ring
            .scale(5, &[1, 2, 3, 4])
            .expect("scaling should succeed");

        assert_eq!(scaled, vec![5, 10, 15, 3]);
    }

    #[test]
    fn negates_polynomial_coefficients() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let negated = ring.neg(&[0, 1, 8, 16]).expect("negation should succeed");

        assert_eq!(negated, vec![0, 16, 9, 1]);
    }

    #[test]
    fn left_rotates_negacyclic_polynomials() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let rotated = ring
            .left_rotate_negacyclic(&[1, 2, 3, 4, 5, 6, 7, 8], 3)
            .expect("rotation should succeed");

        assert_eq!(rotated, vec![11, 10, 9, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn normalizes_full_negacyclic_rotations() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let value = [1, 2, 3, 4];
        let rotated_by_degree = ring
            .left_rotate_negacyclic(&value, 4)
            .expect("rotation by degree should succeed");
        let rotated_by_two_degrees = ring
            .left_rotate_negacyclic(&value, 8)
            .expect("rotation by full cycle should succeed");
        let rotated_by_three_degrees = ring
            .left_rotate_negacyclic(&value, 12)
            .expect("rotation by degree and full cycle should succeed");
        let rotated_by_one = ring
            .left_rotate_negacyclic(&value, 1)
            .expect("rotation by one should succeed");
        let rotated_by_degree_plus_one = ring
            .left_rotate_negacyclic(&value, 5)
            .expect("rotation by degree plus one should succeed");

        assert_eq!(
            rotated_by_degree,
            ring.neg(&value).expect("negation should succeed")
        );
        assert_eq!(rotated_by_two_degrees, value);
        assert_eq!(
            rotated_by_three_degrees,
            ring.neg(&value).expect("negation should succeed")
        );
        assert_eq!(
            rotated_by_degree_plus_one,
            ring.neg(&rotated_by_one).expect("negation should succeed")
        );
    }

    #[test]
    fn applies_linear_proof_style_automorphism() {
        let ring = PolynomialRing::new(8, 17).expect("ring should validate");
        let transformed = ring
            .automorphism(&[1, 2, 3, 4, 5, 6, 7, 8])
            .expect("automorphism should succeed");

        assert_eq!(transformed, vec![1, 9, 10, 11, 12, 13, 14, 15]);
    }

    fn direct_negacyclic_product(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
        let mut output = vec![0_u64; left.len()];
        for (left_index, left_value) in left.iter().copied().enumerate() {
            for (right_index, right_value) in right.iter().copied().enumerate() {
                let product =
                    ((u128::from(left_value) * u128::from(right_value)) % u128::from(modulus))
                        as u64;
                let raw_index = left_index + right_index;
                let output_index = raw_index % left.len();
                if raw_index >= left.len() {
                    output[output_index] = if output[output_index] >= product {
                        output[output_index] - product
                    } else {
                        (u128::from(modulus) + u128::from(output[output_index])
                            - u128::from(product)) as u64
                    };
                } else {
                    output[output_index] =
                        ((u128::from(output[output_index]) + u128::from(product))
                            % u128::from(modulus)) as u64;
                }
            }
        }

        output
    }
}
