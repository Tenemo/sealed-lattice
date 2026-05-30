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

    pub fn add_assign(&self, output: &mut [u64], right: &[u64]) -> CanonicalResult<()> {
        self.validate_coefficients(output)?;
        self.validate_coefficients(right)?;

        for (output_coefficient, right_coefficient) in output.iter_mut().zip(right) {
            *output_coefficient = add_mod(*output_coefficient, *right_coefficient, self.modulus);
        }

        Ok(())
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

    pub fn sub_assign(&self, output: &mut [u64], right: &[u64]) -> CanonicalResult<()> {
        self.validate_coefficients(output)?;
        self.validate_coefficients(right)?;

        for (output_coefficient, right_coefficient) in output.iter_mut().zip(right) {
            *output_coefficient = sub_mod(*output_coefficient, *right_coefficient, self.modulus);
        }

        Ok(())
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

    pub fn scaled_add_assign(
        &self,
        output: &mut [u64],
        scalar: u64,
        value: &[u64],
    ) -> CanonicalResult<()> {
        self.validate_coefficients(output)?;
        self.validate_coefficients(value)?;
        if scalar >= self.modulus {
            return Err(invalid_ring("scalar is not canonical for this modulus"));
        }

        for (output_coefficient, value_coefficient) in output.iter_mut().zip(value) {
            let scaled_coefficient = mul_mod(*value_coefficient, scalar, self.modulus);
            *output_coefficient = add_mod(*output_coefficient, scaled_coefficient, self.modulus);
        }

        Ok(())
    }

    pub fn left_rotate_negacyclic(
        &self,
        value: &[u64],
        rotation: usize,
    ) -> CanonicalResult<Vec<u64>> {
        // Rotation by X^r in Z_q[X]/(X^N+1). Because X^N = -1, the sign flips
        // every N steps, so the full period is 2N (the cycle_length below).
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
        // sigma: f(X) -> f(X^{-1}) in the negacyclic ring. Coordinates 0 and
        // N/2 (half_degree) are the fixed points; the rest swap with a sign flip.
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
        let left_nonzero_count = nonzero_coefficient_count(left);
        let right_nonzero_count = nonzero_coefficient_count(right);
        if left_nonzero_count == 0 || right_nonzero_count == 0 {
            return;
        }
        // Density heuristic: dense enough operands use Karatsuba, otherwise the
        // sparse schoolbook loop below. Both paths produce identical results.
        if self.degree >= 32
            && left_nonzero_count * right_nonzero_count > (self.degree * self.degree) / 2
        {
            let product = self.mul_negacyclic_karatsuba_unchecked(left, right);
            for (output_coefficient, product_coefficient) in output.iter_mut().zip(product) {
                *output_coefficient =
                    add_mod(*output_coefficient, product_coefficient, self.modulus);
            }

            return;
        }
        // Iterate the sparser operand on the outside to skip more zero terms.
        let (outer, inner) = if right_nonzero_count < left_nonzero_count {
            (right, left)
        } else {
            (left, right)
        };

        for (left_index, left_coefficient) in outer.iter().copied().enumerate() {
            if left_coefficient == 0 {
                continue;
            }
            for (right_index, right_coefficient) in inner.iter().copied().enumerate() {
                if right_coefficient == 0 {
                    continue;
                }
                let raw_index = left_index + right_index;
                // `& (degree-1)` is mod N (power-of-two degree); when raw_index
                // wraps past N the sign flips, implementing X^N = -1.
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

    fn mul_negacyclic_karatsuba_unchecked(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        let convolution = karatsuba_convolution_mod(left, right, self.modulus);
        let mut output = vec![0_u64; self.degree];
        for (coefficient_index, coefficient) in convolution.into_iter().enumerate() {
            if coefficient_index < self.degree {
                output[coefficient_index] =
                    add_mod(output[coefficient_index], coefficient, self.modulus);
            } else {
                let target_index = coefficient_index - self.degree;
                output[target_index] = sub_mod(output[target_index], coefficient, self.modulus);
            }
        }

        output
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

fn nonzero_coefficient_count(coefficients: &[u64]) -> usize {
    coefficients
        .iter()
        .filter(|coefficient| **coefficient != 0)
        .count()
}

fn karatsuba_convolution_mod(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    debug_assert_eq!(left.len(), right.len());
    let length = left.len();
    if length <= 16 {
        return schoolbook_convolution_mod(left, right, modulus);
    }

    let half_length = length / 2;
    let (left_low, left_high) = left.split_at(half_length);
    let (right_low, right_high) = right.split_at(half_length);
    let low_product = karatsuba_convolution_mod(left_low, right_low, modulus);
    let high_product = karatsuba_convolution_mod(left_high, right_high, modulus);
    let left_sum = add_polynomial_slices_mod(left_low, left_high, modulus);
    let right_sum = add_polynomial_slices_mod(right_low, right_high, modulus);
    let mut middle_product = karatsuba_convolution_mod(&left_sum, &right_sum, modulus);
    subtract_polynomial_into(&mut middle_product, &low_product, modulus);
    subtract_polynomial_into(&mut middle_product, &high_product, modulus);

    let mut convolution = vec![0_u64; 2 * length - 1];
    add_shifted_polynomial_into(&mut convolution, 0, &low_product, modulus);
    add_shifted_polynomial_into(&mut convolution, half_length, &middle_product, modulus);
    add_shifted_polynomial_into(&mut convolution, 2 * half_length, &high_product, modulus);

    convolution
}

fn schoolbook_convolution_mod(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    let mut convolution = vec![0_u64; left.len() + right.len() - 1];
    for (left_index, left_coefficient) in left.iter().copied().enumerate() {
        if left_coefficient == 0 {
            continue;
        }
        for (right_index, right_coefficient) in right.iter().copied().enumerate() {
            if right_coefficient == 0 {
                continue;
            }
            let target_index = left_index + right_index;
            let product = mul_mod(left_coefficient, right_coefficient, modulus);
            convolution[target_index] = add_mod(convolution[target_index], product, modulus);
        }
    }

    convolution
}

fn add_polynomial_slices_mod(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    debug_assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right)
        .map(|(left_coefficient, right_coefficient)| {
            add_mod(*left_coefficient, *right_coefficient, modulus)
        })
        .collect()
}

fn add_shifted_polynomial_into(output: &mut [u64], shift: usize, value: &[u64], modulus: u64) {
    for (coefficient_index, coefficient) in value.iter().copied().enumerate() {
        let output_index = shift + coefficient_index;
        output[output_index] = add_mod(output[output_index], coefficient, modulus);
    }
}

fn subtract_polynomial_into(output: &mut [u64], value: &[u64], modulus: u64) {
    for (output_coefficient, value_coefficient) in output.iter_mut().zip(value) {
        *output_coefficient = sub_mod(*output_coefficient, *value_coefficient, modulus);
    }
}

// Goldilocks prime 2^64 - 2^32 + 1; from 2^64 = 2^32 - 1 (mod q) the fold
// factor below is 2^32 - 1.
const GOLDILOCKS_MODULUS: u64 = 18_446_744_069_414_584_321;
const GOLDILOCKS_FOLD_FACTOR: u128 = (1_u128 << 32) - 1;
// 36_028_797_018_964_597 = 629*2^55 + 1, so 629*2^55 = -1 (mod q). The fold
// bits (55) and fold factor (629) drive the Solinas-style reduction below.
pub(crate) const LINEAR_PROOF_MODULUS: u64 = 36_028_797_018_964_597;
const LINEAR_PROOF_MODULUS_FOLD_BITS: u32 = 55;
const LINEAR_PROOF_MODULUS_FOLD_MASK: u128 = (1_u128 << LINEAR_PROOF_MODULUS_FOLD_BITS) - 1;
const LINEAR_PROOF_MODULUS_FOLD_FACTOR: i128 = 629;

pub(crate) fn add_mod(left: u64, right: u64, modulus: u64) -> u64 {
    if modulus == GOLDILOCKS_MODULUS {
        return reduce_goldilocks_u128(u128::from(left) + u128::from(right));
    }
    // modulus <= u64::MAX/2 guarantees left + right cannot overflow u64.
    if modulus <= u64::MAX / 2 {
        let sum = left + right;
        return if sum >= modulus { sum - modulus } else { sum };
    }

    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

pub(crate) fn sub_mod(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        (u128::from(modulus) + u128::from(left) - u128::from(right)) as u64
    }
}

pub(crate) fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    if modulus == GOLDILOCKS_MODULUS {
        return reduce_goldilocks_u128(u128::from(left) * u128::from(right));
    }
    if modulus == LINEAR_PROOF_MODULUS {
        return reduce_linear_proof_modulus_u128(u128::from(left) * u128::from(right));
    }
    if modulus <= u64::from(u32::MAX) {
        return left.wrapping_mul(right) % modulus;
    }
    if modulus < (1_u64 << 53) {
        return reduce_u53_product(left, right, modulus);
    }

    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

pub(crate) fn reduce_linear_proof_modulus_u128(value: u128) -> u64 {
    // Two-stage signed fold using 629*2^55 = -1 (mod q); two folds suffice to
    // reduce any 128-bit input into the canonical range.
    let low_part = (value & LINEAR_PROOF_MODULUS_FOLD_MASK) as i128;
    let high_part = value >> LINEAR_PROOF_MODULUS_FOLD_BITS;
    let folded_high = LINEAR_PROOF_MODULUS_FOLD_FACTOR * high_part as i128;
    let folded_high_low_part = folded_high & LINEAR_PROOF_MODULUS_FOLD_MASK as i128;
    let folded_high_high_part = folded_high >> LINEAR_PROOF_MODULUS_FOLD_BITS;
    let mut reduced =
        low_part - folded_high_low_part + LINEAR_PROOF_MODULUS_FOLD_FACTOR * folded_high_high_part;
    let modulus = i128::from(LINEAR_PROOF_MODULUS);
    if reduced < 0 {
        reduced += modulus;
    }
    if reduced >= modulus {
        reduced -= modulus;
    }

    reduced as u64
}

pub(crate) fn positive_mod_linear_proof_i128(value: i128) -> u64 {
    if value >= 0 {
        reduce_linear_proof_modulus_u128(value as u128)
    } else {
        let positive_remainder = reduce_linear_proof_modulus_u128(value.unsigned_abs());
        if positive_remainder == 0 {
            0
        } else {
            LINEAR_PROOF_MODULUS - positive_remainder
        }
    }
}

fn reduce_u53_product(left: u64, right: u64, modulus: u64) -> u64 {
    // f64 approximate quotient plus a bounded correction loop; valid for
    // sub-2^53 moduli where the f64 quotient is exact enough. % is the fallback.
    let product = u128::from(left) * u128::from(right);
    let approximate_quotient = ((left as f64) * (right as f64) / (modulus as f64)) as u64;
    let mut remainder =
        product as i128 - (u128::from(approximate_quotient) * u128::from(modulus)) as i128;
    let modulus_i128 = i128::from(modulus);

    for _ in 0..8 {
        if remainder < 0 {
            remainder += modulus_i128;
            continue;
        }
        if remainder >= modulus_i128 {
            remainder -= modulus_i128;
            continue;
        }

        return remainder as u64;
    }

    (product % u128::from(modulus)) as u64
}

fn reduce_goldilocks_u128(value: u128) -> u64 {
    let first_fold =
        u128::from(value as u64) + u128::from((value >> 64) as u64) * GOLDILOCKS_FOLD_FACTOR;
    let second_fold = u128::from(first_fold as u64)
        + u128::from((first_fold >> 64) as u64) * GOLDILOCKS_FOLD_FACTOR;
    let modulus = u128::from(GOLDILOCKS_MODULUS);
    let mut reduced = second_fold;
    while reduced >= modulus {
        reduced -= modulus;
    }

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
    fn optimized_reduction_matches_generic_modular_arithmetic_for_active_ranges() {
        let moduli = [
            super::LINEAR_PROOF_MODULUS,
            536_903_681_u64,
            70_368_744_177_829_u64,
            140_737_487_306_753_u64,
            (1_u64 << 53) - 111,
            super::GOLDILOCKS_MODULUS,
        ];
        for modulus in moduli {
            let mut state = modulus ^ 0x9e37_79b9_7f4a_7c15;
            let mut cases = vec![
                (0, 0),
                (1, modulus - 1),
                (modulus - 1, modulus - 1),
                (modulus / 2, modulus / 2 + 1),
            ];
            for _ in 0..1024 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let left = state % modulus;
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let right = state % modulus;
                cases.push((left, right));
            }

            for (left, right) in cases {
                assert_eq!(
                    super::add_mod(left, right, modulus),
                    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64,
                    "modulus={modulus}, left={left}, right={right}",
                );
                assert_eq!(
                    super::mul_mod(left, right, modulus),
                    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64,
                    "modulus={modulus}, left={left}, right={right}",
                );
            }
        }

        let linear_proof_modulus = i128::from(super::LINEAR_PROOF_MODULUS);
        for value in [
            0_i128,
            1,
            -1,
            linear_proof_modulus,
            -linear_proof_modulus,
            linear_proof_modulus * 257 + 12_345,
            -(linear_proof_modulus * 257 + 12_345),
        ] {
            let mut expected = value % linear_proof_modulus;
            if expected < 0 {
                expected += linear_proof_modulus;
            }
            assert_eq!(
                super::positive_mod_linear_proof_i128(value),
                expected as u64
            );
        }
    }

    #[test]
    fn dense_karatsuba_product_matches_direct_negacyclic_product() {
        let modulus = 36_028_797_018_964_597_u64;
        let ring = PolynomialRing::new(64, modulus).expect("ring should validate");
        let mut left = Vec::with_capacity(64);
        let mut right = Vec::with_capacity(64);
        let mut state = 0xabc0_1234_5678_9def_u64;
        for coefficient_index in 0..64 {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            left.push((state ^ coefficient_index) % modulus);
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            right.push((state.rotate_left(17) ^ coefficient_index) % modulus);
        }

        let product = ring
            .mul_negacyclic(&left, &right)
            .expect("dense product should succeed");
        let expected = direct_negacyclic_product(&left, &right, modulus);

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
    fn accumulates_scaled_polynomial_coefficients() {
        let ring = PolynomialRing::new(4, 17).expect("ring should validate");
        let mut output = vec![16, 3, 4, 5];

        ring.scaled_add_assign(&mut output, 5, &[1, 2, 3, 4])
            .expect("scaled addition should succeed");

        assert_eq!(output, vec![4, 13, 2, 8]);
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
                let product = ((u128::from(left_value) * u128::from(right_value))
                    % u128::from(modulus)) as u64;
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
                    output[output_index] = ((u128::from(output[output_index])
                        + u128::from(product))
                        % u128::from(modulus)) as u64;
                }
            }
        }

        output
    }
}
