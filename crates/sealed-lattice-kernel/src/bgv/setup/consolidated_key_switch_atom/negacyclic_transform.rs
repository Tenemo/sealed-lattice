//! Negacyclic number-theoretic transform over a consolidated-atom proof
//! field, for products in Z_p[X]/(X^size + 1).
//!
//! The forward transform pre-scales by powers of psi (a primitive
//! 2*size-th root of unity) and runs a cyclic decimation-in-time transform
//! with omega = psi^2; the inverse runs the cyclic transform on inverse
//! twiddles and post-scales by psi^{-i} / size. Twiddle tables are built
//! once per domain so transform cost is measurable without setup noise.

use super::proof_field::ProofFieldParameters;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub(crate) struct NegacyclicDomain<'a, const LIMB_COUNT: usize> {
    pub(crate) parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    pub(crate) size: usize,
    psi_powers: Vec<[u64; LIMB_COUNT]>,
    inverse_psi_powers_scaled: Vec<[u64; LIMB_COUNT]>,
    omega_powers: Vec<[u64; LIMB_COUNT]>,
    inverse_omega_powers: Vec<[u64; LIMB_COUNT]>,
}

impl<'a, const LIMB_COUNT: usize> NegacyclicDomain<'a, LIMB_COUNT> {
    /// Builds the domain for a power-of-two size up to 32768. The field's
    /// primitive 65536th root is stepped down to a primitive 2*size-th root,
    /// which exists because 2 * size divides 65536.
    pub(crate) fn new(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) -> CanonicalResult<Self> {
        if !size.is_power_of_two() || !(2..=32_768).contains(&size) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "negacyclic domain size must be a power of two between 2 and 32768",
            ));
        }
        let root = parameters.raw_value_to_element(&parameters.primitive_65536th_root);
        let mut step_exponent = [0_u64; LIMB_COUNT];
        step_exponent[0] = (65_536 / (2 * size)) as u64;
        let psi = parameters.power(&root, &step_exponent);
        let psi_inverse = parameters.inverse(&psi);
        let omega = parameters.multiply(&psi, &psi);
        let omega_inverse = parameters.inverse(&omega);
        let size_inverse = parameters.inverse(&parameters.raw_value_to_element(&{
            let mut raw = [0_u64; LIMB_COUNT];
            raw[0] = size as u64;
            raw
        }));

        let mut psi_powers = Vec::with_capacity(size);
        let mut inverse_psi_powers_scaled = Vec::with_capacity(size);
        let mut psi_running = parameters.one();
        let mut inverse_psi_running = size_inverse;
        for _ in 0..size {
            psi_powers.push(psi_running);
            inverse_psi_powers_scaled.push(inverse_psi_running);
            psi_running = parameters.multiply(&psi_running, &psi);
            inverse_psi_running = parameters.multiply(&inverse_psi_running, &psi_inverse);
        }

        let mut omega_powers = Vec::with_capacity(size / 2);
        let mut inverse_omega_powers = Vec::with_capacity(size / 2);
        let mut omega_running = parameters.one();
        let mut inverse_omega_running = parameters.one();
        for _ in 0..size / 2 {
            omega_powers.push(omega_running);
            inverse_omega_powers.push(inverse_omega_running);
            omega_running = parameters.multiply(&omega_running, &omega);
            inverse_omega_running = parameters.multiply(&inverse_omega_running, &omega_inverse);
        }

        Ok(Self {
            parameters,
            size,
            psi_powers,
            inverse_psi_powers_scaled,
            omega_powers,
            inverse_omega_powers,
        })
    }

    pub(crate) fn forward_in_place(&self, values: &mut [[u64; LIMB_COUNT]]) {
        debug_assert_eq!(values.len(), self.size);
        for (value, psi_power) in values.iter_mut().zip(self.psi_powers.iter()) {
            *value = self.parameters.multiply(value, psi_power);
        }
        self.cyclic_transform_in_place(values, &self.omega_powers);
    }

    pub(crate) fn inverse_in_place(&self, values: &mut [[u64; LIMB_COUNT]]) {
        debug_assert_eq!(values.len(), self.size);
        self.cyclic_transform_in_place(values, &self.inverse_omega_powers);
        for (value, scaled_inverse_psi) in
            values.iter_mut().zip(self.inverse_psi_powers_scaled.iter())
        {
            *value = self.parameters.multiply(value, scaled_inverse_psi);
        }
    }

    pub(crate) fn pointwise_multiply_in_place(
        &self,
        left: &mut [[u64; LIMB_COUNT]],
        right: &[[u64; LIMB_COUNT]],
    ) {
        for (left_value, right_value) in left.iter_mut().zip(right.iter()) {
            *left_value = self.parameters.multiply(left_value, right_value);
        }
    }

    /// Negacyclic product of two coefficient vectors, leaving inputs intact.
    pub(crate) fn negacyclic_product(
        &self,
        left: &[[u64; LIMB_COUNT]],
        right: &[[u64; LIMB_COUNT]],
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut left_transformed = left.to_vec();
        let mut right_transformed = right.to_vec();
        self.forward_in_place(&mut left_transformed);
        self.forward_in_place(&mut right_transformed);
        self.pointwise_multiply_in_place(&mut left_transformed, &right_transformed);
        self.inverse_in_place(&mut left_transformed);
        left_transformed
    }

    fn cyclic_transform_in_place(
        &self,
        values: &mut [[u64; LIMB_COUNT]],
        twiddles: &[[u64; LIMB_COUNT]],
    ) {
        bit_reverse_permute(values);
        let mut half_block = 1;
        while half_block < self.size {
            let block = half_block * 2;
            let twiddle_stride = self.size / block;
            for block_start in (0..self.size).step_by(block) {
                for offset in 0..half_block {
                    let twiddle = &twiddles[offset * twiddle_stride];
                    let even_index = block_start + offset;
                    let odd_index = even_index + half_block;
                    let twisted = self.parameters.multiply(&values[odd_index], twiddle);
                    let even = values[even_index];
                    values[even_index] = self.parameters.add(&even, &twisted);
                    values[odd_index] = self.parameters.subtract(&even, &twisted);
                }
            }
            half_block = block;
        }
    }
}

fn bit_reverse_permute<const LIMB_COUNT: usize>(values: &mut [[u64; LIMB_COUNT]]) {
    let size = values.len();
    let shift = size.leading_zeros() + 1;
    for index in 0..size {
        let reversed = index.reverse_bits() >> shift;
        if index < reversed {
            values.swap(index, reversed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::{
        eight_limb_group_field_parameters, single_limb_field_parameters,
        sixteen_limb_group_field_parameters,
    };
    use super::*;

    fn deterministic_values<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        count: usize,
        seed: u64,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut state = seed;
        (0..count)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                parameters.unsigned_word_to_element(state)
            })
            .collect()
    }

    fn check_round_trip<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) {
        let domain = NegacyclicDomain::new(parameters, size).expect("domain builds");
        let original = deterministic_values(parameters, size, 0x5eed + size as u64);
        let mut transformed = original.clone();
        domain.forward_in_place(&mut transformed);
        assert_ne!(transformed, original);
        domain.inverse_in_place(&mut transformed);
        assert_eq!(transformed, original);
    }

    #[test]
    fn transform_round_trips_across_sizes_and_fields() {
        let sixteen = sixteen_limb_group_field_parameters();
        let eight = eight_limb_group_field_parameters();
        let single =
            single_limb_field_parameters(2_305_843_009_214_414_849, 1_324_459_744_473_789_483);
        for size in [8, 64, 2048] {
            check_round_trip(&sixteen, size);
            check_round_trip(&eight, size);
            check_round_trip(&single, size);
        }
    }

    fn schoolbook_negacyclic<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        left: &[[u64; LIMB_COUNT]],
        right: &[[u64; LIMB_COUNT]],
    ) -> Vec<[u64; LIMB_COUNT]> {
        let size = left.len();
        let mut product = vec![parameters.zero(); size];
        for (left_index, left_value) in left.iter().enumerate() {
            for (right_index, right_value) in right.iter().enumerate() {
                let term = parameters.multiply(left_value, right_value);
                let wrapped_index = (left_index + right_index) % size;
                if left_index + right_index < size {
                    product[wrapped_index] = parameters.add(&product[wrapped_index], &term);
                } else {
                    product[wrapped_index] = parameters.subtract(&product[wrapped_index], &term);
                }
            }
        }
        product
    }

    #[test]
    fn ntt_product_matches_schoolbook_negacyclic_product() {
        let parameters = sixteen_limb_group_field_parameters();
        let domain = NegacyclicDomain::new(&parameters, 64).expect("domain builds");
        let left = deterministic_values(&parameters, 64, 41);
        let right = deterministic_values(&parameters, 64, 43);
        assert_eq!(
            domain.negacyclic_product(&left, &right),
            schoolbook_negacyclic(&parameters, &left, &right)
        );
    }

    #[test]
    fn monomial_product_wraps_with_negacyclic_sign() {
        let parameters = eight_limb_group_field_parameters();
        let size = 32;
        let domain = NegacyclicDomain::new(&parameters, size).expect("domain builds");
        let mut x = vec![parameters.zero(); size];
        x[1] = parameters.one();
        let mut x_to_size_minus_one = vec![parameters.zero(); size];
        x_to_size_minus_one[size - 1] = parameters.one();
        let product = domain.negacyclic_product(&x, &x_to_size_minus_one);
        assert_eq!(product[0], parameters.negate(&parameters.one()));
        assert!(product[1..].iter().all(|value| *value == parameters.zero()));
    }
}
