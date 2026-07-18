//! Negacyclic number-theoretic transform over a digit-atom proof field, for
//! products in Z_p[X]/(X^size + 1).
//!
//! The forward transform pre-scales by powers of psi (a primitive
//! 2*size-th root of unity) and runs a cyclic decimation-in-time transform
//! with omega = psi^2; the inverse runs the cyclic transform on inverse
//! twiddles and post-scales by psi^{-i} / size. Twiddle tables are built
//! once per domain so transform cost is measurable without setup noise.

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

use super::proof_field::ProofFieldParameters;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[cfg(not(target_arch = "wasm32"))]
const PARALLEL_TRANSFORM_MINIMUM_SIZE: usize = 16_384;

fn apply_butterfly_block<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    block_values: &mut [[u64; LIMB_COUNT]],
    half_block: usize,
    twiddles: &[[u64; LIMB_COUNT]],
    twiddle_stride: usize,
) {
    let (even_values, odd_values) = block_values.split_at_mut(half_block);
    for (offset, (even_value, odd_value)) in even_values
        .iter_mut()
        .zip(odd_values.iter_mut())
        .enumerate()
    {
        let twisted = parameters.multiply(odd_value, &twiddles[offset * twiddle_stride]);
        let even = *even_value;
        *even_value = parameters.add(&even, &twisted);
        *odd_value = parameters.subtract(&even, &twisted);
    }
}

pub(super) fn radix_two_cyclic_transform_in_place<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    values: &mut [[u64; LIMB_COUNT]],
    twiddles: &[[u64; LIMB_COUNT]],
) {
    let size = values.len();
    debug_assert!(size.is_power_of_two());
    debug_assert!(twiddles.len() >= size / 2);
    if size <= 1 {
        return;
    }

    let shift = size.leading_zeros() + 1;
    for index in 0..size {
        let reversed = index.reverse_bits() >> shift;
        if index < reversed {
            values.swap(index, reversed);
        }
    }

    let mut half_block = 1;
    while half_block < size {
        let block = half_block * 2;
        let twiddle_stride = size / block;
        #[cfg(not(target_arch = "wasm32"))]
        if size >= PARALLEL_TRANSFORM_MINIMUM_SIZE && rayon::current_num_threads() > 1 {
            values.par_chunks_mut(block).for_each(|block_values| {
                apply_butterfly_block(
                    parameters,
                    block_values,
                    half_block,
                    twiddles,
                    twiddle_stride,
                );
            });
        } else {
            values.chunks_mut(block).for_each(|block_values| {
                apply_butterfly_block(
                    parameters,
                    block_values,
                    half_block,
                    twiddles,
                    twiddle_stride,
                );
            });
        }
        #[cfg(target_arch = "wasm32")]
        values.chunks_mut(block).for_each(|block_values| {
            apply_butterfly_block(
                parameters,
                block_values,
                half_block,
                twiddles,
                twiddle_stride,
            );
        });
        half_block = block;
    }
}

pub(crate) struct NegacyclicDomain<'a, const LIMB_COUNT: usize> {
    pub(crate) parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    pub(crate) size: usize,
    psi_powers: Vec<[u64; LIMB_COUNT]>,
    inverse_psi_powers_scaled: Vec<[u64; LIMB_COUNT]>,
    omega_powers: Vec<[u64; LIMB_COUNT]>,
    inverse_omega_powers: Vec<[u64; LIMB_COUNT]>,
}

impl<'a, const LIMB_COUNT: usize> NegacyclicDomain<'a, LIMB_COUNT> {
    /// Builds a power-of-two domain supported by the field's stored exact-order
    /// root. The selected field carries a primitive 131072nd root for N=65536;
    /// smaller test fields retain their 65536th-root ceiling.
    pub(crate) fn new(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) -> CanonicalResult<Self> {
        let maximum_size = if parameters.primitive_131072nd_root.is_some() {
            65_536
        } else {
            32_768
        };
        if !size.is_power_of_two() || !(2..=maximum_size).contains(&size) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "negacyclic domain size exceeds the proof field's exact-order root",
            ));
        }
        let (root_raw, root_order) = if size > 32_768 {
            (
                parameters.primitive_131072nd_root.as_ref().ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "negacyclic domain requires an unavailable primitive 131072nd root",
                    )
                })?,
                131_072,
            )
        } else {
            (&parameters.primitive_65536th_root, 65_536)
        };
        let root = parameters.raw_value_to_element(root_raw);
        let mut step_exponent = [0_u64; LIMB_COUNT];
        step_exponent[0] = (root_order / (2 * size)) as u64;
        let psi = parameters.power(&root, &step_exponent);
        let omega = parameters.multiply(&psi, &psi);
        // These are roots of known public orders, so x^(order - 1) is their
        // inverse and avoids two full Fermat exponentiations per domain.
        let mut psi_inverse_exponent = [0_u64; LIMB_COUNT];
        psi_inverse_exponent[0] = (2 * size - 1) as u64;
        let psi_inverse = parameters.power(&psi, &psi_inverse_exponent);
        let mut omega_inverse_exponent = [0_u64; LIMB_COUNT];
        omega_inverse_exponent[0] = (size - 1) as u64;
        let omega_inverse = parameters.power(&omega, &omega_inverse_exponent);
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
        radix_two_cyclic_transform_in_place(self.parameters, values, &self.omega_powers);
    }

    pub(crate) fn inverse_in_place(&self, values: &mut [[u64; LIMB_COUNT]]) {
        debug_assert_eq!(values.len(), self.size);
        radix_two_cyclic_transform_in_place(self.parameters, values, &self.inverse_omega_powers);
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
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::{
        eight_limb_group_field_parameters, selected_key_switch_proof_field_parameters,
        single_limb_field_parameters,
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
        let selected = selected_key_switch_proof_field_parameters();
        let eight = eight_limb_group_field_parameters();
        let single =
            single_limb_field_parameters(2_305_843_009_214_414_849, 1_324_459_744_473_789_483);
        for size in [8, 64, 2048] {
            check_round_trip(&selected, size);
            check_round_trip(&eight, size);
            check_round_trip(&single, size);
        }
    }

    #[test]
    fn selected_field_round_trips_the_complete_ring_domain() {
        check_round_trip(&selected_key_switch_proof_field_parameters(), 65_536);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn parallel_and_single_thread_transforms_are_identical() {
        let parameters =
            single_limb_field_parameters(2_305_843_009_214_414_849, 1_324_459_744_473_789_483);
        let size = PARALLEL_TRANSFORM_MINIMUM_SIZE;
        let domain = NegacyclicDomain::new(&parameters, size).expect("domain builds");
        let original = deterministic_values(&parameters, size, 0x4a11);
        let single_thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("single-thread pool");
        let parallel_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("parallel pool");
        let mut single_thread_values = original.clone();
        single_thread_pool.install(|| domain.forward_in_place(&mut single_thread_values));
        let mut parallel_values = original.clone();
        parallel_pool.install(|| domain.forward_in_place(&mut parallel_values));
        assert_eq!(
            parallel_values, single_thread_values,
            "parallel butterfly blocks must preserve the exact transform output"
        );
        single_thread_pool.install(|| domain.inverse_in_place(&mut single_thread_values));
        parallel_pool.install(|| domain.inverse_in_place(&mut parallel_values));
        assert_eq!(parallel_values, single_thread_values);
        assert_eq!(parallel_values, original);
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
        let parameters = selected_key_switch_proof_field_parameters();
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
