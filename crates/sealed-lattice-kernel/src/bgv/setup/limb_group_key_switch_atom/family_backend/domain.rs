//! Cyclic evaluation domains and coset low-degree extension over the atom
//! proof field.
//!
//! The atom PIOP encodes each length-`trace_size` witness column as the values
//! of a polynomial of degree below `trace_size` on the multiplicative subgroup
//! `H` of that order (the trace domain), then commits its low-degree extension
//! on a `blowup`-times-larger coset `g * K`, where `K` is the subgroup of order
//! `trace_size * blowup` and `g` is a non-`K` coset offset. FRI runs over the
//! coset. Unlike the spike's `NegacyclicDomain` (a `2N`-th-root negacyclic
//! transform for ring products), this is a plain cyclic transform used for
//! polynomial interpolation and evaluation, which is what the low-degree
//! argument needs.
//!
//! The subgroups exist because every atom proof field is a generalized Fermat
//! prime `p = b^64 + 1` with even `b`, so `p - 1 = b^64` has `2^64` as a factor
//! and the field has a power-of-two subgroup of every order up to `2^64`. The
//! spike precomputed only the order-2^16 root; larger domains are computed on
//! demand, which is what lets the full first profile (N = 32768) run without a
//! trace column split.

use super::super::proof_field::ProofFieldParameters;
use super::super::wide_unsigned::{shift_right_one_in_place, subtract_in_place};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

// The proof fields are generalized Fermat primes `p = b^64 + 1` with even `b`,
// so `p - 1 = b^64` is divisible by `2^64`: the field has multiplicative
// subgroups of every order `2^k` for `k <= 64`. The spike precomputed only the
// order-2^16 root, but larger domains exist and are computed on demand
// (`primitive_root_of_order`), which lets the full-profile trace fit without a
// column split. The ceiling is set below the 2-adic valuation with margin for
// the coset offset (order `2 * MAX_TWO_ADIC_ORDER`).
pub(super) const MAX_TWO_ADIC_ORDER: usize = 1 << 20;
const PRECOMPUTED_ROOT_ORDER: usize = 65_536;

// A multiplicative evaluation domain: the cyclic subgroup of a given
// power-of-two order, with its forward/inverse cyclic transforms precomputed.
pub(super) struct CyclicDomain<'a, const LIMB_COUNT: usize> {
    pub(super) parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    pub(super) size: usize,
    // generator^i for i in 0..size (the domain points in transform order).
    domain_points: Vec<[u64; LIMB_COUNT]>,
    forward_twiddles: Vec<[u64; LIMB_COUNT]>,
    inverse_twiddles: Vec<[u64; LIMB_COUNT]>,
    size_inverse: [u64; LIMB_COUNT],
}

impl<'a, const LIMB_COUNT: usize> CyclicDomain<'a, LIMB_COUNT> {
    pub(super) fn new(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) -> CanonicalResult<Self> {
        if !size.is_power_of_two() || !(1..=MAX_TWO_ADIC_ORDER).contains(&size) {
            return Err(invalid_domain(
                "cyclic domain size must be a power of two within the two-adic order",
            ));
        }
        let generator = primitive_root_of_order(parameters, size);
        let generator_inverse = parameters.inverse(&generator);
        let mut domain_points = Vec::with_capacity(size);
        let mut forward_twiddles = Vec::with_capacity(size.max(1) / 2);
        let mut inverse_twiddles = Vec::with_capacity(size.max(1) / 2);
        let mut running = parameters.one();
        for _ in 0..size {
            domain_points.push(running);
            running = parameters.multiply(&running, &generator);
        }
        let mut forward_running = parameters.one();
        let mut inverse_running = parameters.one();
        for _ in 0..size / 2 {
            forward_twiddles.push(forward_running);
            inverse_twiddles.push(inverse_running);
            forward_running = parameters.multiply(&forward_running, &generator);
            inverse_running = parameters.multiply(&inverse_running, &generator_inverse);
        }
        let size_inverse = parameters.inverse(&parameters.unsigned_word_to_element(size as u64));

        Ok(Self {
            parameters,
            size,
            domain_points,
            forward_twiddles,
            inverse_twiddles,
            size_inverse,
        })
    }

    pub(super) fn point(&self, index: usize) -> [u64; LIMB_COUNT] {
        self.domain_points[index]
    }

    // Interpolate the polynomial whose values on this subgroup are `values`,
    // returning its coefficients (low to high). `values.len()` must equal the
    // domain size.
    pub(super) fn interpolate(&self, values: &[[u64; LIMB_COUNT]]) -> Vec<[u64; LIMB_COUNT]> {
        debug_assert_eq!(values.len(), self.size);
        let mut coefficients = values.to_vec();
        self.cyclic_transform(&mut coefficients, &self.inverse_twiddles);
        for coefficient in &mut coefficients {
            *coefficient = self.parameters.multiply(coefficient, &self.size_inverse);
        }
        coefficients
    }

    // Evaluate a coefficient vector (low to high, length <= size, zero-padded)
    // on this subgroup.
    pub(super) fn evaluate(&self, coefficients: &[[u64; LIMB_COUNT]]) -> Vec<[u64; LIMB_COUNT]> {
        debug_assert!(coefficients.len() <= self.size);
        let mut values = vec![self.parameters.zero(); self.size];
        values[..coefficients.len()].copy_from_slice(coefficients);
        self.cyclic_transform(&mut values, &self.forward_twiddles);
        values
    }

    fn cyclic_transform(&self, values: &mut [[u64; LIMB_COUNT]], twiddles: &[[u64; LIMB_COUNT]]) {
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

// Evaluate one coefficient vector (low to high) at an arbitrary field point by
// Horner's rule. Used for out-of-domain (DEEP) evaluations.
pub(super) fn evaluate_polynomial_at<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    point: &[u64; LIMB_COUNT],
) -> [u64; LIMB_COUNT] {
    let mut accumulator = parameters.zero();
    for coefficient in coefficients.iter().rev() {
        accumulator = parameters.add(&parameters.multiply(&accumulator, point), coefficient);
    }
    accumulator
}

// The `blowup`-times low-degree extension of a trace polynomial (given by its
// `trace_size` values on the trace subgroup) evaluated on the coset `offset *
// K`, `K` the subgroup of order `trace_size * blowup`. Returns the coset
// evaluations in `K`-transform order.
#[cfg(test)]
pub(super) fn coset_low_degree_extension<const LIMB_COUNT: usize>(
    trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
    coset_domain: &CyclicDomain<'_, LIMB_COUNT>,
    coset_offset: &[u64; LIMB_COUNT],
    trace_values: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    debug_assert_eq!(trace_values.len(), trace_domain.size);
    debug_assert!(coset_domain.size >= trace_domain.size);
    let parameters = trace_domain.parameters;
    let mut coefficients = trace_domain.interpolate(trace_values);
    // Shift to the coset: p(offset * x) has coefficients c_i * offset^i.
    let mut offset_power = parameters.one();
    for coefficient in &mut coefficients {
        *coefficient = parameters.multiply(coefficient, &offset_power);
        offset_power = parameters.multiply(&offset_power, coset_offset);
    }
    coset_domain.evaluate(&coefficients)
}

// Evaluate a coefficient vector (low to high, length <= coset size) on the
// coset `offset * K` of the given `coset_domain`. Used for committing quotient
// and masked columns whose coefficients are known directly (they exceed the
// trace subgroup size, so `coset_low_degree_extension` does not apply).
pub(super) fn coset_evaluate_coefficients<const LIMB_COUNT: usize>(
    coset_domain: &CyclicDomain<'_, LIMB_COUNT>,
    coset_offset: &[u64; LIMB_COUNT],
    coefficients: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    let parameters = coset_domain.parameters;
    debug_assert!(coefficients.len() <= coset_domain.size);
    let mut shifted = vec![parameters.zero(); coset_domain.size];
    let mut offset_power = parameters.one();
    for (index, coefficient) in coefficients.iter().enumerate() {
        shifted[index] = parameters.multiply(coefficient, &offset_power);
        offset_power = parameters.multiply(&offset_power, coset_offset);
    }
    coset_domain.evaluate(&shifted)
}

// A coset offset outside every FRI domain: a primitive root of order
// `2 * MAX_TWO_ADIC_ORDER`, which cannot lie in any subgroup of order
// `<= MAX_TWO_ADIC_ORDER`, so `offset * K` is disjoint from `K` and stays a
// proper coset under folding (its order stays above the folded subgroup's).
pub(super) fn coset_offset<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
) -> [u64; LIMB_COUNT] {
    compute_primitive_two_adic_root(parameters, (2 * MAX_TWO_ADIC_ORDER).trailing_zeros())
}

fn primitive_root_of_order<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    order: usize,
) -> [u64; LIMB_COUNT] {
    // Orders up to the precomputed 2^16 root step down from it (cheap); larger
    // orders are computed by a short search over the 2-adic tower.
    if order <= PRECOMPUTED_ROOT_ORDER {
        let root = parameters.raw_value_to_element(&parameters.primitive_65536th_root);
        if order == PRECOMPUTED_ROOT_ORDER {
            return root;
        }
        let mut step_exponent = [0_u64; LIMB_COUNT];
        step_exponent[0] = (PRECOMPUTED_ROOT_ORDER / order.max(1)) as u64;
        return parameters.power(&root, &step_exponent);
    }
    compute_primitive_two_adic_root(parameters, order.trailing_zeros())
}

// A primitive `2^log2_order`-th root of unity: for a candidate `z`, `z^((p-1) /
// 2^k)` has order dividing `2^k`, and it is primitive iff its `2^(k-1)` power is
// `-1`. Small `z` are tried until one is primitive (half the field's elements
// give a primitive root, so this succeeds in a couple of tries). `p - 1 = b^64`
// has `v_2 = 64`, so `(p-1)/2^k = (p-1) >> k` exactly for `k <= 64`.
fn compute_primitive_two_adic_root<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    log2_order: u32,
) -> [u64; LIMB_COUNT] {
    debug_assert!((1..=60).contains(&log2_order));
    // exponent = (modulus - 1) >> log2_order.
    let mut exponent = parameters.modulus;
    subtract_in_place(&mut exponent, &{
        let mut one = [0_u64; LIMB_COUNT];
        one[0] = 1;
        one
    });
    for _ in 0..log2_order {
        shift_right_one_in_place(&mut exponent);
    }
    // half power exponent = 2^(log2_order - 1).
    let mut half_power = [0_u64; LIMB_COUNT];
    half_power[0] = 1_u64 << (log2_order - 1);
    let negative_one = parameters.negate(&parameters.one());

    for candidate_word in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        let candidate = parameters.power(
            &parameters.unsigned_word_to_element(candidate_word),
            &exponent,
        );
        if parameters.power(&candidate, &half_power) == negative_one {
            return candidate;
        }
    }
    // The 2-adic order is 64 for these fields; a primitive root is found well
    // within the tried candidates.
    unreachable!("no primitive two-adic root found among small candidates");
}

fn bit_reverse_permute<const LIMB_COUNT: usize>(values: &mut [[u64; LIMB_COUNT]]) {
    let size = values.len();
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
}

fn invalid_domain(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::MalformedLength, message)
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::{
        eight_limb_group_field_parameters, sixteen_limb_group_field_parameters,
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

    #[test]
    fn interpolation_inverts_evaluation() {
        let parameters = sixteen_limb_group_field_parameters();
        for size in [1_usize, 2, 8, 64, 512] {
            let domain = CyclicDomain::new(&parameters, size).expect("domain");
            let coefficients = deterministic_values(&parameters, size, 7 + size as u64);
            let values = domain.evaluate(&coefficients);
            let recovered = domain.interpolate(&values);
            assert_eq!(recovered, coefficients, "round trip at size {size}");
        }
    }

    #[test]
    fn evaluate_agrees_with_horner_on_domain_points() {
        let parameters = eight_limb_group_field_parameters();
        let size = 64;
        let domain = CyclicDomain::new(&parameters, size).expect("domain");
        let coefficients = deterministic_values(&parameters, size, 99);
        let values = domain.evaluate(&coefficients);
        for index in [0_usize, 1, 7, 31, 63] {
            let point = domain.point(index);
            let expected = evaluate_polynomial_at(&parameters, &coefficients, &point);
            assert_eq!(values[index], expected, "point {index}");
        }
    }

    #[test]
    fn coset_low_degree_extension_matches_direct_evaluation() {
        let parameters = sixteen_limb_group_field_parameters();
        let trace_size = 32;
        let blowup = 4;
        let trace_domain = CyclicDomain::new(&parameters, trace_size).expect("trace");
        let coset_domain = CyclicDomain::new(&parameters, trace_size * blowup).expect("coset");
        let offset = coset_offset(&parameters);
        // A degree < trace_size polynomial, given by its values on the trace.
        let coefficients = deterministic_values(&parameters, trace_size, 0xabc);
        let trace_values = trace_domain.evaluate(&coefficients);
        let coset_values =
            coset_low_degree_extension(&trace_domain, &coset_domain, &offset, &trace_values);
        // Each coset value must equal the polynomial evaluated at offset * K^i.
        for index in [0_usize, 1, 5, 63, 127] {
            let point = parameters.multiply(&offset, &coset_domain.point(index));
            let expected = evaluate_polynomial_at(&parameters, &coefficients, &point);
            assert_eq!(coset_values[index], expected, "coset point {index}");
        }
    }

    #[test]
    fn higher_order_domains_beyond_the_precomputed_root_round_trip() {
        // Orders above the precomputed 2^16 root are computed on demand; a
        // correct primitive root makes evaluate/interpolate invert each other.
        let parameters = sixteen_limb_group_field_parameters();
        for log2_order in [17_u32, 18, 19] {
            let size = 1usize << log2_order;
            let domain = CyclicDomain::new(&parameters, size).expect("large domain");
            // A sparse polynomial keeps the test fast at these sizes.
            let mut coefficients = vec![parameters.zero(); size];
            for index in [0_usize, 1, 7, size / 3, size - 1] {
                coefficients[index] = parameters.unsigned_word_to_element(index as u64 + 1);
            }
            let values = domain.evaluate(&coefficients);
            let recovered = domain.interpolate(&values);
            assert_eq!(recovered, coefficients, "round trip at 2^{log2_order}");
        }
    }

    #[test]
    fn computed_primitive_root_has_the_claimed_order() {
        // z^(2^(k-1)) = -1 (primitive) and z^(2^k) = 1 (order divides 2^k).
        let parameters = sixteen_limb_group_field_parameters();
        for log2_order in [17_u32, 18, 20] {
            let root = super::compute_primitive_two_adic_root(&parameters, log2_order);
            let mut full = [0_u64; 13];
            full[0] = 1_u64 << log2_order;
            assert_eq!(parameters.power(&root, &full), parameters.one());
            let mut half = [0_u64; 13];
            half[0] = 1_u64 << (log2_order - 1);
            assert_eq!(
                parameters.power(&root, &half),
                parameters.negate(&parameters.one()),
                "root must be primitive at 2^{log2_order}"
            );
        }
    }

    #[test]
    fn coset_offset_is_outside_the_evaluation_subgroup() {
        let parameters = sixteen_limb_group_field_parameters();
        // offset^size != 1 for any size below the full two-adic order means the
        // coset is disjoint from K; check at a representative coset order.
        let coset_size = 128;
        let offset = coset_offset(&parameters);
        let mut power = parameters.one();
        for _ in 0..coset_size {
            power = parameters.multiply(&power, &offset);
        }
        assert_ne!(power, parameters.one(), "offset must not lie in K");
    }
}
