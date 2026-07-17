//! Cyclic evaluation domains and coset low-degree extension over the atom
//! proof field.
//!
//! The atom PIOP encodes each length-`trace_size` witness column as the values
//! of a polynomial of degree below `trace_size` on the multiplicative subgroup
//! `H` of that order (the trace domain), then commits its low-degree extension
//! on a `blowup`-times-larger coset `g * K`, where `K` is the subgroup of order
//! `trace_size * blowup` and `g` is a non-`K` coset offset. FRI runs over the
//! coset. This cyclic transform handles polynomial interpolation and evaluation;
//! `NegacyclicDomain` separately handles ring products.
//!
//! The subgroups exist because every atom proof field is a generalized Fermat
//! prime `p = b^64 + 1` with even `b`, so `p - 1 = b^64` has `2^64` as a factor
//! and admits the required power-of-two subgroups. Roots above the stored
//! order-2^16 root are computed on demand, allowing N = 32768 to run without a
//! trace-column split.

use super::super::negacyclic_transform::radix_two_cyclic_transform_in_place;
use super::super::proof_field::ProofFieldParameters;
use super::super::wide_unsigned::{shift_right_one_in_place, subtract_in_place};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

// Maximum cyclic domain size. It stays below the fields' 2-adic capacity and
// leaves room for a coset offset of order `2 * MAX_TWO_ADIC_ORDER`.
pub(super) const MAX_TWO_ADIC_ORDER: usize = 1 << 20;
const PRECOMPUTED_ROOT_ORDER: usize = 65_536;

// A multiplicative evaluation domain: the cyclic subgroup of a given
// power-of-two order, retaining only the transform directions its caller uses.
pub(super) struct CyclicDomain<'a, const LIMB_COUNT: usize> {
    pub(super) parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    pub(super) size: usize,
    #[cfg(test)]
    generator: [u64; LIMB_COUNT],
    #[cfg(test)]
    forward_twiddles: Option<Vec<[u64; LIMB_COUNT]>>,
    inverse_twiddles: Option<Vec<[u64; LIMB_COUNT]>>,
    size_inverse: Option<[u64; LIMB_COUNT]>,
}

// Domain geometry without transform tables. Verification and FRI folding need
// subgroup points but never evaluate or interpolate whole polynomials, so they
// should not allocate domain-sized forward and inverse twiddle tables.
pub(super) struct CyclicDomainGeometry<'a, const LIMB_COUNT: usize> {
    parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    pub(super) size: usize,
    generator: [u64; LIMB_COUNT],
    generator_inverse: [u64; LIMB_COUNT],
}

impl<'a, const LIMB_COUNT: usize> CyclicDomainGeometry<'a, LIMB_COUNT> {
    pub(super) fn new(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) -> CanonicalResult<Self> {
        validate_domain_size(size)?;
        let generator = primitive_root_of_order(parameters, size);
        // A subgroup generator satisfies generator^size = 1, so its inverse is
        // generator^(size - 1). The public exponent is at most 20 bits; using
        // the general Fermat inversion here would repeat hundreds of needless
        // field squarings for every FRI layer.
        let generator_inverse = power_by_domain_index(parameters, &generator, size - 1);
        Ok(Self {
            parameters,
            size,
            generator,
            generator_inverse,
        })
    }

    pub(super) fn point(&self, index: usize) -> [u64; LIMB_COUNT] {
        assert!(
            index < self.size,
            "cyclic domain point index must be in range"
        );
        power_by_domain_index(self.parameters, &self.generator, index)
    }

    pub(super) fn inverse_point(&self, index: usize) -> [u64; LIMB_COUNT] {
        assert!(
            index < self.size,
            "cyclic domain point index must be in range"
        );
        power_by_domain_index(self.parameters, &self.generator_inverse, index)
    }

    pub(super) fn generator(&self) -> &[u64; LIMB_COUNT] {
        &self.generator
    }

    pub(super) fn generator_inverse(&self) -> &[u64; LIMB_COUNT] {
        &self.generator_inverse
    }
}

impl<'a, const LIMB_COUNT: usize> CyclicDomain<'a, LIMB_COUNT> {
    #[cfg(test)]
    pub(super) fn new(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) -> CanonicalResult<Self> {
        Self::with_transform_directions(parameters, size, true, true)
    }

    #[cfg(test)]
    pub(super) fn for_evaluation(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) -> CanonicalResult<Self> {
        Self::with_transform_directions(parameters, size, true, false)
    }

    pub(super) fn for_interpolation(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
    ) -> CanonicalResult<Self> {
        Self::with_transform_directions(parameters, size, false, true)
    }

    fn with_transform_directions(
        parameters: &'a ProofFieldParameters<LIMB_COUNT>,
        size: usize,
        include_forward: bool,
        include_inverse: bool,
    ) -> CanonicalResult<Self> {
        let geometry = CyclicDomainGeometry::new(parameters, size)?;
        let generator = *geometry.generator();
        let generator_inverse = *geometry.generator_inverse();
        let mut forward_twiddles = include_forward.then(|| Vec::with_capacity(size.max(1) / 2));
        let mut inverse_twiddles = include_inverse.then(|| Vec::with_capacity(size.max(1) / 2));
        let mut forward_running = parameters.one();
        let mut inverse_running = parameters.one();
        for _ in 0..size / 2 {
            if let Some(twiddles) = &mut forward_twiddles {
                twiddles.push(forward_running);
                forward_running = parameters.multiply(&forward_running, &generator);
            }
            if let Some(twiddles) = &mut inverse_twiddles {
                twiddles.push(inverse_running);
                inverse_running = parameters.multiply(&inverse_running, &generator_inverse);
            }
        }
        let size_inverse = include_inverse
            .then(|| parameters.inverse(&parameters.unsigned_word_to_element(size as u64)));

        Ok(Self {
            parameters,
            size,
            #[cfg(test)]
            generator,
            #[cfg(test)]
            forward_twiddles,
            inverse_twiddles,
            size_inverse,
        })
    }

    #[cfg(test)]
    pub(super) fn point(&self, index: usize) -> [u64; LIMB_COUNT] {
        assert!(
            index < self.size,
            "cyclic domain point index must be in range"
        );
        power_by_domain_index(self.parameters, &self.generator, index)
    }

    // Interpolate the polynomial whose values on this subgroup are `values`,
    // returning its coefficients (low to high). `values.len()` must equal the
    // domain size.
    pub(super) fn interpolate(&self, values: &[[u64; LIMB_COUNT]]) -> Vec<[u64; LIMB_COUNT]> {
        debug_assert_eq!(values.len(), self.size);
        let mut coefficients = values.to_vec();
        let inverse_twiddles = self
            .inverse_twiddles
            .as_deref()
            .expect("cyclic domain was not constructed for interpolation");
        radix_two_cyclic_transform_in_place(self.parameters, &mut coefficients, inverse_twiddles);
        let size_inverse = self
            .size_inverse
            .as_ref()
            .expect("an interpolation domain carries its size inverse");
        for coefficient in &mut coefficients {
            *coefficient = self.parameters.multiply(coefficient, size_inverse);
        }
        coefficients
    }

    // Evaluate a coefficient vector (low to high, length <= size, zero-padded)
    // on this subgroup.
    #[cfg(test)]
    pub(super) fn evaluate(&self, coefficients: &[[u64; LIMB_COUNT]]) -> Vec<[u64; LIMB_COUNT]> {
        debug_assert!(coefficients.len() <= self.size);
        let mut values = vec![self.parameters.zero(); self.size];
        values[..coefficients.len()].copy_from_slice(coefficients);
        self.evaluate_in_place(&mut values);
        values
    }

    // Evaluate one full, zero-padded coefficient buffer in place. Hot prover
    // paths reuse this storage across columns rather than allocating and
    // copying another domain-sized vector for every low-degree extension.
    #[cfg(test)]
    pub(super) fn evaluate_in_place(&self, values: &mut [[u64; LIMB_COUNT]]) {
        debug_assert_eq!(values.len(), self.size);
        let forward_twiddles = self
            .forward_twiddles
            .as_deref()
            .expect("cyclic domain was not constructed for evaluation");
        radix_two_cyclic_transform_in_place(self.parameters, values, forward_twiddles);
    }
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
#[cfg(test)]
pub(super) fn coset_evaluate_coefficients<const LIMB_COUNT: usize>(
    coset_domain: &CyclicDomain<'_, LIMB_COUNT>,
    coset_offset: &[u64; LIMB_COUNT],
    coefficients: &[[u64; LIMB_COUNT]],
) -> Vec<[u64; LIMB_COUNT]> {
    let mut values = vec![coset_domain.parameters.zero(); coset_domain.size];
    coset_evaluate_coefficients_into(coset_domain, coset_offset, coefficients, &mut values);
    values
}

// Evaluate coefficients into a reusable full-domain buffer. The prefix is
// overwritten and the unused tail is cleared before the in-place transform,
// so values left by a longer preceding column cannot affect this evaluation.
#[cfg(test)]
pub(super) fn coset_evaluate_coefficients_into<const LIMB_COUNT: usize>(
    coset_domain: &CyclicDomain<'_, LIMB_COUNT>,
    coset_offset: &[u64; LIMB_COUNT],
    coefficients: &[[u64; LIMB_COUNT]],
    values: &mut [[u64; LIMB_COUNT]],
) {
    debug_assert!(coefficients.len() <= coset_domain.size);
    debug_assert_eq!(values.len(), coset_domain.size);
    values[coefficients.len()..].fill(coset_domain.parameters.zero());
    let mut offset_power = coset_domain.parameters.one();
    for (value, coefficient) in values.iter_mut().zip(coefficients) {
        *value = coset_domain.parameters.multiply(coefficient, &offset_power);
        offset_power = coset_domain
            .parameters
            .multiply(&offset_power, coset_offset);
    }
    coset_domain.evaluate_in_place(values);
}

// Shift one full coefficient buffer onto the coset and evaluate it in place.
// This is used after the prover has formed a weighted coefficient combination.
#[cfg(test)]
pub(super) fn coset_evaluate_coefficients_in_place<const LIMB_COUNT: usize>(
    coset_domain: &CyclicDomain<'_, LIMB_COUNT>,
    coset_offset: &[u64; LIMB_COUNT],
    coefficients: &mut [[u64; LIMB_COUNT]],
) {
    debug_assert_eq!(coefficients.len(), coset_domain.size);
    let parameters = coset_domain.parameters;
    let mut offset_power = parameters.one();
    for coefficient in coefficients.iter_mut() {
        *coefficient = parameters.multiply(coefficient, &offset_power);
        offset_power = parameters.multiply(&offset_power, coset_offset);
    }
    coset_domain.evaluate_in_place(coefficients);
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
        return power_by_domain_index(parameters, &root, PRECOMPUTED_ROOT_ORDER / order.max(1));
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

fn invalid_domain(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::MalformedLength, message)
}

fn validate_domain_size(size: usize) -> CanonicalResult<()> {
    if !size.is_power_of_two() || !(1..=MAX_TWO_ADIC_ORDER).contains(&size) {
        return Err(invalid_domain(
            "cyclic domain size must be a power of two within the two-adic order",
        ));
    }
    Ok(())
}

// Domain indices are public and at most 20 bits wide. Keep their conversion to
// the field's little-endian public exponent representation in one place.
fn power_by_domain_index<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    base: &[u64; LIMB_COUNT],
    index: usize,
) -> [u64; LIMB_COUNT] {
    let mut exponent = [0_u64; LIMB_COUNT];
    exponent[0] = index as u64;
    parameters.power(base, &exponent)
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::{
        eight_limb_group_field_parameters, sixteen_limb_group_field_parameters,
    };
    use super::*;
    use crate::bgv::setup::limb_group_key_switch_atom::family_backend::polynomial::evaluate;

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

    fn check_lightweight_geometry<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
    ) {
        for size in [1_usize, 64, 1 << 17] {
            let geometry = CyclicDomainGeometry::new(parameters, size).expect("domain geometry");
            let mut indices = vec![0, size / 3, size - 1];
            indices.sort_unstable();
            indices.dedup();
            for index in indices {
                let mut full_width_exponent = [0_u64; LIMB_COUNT];
                full_width_exponent[0] = index as u64;
                assert_eq!(
                    geometry.point(index),
                    parameters.power(geometry.generator(), &full_width_exponent),
                    "short public-index exponentiation must match the established field power at size {size}, index {index}"
                );
                assert_eq!(
                    parameters.multiply(&geometry.point(index), &geometry.inverse_point(index)),
                    parameters.one(),
                    "a domain point and its inverse must multiply to one at size {size}, index {index}"
                );
            }
        }
    }

    #[test]
    fn lightweight_domain_geometry_matches_full_width_field_power() {
        check_lightweight_geometry(&eight_limb_group_field_parameters());
        check_lightweight_geometry(&sixteen_limb_group_field_parameters());
    }

    fn check_root_tower_across_precomputed_boundary<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
    ) {
        for larger_order in [1_usize << 17, 1 << 18] {
            let larger_root = primitive_root_of_order(parameters, larger_order);
            let next_root = primitive_root_of_order(parameters, larger_order / 2);
            assert_eq!(
                parameters.multiply(&larger_root, &larger_root),
                next_root,
                "squaring the order-{larger_order} root must produce the next FRI layer root"
            );
        }
    }

    #[test]
    fn computed_roots_continue_the_precomputed_fri_root_tower() {
        check_root_tower_across_precomputed_boundary(&eight_limb_group_field_parameters());
        check_root_tower_across_precomputed_boundary(&sixteen_limb_group_field_parameters());
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
    fn direction_specific_domains_match_the_full_transform_domain() {
        let parameters = sixteen_limb_group_field_parameters();
        let size = 128;
        let coefficients = deterministic_values(&parameters, size, 0x711d);
        let full_domain = CyclicDomain::new(&parameters, size).expect("full domain");
        let evaluation_domain =
            CyclicDomain::for_evaluation(&parameters, size).expect("evaluation domain");
        let interpolation_domain =
            CyclicDomain::for_interpolation(&parameters, size).expect("interpolation domain");

        let expected_values = full_domain.evaluate(&coefficients);
        assert_eq!(evaluation_domain.evaluate(&coefficients), expected_values);
        assert_eq!(
            interpolation_domain.interpolate(&expected_values),
            coefficients
        );
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
            let expected = evaluate(&parameters, &coefficients, &point);
            assert_eq!(values[index], expected, "point {index}");
        }
    }

    #[test]
    fn reusable_coset_buffer_clears_coefficients_from_longer_preceding_columns() {
        let parameters = sixteen_limb_group_field_parameters();
        let size = 128;
        let domain = CyclicDomain::new(&parameters, size).expect("domain");
        let offset = coset_offset(&parameters);
        let longer = deterministic_values(&parameters, 97, 0x1111);
        let shorter = deterministic_values(&parameters, 7, 0x2222);
        let mut reusable = vec![parameters.zero(); size];

        coset_evaluate_coefficients_into(&domain, &offset, &longer, &mut reusable);
        coset_evaluate_coefficients_into(&domain, &offset, &shorter, &mut reusable);
        assert_eq!(
            reusable,
            coset_evaluate_coefficients(&domain, &offset, &shorter),
            "a shorter column must not inherit a transformed tail from prior scratch contents"
        );

        coset_evaluate_coefficients_into(&domain, &offset, &[], &mut reusable);
        assert!(
            reusable.iter().all(|value| *value == parameters.zero()),
            "an empty coefficient vector must clear the complete reusable buffer"
        );
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
            let expected = evaluate(&parameters, &coefficients, &point);
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
