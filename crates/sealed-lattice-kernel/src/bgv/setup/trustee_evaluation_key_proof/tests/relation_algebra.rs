use super::*;
use crate::bgv::modular_arithmetic::pow_mod;

#[test]
fn galois_transpose_matches_forward_automorphism_inner_product() {
    // The lincheck relies on <u, phi_g(s)> = <M_phi^T u, s>; check it for
    // random vectors against the forward automorphism over a profile prime.
    let modulus = DATA_PRIMES[0];
    let degree = 64_usize;
    let mut seed_value = 0x9e3779b97f4a7c15_u64;
    let mut next = || {
        seed_value ^= seed_value << 13;
        seed_value ^= seed_value >> 7;
        seed_value ^= seed_value << 17;
        seed_value % modulus
    };
    for galois_element in [3_usize, 5, 31, 127] {
        let values = (0..degree).map(|_| next()).collect::<Vec<_>>();
        let vector = (0..degree).map(|_| next()).collect::<Vec<_>>();
        let rotated = galois_automorphism_apply(&values, galois_element, modulus)
            .expect("forward automorphism");
        let transposed = galois_automorphism_transpose_apply(&vector, galois_element, modulus)
            .expect("transpose automorphism");
        let dot = |left: &[u64], right: &[u64]| -> u128 {
            left.iter().zip(right.iter()).fold(0_u128, |total, (a, b)| {
                (total + u128::from(*a) * u128::from(*b)) % u128::from(modulus)
            })
        };
        assert_eq!(
            dot(&vector, &rotated),
            dot(&transposed, &values),
            "transpose identity must hold for element {galois_element}"
        );
    }
}

#[test]
fn degree_t_sumcheck_residual_shifts_subgroup_constant() {
    // A sumcheck residual of degree exactly T can hide a false constant by
    // adding a term that vanishes on the trace subgroup: the forged slack is
    // zero at X = 0 but has degree exactly T. This is why the residual column
    // carries its own degree-below-T low-degree proof, which rejects it.
    let modulus = DATA_PRIMES[0];
    let trace_size = 64_usize;
    let trace_root = pow_mod(
        crate::bgv::profile::root_parameters_for_modulus(modulus)
            .expect("root parameters")
            .negacyclic_root,
        (2 * crate::bgv::profile::POLYNOMIAL_DEGREE / trace_size) as u64,
        modulus,
    )
    .expect("trace root");
    let false_constant_delta = 17_u64;
    let true_expected_constant = 123_u64;
    let false_expected_constant = (true_expected_constant + false_constant_delta) % modulus;
    let forged_top_coefficient = (modulus - false_constant_delta) % modulus;

    assert_ne!(forged_top_coefficient, 0);
    assert_eq!(
        (false_expected_constant + forged_top_coefficient) % modulus,
        true_expected_constant
    );

    let mut subgroup_point = 1_u64;
    for _position in 0..trace_size {
        assert_eq!(
            pow_mod(subgroup_point, trace_size as u64, modulus).expect("power"),
            1
        );
        let forged_residual_at_trace_point = forged_top_coefficient;
        assert_eq!(
            (false_expected_constant + forged_residual_at_trace_point) % modulus,
            true_expected_constant,
            "the degree-T slack preserves the false sumcheck on the trace subgroup"
        );
        subgroup_point =
            (u128::from(subgroup_point) * u128::from(trace_root) % u128::from(modulus)) as u64;
    }

    let mut forged_residual_coefficients = vec![0_u64; trace_size + 1];
    forged_residual_coefficients[trace_size] = forged_top_coefficient;
    assert_eq!(forged_residual_coefficients[0], 0);
    assert!(
        forged_residual_coefficients.len() > trace_size,
        "the forged residual has degree T and violates the new degree-below-T bound"
    );
}
