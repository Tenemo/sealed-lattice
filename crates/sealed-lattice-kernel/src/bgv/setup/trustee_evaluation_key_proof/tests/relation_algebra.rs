use super::*;

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
