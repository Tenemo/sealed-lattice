use super::*;

#[test]
fn score_bit_count_matches_domain() {
    assert_eq!(score_bit_count(0), 1);
    assert_eq!(score_bit_count(1), 1);
    assert_eq!(score_bit_count(10), 4);
    assert_eq!(score_bit_count(200), 8);
    assert_eq!(score_bit_count(500), 9);
}

#[test]
fn interpolation_reproduces_sampled_values() {
    let values = [5_u64, 9, 2, 7, 65_000];
    let coefficients = interpolate_coefficients(&values).expect("interpolate");
    for (point, value) in values.iter().enumerate() {
        assert_eq!(evaluate_plaintext(&coefficients, point as u64), *value);
    }
}

#[test]
fn bit_extraction_polynomials_recover_each_bit_over_domain() {
    let domain_max = 20_u64;
    let polynomials = bit_extraction_polynomials(domain_max).expect("bit polynomials");
    assert_eq!(polynomials.len(), score_bit_count(domain_max));
    for value in 0..=domain_max {
        for (bit, polynomial) in polynomials.iter().enumerate() {
            let expected = (value >> bit) & 1;
            assert_eq!(evaluate_plaintext(polynomial, value), expected);
        }
    }
}
