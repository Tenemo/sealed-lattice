use super::*;

#[test]
fn interpolation_reproduces_sampled_values() {
    let values = [5_u64, 9, 2, 7, 65_000];
    let coefficients = interpolate_coefficients(&values).expect("interpolate");
    for (point, value) in values.iter().enumerate() {
        assert_eq!(evaluate_plaintext(&coefficients, point as u64), *value);
    }
}
