use super::*;

#[test]
fn centered_binomial_eta2_samples_match_certified_sampler() {
    let seed_hash = "1".repeat(128);
    let samples = sample_centered_binomial_eta2(&seed_hash, "trustee-1", "local-error");
    for sample in samples {
        let position = sample["position"].as_u64().expect("position") as usize;
        let position_text = position.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-v1",
            &[
                seed_hash.as_bytes(),
                b"trustee-1",
                b"local-error",
                position_text.as_bytes(),
            ],
        );
        let expected_value = i64::from(output[0] & 1) + i64::from((output[0] >> 1) & 1)
            - i64::from((output[0] >> 2) & 1)
            - i64::from((output[0] >> 3) & 1);

        assert_eq!(sample["value"], expected_value);
        assert!((-2..=2).contains(&expected_value));
    }
}

#[test]
fn dense_centered_binomial_eta2_sampler_consumes_full_hash_blocks() {
    let seed_hash = "1".repeat(128);
    let coefficients =
        dense_centered_binomial_coefficients(&seed_hash, "trustee-1", "fixture-error");
    let first_block = hash512(
        "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-dense-v1",
        &[seed_hash.as_bytes(), b"trustee-1", b"fixture-error", b"0"],
    );
    let second_block = hash512(
        "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-dense-v1",
        &[seed_hash.as_bytes(), b"trustee-1", b"fixture-error", b"1"],
    );

    assert_eq!(coefficients.len(), POLYNOMIAL_DEGREE);
    assert!(coefficients.iter().all(|value| (-2..=2).contains(value)));
    assert_eq!(
        coefficients[0],
        centered_binomial_eta2_value_from_byte(first_block[0])
    );
    assert_eq!(
        coefficients[1],
        centered_binomial_eta2_value_from_byte(first_block[0] >> 4)
    );
    assert_eq!(
        coefficients[127],
        centered_binomial_eta2_value_from_byte(first_block[63] >> 4)
    );
    assert_eq!(
        coefficients[128],
        centered_binomial_eta2_value_from_byte(second_block[0])
    );
}
