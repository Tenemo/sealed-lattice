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
