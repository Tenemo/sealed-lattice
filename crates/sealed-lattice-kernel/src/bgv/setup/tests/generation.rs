use super::*;

#[test]
fn passive_setup_generation_is_verifiable() {
    let first = setup_package_ref();

    assert_eq!(
        first["collectivePublicKey"]["coefficientMaterial"]["objectType"],
        "BgvCollectivePublicKeyCoefficientMaterial"
    );
    assert_eq!(
        first["collectivePublicKey"]["collectivePublicKeyCoefficientRoot"]
            .as_str()
            .expect("collective public key coefficient root")
            .len(),
        128
    );
    verify_passive_setup_package_from_request(&serde_json::json!({
        "setupPackage": first.clone(),
        "expectedRosterHash": request()["rosterHash"],
    }))
    .expect("verify setup package");
}

#[test]
fn passive_setup_collective_key_uses_evaluator_decryptable_contract() {
    let evaluator_key = setup_derived_evaluator_key();

    let ciphertext = evaluator_key
        .encrypt_slots(&[13, 21, 34, 55], "setup-derived-evaluator-encryption")
        .expect("encrypt");
    let decrypted = evaluator_key
        .decrypt_to_slots(&ciphertext)
        .expect("decrypt setup-derived ciphertext");

    assert_eq!(&decrypted[..4], &[13, 21, 34, 55]);
}

#[test]
fn passive_setup_private_witness_is_required_for_test_decryption_key() {
    let package = setup_package();

    let error = match super::development_evaluator_key_from_passive_setup_package(
        &package,
        "wrong-private-setup-seed",
    ) {
        Ok(_) => panic!("wrong private setup witness must reject"),
        Err(error) => error,
    };

    assert!(
        error
            .message
            .contains("private setup witness seed commitment"),
        "{}",
        error.message
    );

    super::development_evaluator_key_from_passive_setup_package(
        &package,
        "passive-bgv-setup-test-seed",
    )
    .expect("matching private setup witness rebuilds the test decryption key");
}

#[test]
fn passive_setup_uses_rejection_sampled_setup_distributions() {
    assert_eq!(reduce_unbiased_u64(u64::MAX, 3), None);
    assert_eq!(reduce_unbiased_u64(u64::MAX, 2), Some(1));
    assert_eq!(reduce_unbiased_u64(6, 3), Some(0));
    assert_eq!(reduce_unbiased_u64(7, 0), None);

    let secret_samples =
        sample_small_distribution(&"1".repeat(128), "trustee-1", "local-secret-share", -1, 1)
            .expect("the fixed private sampler derives within its candidate-draw limit");
    for sample in secret_samples {
        let value = sample["value"].as_i64().expect("secret sample");
        assert!((-1..=1).contains(&value));
    }
    for modulus in DATA_PRIMES {
        let sample = sample_residue(&"1".repeat(128), "public-sample", 17, modulus);
        let sample =
            sample.expect("the fixed public sampler derives within its candidate-draw limit");
        assert!(sample < modulus);
    }
}
