use super::*;

#[test]
fn passive_setup_generation_is_deterministic_and_verifiable() {
    let first = setup_package_ref();

    assert_eq!(
        first["setupPackageHash"], EXPECTED_PASSIVE_SETUP_TEST_PACKAGE_HASH,
        "passive setup generation must remain deterministic for the fixed test seed"
    );
    assert_eq!(first["setupInputs"]["defaultSetupSeedUsed"], false);
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
    assert!(
        first["participants"][0]
            .get("sampledLocalSecretCoefficients")
            .is_none()
    );
    assert!(
        first["participants"][0]
            .get("sampledLocalErrorCoefficients")
            .is_none()
    );
    assert!(first["setupInputs"].get("privateSetupSeedHash").is_none());
    assert!(first.get("privateSetupSeedHash").is_none());

    let verification = verify_passive_setup_package_from_request(&serde_json::json!({
        "setupPackage": first.clone(),
        "expectedRosterHash": request()["rosterHash"],
    }))
    .expect("verify setup package");
    assert_eq!(verification["ok"], true);
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
fn passive_setup_keeps_special_prime_out_of_public_exposure() {
    let package = setup_package_ref();
    let public_samples = &package["certificates"]["publicRlweSamplesByBasis"];

    assert_eq!(
        public_samples["QPPublic"]["relinearizationKeys"],
        serde_json::json!(0)
    );
    assert_eq!(
        public_samples["QPPublic"]["rotationKeys"],
        serde_json::json!(0)
    );
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
fn passive_setup_marks_default_development_seed_usage() {
    let mut request = request();
    request
        .as_object_mut()
        .expect("request should be an object")
        .remove("setupSeed");

    let package =
        generate_passive_setup_package_from_request(&request).expect("default seed setup");

    assert_eq!(package["setupInputs"]["defaultSetupSeedUsed"], true);
}

#[test]
fn passive_setup_uses_rejection_sampled_setup_distributions() {
    assert_eq!(reduce_unbiased_u64(u64::MAX, 3), None);
    assert_eq!(reduce_unbiased_u64(u64::MAX, 2), Some(1));
    assert_eq!(reduce_unbiased_u64(6, 3), Some(0));
    assert_eq!(reduce_unbiased_u64(7, 0), None);

    let secret_samples =
        sample_small_distribution(&"1".repeat(128), "trustee-1", "local-secret-share", -1, 1);
    for sample in secret_samples {
        let value = sample["value"].as_i64().expect("secret sample");
        assert!((-1..=1).contains(&value));
    }
    for modulus in DATA_PRIMES {
        let sample = sample_residue(&"1".repeat(128), "public-sample", 17, modulus);
        assert!(sample < modulus);
    }
}

#[test]
fn public_common_random_polynomial_root_matches_canonical_object_hash() {
    let package = setup_package();
    let setup_seed_hash = package["setupInputs"]["setupSeedHash"]
        .as_str()
        .expect("setup seed hash");
    let common_random_polynomial_record = serde_json::json!({
        "objectType": "BgvPublicCommonRandomPolynomial",
        "objectVersion": 1,
        "ceremonyId": package["setupInputs"]["ceremonyId"],
        "rosterHash": package["setupInputs"]["rosterHash"],
        "setupSeedHash": setup_seed_hash,
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "sampledResidues": sample_public_residues(
            setup_seed_hash,
            "public-common-random-polynomial",
            DATA_PRIMES[0],
        ),
    });
    let actual_root = package["collectivePublicKey"]["record"]["publicCommonRandomPolynomialRoot"]
        .as_str()
        .expect("public common random polynomial root");
    let expected_root = derive_canonical_object_hash(&common_random_polynomial_record)
        .expect("common random polynomial root");

    assert_eq!(actual_root, expected_root);
}
