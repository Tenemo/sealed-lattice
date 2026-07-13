use super::*;

#[test]
fn passive_setup_rejects_non_canonical_roster_positions_and_hashes() {
    let mut missing_seed_request = request();
    missing_seed_request
        .as_object_mut()
        .expect("the setup request is an object")
        .remove("setupSeed");
    assert!(generate_passive_setup_package_from_request(&missing_seed_request).is_err());

    let mut empty_seed_request = request();
    empty_seed_request["setupSeed"] = serde_json::json!("");
    assert!(generate_passive_setup_package_from_request(&empty_seed_request).is_err());

    let mut duplicate_position_request = request();
    duplicate_position_request["participants"][1]["rosterPosition"] = serde_json::json!(0);
    assert!(generate_passive_setup_package_from_request(&duplicate_position_request).is_err());

    let mut out_of_range_position_request = request();
    out_of_range_position_request["participants"][2]["rosterPosition"] = serde_json::json!(3);
    assert!(generate_passive_setup_package_from_request(&out_of_range_position_request).is_err());

    let mut uppercase_hash_request = request();
    let uppercase_manifest_hash = uppercase_hash_request["manifestHash"]
        .as_str()
        .expect("manifest hash")
        .to_ascii_uppercase();
    uppercase_hash_request["manifestHash"] = serde_json::json!(uppercase_manifest_hash);
    assert!(generate_passive_setup_package_from_request(&uppercase_hash_request).is_err());
}

#[test]
fn passive_setup_verification_rejects_mutated_roots() {
    let mut package = setup_package();
    package["collectivePublicKey"]["collectivePublicKeyRoot"] = serde_json::json!("0".repeat(128));

    assert!(
        verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .is_err()
    );
}

#[test]
fn passive_setup_verification_rejects_rebound_internal_inconsistency() {
    let mut package = setup_package();
    package["collectivePublicKey"]["record"]["publicKeyShareRoots"][0] =
        serde_json::json!("f".repeat(128));
    rebind_setup_package_hash(&mut package);

    assert!(
        verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .is_err()
    );
}

#[test]
fn passive_setup_payload_validation_rejects_coefficient_material_mutations() {
    let package = setup_package();

    let mut changed_coefficient_root = package.clone();
    changed_coefficient_root["collectivePublicKey"]["collectivePublicKeyCoefficientRoot"] =
        serde_json::json!(valid_hash('4'));
    assert_setup_package_payload_is_rejected(
        changed_coefficient_root,
        "collective public key coefficient root mutation",
    );

    let mut changed_public_key_coefficients = setup_package();
    let coefficient_hex = changed_public_key_coefficients["collectivePublicKey"]
        ["coefficientMaterial"]["coefficientTables"][0]["componentZeroCoefficientsLeHex"]
        .as_str()
        .expect("coefficient hex")
        .to_string();
    let replacement_nibble = if coefficient_hex.ends_with('0') {
        "1"
    } else {
        "0"
    };
    changed_public_key_coefficients["collectivePublicKey"]["coefficientMaterial"]["coefficientTables"]
        [0]["componentZeroCoefficientsLeHex"] = serde_json::json!(format!(
        "{}{}",
        &coefficient_hex[..coefficient_hex.len() - 1],
        replacement_nibble
    ));
    assert_setup_package_payload_is_rejected(
        changed_public_key_coefficients,
        "collective public key coefficient byte mutation",
    );
}

#[test]
fn passive_setup_payload_validation_rejects_binding_mutations() {
    let package = setup_package();
    let mutations: Vec<SetupPackageMutation> = vec![
        (
            "BGV public key root",
            Box::new(|mutated_package| {
                mutated_package["collectivePublicKey"]["bgvPublicKeyRoot"] =
                    serde_json::json!(valid_hash('0'));
            }),
        ),
        (
            "threshold share verification key root",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyRoot"] =
                    serde_json::json!(valid_hash('1'));
            }),
        ),
        (
            "trustee threshold verification key hash",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["verificationKeySet"]["trusteeThresholdVerificationKeyHashes"]
                    [0] = serde_json::json!(valid_hash('2'));
            }),
        ),
        (
            "relinearization key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["evaluationKeyMaterialCommitment"]["relinearizationKeyRoot"] =
                    serde_json::json!(valid_hash('3'));
            }),
        ),
        (
            "key-switch key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["evaluationKeyMaterialCommitment"]["keySwitchKeyRoot"] =
                    serde_json::json!(valid_hash('4'));
            }),
        ),
        (
            "rotation set hash",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["record"]["rotSetHash"] =
                    serde_json::json!(valid_hash('6'));
            }),
        ),
        (
            "rotation key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["evaluationKeyMaterialCommitment"]["rotationKeyRoots"]
                    [0]["rotationKeyRoot"] = serde_json::json!(valid_hash('7'));
            }),
        ),
    ];

    for (mutation_description, mutate_package) in mutations {
        let mut mutated_package = package.clone();
        mutate_package(&mut mutated_package);
        assert_setup_package_payload_is_rejected(mutated_package, mutation_description);
    }
}

#[test]
fn passive_setup_payload_validation_rejects_bgv_parameter_hash_mutation() {
    let mut mutated_package = setup_package();
    mutated_package["bgvParametersHash"] = serde_json::json!(valid_hash('b'));
    assert_setup_package_payload_is_rejected(mutated_package, "BGV parameters hash");
}

#[test]
fn passive_setup_rejects_wrong_request_and_recovery_state_shapes() {
    let mut empty_identity_request = request();
    empty_identity_request["participants"][0]["trusteeIdentity"] = serde_json::json!("");
    assert!(generate_passive_setup_package_from_request(&empty_identity_request).is_err());

    let mut duplicate_identity_request = request();
    duplicate_identity_request["participants"][1]["trusteeIdentity"] =
        duplicate_identity_request["participants"][0]["trusteeIdentity"].clone();
    assert!(generate_passive_setup_package_from_request(&duplicate_identity_request).is_err());

    let mut non_normalized_identity_request = request();
    non_normalized_identity_request["participants"][1]["trusteeIdentity"] =
        serde_json::json!("trustee-e\u{301}");
    assert!(generate_passive_setup_package_from_request(&non_normalized_identity_request).is_err());

    let mut too_small_roster_request = request();
    too_small_roster_request["participants"] = serde_json::json!([
        { "trusteeIdentity": "trustee-1", "rosterPosition": 0 },
        { "trusteeIdentity": "trustee-2", "rosterPosition": 1 }
    ]);
    assert!(generate_passive_setup_package_from_request(&too_small_roster_request).is_err());

    let mut too_large_roster_request = request();
    too_large_roster_request["participants"] = serde_json::Value::Array(
        (0..51)
            .map(|participant_index| {
                serde_json::json!({
                    "trusteeIdentity": format!("trustee-{participant_index}"),
                    "rosterPosition": participant_index,
                })
            })
            .collect(),
    );
    assert!(generate_passive_setup_package_from_request(&too_large_roster_request).is_err());

    for invalid_participant_count in [2_usize, 51_usize] {
        let minimally_shaped_package = serde_json::json!({
            "objectType": "BgvPassiveSetupPackage",
            "participants": vec![serde_json::json!({}); invalid_participant_count],
        });
        assert!(
            validate_setup_package_shape(&minimally_shaped_package).is_err(),
            "participant count {invalid_participant_count} must be rejected by verification shape checks"
        );
    }

    let mut malformed_threshold_hash_request = request();
    malformed_threshold_hash_request["thresholdParametersHash"] = serde_json::json!("not-a-hash");
    assert!(
        generate_passive_setup_package_from_request(&malformed_threshold_hash_request).is_err()
    );

    let package = setup_package();
    for (mutation_description, mutate_package) in [
        (
            "setup ceremony id",
            Box::new(|mutated_package: &mut serde_json::Value| {
                mutated_package["setupInputs"]["ceremonyId"] = serde_json::json!("ceremony-stale");
            }) as Box<dyn Fn(&mut serde_json::Value)>,
        ),
        (
            "participant recovery epoch",
            Box::new(|mutated_package: &mut serde_json::Value| {
                mutated_package["participants"][0]["recoveryEpoch"] = serde_json::json!(99);
            }),
        ),
        (
            "participant device epoch",
            Box::new(|mutated_package: &mut serde_json::Value| {
                mutated_package["participants"][0]["deviceEpoch"] = serde_json::json!(99);
            }),
        ),
        (
            "threshold recovery universe",
            Box::new(|mutated_package: &mut serde_json::Value| {
                mutated_package["thresholdVerificationMaterial"]["verificationKeySet"]["participantInterpolationUniverse"]
                    [0]["recoveryEpoch"] = serde_json::json!(99);
            }),
        ),
    ] {
        let mut mutated_package = package.clone();
        mutate_package(&mut mutated_package);
        assert_setup_package_payload_is_rejected(mutated_package, mutation_description);
    }
}

#[test]
fn passive_setup_verification_rejects_a_missing_rotation_key() {
    let package = setup_package();
    let rotations = package["evaluationKeys"]["rotSet"]["rotations"]
        .as_array()
        .expect("rotations");
    assert_eq!(rotations.len(), 23);
    assert_eq!(rotations[0], serde_json::json!(3));

    let mut missing_packed_rank_key = package.clone();
    missing_packed_rank_key["evaluationKeys"]["evaluationKeyMaterialCommitment"]
        ["rotationKeyRoots"]
        .as_array_mut()
        .expect("rotation roots")
        .remove(0);
    assert_setup_package_payload_is_rejected(
        missing_packed_rank_key,
        "missing generator-ordered packed-rank rotation key",
    );
}
