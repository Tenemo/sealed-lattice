use super::*;

#[test]
fn passive_setup_rejects_externally_supplied_setup_material_secret_fields() {
    for field_name in [
        "globalSecretPolynomial",
        "externallySuppliedSetupSecret",
        "externallySuppliedSetupKeyMaterial",
        "fullSecretKey",
        "collectiveSecretKey",
        "fullSecretReconstruction",
        "thresholdSecretShares",
    ] {
        let mut request = request();
        request["participants"][0][field_name] = serde_json::json!("forbidden");

        let error = generate_passive_setup_package_from_request(&request)
            .expect_err("setup must reject externally supplied secret material");
        assert!(
            error.message.contains(field_name),
            "{field_name}: {}",
            error.message
        );
    }
}

#[test]
fn passive_setup_rejects_non_canonical_roster_positions_and_hashes() {
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

    let mut changed_coefficient_material = package;
    changed_coefficient_material["collectivePublicKey"]["coefficientMaterial"]["modulusSummaries"]
        [0]["componentZeroCoefficientDerivationHash512"] = serde_json::json!("1".repeat(128));
    assert_setup_package_payload_is_rejected(
        changed_coefficient_material,
        "collective public key coefficient material mutation",
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
fn passive_setup_verification_rejects_nested_secret_material() {
    let mut package = setup_package();
    package["participants"][0]["globalSecretPolynomial"] = serde_json::json!("forbidden");
    rebind_setup_package_hash(&mut package);

    assert!(
        verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .is_err()
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
                mutated_package["thresholdVerificationMaterial"]["trusteeThresholdVerificationKeyHashes"]
                    [0] = serde_json::json!(valid_hash('2'));
            }),
        ),
        (
            "relinearization key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["relinearizationKeyRoot"] =
                    serde_json::json!(valid_hash('3'));
            }),
        ),
        (
            "key-switch key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["keySwitchKeyRoot"] =
                    serde_json::json!(valid_hash('4'));
            }),
        ),
        (
            "key-switch decomposition hash",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["keySwitchDecompositionHash"] =
                    serde_json::json!(valid_hash('5'));
            }),
        ),
        (
            "rotation set hash",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["rotSetHash"] =
                    serde_json::json!(valid_hash('6'));
            }),
        ),
        (
            "rotation key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["rotationKeyRoots"][0]["rotationKeyRoot"] =
                    serde_json::json!(valid_hash('7'));
            }),
        ),
        (
            "setup parameter certificate hash",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["setupParameterCertificateHash"] =
                    serde_json::json!(valid_hash('8'));
            }),
        ),
        (
            "target-threshold decryptability certificate hash",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["targetThresholdDecryptabilityCertificateHash"] =
                    serde_json::json!(valid_hash('8'));
            }),
        ),
        (
            "target-threshold decryptability certificate key root",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["targetThresholdDecryptabilityCertificate"]["keyBinding"]
                    ["collectivePublicKeyRoot"] = serde_json::json!(valid_hash('8'));
            }),
        ),
        (
            "collective secret distribution certificate hash",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["collectiveSecretDistributionCertificateHash"] =
                    serde_json::json!(valid_hash('9'));
            }),
        ),
        (
            "target decryption PartDec missing",
            Box::new(|mutated_package| {
                mutated_package["targetDecryptionStatus"]["targetPartDecImplemented"] =
                    serde_json::json!(false);
            }),
        ),
        (
            "target decryption C1-C4 claim",
            Box::new(|mutated_package| {
                mutated_package["targetDecryptionStatus"]["targetC1C4StatusAccepted"] =
                    serde_json::json!(true);
            }),
        ),
        (
            "final security status",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["setupParameterCertificate"]["finalSecurityStatus"] =
                    serde_json::json!("accepted");
            }),
        ),
        (
            "development encryption direct proof claim",
            Box::new(|mutated_package| {
                mutated_package["developmentEncryptionFixture"]["fixture"]["directProofClaim"] =
                    serde_json::json!(true);
            }),
        ),
        (
            "evaluation key material commitment",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["evaluationKeyMaterialCommitment"]["record"]["sampledRelationChecks"]
                    [0]["samples"][0]["relationMatches"] = serde_json::json!(false);
            }),
        ),
        (
            "evaluation key chunk root",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["evaluationKeyStreamingCommitment"]["commitment"]
                    ["chunkRoot"] = serde_json::json!(valid_hash('a'));
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
fn passive_setup_payload_validation_rejects_evaluator_binding_mutations() {
    let package = setup_package();
    for field_name in [
        "evaluatorBindingContextHash",
        "encryptedBallotAggregateLayoutHash",
        "directAggregateLayoutHash",
        "comparisonInputDerivationCircuitHash",
        "encryptedComparisonInputHash",
        "encryptedSparseTargetProjectionHash",
        "targetLayoutHash",
        "passiveSetupEvaluatorContextBindingHash",
    ] {
        let mut mutated_package = package.clone();
        mutated_package["profileBindings"][field_name] = serde_json::json!(valid_hash('b'));
        assert_setup_package_payload_is_rejected(mutated_package, field_name);
    }
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
            "certificates": {
                "setupParameterCertificate": {
                    "finalSecurityStatus": "acceptedForDirectEvaluatorReplayTargetPending",
                },
            },
            "targetDecryptionStatus": {
                "targetC1C4StatusAccepted": false,
                "targetPartDecImplemented": true,
                "setupMaterialMatchesTargetDecryption": true,
            },
            "objectType": "BgvPassiveSetupPackage",
            "objectVersion": 1,
            "participants": vec![serde_json::json!({}); invalid_participant_count],
            "setupInputs": {
                "participantCount": invalid_participant_count,
            },
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "externallySuppliedSetupMaterialBoundary": {
                "rawSecretSharesExported": false,
                "transcriptAcceptsExternallySuppliedSecretReconstruction": false,
            },
        });
        assert!(
            validate_setup_package_shape(&minimally_shaped_package).is_err(),
            "participant count {invalid_participant_count} must be rejected by verification shape checks"
        );
    }

    let stale_security_status_package = serde_json::json!({
        "certificates": {
            "setupParameterCertificate": {
                "finalSecurityStatus": "pendingQTarget",
            },
        },
        "targetDecryptionStatus": {
            "targetC1C4StatusAccepted": false,
            "targetPartDecImplemented": true,
            "setupMaterialMatchesTargetDecryption": true,
        },
        "objectType": "BgvPassiveSetupPackage",
        "objectVersion": 1,
        "participants": vec![serde_json::json!({}); 3],
        "setupInputs": {
            "participantCount": 3,
        },
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "externallySuppliedSetupMaterialBoundary": {
            "rawSecretSharesExported": false,
            "transcriptAcceptsExternallySuppliedSecretReconstruction": false,
        },
    });
    let stale_status_error = validate_setup_package_shape(&stale_security_status_package)
        .expect_err("stale setup security status must be refused before encrypted evaluation");
    assert!(
        stale_status_error
            .message
            .contains("accept direct evaluator replay HE security"),
        "{}",
        stale_status_error.message
    );

    let mut malformed_threshold_hash_request = request();
    malformed_threshold_hash_request["thresholdProfileHash"] = serde_json::json!("not-a-hash");
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
            "setup participant count",
            Box::new(|mutated_package: &mut serde_json::Value| {
                mutated_package["setupInputs"]["participantCount"] = serde_json::json!(4);
            }),
        ),
        (
            "setup participant identities",
            Box::new(|mutated_package: &mut serde_json::Value| {
                mutated_package["setupInputs"]["participantIdentities"][0] =
                    serde_json::json!("trustee-clone");
            }),
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
fn passive_setup_verification_rejects_rotation_set_gaps() {
    let package = setup_package();
    let rotations = package["evaluationKeys"]["rotSet"]["rotations"]
        .as_array()
        .expect("rotations");
    assert_eq!(rotations.len(), 23);
    assert_eq!(rotations[0], serde_json::json!(3));
    assert_eq!(
        package["evaluationKeys"]["rotSet"]["requiredRotationGroups"][0]["purpose"],
        "direct-score-packing-generator-basis"
    );
    assert_eq!(
        package["evaluationKeys"]["rotSet"]["requiredRotationGroups"][1]["purpose"],
        "generator-ordered-packed-rank-forward-basis"
    );
    assert_eq!(
        package["evaluationKeys"]["rotSet"]["requiredRotationGroups"][2]["purpose"],
        "generator-ordered-packed-rank-return-basis"
    );

    let mut missing_packed_rank_key = package.clone();
    missing_packed_rank_key["evaluationKeys"]["rotationKeyRoots"]
        .as_array_mut()
        .expect("rotation roots")
        .remove(0);
    assert_setup_package_payload_is_rejected(
        missing_packed_rank_key,
        "missing generator-ordered packed-rank rotation key",
    );

    let mut wrong_required_rotation_group = package.clone();
    wrong_required_rotation_group["evaluationKeys"]["rotSet"]["requiredRotationGroups"][0]["rotations"]
        [0] = serde_json::json!(1);
    assert_setup_package_payload_is_rejected(
        wrong_required_rotation_group,
        "wrong direct score packing rotation group",
    );
}
