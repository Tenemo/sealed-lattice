use super::sampling::reduce_unbiased_u64;
use super::validation::validate_setup_package_shape;
use super::{
    DATA_PRIMES, PASSIVE_SETUP_PROFILE_ID, POLYNOMIAL_DEGREE,
    generate_passive_setup_package_from_request, sample_centered_binomial_eta2,
    sample_public_residues, sample_small_distribution, verify_passive_setup_package_from_request,
};
use crate::hashing::{derive_protocol_digest, hash512};

type SetupPackageMutation = (&'static str, Box<dyn Fn(&mut serde_json::Value)>);

fn request() -> serde_json::Value {
    serde_json::json!({
        "ceremonyId": "ceremony-main",
        "manifestDigest": derive_protocol_digest(
            "ElectionManifestDigest",
            &serde_json::json!({ "manifest": "m8-test" }),
        ).expect("manifest digest"),
        "rosterDigest": derive_protocol_digest(
            "RosterDigest",
            &serde_json::json!({ "roster": "m8-test" }),
        ).expect("roster digest"),
        "thresholdProfileDigest": derive_protocol_digest(
            "ThresholdProfileDigest",
            &serde_json::json!({ "threshold": "m8-test" }),
        ).expect("threshold digest"),
        "participants": [
            { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
            { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 4 },
            { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 5 }
        ],
        "setupSeed": "m8-test-seed",
    })
}

fn rebind_setup_package_digest(package: &mut serde_json::Value) {
    let mut digest_input = package.clone();
    digest_input
        .as_object_mut()
        .expect("setup package must be an object")
        .remove("setupPackageDigest");
    package["setupPackageDigest"] = serde_json::json!(
        derive_protocol_digest("BGVPassiveSetupPackageDigest", &digest_input)
            .expect("setup package digest")
    );
}

fn valid_digest(fill: char) -> String {
    fill.to_string().repeat(128)
}

fn assert_rebound_package_is_rejected(mut package: serde_json::Value, mutation_description: &str) {
    rebind_setup_package_digest(&mut package);
    assert!(
        verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .is_err(),
        "{mutation_description} should be rejected"
    );
}

#[test]
fn passive_setup_generation_is_deterministic_and_verifiable() {
    let first = generate_passive_setup_package_from_request(&request()).expect("first setup");
    let second = generate_passive_setup_package_from_request(&request()).expect("second setup");

    assert_eq!(first["setupPackageDigest"], second["setupPackageDigest"]);
    assert_eq!(
        first["kllpsCompatibility"]["setupMaterialCompatibleWithKLLPS"],
        true
    );
    assert_eq!(
        first["kllpsCompatibility"]["KLLPSPartDecImplemented"],
        false
    );
    assert_eq!(
        first["certificates"]["setupParameterCertificate"]["finalSecurityStatus"],
        "pendingQTarget"
    );
    assert_eq!(first["setupInputs"]["defaultSetupSeedUsed"], false);
    assert_eq!(
        first["participants"][0]["sampleDisclosure"],
        "commitment-digests-and-roots-only"
    );
    assert_eq!(
        first["participants"][0]["sampledLocalSecretCoefficientsIncluded"],
        false
    );
    assert_eq!(
        first["participants"][0]["sampledLocalErrorCoefficientsIncluded"],
        false
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

    let verification = verify_passive_setup_package_from_request(&serde_json::json!({
        "setupPackage": first,
        "expectedRosterDigest": request()["rosterDigest"],
    }))
    .expect("verify setup package");
    assert_eq!(verification["ok"], true);
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
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    assert_eq!(
        package["certificates"]["collectiveSecretDistributionCertificate"]["localShareSampler"]["samplerId"],
        "hash-derived-rejection-sampled-balanced-ternary-local-share-v2"
    );
    assert_eq!(
        package["certificates"]["errorDistributionCertificate"]["crpPublicSampleDistribution"]["distributionKind"],
        "hash-to-modulus-rejection-sampled-uniform-public-sample"
    );
    assert_eq!(
        package["certificates"]["errorDistributionCertificate"]["rejectionSamplingRules"]
            .as_array()
            .expect("rejection sampling rules")
            .len(),
        2
    );

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
        let sample = super::sample_residue(&"1".repeat(128), "public-sample", 17, modulus);
        assert!(sample < modulus);
    }
}

#[test]
fn public_common_random_polynomial_uses_its_own_root_namespace() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    let setup_seed_digest = package["setupInputs"]["setupSeedDigest"]
        .as_str()
        .expect("setup seed digest");
    let common_random_polynomial_record = serde_json::json!({
        "objectType": "BgvPublicCommonRandomPolynomial",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": package["setupInputs"]["ceremonyId"],
        "rosterDigest": package["setupInputs"]["rosterDigest"],
        "setupSeedDigest": setup_seed_digest,
        "basisId": "sealed-lattice-bgv-rns-data-basis-v1",
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "sampledResidues": sample_public_residues(
            setup_seed_digest,
            "public-common-random-polynomial",
            DATA_PRIMES[0],
        ),
    });
    let actual_root = package["collectivePublicKey"]["record"]["publicCommonRandomPolynomialRoot"]
        .as_str()
        .expect("public common random polynomial root");
    let expected_root = derive_protocol_digest(
        "BGVPublicCommonRandomPolynomialRoot",
        &common_random_polynomial_record,
    )
    .expect("common random polynomial root");
    let old_public_key_share_namespace_root =
        derive_protocol_digest("PublicKeyShareRoot", &common_random_polynomial_record)
            .expect("old public key share namespace root");

    assert_eq!(actual_root, expected_root);
    assert_ne!(actual_root, old_public_key_share_namespace_root);
}

#[test]
fn passive_setup_rejects_trusted_dealer_secret_fields() {
    let mut request = request();
    request["globalSecretPolynomial"] = serde_json::json!("forbidden");

    assert!(generate_passive_setup_package_from_request(&request).is_err());
}

#[test]
fn passive_setup_rejects_non_canonical_roster_positions_and_digests() {
    let mut duplicate_position_request = request();
    duplicate_position_request["participants"][1]["rosterPosition"] = serde_json::json!(0);
    assert!(generate_passive_setup_package_from_request(&duplicate_position_request).is_err());

    let mut out_of_range_position_request = request();
    out_of_range_position_request["participants"][2]["rosterPosition"] = serde_json::json!(3);
    assert!(generate_passive_setup_package_from_request(&out_of_range_position_request).is_err());

    let mut uppercase_digest_request = request();
    let uppercase_manifest_digest = uppercase_digest_request["manifestDigest"]
        .as_str()
        .expect("manifest digest")
        .to_ascii_uppercase();
    uppercase_digest_request["manifestDigest"] = serde_json::json!(uppercase_manifest_digest);
    assert!(generate_passive_setup_package_from_request(&uppercase_digest_request).is_err());
}

#[test]
fn passive_setup_verification_rejects_mutated_roots() {
    let mut package = generate_passive_setup_package_from_request(&request()).expect("setup");
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
    let mut package = generate_passive_setup_package_from_request(&request()).expect("setup");
    package["collectivePublicKey"]["record"]["publicKeyShareRoots"][0] =
        serde_json::json!("f".repeat(128));
    rebind_setup_package_digest(&mut package);

    assert!(
        verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .is_err()
    );
}

#[test]
fn passive_setup_verification_rejects_nested_secret_material() {
    let mut package = generate_passive_setup_package_from_request(&request()).expect("setup");
    package["participants"][0]["globalSecretPolynomial"] = serde_json::json!("forbidden");
    rebind_setup_package_digest(&mut package);

    assert!(
        verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .is_err()
    );
}

#[test]
fn passive_setup_verification_rejects_rebound_binding_mutations() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    let mutations: Vec<SetupPackageMutation> = vec![
        (
            "BGV public key root",
            Box::new(|mutated_package| {
                mutated_package["collectivePublicKey"]["bgvPublicKeyRoot"] =
                    serde_json::json!(valid_digest('0'));
            }),
        ),
        (
            "threshold share verification key root",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["thresholdShareVerificationKeyRoot"] =
                    serde_json::json!(valid_digest('1'));
            }),
        ),
        (
            "trustee threshold verification key digest",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["trusteeThresholdVerificationKeyDigests"]
                    [0] = serde_json::json!(valid_digest('2'));
            }),
        ),
        (
            "relinearization key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["relinearizationKeyRoot"] =
                    serde_json::json!(valid_digest('3'));
            }),
        ),
        (
            "key-switch key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["keySwitchKeyRoot"] =
                    serde_json::json!(valid_digest('4'));
            }),
        ),
        (
            "key-switch decomposition digest",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["keySwitchDecompositionDigest"] =
                    serde_json::json!(valid_digest('5'));
            }),
        ),
        (
            "rotation set digest",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["rotSetDigest"] =
                    serde_json::json!(valid_digest('6'));
            }),
        ),
        (
            "rotation key root",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["rotationKeyRoots"][0]["rotationKeyRoot"] =
                    serde_json::json!(valid_digest('7'));
            }),
        ),
        (
            "setup parameter certificate digest",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["setupParameterCertificateDigest"] =
                    serde_json::json!(valid_digest('8'));
            }),
        ),
        (
            "collective secret distribution certificate digest",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["collectiveSecretDistributionCertificateDigest"] =
                    serde_json::json!(valid_digest('9'));
            }),
        ),
        (
            "KLLPS PartDec claim",
            Box::new(|mutated_package| {
                mutated_package["kllpsCompatibility"]["KLLPSPartDecImplemented"] =
                    serde_json::json!(true);
            }),
        ),
        (
            "KLLPS C1-C4 claim",
            Box::new(|mutated_package| {
                mutated_package["kllpsCompatibility"]["KLLPSC1C4Certified"] =
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
            "development encryption bridge claim",
            Box::new(|mutated_package| {
                mutated_package["developmentEncryptionFixture"]["fixture"]["m9BridgeEncryptionClaim"] =
                    serde_json::json!(true);
            }),
        ),
        (
            "relinearization arithmetic fixture",
            Box::new(|mutated_package| {
                mutated_package["evaluationKeys"]["relinearizationArithmeticFixture"]["fixture"]
                    ["sampledCoefficientChecks"][0]["recompositionMatches"] =
                    serde_json::json!(false);
            }),
        ),
        (
            "evaluation key chunk root",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["evaluationKeyStreamingFixture"]["fixture"]["chunkRoot"] =
                    serde_json::json!(valid_digest('a'));
            }),
        ),
    ];

    for (mutation_description, mutate_package) in mutations {
        let mut mutated_package = package.clone();
        mutate_package(&mut mutated_package);
        assert_rebound_package_is_rejected(mutated_package, mutation_description);
    }
}

#[test]
fn passive_setup_verification_rejects_evaluator_binding_mutations() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    for field_name in [
        "encryptedAggregateBridgeDigest",
        "encryptedAggregateTargetBasisDataRoot",
        "encryptedAggregateReconstructionDigest",
        "scoreBitDerivationCircuitDigest",
        "comparisonInputDerivationCircuitDigest",
        "encryptedScoreBitInputDigest",
        "encryptedComparisonInputDigest",
        "bitSlicedComparatorDigest",
        "encryptedSparseTargetProjectionDigest",
        "m8EvaluatorContextBindingDigest",
    ] {
        let mut mutated_package = package.clone();
        mutated_package["profileBindings"][field_name] = serde_json::json!(valid_digest('b'));
        assert_rebound_package_is_rejected(mutated_package, field_name);
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
                    "finalSecurityStatus": "pendingQTarget",
                },
            },
            "kllpsCompatibility": {
                "KLLPSC1C4Certified": false,
                "KLLPSPartDecImplemented": false,
                "setupMaterialCompatibleWithKLLPS": true,
            },
            "objectType": "BgvPassiveSetupPackage",
            "objectVersion": 1,
            "participants": vec![serde_json::json!({}); invalid_participant_count],
            "setupInputs": {
                "participantCount": invalid_participant_count,
            },
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
            "trustedDealerBoundary": {
                "rawSecretSharesExported": false,
                "transcriptValidCentralizedSecretReconstruction": false,
            },
        });
        assert!(
            validate_setup_package_shape(&minimally_shaped_package).is_err(),
            "participant count {invalid_participant_count} must be rejected by verification shape checks"
        );
    }

    let mut malformed_threshold_digest_request = request();
    malformed_threshold_digest_request["thresholdProfileDigest"] =
        serde_json::json!("not-a-digest");
    assert!(
        generate_passive_setup_package_from_request(&malformed_threshold_digest_request).is_err()
    );

    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
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
        assert_rebound_package_is_rejected(mutated_package, mutation_description);
    }
}

#[test]
fn passive_setup_verification_rejects_rotation_set_gaps() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");

    let mut missing_bit_sliced_projection_key = package.clone();
    missing_bit_sliced_projection_key["evaluationKeys"]["rotationKeyRoots"]
        .as_array_mut()
        .expect("rotation roots")
        .remove(0);
    assert_rebound_package_is_rejected(
        missing_bit_sliced_projection_key,
        "missing bit-sliced projection rotation key",
    );

    let mut missing_score_derivation_key = package.clone();
    missing_score_derivation_key["evaluationKeys"]["rotationKeyRoots"]
        .as_array_mut()
        .expect("rotation roots")
        .retain(|root| root["rotation"] != serde_json::json!(32));
    assert_rebound_package_is_rejected(
        missing_score_derivation_key,
        "missing score-bit derivation rotation key",
    );

    let mut missing_rank_accumulation_key = package.clone();
    missing_rank_accumulation_key["evaluationKeys"]["rotationKeyRoots"]
        .as_array_mut()
        .expect("rotation roots")
        .retain(|root| root["rotation"] != serde_json::json!(256));
    assert_rebound_package_is_rejected(
        missing_rank_accumulation_key,
        "missing rank-accumulation rotation key",
    );

    let mut missing_target_projection_key = package.clone();
    missing_target_projection_key["evaluationKeys"]["rotationKeyRoots"]
        .as_array_mut()
        .expect("rotation roots")
        .retain(|root| root["rotation"] != serde_json::json!(4096));
    assert_rebound_package_is_rejected(
        missing_target_projection_key,
        "missing target-projection rotation key",
    );

    let mut wrong_required_rotation_group = package;
    wrong_required_rotation_group["evaluationKeys"]["rotSet"]["requiredRotationGroups"][0]["rotations"]
        [0] = serde_json::json!(3);
    assert_rebound_package_is_rejected(
        wrong_required_rotation_group,
        "wrong bit-sliced rotation group",
    );
}

#[test]
fn centered_binomial_eta2_samples_match_certified_sampler() {
    let seed_digest = "1".repeat(128);
    let samples = sample_centered_binomial_eta2(&seed_digest, "trustee-1", "local-error");
    for sample in samples {
        let position = sample["position"].as_u64().expect("position") as usize;
        let position_text = position.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-v1",
            &[
                seed_digest.as_bytes(),
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
