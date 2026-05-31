use super::sampling::{reduce_unbiased_u64, sample_residue};
use super::validation::validate_setup_package_shape;
use super::{
    DATA_PRIMES, PASSIVE_SETUP_PROFILE_ID, POLYNOMIAL_DEGREE, dense_centered_binomial_coefficients,
    generate_passive_setup_package_from_request, sample_centered_binomial_eta2,
    sample_public_residues, sample_small_distribution, verify_passive_setup_package_from_request,
};
use crate::bgv::evaluator::{
    circuit::{EvaluatorContext, modulus_switch_to, validate_evaluation_keys},
    engine::{DevelopmentBgvKey, ciphertext_tensor, encode_slots_to_coefficients},
    key_switch::{generate_galois_key, generate_relinearization_key, relinearize, rotate},
    top_k::DIRECT_COMPARISON_OUTPUT_LEVEL,
};
use crate::bgv::modular_arithmetic::{add_mod, sub_mod};
use crate::bgv::ntt::forward_negacyclic_ntt;
use crate::bgv::profile::PLAINTEXT_MODULUS;
use crate::hashing::{derive_protocol_hash, hash512};

type SetupPackageMutation = (&'static str, Box<dyn Fn(&mut serde_json::Value)>);

fn request() -> serde_json::Value {
    serde_json::json!({
        "ceremonyId": "ceremony-main",
        "manifestHash": derive_protocol_hash(
            "ElectionManifestHash",
            &serde_json::json!({ "manifest": "passive-bgv-setup-test" }),
        ).expect("manifest hash"),
        "rosterHash": derive_protocol_hash(
            "RosterHash",
            &serde_json::json!({ "roster": "passive-bgv-setup-test" }),
        ).expect("roster hash"),
        "thresholdProfileHash": derive_protocol_hash(
            "ThresholdProfileHash",
            &serde_json::json!({ "threshold": "passive-bgv-setup-test" }),
        ).expect("threshold hash"),
        "participants": [
            { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
            { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 4 },
            { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 5 }
        ],
        "setupSeed": "passive-bgv-setup-test-seed",
    })
}

fn rebind_setup_package_hash(package: &mut serde_json::Value) {
    let mut hash_input = package.clone();
    hash_input
        .as_object_mut()
        .expect("setup package must be an object")
        .remove("setupPackageHash");
    package["setupPackageHash"] = serde_json::json!(
        derive_protocol_hash("BGVPassiveSetupPackageHash", &hash_input)
            .expect("setup package hash")
    );
}

fn valid_hash(fill: char) -> String {
    fill.to_string().repeat(128)
}

fn setup_derived_evaluator_key(package: &serde_json::Value) -> DevelopmentBgvKey {
    let setup_seed_hash = package["setupInputs"]["setupSeedHash"]
        .as_str()
        .expect("setup seed hash");
    let participant_identities = package["participants"]
        .as_array()
        .expect("participants")
        .iter()
        .map(|participant| {
            participant["trusteeIdentity"]
                .as_str()
                .expect("trustee identity")
                .to_string()
        })
        .collect::<Vec<_>>();
    let (collective_secret, _) =
        super::key_material::collective_signed_secret_and_error_coefficients(
            setup_seed_hash,
            &participant_identities,
        );
    let public_key_coefficients =
        super::key_material::collective_public_key_coefficients_by_modulus_from_setup_package(
            package,
        )
        .expect("collective public key coefficients");
    let public_b = public_key_coefficients
        .iter()
        .map(|coefficients| coefficients.component_zero_coefficients.clone())
        .collect::<Vec<_>>();
    let public_a = public_key_coefficients
        .iter()
        .map(|coefficients| coefficients.component_one_coefficients.clone())
        .collect::<Vec<_>>();

    DevelopmentBgvKey::from_collective_components(collective_secret, public_b, public_a)
        .expect("setup-derived evaluator key")
}

fn automorphism_residues(input: &[u64], galois_element: usize, modulus: u64) -> Vec<u64> {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_u64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % ring_order;
        if exponent < POLYNOMIAL_DEGREE {
            output[exponent] =
                add_mod(output[exponent], *value, modulus).expect("automorphism add");
        } else {
            output[exponent - POLYNOMIAL_DEGREE] =
                sub_mod(output[exponent - POLYNOMIAL_DEGREE], *value, modulus)
                    .expect("automorphism subtract");
        }
    }

    output
}

fn assert_rebound_package_is_rejected(mut package: serde_json::Value, mutation_description: &str) {
    rebind_setup_package_hash(&mut package);
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

    assert_eq!(first["setupPackageHash"], second["setupPackageHash"]);
    assert_eq!(first["kllpsStatus"]["setupMaterialMatchesKLLPS"], true);
    assert_eq!(first["kllpsStatus"]["KLLPSPartDecStatusImplemented"], false);
    assert_eq!(
        first["certificates"]["setupParameterCertificate"]["finalSecurityStatus"],
        "pendingQTarget"
    );
    assert_eq!(first["setupInputs"]["defaultSetupSeedUsed"], false);
    assert_eq!(
        first["participants"][0]["sampleDisclosure"],
        "commitment-hashes-and-roots-only"
    );
    assert_eq!(
        first["participants"][0]["sampledLocalSecretCoefficientsIncluded"],
        false
    );
    assert_eq!(
        first["participants"][0]["sampledLocalErrorCoefficientsIncluded"],
        false
    );
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

    let verification = verify_passive_setup_package_from_request(&serde_json::json!({
        "setupPackage": first,
        "expectedRosterHash": request()["rosterHash"],
    }))
    .expect("verify setup package");
    assert_eq!(verification["ok"], true);
}

#[test]
fn passive_setup_collective_key_uses_evaluator_decryptable_contract() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    let evaluator_key = setup_derived_evaluator_key(&package);

    let ciphertext = evaluator_key
        .encrypt_slots(&[13, 21, 34, 55], "setup-derived-evaluator-encryption")
        .expect("encrypt");
    let decrypted = evaluator_key
        .decrypt_to_slots(&ciphertext)
        .expect("decrypt setup-derived ciphertext");

    assert_eq!(&decrypted[..4], &[13, 21, 34, 55]);
}

#[test]
fn passive_setup_collective_key_drives_evaluator_key_switch_primitives() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    let evaluator_key = setup_derived_evaluator_key(&package);
    let context =
        EvaluatorContext::from_key(evaluator_key, "setup-derived-evaluation-key-switch", 3)
            .expect("setup-derived evaluator context");

    assert!(
        validate_evaluation_keys(&context, 3, "setup-derived-evaluation-key-validation")
            .expect("validate evaluation keys")
    );
}

#[test]
fn passive_setup_evaluation_key_material_stream_drives_key_switch_primitives() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    let evaluator_key = setup_derived_evaluator_key(&package);
    let sampled_checks = package["evaluationKeys"]["evaluationKeyMaterialCommitment"]["record"]
        ["sampledRelationChecks"]
        .as_array()
        .expect("sampled relation checks");
    let relinearization_seed = sampled_checks
        .iter()
        .find(|check| {
            check["keyKind"] == "relinearization"
                && check["level"] == DIRECT_COMPARISON_OUTPUT_LEVEL
        })
        .and_then(|check| check["keyStreamSeed"].as_str())
        .expect("direct comparison output relinearization stream seed");
    let rotation_check = sampled_checks
        .iter()
        .find(|check| {
            check["keyKind"] == "rotation"
                && check["level"] == DIRECT_COMPARISON_OUTPUT_LEVEL
                && check["purpose"] == "generator-ordered-packed-rank-return"
        })
        .expect("direct comparison output return rotation stream check");
    let rotation = rotation_check["rotation"]
        .as_u64()
        .expect("rotation")
        .try_into()
        .expect("rotation fits usize");
    let rotation_seed = rotation_check["keyStreamSeed"]
        .as_str()
        .expect("rotation stream seed");

    let left = modulus_switch_to(
        &evaluator_key
            .encrypt_slots(&[2, 3, 4, 5], "setup-material-left")
            .expect("left"),
        DIRECT_COMPARISON_OUTPUT_LEVEL,
    )
    .expect("left level");
    let right = modulus_switch_to(
        &evaluator_key
            .encrypt_slots(&[7, 8, 9, 10], "setup-material-right")
            .expect("right"),
        DIRECT_COMPARISON_OUTPUT_LEVEL,
    )
    .expect("right level");
    let relinearization_key = generate_relinearization_key(
        &evaluator_key,
        DIRECT_COMPARISON_OUTPUT_LEVEL,
        relinearization_seed,
    )
    .expect("setup stream relinearization key");
    let product = relinearize(
        &ciphertext_tensor(&left, &right).expect("tensor"),
        &relinearization_key,
    )
    .expect("relinearize with setup stream key");
    let product_slots = evaluator_key
        .decrypt_to_slots(&product)
        .expect("product decrypt");
    assert_eq!(&product_slots[..4], &[14, 24, 36, 50]);

    let rotation_key = generate_galois_key(
        &evaluator_key,
        rotation,
        DIRECT_COMPARISON_OUTPUT_LEVEL,
        rotation_seed,
    )
    .expect("setup stream rotation key");
    let rotated = rotate(&left, rotation, &rotation_key).expect("rotate with setup stream key");
    let plaintext_coefficients =
        encode_slots_to_coefficients(&[2, 3, 4, 5]).expect("encode plaintext");
    let rotated_coefficients =
        automorphism_residues(&plaintext_coefficients, rotation, PLAINTEXT_MODULUS);
    let expected_slots =
        forward_negacyclic_ntt(&rotated_coefficients, PLAINTEXT_MODULUS).expect("decode");
    let rotated_slots = evaluator_key
        .decrypt_to_slots(&rotated)
        .expect("rotated decrypt");
    assert_eq!(rotated_slots, expected_slots);
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
        let sample = sample_residue(&"1".repeat(128), "public-sample", 17, modulus);
        assert!(sample < modulus);
    }
}

#[test]
fn public_common_random_polynomial_uses_its_own_root_namespace() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    let setup_seed_hash = package["setupInputs"]["setupSeedHash"]
        .as_str()
        .expect("setup seed hash");
    let common_random_polynomial_record = serde_json::json!({
        "objectType": "BgvPublicCommonRandomPolynomial",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": package["setupInputs"]["ceremonyId"],
        "rosterHash": package["setupInputs"]["rosterHash"],
        "setupSeedHash": setup_seed_hash,
        "basisId": "sealed-lattice-bgv-rns-data-basis-v1",
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
    let expected_root = derive_protocol_hash(
        "BGVPublicCommonRandomPolynomialRoot",
        &common_random_polynomial_record,
    )
    .expect("common random polynomial root");
    let old_public_key_share_namespace_root =
        derive_protocol_hash("PublicKeyShareRoot", &common_random_polynomial_record)
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
    rebind_setup_package_hash(&mut package);

    assert!(
        verify_passive_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .is_err()
    );
}

#[test]
fn passive_setup_verification_rejects_rebound_coefficient_material_mutations() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");

    let mut changed_coefficient_root = package.clone();
    changed_coefficient_root["collectivePublicKey"]["collectivePublicKeyCoefficientRoot"] =
        serde_json::json!(valid_hash('4'));
    assert_rebound_package_is_rejected(
        changed_coefficient_root,
        "collective public key coefficient root mutation",
    );

    let mut changed_coefficient_material = package;
    changed_coefficient_material["collectivePublicKey"]["coefficientMaterial"]["modulusSummaries"]
        [0]["componentZeroCoefficientDerivationHash512"] = serde_json::json!("1".repeat(128));
    assert_rebound_package_is_rejected(
        changed_coefficient_material,
        "collective public key coefficient material mutation",
    );
}

#[test]
fn passive_setup_verification_rejects_nested_secret_material() {
    let mut package = generate_passive_setup_package_from_request(&request()).expect("setup");
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
fn passive_setup_verification_rejects_rebound_binding_mutations() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
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
            "collective secret distribution certificate hash",
            Box::new(|mutated_package| {
                mutated_package["certificates"]["collectiveSecretDistributionCertificateHash"] =
                    serde_json::json!(valid_hash('9'));
            }),
        ),
        (
            "KLLPS PartDec claim",
            Box::new(|mutated_package| {
                mutated_package["kllpsStatus"]["KLLPSPartDecStatusImplemented"] =
                    serde_json::json!(true);
            }),
        ),
        (
            "KLLPS C1-C4 claim",
            Box::new(|mutated_package| {
                mutated_package["kllpsStatus"]["KLLPSC1C4StatusAccepted"] = serde_json::json!(true);
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
                mutated_package["developmentEncryptionFixture"]["fixture"]["bridgeEncryptionClaim"] =
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
        assert_rebound_package_is_rejected(mutated_package, mutation_description);
    }
}

#[test]
fn passive_setup_verification_rejects_evaluator_binding_mutations() {
    let package = generate_passive_setup_package_from_request(&request()).expect("setup");
    for field_name in [
        "evaluatorBindingContextHash",
        "encryptedAggregateBridgeHash",
        "encryptedAggregateTargetBasisRoot",
        "encryptedAggregateReconstructionHash",
        "scoreBitDerivationCircuitHash",
        "comparisonInputDerivationCircuitHash",
        "encryptedScoreBitInputHash",
        "encryptedComparisonInputHash",
        "bitSlicedComparatorHash",
        "encryptedSparseTargetProjectionHash",
        "passiveSetupEvaluatorContextBindingHash",
    ] {
        let mut mutated_package = package.clone();
        mutated_package["profileBindings"][field_name] = serde_json::json!(valid_hash('b'));
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
            "kllpsStatus": {
                "KLLPSC1C4StatusAccepted": false,
                "KLLPSPartDecStatusImplemented": false,
                "setupMaterialMatchesKLLPS": true,
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

    let mut malformed_threshold_hash_request = request();
    malformed_threshold_hash_request["thresholdProfileHash"] = serde_json::json!("not-a-hash");
    assert!(
        generate_passive_setup_package_from_request(&malformed_threshold_hash_request).is_err()
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
    let rotations = package["evaluationKeys"]["rotSet"]["rotations"]
        .as_array()
        .expect("rotations");
    assert_eq!(rotations.len(), 56);
    assert_eq!(rotations[0], serde_json::json!(3));
    assert_eq!(
        package["evaluationKeys"]["rotSet"]["requiredRotationGroups"][0]["purpose"],
        "aggregate-score-packing"
    );
    assert_eq!(
        package["evaluationKeys"]["rotSet"]["requiredRotationGroups"][1]["purpose"],
        "generator-ordered-packed-rank"
    );

    let mut missing_packed_rank_key = package.clone();
    missing_packed_rank_key["evaluationKeys"]["rotationKeyRoots"]
        .as_array_mut()
        .expect("rotation roots")
        .remove(0);
    assert_rebound_package_is_rejected(
        missing_packed_rank_key,
        "missing generator-ordered packed-rank rotation key",
    );

    let mut wrong_required_rotation_group = package.clone();
    wrong_required_rotation_group["evaluationKeys"]["rotSet"]["requiredRotationGroups"][0]["rotations"]
        [0] = serde_json::json!(1);
    assert_rebound_package_is_rejected(
        wrong_required_rotation_group,
        "wrong aggregate score packing rotation group",
    );
}

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

fn centered_binomial_eta2_value_from_byte(byte: u8) -> i64 {
    i64::from(byte & 1) + i64::from((byte >> 1) & 1)
        - i64::from((byte >> 2) & 1)
        - i64::from((byte >> 3) & 1)
}
