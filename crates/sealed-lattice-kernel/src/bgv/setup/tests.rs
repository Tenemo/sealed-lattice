use super::sampling::{
    reduce_unbiased_u64, sample_centered_binomial_eta2, sample_residue, sample_small_distribution,
};
use super::validation::validate_setup_package_shape;
use super::{
    DATA_PRIMES, PASSIVE_SETUP_PROFILE_ID, POLYNOMIAL_DEGREE, dense_centered_binomial_coefficients,
    generate_passive_setup_package_from_request, read_public_evaluation_key_rotation_requests,
    sample_public_residues, selected_public_evaluation_key_rotation_requests,
    verify_passive_setup_package_from_request,
};
use crate::bgv::evaluator::{
    circuit::{EvaluatorContext, modulus_switch_to, multiply, validate_evaluation_keys},
    engine::{DevelopmentBgvKey, ciphertext_tensor, encode_slots_to_coefficients},
    key_switch::{generate_galois_key, generate_relinearization_key, relinearize, rotate},
    top_k::DIRECT_COMPARISON_OUTPUT_LEVEL,
};
use crate::bgv::modular_arithmetic::{add_mod, sub_mod};
use crate::bgv::ntt::forward_negacyclic_ntt;
use crate::bgv::profile::{
    PLAINTEXT_MODULUS, data_basis_modulus_bits, extended_basis_modulus_bits,
};
use crate::hashing::{derive_protocol_hash, hash512};
use std::sync::OnceLock;

type SetupPackageMutation = (&'static str, Box<dyn Fn(&mut serde_json::Value)>);

static PASSIVE_SETUP_TEST_PACKAGE: OnceLock<serde_json::Value> = OnceLock::new();

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

fn setup_package() -> serde_json::Value {
    PASSIVE_SETUP_TEST_PACKAGE
        .get_or_init(|| generate_passive_setup_package_from_request(&request()).expect("setup"))
        .clone()
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
    let private_setup_seed_hash =
        super::input::private_passive_setup_seed_hash_from_package_witness(
            package,
            "passive-bgv-setup-test-seed",
        )
        .expect("private setup seed hash");
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
            &private_setup_seed_hash,
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

fn rebind_public_evaluation_key_material_hash(material: &mut serde_json::Value) {
    material
        .as_object_mut()
        .expect("public evaluation-key material must be an object")
        .remove("publicEvaluationKeyMaterialHash");
    material["publicEvaluationKeyMaterialHash"] = serde_json::json!(
        derive_protocol_hash("EvaluationKeySetDigest", material)
            .expect("public evaluation-key material hash")
    );
}

fn public_evaluation_key_material_error(
    package: &serde_json::Value,
    material: &serde_json::Value,
    working_level: usize,
) -> crate::encoding::CanonicalError {
    match super::public_evaluation_keys_from_material(package, material, working_level) {
        Ok(_) => panic!("public evaluation-key material mutation must reject"),
        Err(error) => error,
    }
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
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationProfileId"],
        super::THRESHOLD_LSSS_SHARE_VERIFICATION_PROFILE_ID
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["decryptionThreshold"],
        1
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["algebraicPartDecProofStatus"],
        "ZeroKnowledgeShareEquationProofPending"
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["publicKeyShareCoefficientMaterialStatus"],
        "root-bound-public-sidecar-required"
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["publicKeyShareCoefficientMaterialRoots"]
            .as_array()
            .expect("public key-share coefficient roots")
            .len(),
        3
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["lsssSecretSharesExported"],
        false
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["trusteeVerificationKeys"][0]["proofSystemStatus"],
        "ZeroKnowledgeShareEquationProofPending"
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["trusteeVerificationKeys"][0]["publicKeyShareCoefficientMaterialIncluded"],
        false
    );
    assert_eq!(
        first["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
            ["trusteeVerificationKeys"][0]["thresholdSecretShareExported"],
        false
    );
    assert_eq!(
        first["certificates"]["setupParameterCertificate"]["finalSecurityStatus"],
        "acceptedForSetupBridgeEvaluatorTargetPending"
    );
    assert_eq!(
        first["certificates"]["targetThresholdDecryptabilityCertificate"]["ciphertextCompatibilityStatus"],
        "TargetThresholdDecryptabilityCompatibilityCertified"
    );
    assert_eq!(
        first["certificates"]["targetThresholdDecryptabilityCertificate"]["downstreamProtocolStatus"],
        "TargetDecryptionShareProtocolStillDownstream"
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
    assert!(first["setupInputs"].get("privateSetupSeedHash").is_none());
    assert!(first.get("privateSetupSeedHash").is_none());

    let verification = verify_passive_setup_package_from_request(&serde_json::json!({
        "setupPackage": first,
        "expectedRosterHash": request()["rosterHash"],
    }))
    .expect("verify setup package");
    assert_eq!(verification["ok"], true);
}

#[test]
fn passive_setup_collective_key_uses_evaluator_decryptable_contract() {
    let package = setup_package();
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
fn passive_setup_security_certificate_keeps_special_prime_out_of_public_exposure() {
    let package = setup_package();
    let setup_parameter_certificate = &package["certificates"]["setupParameterCertificate"];
    let he_security_certificate = &package["certificates"]["heSecurityCertificate"];
    let public_samples = &package["certificates"]["publicRlweSamplesByBasis"];

    assert_eq!(
        setup_parameter_certificate["qDataBits"],
        serde_json::json!(data_basis_modulus_bits())
    );
    assert_eq!(
        setup_parameter_certificate["qExtendedUtilityBits"],
        serde_json::json!(extended_basis_modulus_bits())
    );
    assert_eq!(
        setup_parameter_certificate["largestExposedBasisClassWithoutQTarget"],
        serde_json::json!("Q_data")
    );
    assert_eq!(
        setup_parameter_certificate["largestExposedModulusBitsWithoutQTarget"],
        serde_json::json!(data_basis_modulus_bits())
    );
    assert_eq!(
        setup_parameter_certificate["specialPrimeExposureStatus"],
        serde_json::json!("not-exposed-by-current-setup-bridge-evaluator-public-material")
    );
    assert_eq!(
        he_security_certificate["assessedRing"]["largestExposedBasisClass"],
        serde_json::json!("Q_data")
    );
    assert_eq!(
        he_security_certificate["assessedRing"]["largestExposedModulusBits"],
        serde_json::json!(data_basis_modulus_bits())
    );
    assert_eq!(
        he_security_certificate["assessedRing"]["extendedUtilityExposureStatus"],
        serde_json::json!("not-exposed-by-current-setup-bridge-evaluator-public-material")
    );
    assert_eq!(
        he_security_certificate["standardRows"]["postQuantumTernary128"]["status"],
        serde_json::json!("accepted")
    );
    assert_eq!(
        public_samples["QPPublic"]["exposedOnAcceptedSetupBridgeEvaluatorPath"],
        serde_json::json!(false)
    );
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
fn passive_setup_public_evaluation_key_material_drives_relinearization_without_private_witness() {
    let package = setup_package();
    let evaluator_key = setup_derived_evaluator_key(&package);
    let public_material =
        super::generate_passive_setup_public_evaluation_key_material_from_request(
            &serde_json::json!({
                "setupPackage": package,
                "setupPrivateWitness": {
                    "setupSeed": "passive-bgv-setup-test-seed",
                },
                "workingLevel": 1,
            }),
        )
        .expect("public evaluation-key material");
    let public_context =
        EvaluatorContext::from_passive_setup_public_material(&package, &public_material, 1)
            .expect("public evaluator context");
    let left = modulus_switch_to(
        &evaluator_key
            .encrypt_slots(&[2, 3, 4], "public-material-left")
            .expect("left"),
        1,
    )
    .expect("left level");
    let right = modulus_switch_to(
        &evaluator_key
            .encrypt_slots(&[5, 6, 7], "public-material-right")
            .expect("right"),
        1,
    )
    .expect("right level");

    let product = multiply(&public_context, &left, &right).expect("public material multiply");
    let decrypted = evaluator_key
        .decrypt_to_slots(&product)
        .expect("decrypt public material product");

    assert_eq!(&decrypted[..3], &[10, 18, 28]);
    assert!(public_material.get("setupPrivateWitness").is_none());
    assert!(public_material.get("privateSetupSeedHash").is_none());
}

#[test]
fn passive_setup_public_evaluation_key_material_drives_rotation_without_private_witness() {
    let package = setup_package();
    let evaluator_key = setup_derived_evaluator_key(&package);
    let rotation_request = package["evaluationKeys"]["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots")
        .iter()
        .find(|entry| entry["level"].as_u64() == Some(DIRECT_COMPARISON_OUTPUT_LEVEL as u64))
        .expect("direct-comparison return rotation key");
    let galois_element = rotation_request["rotation"]
        .as_u64()
        .expect("rotation")
        .try_into()
        .expect("rotation fits usize");
    let level = rotation_request["level"]
        .as_u64()
        .expect("level")
        .try_into()
        .expect("level fits usize");
    let public_material =
        super::generate_passive_setup_public_evaluation_key_material_from_request(
            &serde_json::json!({
                "setupPackage": package,
                "setupPrivateWitness": {
                    "setupSeed": "passive-bgv-setup-test-seed",
                },
                "workingLevel": 1,
                "rotationKeys": [
                    {
                        "rotation": galois_element,
                        "level": level,
                    }
                ],
            }),
        )
        .expect("public evaluation-key material");
    let public_context =
        EvaluatorContext::from_passive_setup_public_material(&package, &public_material, 1)
            .expect("public evaluator context");
    let slots = [11_u64, 22, 33, 44, 55, 66, 77, 88];
    let source = modulus_switch_to(
        &evaluator_key
            .encrypt_slots(&slots, "public-material-rotation")
            .expect("encrypt"),
        level,
    )
    .expect("source level");
    let galois_key = public_context
        .resolve_galois_key(galois_element, level, "unused-public-rotation-fallback")
        .expect("public rotation key");
    let rotated = rotate(&source, galois_element, &galois_key).expect("rotate");
    let plaintext_coefficients = encode_slots_to_coefficients(&slots).expect("encode");
    let rotated_coefficients =
        automorphism_residues(&plaintext_coefficients, galois_element, PLAINTEXT_MODULUS);
    let expected_slots =
        forward_negacyclic_ntt(&rotated_coefficients, PLAINTEXT_MODULUS).expect("decode");

    assert_eq!(
        evaluator_key.decrypt_to_slots(&rotated).expect("decrypt"),
        expected_slots
    );
}

#[test]
#[ignore = "representative full-level public evaluation-key material is a manual setup/evaluator closure check"]
fn passive_setup_representative_full_level_public_evaluation_key_material_exercises_selected_keys()
{
    let package = setup_package();
    let evaluator_key = setup_derived_evaluator_key(&package);
    let full_level = DATA_PRIMES.len() - 1;
    let expected_rotation_schedule = selected_public_evaluation_key_rotation_requests(full_level)
        .expect("selected full rotation schedule");
    let full_level_rotation = expected_rotation_schedule
        .iter()
        .copied()
        .find(|(_, level)| *level == full_level)
        .expect("full-level selected rotation");
    let direct_return_rotation = expected_rotation_schedule
        .iter()
        .copied()
        .find(|(_, level)| *level == DIRECT_COMPARISON_OUTPUT_LEVEL)
        .expect("direct-comparison return rotation");
    let public_material =
        super::generate_passive_setup_public_evaluation_key_material_from_request(
            &serde_json::json!({
                "setupPackage": package,
                "setupPrivateWitness": {
                    "setupSeed": "passive-bgv-setup-test-seed",
                },
                "workingLevel": full_level,
                "rotationKeys": [
                    {
                        "rotation": full_level_rotation.0,
                        "level": full_level_rotation.1,
                    },
                    {
                        "rotation": direct_return_rotation.0,
                        "level": direct_return_rotation.1,
                    }
                ],
            }),
        )
        .expect("representative full-level public evaluation-key material");
    let public_context = EvaluatorContext::from_passive_setup_public_material(
        &package,
        &public_material,
        full_level,
    )
    .expect("full-schedule public evaluator context");

    assert_eq!(
        public_material["relinearizationKeys"]
            .as_array()
            .expect("relinearization keys")
            .len(),
        full_level
    );
    assert_eq!(
        public_material["rotationKeys"]
            .as_array()
            .expect("rotation keys")
            .len(),
        2
    );
    for (galois_element, level) in [full_level_rotation, direct_return_rotation] {
        assert!(
            public_context.has_public_rotation_key(galois_element, level),
            "missing selected rotation key {galois_element} at level {level}",
        );
    }

    let left = evaluator_key
        .encrypt_slots(&[2, 3, 4, 5], "full-schedule-left")
        .expect("left");
    let right = evaluator_key
        .encrypt_slots(&[7, 11, 13, 17], "full-schedule-right")
        .expect("right");
    for level in 1..=full_level {
        let product = multiply(
            &public_context,
            &modulus_switch_to(&left, level).expect("left level"),
            &modulus_switch_to(&right, level).expect("right level"),
        )
        .expect("public full-schedule multiply");
        let decrypted = evaluator_key
            .decrypt_to_slots(&product)
            .expect("decrypt public full-schedule product");

        assert_eq!(&decrypted[..4], &[14, 33, 52, 85], "level {level}");
    }

    let rotation_slots = (0_u64..32).map(|slot| slot * 3 + 1).collect::<Vec<_>>();
    let rotation_source = evaluator_key
        .encrypt_slots(&rotation_slots, "full-schedule-rotation")
        .expect("rotation source");
    let plaintext_coefficients =
        encode_slots_to_coefficients(&rotation_slots).expect("encode rotation slots");
    for (galois_element, level) in [full_level_rotation, direct_return_rotation] {
        let source_at_level =
            modulus_switch_to(&rotation_source, level).expect("rotation source level");
        let rotation_key = public_context
            .resolve_galois_key(
                galois_element,
                level,
                "unused-public-full-schedule-rotation",
            )
            .expect("selected public rotation key");
        let rotated = rotate(&source_at_level, galois_element, &rotation_key).expect("rotate");
        let rotated_coefficients =
            automorphism_residues(&plaintext_coefficients, galois_element, PLAINTEXT_MODULUS);
        let expected_slots =
            forward_negacyclic_ntt(&rotated_coefficients, PLAINTEXT_MODULUS).expect("decode");

        assert_eq!(
            evaluator_key.decrypt_to_slots(&rotated).expect("decrypt"),
            expected_slots,
            "rotation {galois_element} at level {level}",
        );
    }

    assert!(public_material.get("setupPrivateWitness").is_none());
    assert!(public_material.get("privateSetupSeedHash").is_none());
}

#[test]
fn public_evaluation_key_default_rotation_requests_follow_selected_schedule() {
    let package = setup_package();
    let full_schedule = selected_public_evaluation_key_rotation_requests(DATA_PRIMES.len() - 1)
        .expect("full selected rotation schedule");
    let comparison_return_schedule =
        selected_public_evaluation_key_rotation_requests(DIRECT_COMPARISON_OUTPUT_LEVEL)
            .expect("comparison return schedule");
    let low_level_schedule =
        selected_public_evaluation_key_rotation_requests(1).expect("low-level schedule");

    assert_eq!(full_schedule.len(), 20);
    assert_eq!(comparison_return_schedule.len(), 5);
    assert!(low_level_schedule.is_empty());
    assert!(
        full_schedule
            .iter()
            .any(|(rotation, level)| *rotation == 3 && *level == DATA_PRIMES.len() - 1)
    );
    assert!(
        full_schedule
            .iter()
            .any(|(rotation, level)| *rotation == 2 * POLYNOMIAL_DEGREE - 1
                && *level == DATA_PRIMES.len() - 1)
    );
    assert!(
        full_schedule
            .iter()
            .any(|(_, level)| *level == DIRECT_COMPARISON_OUTPUT_LEVEL)
    );

    let committed_rotation_schedule = package["evaluationKeys"]["evaluationKeyMaterialCommitment"]
        ["rotationKeyRoots"]
        .as_array()
        .expect("rotation key roots")
        .iter()
        .map(|entry| {
            (
                entry["rotation"]
                    .as_u64()
                    .expect("rotation")
                    .try_into()
                    .expect("rotation fits usize"),
                entry["level"]
                    .as_u64()
                    .expect("level")
                    .try_into()
                    .expect("level fits usize"),
            )
        })
        .collect::<Vec<(usize, usize)>>();
    let committed_relinearization_levels = package["evaluationKeys"]["evaluationKeyMaterialCommitment"]
        ["relinearizationKeyRecord"]["levelSchedule"]
        .as_array()
        .expect("relinearization level schedule")
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .expect("level")
                .try_into()
                .expect("level fits usize")
        })
        .collect::<Vec<usize>>();

    assert_eq!(committed_rotation_schedule, full_schedule);
    assert_eq!(
        committed_relinearization_levels,
        (1..DATA_PRIMES.len()).collect::<Vec<_>>()
    );
}

#[test]
fn public_evaluation_key_rotation_request_rejects_duplicates_before_generation() {
    let request = serde_json::json!({
        "rotationKeys": [
            { "rotation": 3, "level": DIRECT_COMPARISON_OUTPUT_LEVEL },
            { "rotation": 3, "level": DIRECT_COMPARISON_OUTPUT_LEVEL }
        ]
    });

    let error =
        read_public_evaluation_key_rotation_requests(&request, DIRECT_COMPARISON_OUTPUT_LEVEL)
            .expect_err("duplicate rotation requests must reject");

    assert!(
        error.message.contains("must not repeat"),
        "{}",
        error.message
    );
}

#[test]
fn passive_setup_public_evaluation_key_material_rejects_wrong_roots() {
    let package = setup_package();
    let mut public_material =
        super::generate_passive_setup_public_evaluation_key_material_from_request(
            &serde_json::json!({
                "setupPackage": package,
                "setupPrivateWitness": {
                    "setupSeed": "passive-bgv-setup-test-seed",
                },
                "workingLevel": 1,
            }),
        )
        .expect("public evaluation-key material");
    public_material["evaluationKeyRoot"] = serde_json::json!("0".repeat(128));

    let error =
        match EvaluatorContext::from_passive_setup_public_material(&package, &public_material, 1) {
            Ok(_) => panic!("wrong evaluation key root must reject"),
            Err(error) => error,
        };

    assert!(
        error
            .message
            .contains("public evaluation-key material evaluation key root"),
        "{}",
        error.message
    );
}

#[test]
fn passive_setup_public_evaluation_key_material_rejects_rebound_wrong_roots_and_secret_leaks() {
    let package = setup_package();
    let public_material =
        super::generate_passive_setup_public_evaluation_key_material_from_request(
            &serde_json::json!({
                "setupPackage": package,
                "setupPrivateWitness": {
                    "setupSeed": "passive-bgv-setup-test-seed",
                },
                "workingLevel": 1,
            }),
        )
        .expect("public evaluation-key material");

    let mut wrong_collective_root = public_material.clone();
    wrong_collective_root["collectivePublicKeyRoot"] = serde_json::json!("0".repeat(128));
    rebind_public_evaluation_key_material_hash(&mut wrong_collective_root);
    let root_error = public_evaluation_key_material_error(&package, &wrong_collective_root, 1);
    assert!(
        root_error.message.contains("collective public key root"),
        "{}",
        root_error.message
    );

    let mut leaked_private_witness = public_material.clone();
    leaked_private_witness["setupPrivateWitness"] =
        serde_json::json!({ "setupSeed": "passive-bgv-setup-test-seed" });
    rebind_public_evaluation_key_material_hash(&mut leaked_private_witness);
    let leak_error = public_evaluation_key_material_error(&package, &leaked_private_witness, 1);
    assert!(
        leak_error.message.contains("setupPrivateWitness"),
        "{}",
        leak_error.message
    );

    let mut raw_secret_export = public_material.clone();
    raw_secret_export["rawSecretMaterialExported"] = serde_json::json!(true);
    rebind_public_evaluation_key_material_hash(&mut raw_secret_export);
    let raw_secret_error = public_evaluation_key_material_error(&package, &raw_secret_export, 1);
    assert!(
        raw_secret_error.message.contains("raw secret material"),
        "{}",
        raw_secret_error.message
    );

    let mut trusted_dealer_material = public_material.clone();
    trusted_dealer_material["trustedDealerKeyMaterial"] =
        serde_json::json!({ "secret": "forbidden" });
    rebind_public_evaluation_key_material_hash(&mut trusted_dealer_material);
    let trusted_dealer_error =
        public_evaluation_key_material_error(&package, &trusted_dealer_material, 1);
    assert!(
        trusted_dealer_error
            .message
            .contains("trustedDealerKeyMaterial"),
        "{}",
        trusted_dealer_error.message
    );

    let mut duplicate_relinearization = public_material.clone();
    let duplicate_entry = duplicate_relinearization["relinearizationKeys"][0].clone();
    duplicate_relinearization["relinearizationKeys"]
        .as_array_mut()
        .expect("relinearization keys are an array")
        .push(duplicate_entry);
    rebind_public_evaluation_key_material_hash(&mut duplicate_relinearization);
    let duplicate_error =
        public_evaluation_key_material_error(&package, &duplicate_relinearization, 1);
    assert!(
        duplicate_error
            .message
            .contains("repeats a relinearization"),
        "{}",
        duplicate_error.message
    );
}

#[test]
fn passive_setup_collective_key_drives_evaluator_key_switch_primitives() {
    let package = setup_package();
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
    let package = setup_package();
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
                && check["purpose"] == "generator-ordered-packed-rank-return-basis"
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
    let package = setup_package();
    assert_eq!(
        package["certificates"]["collectiveSecretDistributionCertificate"]["localShareSampler"]["samplerId"],
        "hash-derived-owner-routed-standard-ternary-collective-share-v1"
    );
    assert_eq!(
        package["certificates"]["collectiveSecretDistributionCertificate"]["resultingGlobalSecretDistribution"]
            ["isPlainDenseTernary"],
        true
    );
    assert_eq!(
        package["certificates"]["heSecurityCertificate"]["acceptedForSetupBridgeEvaluator"],
        true
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
    let package = setup_package();
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
    for field_name in [
        "globalSecretPolynomial",
        "trustedDealerSecret",
        "trustedDealerKeyMaterial",
        "fullSecretKey",
        "collectiveSecretKey",
        "fullSecretReconstruction",
        "thresholdSecretShares",
    ] {
        let mut request = request();
        request["participants"][0][field_name] = serde_json::json!("forbidden");

        let error = generate_passive_setup_package_from_request(&request)
            .expect_err("setup must reject centralized secret material");
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
fn passive_setup_verification_rejects_rebound_coefficient_material_mutations() {
    let package = setup_package();

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
    assert_rebound_package_is_rejected(
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
fn passive_setup_verification_rejects_algebraic_share_verification_mutations() {
    let package = setup_package();
    let mutations: Vec<SetupPackageMutation> = vec![
        (
            "algebraic threshold share verification key root",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["algebraicShareVerificationKeyRoot"] =
                    serde_json::json!(valid_hash('1'));
            }),
        ),
        (
            "algebraic threshold share verification proof status",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
                    ["algebraicPartDecProofStatus"] =
                    serde_json::json!("AlgebraicPartDecShareEquationProofVerified");
            }),
        ),
        (
            "algebraic threshold share export flag",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
                    ["trusteeVerificationKeys"][0]["thresholdSecretShareExported"] =
                    serde_json::json!(true);
            }),
        ),
        (
            "public key-share coefficient material root",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
                    ["trusteeVerificationKeys"][0]["publicKeyShareCoefficientMaterialRoot"] =
                    serde_json::json!(valid_hash('2'));
            }),
        ),
        (
            "public key-share coefficient material set order",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
                    ["publicKeyShareCoefficientMaterialRoots"][0] =
                    serde_json::json!(valid_hash('3'));
            }),
        ),
        (
            "public key-share coefficient material inclusion flag",
            Box::new(|mutated_package| {
                mutated_package["thresholdVerificationMaterial"]["verificationKeySet"]["algebraicShareVerificationKeySet"]
                    ["trusteeVerificationKeys"][0]["publicKeyShareCoefficientMaterialIncluded"] =
                    serde_json::json!(true);
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
fn passive_setup_verification_rejects_rebound_binding_mutations() {
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
    let package = setup_package();
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
        "targetLayoutHash",
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
                    "finalSecurityStatus": "acceptedForSetupBridgeEvaluatorTargetPending",
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

    let stale_security_status_package = serde_json::json!({
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
        "participants": vec![serde_json::json!({}); 3],
        "setupInputs": {
            "participantCount": 3,
        },
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "trustedDealerBoundary": {
            "rawSecretSharesExported": false,
            "transcriptValidCentralizedSecretReconstruction": false,
        },
    });
    let stale_status_error = validate_setup_package_shape(&stale_security_status_package)
        .expect_err("stale setup security status must be refused before encrypted evaluation");
    assert!(
        stale_status_error
            .message
            .contains("accept setup-bridge-evaluator HE security"),
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
        assert_rebound_package_is_rejected(mutated_package, mutation_description);
    }
}

#[test]
fn passive_setup_verification_rejects_rotation_set_gaps() {
    let package = setup_package();
    let rotations = package["evaluationKeys"]["rotSet"]["rotations"]
        .as_array()
        .expect("rotations");
    assert_eq!(rotations.len(), 20);
    assert_eq!(rotations[0], serde_json::json!(3));
    assert_eq!(
        package["evaluationKeys"]["rotSet"]["requiredRotationGroups"][0]["purpose"],
        "aggregate-score-packing-generator-basis"
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
