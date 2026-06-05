use super::*;

#[test]
fn passive_setup_public_evaluation_key_material_drives_relinearization_without_private_witness() {
    let evaluator_key = setup_derived_evaluator_key();
    let public_material = level_one_public_material();
    let public_context = level_one_public_context();
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

    let product = multiply(public_context, &left, &right).expect("public material multiply");
    let decrypted = evaluator_key
        .decrypt_to_slots(&product)
        .expect("decrypt public material product");

    assert_eq!(&decrypted[..3], &[10, 18, 28]);
    assert!(public_material.get("setupPrivateWitness").is_none());
    assert!(public_material.get("privateSetupSeedHash").is_none());
}

#[test]
fn passive_setup_public_evaluation_key_material_drives_rotation_without_private_witness() {
    let evaluator_key = setup_derived_evaluator_key();
    let (galois_element, level) = direct_comparison_rotation_request();
    let public_context = rotation_public_context();
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
    let evaluator_key = setup_derived_evaluator_key();
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
    let mut public_material = level_one_public_material().clone();
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
    let public_material = level_one_public_material();

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
fn passive_setup_evaluation_key_material_stream_drives_key_switch_primitives() {
    let package = setup_package();
    let evaluator_key = setup_derived_evaluator_key();
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
        evaluator_key,
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
        evaluator_key,
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
