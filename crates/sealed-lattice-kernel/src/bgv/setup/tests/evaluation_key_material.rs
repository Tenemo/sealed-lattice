use super::*;
use crate::bgv::evaluator::top_k::SELECTED_EVALUATOR_WORKING_LEVEL;

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
fn selected_rotation_key_schedule_matches_package_commitment() {
    let package = setup_package();
    let full_schedule = selected_public_evaluation_key_rotation_requests()
        .expect("full selected rotation schedule");

    assert_eq!(full_schedule.len(), 23);
    assert!(
        full_schedule
            .iter()
            .any(|(rotation, level)| *rotation == 3 && *level == SELECTED_EVALUATOR_WORKING_LEVEL)
    );
    assert!(
        full_schedule
            .iter()
            .any(|(rotation, level)| *rotation == 2 * POLYNOMIAL_DEGREE - 1
                && *level == SELECTED_EVALUATOR_WORKING_LEVEL)
    );
    // One key per element at the working level; truncation serves the
    // comparison output level.
    assert!(
        full_schedule
            .iter()
            .all(|(_, level)| *level == SELECTED_EVALUATOR_WORKING_LEVEL)
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
        vec![SELECTED_EVALUATOR_WORKING_LEVEL]
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

    let error = read_public_evaluation_key_rotation_requests(&request)
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

    let mut externally_supplied_material = public_material.clone();
    externally_supplied_material["externallySuppliedSetupKeyMaterial"] =
        serde_json::json!({ "secret": "forbidden" });
    rebind_public_evaluation_key_material_hash(&mut externally_supplied_material);
    let externally_supplied_material_error =
        public_evaluation_key_material_error(&package, &externally_supplied_material, 1);
    assert!(
        externally_supplied_material_error
            .message
            .contains("externallySuppliedSetupKeyMaterial"),
        "{}",
        externally_supplied_material_error.message
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
                && check["level"] == SELECTED_EVALUATOR_WORKING_LEVEL
        })
        .and_then(|check| check["keyStreamSeed"].as_str())
        .expect("working-level relinearization stream seed");
    let rotation_check = sampled_checks
        .iter()
        .find(|check| {
            check["keyKind"] == "rotation"
                && check["level"] == SELECTED_EVALUATOR_WORKING_LEVEL
                && check["purpose"] == "generator-ordered-packed-rank-return-basis"
        })
        .expect("packed-rank return rotation stream check");
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
    // The schedule key is generated at the working level; relinearizing a
    // comparison-output-level ciphertext exercises the truncation window the
    // evaluator consumes.
    let relinearization_key = generate_relinearization_key(
        evaluator_key,
        SELECTED_EVALUATOR_WORKING_LEVEL,
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
        SELECTED_EVALUATOR_WORKING_LEVEL,
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
