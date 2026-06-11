use super::*;

#[test]
fn collective_setup_verifier_refuses_forbidden_accepted_path_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_forbidden_accepted_path_material",
    );
    let mut seeded_package = minimal_collective_setup_package();
    seeded_package["setupSeed"] = serde_json::json!("externally-supplied-seed");
    rebind_collective_setup_package_hash(&mut seeded_package);

    let seeded_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": seeded_package,
    }))
    .expect("verification response");

    assert_eq!(seeded_result["verifierStatus"], "refused");
    assert_eq!(
        seeded_result["refusedObjects"][0]["reasonCode"],
        "acceptedPathForbiddenField"
    );

    let mut externally_supplied_threshold_package = minimal_collective_setup_package();
    externally_supplied_threshold_package["externallySuppliedThresholdShareCommitmentMaterial"] =
        serde_json::json!({ "root": valid_hash('5') });
    rebind_collective_setup_package_hash(&mut externally_supplied_threshold_package);

    let externally_supplied_threshold_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": externally_supplied_threshold_package,
        }))
        .expect("verification response");

    assert_eq!(
        externally_supplied_threshold_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        externally_supplied_threshold_result["refusedObjects"][0]["reasonCode"],
        "acceptedPathForbiddenField"
    );

    let legacy_external_setup_role_field = [
        "central",
        "Trusted",
        "Setup",
        "Authority",
        "ThresholdShareCommitments",
    ]
    .join("");
    let mut legacy_external_setup_role_package = minimal_collective_setup_package();
    legacy_external_setup_role_package[legacy_external_setup_role_field.as_str()] =
        serde_json::json!({ "root": valid_hash('6') });
    rebind_collective_setup_package_hash(&mut legacy_external_setup_role_package);

    let legacy_external_setup_role_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": legacy_external_setup_role_package,
        }))
        .expect("verification response");

    assert_eq!(
        legacy_external_setup_role_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        legacy_external_setup_role_result["refusedObjects"][0]["reasonCode"],
        "secretMaterialPresent"
    );
}

#[test]
fn collective_setup_verifier_refuses_generic_key_switch_material_by_default() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_generic_key_switch_material_by_default",
    );
    let mut package = minimal_collective_setup_package();
    package["genericKeySwitchKeys"] = serde_json::json!({ "keyRoot": valid_hash('4') });
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "genericKeySwitchOutsideProfile"
    );
}

#[test]
fn collective_setup_verifier_refuses_evaluator_schedule_drift() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_evaluator_schedule_drift");
    let mut package = minimal_collective_setup_package();
    package["evaluatorKeySchedule"]["requiredGaloisSetHash"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "requiredGaloisSetHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_evaluation_key_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_evaluation_key_material",
    );
    let mut relin_package = minimal_collective_setup_package();
    let evaluator_key_schedule_root =
        relin_package["evaluatorKeySchedule"]["evaluatorKeyScheduleRoot"].clone();
    relin_package["relinearizationKeyShareRounds"] = serde_json::json!({
        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
    });
    rebind_collective_setup_package_hash(&mut relin_package);

    let relin_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": relin_package,
    }))
    .expect("verification response");

    assert_eq!(relin_result["verifierStatus"], "refused");
    assert_eq!(
        relin_result["refusedObjects"][0]["reasonCode"],
        "relinearizationKeyShareRoundsTypeMismatch"
    );

    let mut evaluation_key_package = minimal_collective_setup_package();
    evaluation_key_package["evaluationKeys"] = serde_json::json!({
        "evaluationKeyRoot": valid_hash('9'),
    });
    rebind_collective_setup_package_hash(&mut evaluation_key_package);

    let evaluation_key_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": evaluation_key_package,
        }))
        .expect("verification response");

    assert_eq!(evaluation_key_result["verifierStatus"], "refused");
    assert_eq!(
        evaluation_key_result["refusedObjects"][0]["reasonCode"],
        "evaluationKeysUnexpectedField"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_evaluation_key_proof_container_roots() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_evaluation_key_proof_container_roots",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let relinearization_root =
        package["relinearizationKeyShareRounds"]["relinearizationKeyShareRoundsRoot"].clone();
    let first_galois_batch_root =
        package["galoisKeyShareBatches"][0]["galoisKeyShareBatchRoot"].clone();
    let evaluation_key_set_hash = package["evaluationKeys"]["evaluationKeySetHash"].clone();
    let accepted_hashes = accepted_hashes_from_package(package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    let relinearization_root = relinearization_root.as_str().expect("relinearization root");
    let first_galois_batch_root = first_galois_batch_root.as_str().expect("Galois batch root");
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == relinearization_root)
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == first_galois_batch_root)
    );
    let evaluation_key_set_hash = evaluation_key_set_hash
        .as_str()
        .expect("evaluation key set hash");
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == evaluation_key_set_hash)
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_transported_public_evaluation_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_transported_public_evaluation_key_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    let evaluation_key_set_hash = package["evaluationKeys"]["evaluationKeySetHash"]
        .as_str()
        .expect("evaluation-key set hash")
        .to_string();
    let public_material_root = package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"]
        .as_str()
        .expect("public evaluation-key material root")
        .to_string();
    let accepted_hashes = accepted_hashes_from_package(&package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == &evaluation_key_set_hash)
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == &public_material_root)
    );
}

#[test]
#[ignore = "manual accepted setup closure diagnostic"]
fn manual_accepted_setup_collective_setup_verifier_accepts_all_transported_public_setup_companions()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "manual_accepted_setup_collective_setup_verifier_accepts_all_transported_public_setup_companions",
    );
    let (package, companions) = setup_package_with_transported_public_setup_companions();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": companions.vss_coefficient_commitment_material,
        "verifiedVssCoefficientCommitmentMaterial": companions.verified_vss_coefficient_commitment_material,
        "transportedSameSecretProofMaterial": companions.same_secret_proof_material,
        "transportedPublicKeyShareMaterial": companions.public_key_share_material,
        "transportedPublicKeyShareProofMaterial": companions.public_key_share_proof_material,
        "transportedEvaluationKeyShareComponentMaterial": companions.evaluation_key_share_component_material,
        "transportedEvaluationKeyShareProofMaterial": companions.evaluation_key_share_proof_material,
        "transportedPublicEvaluationKeyMaterial": companions.public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"],
        "accepted",
        "terminal setup verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(result["currentPhase"], "setupPackageVerification");
    assert_eq!(
        result["acceptedSetupHandoff"]["objectType"],
        "CollectiveBgvAcceptedSetupHandoff"
    );
    assert!(
        result["acceptedSetupHandoff"]["acceptedSetupHandoffRoot"].is_string(),
        "accepted terminal setup response must carry a handoff root"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_material_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_material_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    let expected_manifest =
        public_evaluation_key_material_manifest(&package, &package["evaluationKeys"])
            .expect("public evaluation-key material manifest");
    let mut tampered_manifest = expected_manifest;
    tampered_manifest["materialSource"] =
        serde_json::json!("tampered-public-evaluation-key-material");
    let tampered_material_bytes =
        encode_public_evaluation_key_material_manifest(&tampered_manifest)
            .expect("tampered public evaluation-key material bytes");
    rebind_public_evaluation_key_material_transport(
        &mut package,
        &mut transported_public_evaluation_key_material,
        tampered_material_bytes,
    );

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicEvaluationKeyMaterialManifestMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_uses_request_side_evaluation_key_component_chunks()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_uses_request_side_evaluation_key_component_chunks",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let component_material_set =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);
    let transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareComponentMaterial": component_material_set,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_galois_key_loader_refuses_reduced_ring_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_galois_key_loader_refuses_reduced_ring_material",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();

    let error =
        match accepted_setup_public_galois_keys_from_transport(package, &serde_json::json!({})) {
            Ok(_) => panic!("reduced-ring material must not become runtime Galois keys"),
            Err(error) => error,
        };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring component vectors")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_relinearization_key_loader_refuses_reduced_ring_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_relinearization_key_loader_refuses_reduced_ring_material",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();

    let error = match accepted_setup_public_relinearization_keys_from_transport(
        package,
        &serde_json::json!({}),
    ) {
        Ok(_) => panic!("reduced-ring material must not become runtime relinearization keys"),
        Err(error) => error,
    };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring component vectors")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_relinearization_round_one_generation_refuses_independent_source_square() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_relinearization_round_one_generation_refuses_independent_source_square",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let proof_record_snapshot =
        package["relinearizationKeyShareRounds"]["roundOneRecords"][0].clone();
    let trustee_roster_position = proof_record_snapshot["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let level = proof_record_snapshot["level"].as_u64().expect("level");
    let ring_degree = proof_record_snapshot["ringDegree"]
        .as_u64()
        .expect("ring degree") as usize;
    let key_switch_seed_hex = proof_record_snapshot["keySwitchSeedHex"]
        .as_str()
        .expect("key-switch seed");
    let legacy_source = legacy_relinearization_source_square_coefficients_for_fixture(
        trustee_roster_position,
        ring_degree,
    );
    let fixture_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Relinearization,
        trustee_roster_position,
        level,
        None,
        ring_degree,
        key_switch_seed_hex,
        Some(&legacy_source),
    );
    let mut proof_record = proof_record_snapshot.clone();
    proof_record["keySwitchComponentVectorRoot"] =
        serde_json::json!(fixture_material.component_vector_root.clone());
    proof_record["keySwitchComponentVectors"] =
        serde_json::json!(fixture_material.component_vector_entries.clone());
    let statement_record =
        &package["sameSecretConsistency"]["statementRecords"][trustee_roster_position as usize];
    let constant_commitments =
        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let proof_randomness_seed_hex = derive_protocol_hash(
        "RelinearizationRoundOneProofRandomness",
        &serde_json::json!({
            "trusteeRosterPosition": trustee_roster_position,
            "level": level,
            "rotation": serde_json::Value::Null,
        }),
    )
    .expect("proof randomness seed");
    let witness = EvaluationKeyShareLnpProofWitness {
        secret_coefficients: evaluation_key_secret_coefficients_for_fixture(
            trustee_roster_position,
            ring_degree,
        ),
        opening_randomness_by_limb: (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    0,
                    ring_degree,
                )
            })
            .collect(),
        error_coefficients_by_digit: fixture_material.error_coefficients_by_digit.clone(),
        relinearization_source_coefficients_by_digit: fixture_material
            .relinearization_source_coefficients_by_digit
            .clone(),
        round_one_aggregate_source_coefficients_by_digit: Vec::new(),
    };
    let error = match generate_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofGenerationInput {
            proof_family: EvaluationKeyShareProofFamily::Relinearization,
            public_matrix_seed_hash,
            proof_record: &proof_record,
            same_secret_statement_record: statement_record,
            constant_commitments: &constant_commitments,
            component_b_by_digit: &fixture_material.component_b_by_digit,
            setup_proof_binding: &setup_proof_binding,
            transported_key_switch_component_material: None,
            witness: &witness,
            proof_randomness_seed_hex: &proof_randomness_seed_hex,
        },
    ) {
        Ok(_) => panic!("round-one source-square shortcut must reject"),
        Err(error) => error,
    };

    assert!(
        error.message.contains(
            "round-one relinearization source witness must equal the same-secret witness"
        ),
        "{}",
        error.message
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_duplicated_public_evaluation_key_component_chunks()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_duplicated_public_evaluation_key_component_chunks",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let component_material_set =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);
    let mut transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    transported_public_evaluation_key_material["componentMaterials"] =
        component_material_set["componentMaterials"].clone();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("must not duplicate evaluation-key component material chunks")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_proof_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let transported_proof_material =
        move_first_galois_key_share_lnp_proof_bytes_to_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_lnp_proof_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_lnp_proof_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut transported_proof_material =
        move_first_galois_key_share_lnp_proof_bytes_to_transport(&mut package);
    transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("transported evaluation-key proof material hashes do not match chunks")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_component_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_galois_lnp_proofs_from_transported_component_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let transported_component_material =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareComponentMaterial": transported_component_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_component_material_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_galois_component_material_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut transported_component_material =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);
    transported_component_material["componentMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareComponentMaterial": transported_component_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("transported evaluation-key component material hash metadata does not match supplied chunks")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoAggregateRoots"][0]["roundTwoAggregateRoot"] =
        serde_json::json!(valid_hash('b'));
    rebind_relinearization_key_share_rounds_root(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationRoundTwoAggregateRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_source_square_binding_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_source_square_binding_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["sourceSquareBindingRoot"] =
        serde_json::json!(valid_hash('d'));
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]
        .as_object_mut()
        .expect("relinearization round-one record")
        .remove("roundOneProofRoot");
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]
        .as_object_mut()
        .expect("relinearization round-one record")
        .remove("roundOneRecordRoot");
    let round_one_proof_root = derive_protocol_hash(
        "RelinearizationKeyShareProofRoot",
        &package["relinearizationKeyShareRounds"]["roundOneRecords"][0],
    )
    .expect("relinearization round-one proof root");
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["roundOneProofRoot"] =
        serde_json::json!(round_one_proof_root);
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["roundOneRecordRoot"] =
        serde_json::json!(valid_hash('c'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert_eq!(
        result["refusedObjects"][0]["message"],
        "sourceSquareBindingRoot does not match the canonical relinearization source-square binding"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("shared by scheduled level and round")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_one_source_square_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_one_source_square_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneAggregateRoots"][0]["roundOneSourceSquareAggregateRoot"] =
        serde_json::json!(valid_hash('e'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationRoundOneSourceSquareAggregateRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_linkage_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_linkage_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoRecords"][0]["roundOneSourceSquareBindingRoot"] =
        serde_json::json!(valid_hash('f'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert_eq!(
        result["refusedObjects"][0]["message"],
        "relinearization round-two record must bind the accepted round-one record, share, aggregate, and source-square roots"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_source_square_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoAggregateRoots"][0]["roundTwoSourceSquareAggregateRoot"] =
        serde_json::json!(valid_hash('a'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationRoundTwoSourceSquareAggregateRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_same_secret_family_root_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_same_secret_family_root_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('e'));
    rebind_relinearization_key_share_rounds_root(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("shared by scheduled rotation and level")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_galois_batch_schedule_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_galois_batch_schedule_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["galoisKeyShareBatches"][0]["requiredGaloisKeySchedule"][0]["rotation"] =
        serde_json::json!(999_u64);
    rebind_galois_key_share_batch_root(&mut package, 0);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_assembly_root_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_assembly_root_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["evaluationKeys"]["relinearizationKeyRoots"][0]["relinearizationKeyRoot"] =
        serde_json::json!(valid_hash('c'));
    rebind_public_evaluation_key_set_hash(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyRelinearizationKeyRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_missing_and_extra_evaluation_keys() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_missing_and_extra_evaluation_keys",
    );
    let mut missing_galois_key = evaluation_key_proof_container_bearing_collective_setup_package();
    missing_galois_key["evaluationKeys"]["galoisKeyRoots"]
        .as_array_mut()
        .expect("Galois key roots")
        .pop();
    rebind_public_evaluation_key_set_hash(&mut missing_galois_key);
    rebind_collective_setup_package_hash(&mut missing_galois_key);

    let missing_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": missing_galois_key,
    }))
    .expect("verification response");

    assert_eq!(missing_result["verifierStatus"], "refused");
    assert_eq!(
        missing_result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyGaloisKeyCountMismatch"
    );

    let mut extra_generic_key = evaluation_key_proof_container_bearing_collective_setup_package();
    extra_generic_key["evaluationKeys"]["genericKeySwitchKeyRoots"] =
        serde_json::json!([valid_hash('d')]);
    rebind_public_evaluation_key_set_hash(&mut extra_generic_key);
    rebind_collective_setup_package_hash(&mut extra_generic_key);

    let extra_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": extra_generic_key,
    }))
    .expect("verification response");

    assert_eq!(extra_result["verifierStatus"], "refused");
    assert_eq!(
        extra_result["refusedObjects"][0]["reasonCode"],
        "evaluationKeysGenericKeySwitchOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_relinearization_round_two_generation_refuses_aggregate_source_product_mismatch()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_relinearization_round_two_generation_refuses_aggregate_source_product_mismatch",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let proof_record = package["relinearizationKeyShareRounds"]["roundTwoRecords"][0].clone();
    let trustee_roster_position = proof_record["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let level = proof_record["level"].as_u64().expect("level");
    let ring_degree = proof_record["ringDegree"].as_u64().expect("ring degree") as usize;
    let key_switch_seed_hex = proof_record["keySwitchSeedHex"]
        .as_str()
        .expect("key-switch seed");
    let round_two_source = relinearization_round_two_source_coefficients_for_fixture(
        trustee_roster_position,
        ring_degree,
    );
    let fixture_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Relinearization,
        trustee_roster_position,
        level,
        None,
        ring_degree,
        key_switch_seed_hex,
        Some(&round_two_source),
    );
    let statement_record =
        &package["sameSecretConsistency"]["statementRecords"][trustee_roster_position as usize];
    let constant_commitments =
        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
    let constant_commitment_values = constant_commitments
        .iter()
        .map(crate::bgv::setup::commitment::setup_commitment_full_value)
        .collect::<Vec<_>>();
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let proof_randomness_seed_hex = derive_protocol_hash(
        "RelinearizationRoundTwoProofRandomness",
        &serde_json::json!({
            "trusteeRosterPosition": trustee_roster_position,
            "level": level,
            "rotation": serde_json::Value::Null,
        }),
    )
    .expect("proof randomness seed");
    let request = serde_json::json!({
        "proofFamily": "relinearization-key-share",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "proofRecord": proof_record,
        "sameSecretStatementRecord": statement_record,
        "constantCommitments": constant_commitment_values,
        "setupProofBinding": setup_proof_binding,
        "secretCoefficients": evaluation_key_secret_coefficients_for_fixture(
            trustee_roster_position,
            ring_degree,
        ),
        "openingRandomnessByLimb": (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    0,
                    ring_degree,
                )
            })
            .collect::<Vec<_>>(),
        "errorCoefficientsByDigit": fixture_material.error_coefficients_by_digit,
        "relinearizationSourceCoefficientsByDigit": fixture_material
            .relinearization_source_coefficients_by_digit,
        "roundOneAggregateSourceCoefficientsByDigit": vec![
            vec![0_i128; ring_degree];
            fixture_material.component_b_by_digit.len()
        ],
        "proofRandomnessSource": "development-deterministic-fixture",
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
    });

    let error = match generate_evaluation_key_share_lnp_proof_from_request(&request) {
        Ok(_) => panic!("round-two source product mismatch must reject"),
        Err(error) => error,
    };

    assert!(
        error.message.contains(
            "round-two relinearization source witness must equal the trustee secret times the accepted round-one aggregate source"
        ),
        "{}",
        error.message
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_generate_evaluation_key_share_lnp_proof_command_self_verifies_galois_proof()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_generate_evaluation_key_share_lnp_proof_command_self_verifies_galois_proof",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let proof_record = package["galoisKeyShareBatches"][0]["galoisKeyShareProofs"][0].clone();
    let trustee_roster_position = proof_record["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let rotation = proof_record["rotation"].as_u64().expect("rotation");
    let level = proof_record["level"].as_u64().expect("level");
    let ring_degree = proof_record["ringDegree"].as_u64().expect("ring degree") as usize;
    let key_switch_seed_hex = proof_record["keySwitchSeedHex"]
        .as_str()
        .expect("key-switch seed");
    let fixture_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Galois,
        trustee_roster_position,
        level,
        Some(rotation),
        ring_degree,
        key_switch_seed_hex,
        None,
    );
    let statement_record =
        &package["sameSecretConsistency"]["statementRecords"][trustee_roster_position as usize];
    let constant_commitments =
        same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
    let constant_commitment_values = constant_commitments
        .iter()
        .map(crate::bgv::setup::commitment::setup_commitment_full_value)
        .collect::<Vec<_>>();
    let setup_proof_binding = setup_proof_binding_for_test_package(package);
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let proof_randomness_seed_hex = derive_protocol_hash(
        "GaloisKeyShareProofRandomness",
        &serde_json::json!({
            "trusteeRosterPosition": trustee_roster_position,
            "level": level,
            "rotation": rotation,
        }),
    )
    .expect("proof randomness seed");
    let request = serde_json::json!({
        "proofFamily": "galois-key-share",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "proofRecord": proof_record,
        "sameSecretStatementRecord": statement_record,
        "constantCommitments": constant_commitment_values,
        "setupProofBinding": setup_proof_binding,
        "secretCoefficients": evaluation_key_secret_coefficients_for_fixture(
            trustee_roster_position,
            ring_degree,
        ),
        "openingRandomnessByLimb": (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(
                    trustee_roster_position,
                    rns_limb_index,
                    0,
                    ring_degree,
                )
            })
            .collect::<Vec<_>>(),
        "errorCoefficientsByDigit": fixture_material.error_coefficients_by_digit,
        "proofRandomnessSource": "development-deterministic-fixture",
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
    });

    let result = generate_evaluation_key_share_lnp_proof_from_request(&request)
        .expect("generated evaluation-key proof");

    assert_eq!(
        result["ok"],
        true,
        "terminal setup verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(result["operation"], "generateEvaluationKeyShareLnpProof");
    assert_eq!(result["proofFamily"], "galois-key-share");
    assert!(
        result["galoisKeyShareTboxParameterProfileHash"]
            .as_str()
            .is_some()
    );
    let proof_bytes = decode_hex(result["proofBytesHex"].as_str().expect("proof bytes hex"))
        .expect("proof bytes");
    assert_eq!(
        result["proofSizeBytes"].as_u64(),
        Some(u64::try_from(proof_bytes.len()).expect("proof size fits u64"))
    );
    assert_eq!(
        result["proofBytesHash"].as_str().expect("proof bytes hash"),
        evaluation_key_share_lnp_relation_proof_bytes_hash(
            EvaluationKeyShareProofFamily::Galois,
            &proof_bytes,
        ),
    );
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family: EvaluationKeyShareProofFamily::Galois,
            public_matrix_seed_hash,
            proof_record: &request["proofRecord"],
            same_secret_statement_record: statement_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding: &setup_proof_binding,
            transported_key_switch_component_material: None,
            proof_bytes: &proof_bytes,
        },
    )
    .expect("returned proof verifies");
    assert_eq!(
        result["statementHash"].as_str().expect("statement hash"),
        verification.statement_hash_hex
    );
    assert_eq!(
        result["relationCommitmentHash"]
            .as_str()
            .expect("relation commitment hash"),
        verification.relation_commitment_hash_hex
    );
    assert_eq!(
        result["tboxCommitmentPrefixHash"]
            .as_str()
            .expect("tbox commitment prefix hash"),
        verification.tbox_commitment_prefix_hash
    );

    let mut rejected_request = request;
    rejected_request["relinearizationSourceCoefficientsByDigit"] =
        serde_json::json!([vec![0_i64; ring_degree]]);
    let error = match generate_evaluation_key_share_lnp_proof_from_request(&rejected_request) {
        Ok(_) => panic!("Galois command must reject relinearization-only source witness material"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("must not be provided for Galois proof generation"),
        "{}",
        error.message
    );
}
