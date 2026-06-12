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
    let trustee_proof_set_root =
        package["trusteeEvaluationKeyProofs"]["trusteeEvaluationKeyProofSetRoot"].clone();
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
    for expected_hash in [
        relinearization_root.as_str().expect("relinearization root"),
        first_galois_batch_root.as_str().expect("Galois batch root"),
        trustee_proof_set_root
            .as_str()
            .expect("trustee evaluation-key proof set root"),
        evaluation_key_set_hash
            .as_str()
            .expect("evaluation key set hash"),
    ] {
        assert!(
            accepted_hashes
                .iter()
                .any(|accepted_hash| accepted_hash == expected_hash),
            "accepted hashes must cover {expected_hash}"
        );
    }
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

    assert_eq!(
        result["verifierStatus"],
        "outsideProfile",
        "unexpected verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
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

    assert_eq!(
        result["verifierStatus"],
        "outsideProfile",
        "unexpected verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_trustee_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_trustee_proofs_from_transported_proof_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let proof_material_set =
        move_first_trustee_evaluation_key_proof_bytes_to_transport(&mut package);
    let transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": proof_material_set,
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_trustee_proof_chunk()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_trustee_proof_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut proof_material_set =
        move_first_trustee_evaluation_key_proof_bytes_to_transport(&mut package);
    let chunk_bytes_hex = proof_material_set["proofMaterials"][0]["chunks"][0]["bytesHex"]
        .as_str()
        .expect("transported proof chunk bytes")
        .to_string();
    let mut tampered = chunk_bytes_hex.into_bytes();
    tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
    proof_material_set["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!(String::from_utf8(tampered).expect("tampered chunk hex"));

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": proof_material_set,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoAggregateRoots"][0]["roundTwoAggregateRoot"] =
        serde_json::json!(valid_hash('7'));
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('3'));
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["galoisKeyShareBatches"][0]["galoisKeyShareMaterialRecords"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('2'));
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
        serde_json::json!(9_999);
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
            .contains("frozen RequiredGaloisSetHash and schedule")
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
    package["relinearizationKeyShareRounds"]["sameSecretProofSetRoot"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationKeyShareRoundsBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_missing_trustee_evaluation_key_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_missing_trustee_evaluation_key_proofs",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("trusteeEvaluationKeyProofs");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "pending");
    assert!(
        result["missingObjects"]
            .as_array()
            .expect("missing objects")
            .iter()
            .any(|missing| missing == "trusteeEvaluationKeyProofs")
    );
}

#[test]
fn collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records",
    );
    let mut package = minimal_collective_setup_package();
    package["trusteeEvaluationKeyProofs"] = serde_json::json!({
        "objectType": "TrusteeEvaluationKeyProofSet",
    });
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofsWithoutShareRecords"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_accounting_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_accounting_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["trusteeEvaluationKeyProofs"]["proofAccountingHash"] =
        serde_json::json!(valid_hash('1'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("proofAccountingHash")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_statement_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_statement_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["statementHash"] =
        serde_json::json!(valid_hash('4'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("statementHash must match the statement rebuilt")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_trustee_proof_bytes() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_trustee_proof_bytes",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let proof_bytes_hex = package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofBytesHex"]
        .as_str()
        .expect("embedded trustee proof bytes")
        .to_string();
    let mut tampered_bytes = decode_hex(&proof_bytes_hex).expect("trustee proof bytes");
    let tamper_position = tampered_bytes.len() / 2;
    tampered_bytes[tamper_position] ^= 0x01;
    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofBytesHex"] =
        serde_json::json!(to_hex(&tampered_bytes));
    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["proofBytesHash"] =
        serde_json::json!(trustee_evaluation_key_proof_bytes_hash(&tampered_bytes));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_round_two_records_with_substituted_aggregate_source_cannot_reprove() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_round_two_records_with_substituted_aggregate_source_cannot_reprove",
    );
    // A trustee whose round-two share multiplies a substituted aggregate
    // cannot generate a verifying proof: the statement carries the aggregate
    // recomputed from the round-one records, so the honest witness fails the
    // batched relation at proving time.
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let honest_aggregates = round_one_aggregate_diagonals_from_fixture_package(package, None);
    let scheduled_level = *honest_aggregates
        .keys()
        .next()
        .expect("scheduled relinearization level");
    let mut substituted_aggregates = honest_aggregates
        .get(&scheduled_level)
        .expect("aggregate diagonals")
        .clone();
    substituted_aggregates[0][0] = (substituted_aggregates[0][0] + 1) % DATA_PRIMES[0];
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    let substituted_source = relinearization_round_two_source_by_digit_for_fixture(
        0,
        ring_degree,
        &substituted_aggregates,
    );
    let schedule = &package["evaluatorKeySchedule"];
    let key_switch_seed_hex =
        relinearization_key_switch_seed_for_test(schedule, "round-two", scheduled_level);
    let substituted_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Relinearization,
        0,
        scheduled_level,
        None,
        ring_degree,
        &key_switch_seed_hex,
        Some(&substituted_source),
    );

    let mut tampered_package = package.clone();
    let record = &mut tampered_package["relinearizationKeyShareRounds"]["roundTwoRecords"][0];
    assert_eq!(record["trusteeRosterPosition"], 0);
    record["keySwitchComponentVectorRoot"] =
        serde_json::json!(substituted_material.component_vector_root.clone());
    record["roundTwoShareRoot"] =
        serde_json::json!(substituted_material.component_vector_root.clone());
    record["keySwitchComponentVectors"] =
        serde_json::json!(substituted_material.component_vector_entries.clone());

    let aggregates = round_one_aggregate_diagonals_from_fixture_package(&tampered_package, None);
    let statement =
        trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
            setup_package: &tampered_package,
            transported_key_switch_component_material: None,
            transported_constant_commitments: &BTreeMap::new(),
            round_one_aggregate_diagonals_by_level: &aggregates,
            trustee_roster_position: 0,
        })
        .expect("statement over substituted round-two share");
    let witness = trustee_evaluation_key_witness_for_fixture(0, ring_degree, &statement);
    let proof_randomness_seed_hex = derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &serde_json::json!({
            "fixture": "substituted-aggregate-reprove",
            "trusteeRosterPosition": 0,
        }),
    )
    .expect("proof randomness seed");

    let error = match prove_evaluation_key_share(&statement, &witness, &proof_randomness_seed_hex) {
        Ok(_) => panic!("substituted aggregate source must not prove"),
        Err(error) => error,
    };

    assert!(
        error.message.contains("witness does not satisfy") || error.message.contains("sumcheck"),
        "{}",
        error.message
    );
}
