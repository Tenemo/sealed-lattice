use super::*;

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
        "evaluationKeysTypeMismatch"
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
fn collective_setup_verifier_refuses_drifted_terminal_certificate_hashes() {
    // Drifting a present certificate hash and recomputing the outer package hash
    // must be refused before any missing-object pending, proving the verifier
    // recomputes each certificate root rather than trusting the package copy.
    for certificate_hash_field in [
        "setupCommitmentSecurityCertificateHash",
        "setupTransportCertificateHash",
        "setupProofAccountingCertificateHash",
        "heSecurityCertificateHash",
        "activeStaticSetupTheoremCertificateHash",
    ] {
        let mut package = minimal_collective_setup_package();
        let bound_hash = package[certificate_hash_field]
            .as_str()
            .unwrap_or_else(|| panic!("{certificate_hash_field} must be present"))
            .to_string();
        package[certificate_hash_field] = serde_json::json!(drift_hash(&bound_hash));
        rebind_collective_setup_package_hash(&mut package);

        let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .expect("verification response");

        assert_eq!(
            result["verifierStatus"], "refused",
            "drifting {certificate_hash_field} must refuse before any missing-object pending",
        );
    }
}

#[test]
#[ignore = "terminal recomputed-root refusal matrix at profile ring"]
fn manual_accepted_setup_refuses_every_recomputed_accepted_root_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "manual_accepted_setup_refuses_every_recomputed_accepted_root_drift",
    );
    let (package, companions) = setup_package_with_transported_public_setup_companions();
    let verify = |candidate: &serde_json::Value| {
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": candidate,
            "transportedVssCoefficientCommitmentMaterial": companions.vss_coefficient_commitment_material,
            "verifiedVssCoefficientCommitmentMaterial": companions.verified_vss_coefficient_commitment_material,
            "transportedSameSecretProofMaterial": companions.same_secret_proof_material,
            "transportedPublicKeyShareMaterial": companions.public_key_share_material,
            "transportedPublicKeyShareProofMaterial": companions.public_key_share_proof_material,
            "transportedEvaluationKeyShareComponentMaterial": companions.evaluation_key_share_component_material,
            "transportedEvaluationKeyShareProofMaterial": companions.evaluation_key_share_proof_material,
            "transportedPublicEvaluationKeyMaterial": companions.public_evaluation_key_material,
        }))
        .expect("verification response")
    };

    assert_eq!(
        verify(&package)["verifierStatus"],
        "accepted",
        "baseline terminal package must accept before the recomputed-root matrix",
    );

    // The matrix is driven by the verifier's own accepted-root enumeration, so it
    // covers exactly the root set the accept response binds: every accepted root,
    // drifted at every occurrence with the outer package hash recomputed, must be
    // refused. A root the verifier never recomputes would silently survive here.
    let accepted_roots = crate::bgv::setup::accepted_setup::accepted_hashes_from_package(&package);
    let package_hash = package["setupPackageHash"]
        .as_str()
        .expect("setup package hash")
        .to_string();

    let mut unbound_roots = Vec::new();
    let mut covered_root_count = 0_usize;
    for root in &accepted_roots {
        if root == &package_hash {
            continue;
        }
        let mut drifted = package.clone();
        let occurrences = drift_all_occurrences(&mut drifted, root, &drift_hash(root));
        assert!(
            occurrences >= 1,
            "accepted root {root} was not located in the terminal package graph",
        );
        rebind_collective_setup_package_hash(&mut drifted);
        if verify(&drifted)["verifierStatus"] != "refused" {
            unbound_roots.push(root.clone());
        }
        covered_root_count += 1;
    }
    assert!(
        unbound_roots.is_empty(),
        "terminal package accepted roots that the verifier does not recompute and refuse: {unbound_roots:?}",
    );
    assert!(
        covered_root_count >= 12,
        "completeness floor: the terminal accepted package must bind the full first-profile root set, covered {covered_root_count}",
    );

    // Drifting the outer package hash without recomputation is a package-hash
    // mismatch, the structural guard the per-root rebinds rely on.
    let mut drifted_package_hash = package.clone();
    drifted_package_hash["setupPackageHash"] = serde_json::json!(drift_hash(&package_hash));
    assert_eq!(
        verify(&drifted_package_hash)["verifierStatus"],
        "refused",
        "drifting the outer setup package hash must be refused",
    );
}

#[test]
#[ignore = "manual accepted setup closure diagnostic"]
fn manual_accepted_setup_collective_setup_verifier_refuses_terminal_trustee_proof_statement_hash_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "manual_accepted_setup_collective_setup_verifier_refuses_terminal_trustee_proof_statement_hash_drift",
    );
    let (mut package, companions) = setup_package_with_transported_public_setup_companions();

    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["statementHash"] =
        serde_json::json!(valid_hash('4'));
    rebind_trustee_evaluation_key_proof_record_root(&mut package, 0);
    rebind_trustee_evaluation_key_proof_set_root(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

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
        "refused",
        "terminal setup verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
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
    assert!(result["acceptedSetupHandoff"].is_null());
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

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofsMissing"
    );
    assert_eq!(
        result["refusedObjects"][0]["objectPath"],
        "setupPackage.trusteeEvaluationKeyProofs"
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_trustee_evaluation_key_proof_container()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_trustee_evaluation_key_proof_container",
    );

    for field_name in ["proofRecords", "trusteeEvaluationKeyProofSetRoot"] {
        let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
        package["trusteeEvaluationKeyProofs"]
            .as_object_mut()
            .expect("trustee evaluation-key proof set")
            .remove(field_name);
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
                .contains(field_name)
        );
        assert_eq!(
            result["refusedObjects"][0]["objectPath"],
            "setupPackage.trusteeEvaluationKeyProofs"
        );
        assert!(result["acceptedSetupHandoff"].is_null());
    }
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_extra_and_duplicate_trustee_evaluation_key_proofs()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_extra_and_duplicate_trustee_evaluation_key_proofs",
    );

    let mut extra_proof_package = evaluation_key_proof_container_bearing_collective_setup_package();
    let duplicate_proof_record =
        extra_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"][0].clone();
    extra_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"]
        .as_array_mut()
        .expect("trustee evaluation-key proof records")
        .push(duplicate_proof_record);
    rebind_trustee_evaluation_key_proof_set_root(&mut extra_proof_package);
    rebind_setup_key_correctness_certificate(&mut extra_proof_package);
    rebind_collective_setup_package_hash(&mut extra_proof_package);
    assert_refuses_trustee_evaluation_key_proof_variant(
        extra_proof_package,
        "proofRecords must contain one proof per trustee",
    );

    let mut duplicate_proof_package =
        evaluation_key_proof_container_bearing_collective_setup_package();
    duplicate_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"][1] =
        duplicate_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"][0].clone();
    rebind_trustee_evaluation_key_proof_record_root(&mut duplicate_proof_package, 1);
    rebind_trustee_evaluation_key_proof_set_root(&mut duplicate_proof_package);
    rebind_setup_key_correctness_certificate(&mut duplicate_proof_package);
    rebind_collective_setup_package_hash(&mut duplicate_proof_package);
    assert_refuses_trustee_evaluation_key_proof_variant(
        duplicate_proof_package,
        "proof records must be ordered by roster position",
    );
}

fn assert_refuses_trustee_evaluation_key_proof_variant(
    package: serde_json::Value,
    message_fragment: &str,
) {
    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert_eq!(
        result["refusedObjects"][0]["objectPath"],
        "setupPackage.trusteeEvaluationKeyProofs"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains(message_fragment)
    );
    assert!(result["acceptedSetupHandoff"].is_null());
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
    let package = evaluation_key_proof_container_bearing_collective_setup_package();

    let mut noncanonical_claim_package = package.clone();
    mutate_first_trustee_evaluation_key_proof_bytes_and_rebind(
        &mut noncanonical_claim_package,
        |proof_bytes| {
            set_first_masked_consistency_claim_to_noncanonical_modulus(proof_bytes);
        },
    );
    let noncanonical_claim_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": noncanonical_claim_package,
        }))
        .expect("verification response");

    assert_eq!(noncanonical_claim_result["verifierStatus"], "refused");
    assert_eq!(
        noncanonical_claim_result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );

    let mut low_degree_shape_package = package;
    let trustee_roster_position = low_degree_shape_package["trusteeEvaluationKeyProofs"]
        ["proofRecords"][0]["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let round_one_aggregate_diagonals =
        round_one_aggregate_diagonals_from_fixture_package(&low_degree_shape_package, None);
    let statement =
        trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
            setup_package: &low_degree_shape_package,
            transported_key_switch_component_material: None,
            transported_constant_commitments: &BTreeMap::new(),
            round_one_aggregate_diagonals_by_level: &round_one_aggregate_diagonals,
            trustee_roster_position,
        })
        .expect("trustee evaluation-key statement");
    let total_error_column_count = statement.keys.iter().map(|key| key.level + 1).sum();
    let linkage_commitment_count = statement
        .same_secret_linkage
        .as_ref()
        .expect("trustee evaluation-key same-secret linkage")
        .commitments
        .len();
    mutate_first_trustee_evaluation_key_proof_bytes_and_rebind(
        &mut low_degree_shape_package,
        |proof_bytes| {
            set_first_limb_low_degree_fold_count_to_wrong_value(
                proof_bytes,
                statement.ring_degree,
                total_error_column_count,
                linkage_commitment_count,
            );
        },
    );
    let low_degree_shape_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": low_degree_shape_package,
        }))
        .expect("verification response");

    assert_eq!(low_degree_shape_result["verifierStatus"], "refused");
    assert_eq!(
        low_degree_shape_result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert!(
        low_degree_shape_result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("low-degree committed fold count does not match the statement")
    );
    assert!(low_degree_shape_result["acceptedSetupHandoff"].is_null());
}

fn mutate_first_trustee_evaluation_key_proof_bytes_and_rebind(
    package: &mut serde_json::Value,
    mutate_proof_bytes: impl FnOnce(&mut [u8]),
) {
    let proof_record = &mut package["trusteeEvaluationKeyProofs"]["proofRecords"][0];
    let proof_bytes_hex = proof_record["proofBytesHex"]
        .as_str()
        .expect("embedded trustee proof bytes")
        .to_string();
    let mut proof_bytes = decode_hex(&proof_bytes_hex).expect("trustee proof bytes");
    mutate_proof_bytes(&mut proof_bytes);
    proof_record["proofBytesHex"] = serde_json::json!(to_hex(&proof_bytes));
    proof_record["proofBytesHash"] =
        serde_json::json!(trustee_evaluation_key_proof_bytes_hash(&proof_bytes));
    proof_record["proofSizeBytes"] = serde_json::json!(proof_bytes.len());
    rebind_trustee_evaluation_key_proof_record_root(package, 0);
    rebind_trustee_evaluation_key_proof_set_root(package);
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);
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
