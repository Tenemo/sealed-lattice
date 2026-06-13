use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_same_secret_statements() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_same_secret_statements",
    );
    let mut wrong_constant_package = minimal_collective_setup_package();
    wrong_constant_package["sameSecretConsistency"]["statementRecords"][0]["constantCoefficientCommitmentRoots"]
        [0]["commitmentRoot"] = serde_json::json!(valid_hash('4'));
    rebind_collective_same_secret_statement_roots(&mut wrong_constant_package);
    rebind_collective_setup_package_hash(&mut wrong_constant_package);

    let wrong_constant_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_constant_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_constant_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_constant_result["refusedObjects"][0]["reasonCode"],
        "sameSecretConstantCommitmentRootMismatch"
    );

    let mut wrong_statement_root_package = minimal_collective_setup_package();
    wrong_statement_root_package["sameSecretConsistency"]["statementRecords"][0]["sameSecretStatementRoot"] =
        serde_json::json!(valid_hash('5'));
    rebind_collective_same_secret_consistency_root(&mut wrong_statement_root_package);
    rebind_collective_setup_package_hash(&mut wrong_statement_root_package);

    let wrong_statement_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_statement_root_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_statement_root_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_statement_root_result["refusedObjects"][0]["reasonCode"],
        "sameSecretStatementRootMismatch"
    );

    let mut wrong_family_binding_package = minimal_collective_setup_package();
    wrong_family_binding_package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_same_secret_consistency_root(&mut wrong_family_binding_package);
    rebind_collective_setup_package_hash(&mut wrong_family_binding_package);

    let wrong_family_binding_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_family_binding_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_family_binding_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_family_binding_result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofFamilyBindingRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_proofs_before_public_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_proofs_before_public_key_material",
    );
    let package = same_secret_proof_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!([
            "publicKeyShareMaterial",
            "publicKeyShareLnpProofs",
            "collectivePublicKey",
            "collectivePublicKeyRoot"
        ])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_weakened_same_secret_proof_model_status()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_weakened_same_secret_proof_model_status",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofModelStatus"] =
        serde_json::json!("weakened-same-secret-proof-model");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofSetProfileMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_proofs_from_transported_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_proofs_from_transported_material",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let material_bytes = encode_transport_material_from_package(&package);
    let transported_material = transported_material_value(&material_bytes);
    let transport_derivation =
        derive_threshold_share_commitments_from_transport_request(&serde_json::json!({
            "setupContext": package["setupContext"],
            "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
            "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
            "sourceTrusteeCoefficientCommitmentRecords": package["vssCoefficientCommitments"]["sourceTrusteeRecords"],
            "transportedVssCoefficientCommitmentMaterial": transported_material,
        }))
        .expect("transported threshold derivation");
    package["vssCoefficientCommitmentMaterial"] =
        transport_derivation["vssCoefficientCommitmentMaterial"].clone();
    package["thresholdShareCommitments"] =
        transport_derivation["thresholdShareCommitments"].clone();
    // The anchor statement binds the accepted public VSS material root, so the
    // transported-material package regenerates its anchor proofs against the
    // transported material reference root.
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let setup_transport_certificate =
        setup_transport_certificate_fixture(&profile, &package["vssCoefficientCommitmentMaterial"]);
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(
        result["verifierStatus"], "refused",
        "unexpected verifier result: {result}"
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], "vssMaterialTransportReferenceMetadataMismatch",
        "unexpected verifier result: {result}"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_proofs_from_transported_proof_material",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let transported_proof_material = move_same_secret_proof_bytes_to_transport(&mut package);
    // Request-side proof sidecars must be aggregated by the setup transport
    // certificate before the verifier reaches the terminal missing-object
    // gate.
    append_transport_certificate_entries_from_material_set(
        &mut package,
        &transported_proof_material,
        "proofMaterials",
        "proofMaterialRoot",
        "sameSecretProofMaterial",
        "same-secret-proof-material",
        DIRECT_TRANSPORT_CERTIFICATE_FIELDS,
    );
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedSameSecretProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(
        result["verifierStatus"], "pending",
        "unexpected verifier result: {result}"
    );
    assert_eq!(
        result["missingObjects"],
        serde_json::json!([
            "publicKeyShareMaterial",
            "publicKeyShareLnpProofs",
            "collectivePublicKey",
            "collectivePublicKeyRoot"
        ])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_same_secret_proof_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_same_secret_proof_chunk",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let mut transported_proof_material = move_same_secret_proof_bytes_to_transport(&mut package);
    transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedSameSecretProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_proof_bytes_hash() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_proof_bytes_hash",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["proofBytesHash"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_statement_hash() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_statement_hash",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["statementHash"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_bytes_with_drifted_content()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_bytes_with_drifted_content",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let proof_record = &mut package["sameSecretProofs"]["proofRecords"][0];
    let mut proof_bytes = decode_hex(
        proof_record["proofBytesHex"]
            .as_str()
            .expect("embedded proof bytes"),
    )
    .expect("proof bytes");
    let last_byte_index = proof_bytes.len() - 1;
    proof_bytes[last_byte_index] ^= 1;
    // Keep the cheap size and hash checks satisfied so the refusal must come
    // from the succinct argument verification itself.
    proof_record["proofBytesHex"] = serde_json::json!(to_hex(&proof_bytes));
    proof_record["proofBytesHash"] = serde_json::json!(
        crate::bgv::setup::trustee_evaluation_key_proof::same_secret_anchor_proof_bytes_hash(
            &proof_bytes
        )
    );
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_root_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_root_drift",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_same_secret_proof_set_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofConsistencyRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_record_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_record_drift",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_same_secret_proof_set_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_rebinding() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_proof_family_rebinding",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["proofFamily"] =
        serde_json::json!("trustee-evaluation-key");
    rebind_collective_same_secret_proof_set_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
}
