use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_same_secret_statements() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_same_secret_statements",
    );
    assert_minimal_collective_setup_package_refused(
        "wrong same-secret constant coefficient commitment root",
        |package| {
            package["sameSecretConsistency"]["statementRecords"][0]["constantCoefficientCommitmentRoots"]
                [0]["commitmentRoot"] = serde_json::json!(valid_hash('4'));
            rebind_collective_same_secret_statement_roots(package);
        },
        "sameSecretConstantCommitmentRootMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong same-secret statement root",
        |package| {
            package["sameSecretConsistency"]["statementRecords"][0]["sameSecretStatementRoot"] =
                serde_json::json!(valid_hash('5'));
            rebind_collective_same_secret_consistency_root(package);
        },
        "sameSecretStatementRootMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong same-secret proof family binding root",
        |package| {
            package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"] =
                serde_json::json!(valid_hash('6'));
            rebind_collective_same_secret_consistency_root(package);
        },
        "sameSecretProofFamilyBindingRootMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_rebound_malformed_same_secret_anchor_commitment_sets() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_rebound_malformed_same_secret_anchor_commitment_sets",
    );

    let mut missing_commitment_package = minimal_collective_setup_package();
    missing_commitment_package["sameSecretConsistency"]["statementRecords"][0]
        ["constantCoefficientCommitmentRoots"]
        .as_array_mut()
        .expect("same-secret constant commitment roots")
        .pop();
    assert_same_secret_anchor_commitment_set_mismatch(
        "missing same-secret anchor commitment",
        missing_commitment_package,
    );

    let mut extra_commitment_package = minimal_collective_setup_package();
    let extra_commitment = extra_commitment_package["sameSecretConsistency"]["statementRecords"][0]
        ["constantCoefficientCommitmentRoots"][0]
        .clone();
    extra_commitment_package["sameSecretConsistency"]["statementRecords"][0]
        ["constantCoefficientCommitmentRoots"]
        .as_array_mut()
        .expect("same-secret constant commitment roots")
        .push(extra_commitment);
    assert_same_secret_anchor_commitment_set_mismatch(
        "extra same-secret anchor commitment",
        extra_commitment_package,
    );

    let mut reordered_commitment_package = minimal_collective_setup_package();
    reordered_commitment_package["sameSecretConsistency"]["statementRecords"][0]
        ["constantCoefficientCommitmentRoots"]
        .as_array_mut()
        .expect("same-secret constant commitment roots")
        .swap(0, 1);
    assert_same_secret_anchor_commitment_set_mismatch(
        "reordered same-secret anchor commitments",
        reordered_commitment_package,
    );

    let mut duplicated_commitment_package = minimal_collective_setup_package();
    let duplicated_commitment =
        duplicated_commitment_package["sameSecretConsistency"]["statementRecords"][0]
            ["constantCoefficientCommitmentRoots"][0]
            .clone();
    duplicated_commitment_package["sameSecretConsistency"]["statementRecords"][0]["constantCoefficientCommitmentRoots"]
        [1] = duplicated_commitment;
    assert_same_secret_anchor_commitment_set_mismatch(
        "duplicated same-secret anchor commitment",
        duplicated_commitment_package,
    );

    let mut wrong_limb_commitment_package = minimal_collective_setup_package();
    wrong_limb_commitment_package["sameSecretConsistency"]["statementRecords"][0]["constantCoefficientCommitmentRoots"]
        [0]["rnsLimbIndex"] = serde_json::json!(1);
    assert_same_secret_anchor_commitment_set_mismatch(
        "wrong same-secret anchor commitment RNS limb index",
        wrong_limb_commitment_package,
    );
}

fn assert_same_secret_anchor_commitment_set_mismatch(
    case_label: &str,
    mut package: serde_json::Value,
) {
    rebind_collective_same_secret_statement_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_setup_package(package);

    assert_eq!(
        result["verifierStatus"], "refused",
        "{case_label}: unexpected verifier result: {result}"
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], "sameSecretConstantCommitmentRootMismatch",
        "{case_label}: unexpected refusal reason code: {result}"
    );
    assert!(
        result.get("acceptedSetupHandoff").is_none(),
        "{case_label}: refused same-secret anchor packages must not return an accepted setup handoff"
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
            "publicKeyShareSuccinctProofs",
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_same_secret_proof_container() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_same_secret_proof_container",
    );

    for (field_name, reason_code) in [
        ("proofRecords", "sameSecretProofRecordsMissing"),
        ("sameSecretProofSetRoot", "sameSecretProofSetRootMissing"),
    ] {
        let mut package = same_secret_proof_bearing_collective_setup_package();
        package["sameSecretProofs"]
            .as_object_mut()
            .expect("same-secret proof set")
            .remove(field_name);
        rebind_collective_setup_package_hash(&mut package);

        let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .expect("verification response");

        assert_eq!(result["verifierStatus"], "refused");
        assert_eq!(result["refusedObjects"][0]["reasonCode"], reason_code);
        assert_eq!(
            result["refusedObjects"][0]["objectPath"],
            format!("setupPackage.sameSecretProofs.{field_name}")
        );
        assert!(result["acceptedSetupHandoff"].is_null());
    }
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
            "publicKeyShareSuccinctProofs",
            "collectivePublicKey",
            "collectivePublicKeyRoot"
        ])
    );
}

#[test]
#[ignore = "manual accepted setup closure diagnostic"]
fn manual_accepted_setup_collective_setup_verifier_refuses_terminal_same_secret_statement_hash_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "manual_accepted_setup_collective_setup_verifier_refuses_terminal_same_secret_statement_hash_drift",
    );
    let (mut package, mut companions) = setup_package_with_transported_public_setup_companions();

    rebind_first_terminal_same_secret_proof_material_root_after_statement_hash_drift(
        &mut package,
        &mut companions.same_secret_proof_material,
        valid_hash('7'),
    );

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
        "sameSecretProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("statementHash must match the rebuilt anchor statement")
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

fn rebind_first_terminal_same_secret_proof_material_root_after_statement_hash_drift(
    package: &mut serde_json::Value,
    transported_same_secret_proof_material: &mut serde_json::Value,
    drifted_statement_hash: String,
) {
    let proof_record = &mut package["sameSecretProofs"]["proofRecords"][0];
    let old_proof_material_root = proof_record["proofMaterialRoot"]
        .as_str()
        .expect("same-secret proof material root")
        .to_string();
    proof_record["statementHash"] = serde_json::json!(drifted_statement_hash);

    let proof_material = &mut transported_same_secret_proof_material["proofMaterials"][0];
    let chunks = proof_material["chunks"]
        .as_array()
        .expect("same-secret proof material chunks")
        .iter()
        .map(|chunk| {
            decode_hex(
                chunk["bytesHex"]
                    .as_str()
                    .expect("same-secret proof chunk bytes"),
            )
            .expect("same-secret proof chunk bytes")
        })
        .collect::<Vec<_>>();
    let transport_hashes = setup_proof_material_transport_hashes(
        "same-secret-linkage-anchor",
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )
    .expect("same-secret proof transport hashes");
    let new_proof_material_root =
        same_secret_anchor_proof_material_root(proof_record, &transport_hashes)
            .expect("same-secret proof material root");
    proof_record["proofMaterialRoot"] = serde_json::json!(new_proof_material_root.clone());
    proof_material["proofMaterialRoot"] = serde_json::json!(new_proof_material_root.clone());

    let transported_objects = package["setupTransportCertificate"]["transportedObjects"]
        .as_array_mut()
        .expect("setup transport certificate objects");
    let matching_object = transported_objects
        .iter_mut()
        .find(|transported_object| {
            transported_object["objectName"].as_str() == Some("sameSecretProofMaterial")
                && transported_object["objectRoot"].as_str()
                    == Some(old_proof_material_root.as_str())
        })
        .expect("same-secret proof material transport certificate object");
    matching_object["objectRoot"] = serde_json::json!(new_proof_material_root);
    let certificate_hash =
        rebind_setup_transport_certificate(&mut package["setupTransportCertificate"]);
    package["setupTransportCertificateHash"] = serde_json::json!(certificate_hash);

    rebind_same_secret_proof_record_root(package, 0);
    rebind_collective_same_secret_proof_roots(package);
    rebind_collective_same_secret_proof_set_root(package);
    rebind_collective_setup_package_hash(package);
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
    let package = same_secret_proof_bearing_collective_setup_package();

    let mut noncanonical_claim_package = package.clone();
    mutate_first_same_secret_proof_bytes_and_rebind(
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
        "sameSecretProofVerificationFailed"
    );

    let mut low_degree_shape_package = package;
    let ring_degree = low_degree_shape_package["sameSecretProofs"]["proofRecords"][0]["ringDegree"]
        .as_u64()
        .expect("same-secret proof ring degree") as usize;
    let same_secret_error_column_count = 0;
    let same_secret_linkage_commitment_count = DATA_PRIMES.len();
    mutate_first_same_secret_proof_bytes_and_rebind(&mut low_degree_shape_package, |proof_bytes| {
        set_first_limb_low_degree_fold_count_to_wrong_value(
            proof_bytes,
            ring_degree,
            same_secret_error_column_count,
            same_secret_linkage_commitment_count,
        );
    });
    let low_degree_shape_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": low_degree_shape_package,
        }))
        .expect("verification response");

    assert_eq!(low_degree_shape_result["verifierStatus"], "refused");
    assert_eq!(
        low_degree_shape_result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );
    assert!(
        low_degree_shape_result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("low-degree committed fold count does not match the statement")
    );
    assert!(low_degree_shape_result["acceptedSetupHandoff"].is_null());
}

fn mutate_first_same_secret_proof_bytes_and_rebind(
    package: &mut serde_json::Value,
    mutate_proof_bytes: impl FnOnce(&mut [u8]),
) {
    let proof_record = &mut package["sameSecretProofs"]["proofRecords"][0];
    let mut proof_bytes = decode_hex(
        proof_record["proofBytesHex"]
            .as_str()
            .expect("embedded proof bytes"),
    )
    .expect("proof bytes");
    mutate_proof_bytes(&mut proof_bytes);
    proof_record["proofBytesHex"] = serde_json::json!(to_hex(&proof_bytes));
    proof_record["proofBytesHash"] = serde_json::json!(
        crate::bgv::setup::trustee_evaluation_key_proof::same_secret_anchor_proof_bytes_hash(
            &proof_bytes
        )
    );
    proof_record["proofSizeBytes"] = serde_json::json!(proof_bytes.len());
    rebind_same_secret_proof_record_root(package, 0);
    rebind_collective_same_secret_proof_roots(package);
    rebind_collective_same_secret_proof_set_root(package);
    rebind_collective_setup_package_hash(package);
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
