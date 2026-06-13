use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_public_key_share_statements() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_public_key_share_statements",
    );
    let mut wrong_public_a_package = minimal_collective_setup_package();
    wrong_public_a_package["publicKeyShares"]["shareRecords"][0]["publicAPolynomialRoot"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_public_key_share_roots(&mut wrong_public_a_package);
    rebind_collective_setup_package_hash(&mut wrong_public_a_package);

    let wrong_public_a_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_public_a_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_public_a_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_public_a_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareCommonBindingMismatch"
    );

    let mut wrong_proof_binding_package = minimal_collective_setup_package();
    wrong_proof_binding_package["publicKeyShareProofs"]["proofRecords"][0]["sameSecretStatementRoot"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_public_key_share_proof_roots(&mut wrong_proof_binding_package);
    rebind_collective_setup_package_hash(&mut wrong_proof_binding_package);

    let wrong_proof_binding_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_proof_binding_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_proof_binding_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_proof_binding_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareProofBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_succinct_proofs_before_collective_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_succinct_proofs_before_collective_key_material",
    );
    let package = public_key_share_succinct_proof_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["collectivePublicKey", "collectivePublicKeyRoot"])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_succinct_proofs_before_missing_terminal_objects()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_succinct_proofs_before_missing_terminal_objects",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["proofModelStatus"] =
        serde_json::json!("weakened-public-key-share-proof-model");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofSetProfileMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_succinct_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_succinct_proofs_from_transported_proof_material",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    let transported_proof_material =
        move_public_key_share_succinct_proof_bytes_to_transport(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["collectivePublicKey", "collectivePublicKeyRoot"])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_succinct_proof_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_succinct_proof_chunk",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    let mut transported_proof_material =
        move_public_key_share_succinct_proof_bytes_to_transport(&mut package);
    transported_proof_material["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!("00");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicKeyShareProofMaterial": transported_proof_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_reports_pending_transported_public_key_share_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_reports_pending_transported_public_key_share_material",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    move_public_key_share_material_to_transport(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["transportedPublicKeyShareMaterial"])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_material_from_transport()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_public_key_share_material_from_transport",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    let transported_public_key_share_material =
        move_public_key_share_material_to_transport(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicKeyShareMaterial": transported_public_key_share_material,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["collectivePublicKey", "collectivePublicKeyRoot"])
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_public_key_share_material",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    let mut transported_public_key_share_material =
        move_public_key_share_material_to_transport(&mut package);
    transported_public_key_share_material["chunks"][0]["bytesHex"] = serde_json::json!("00");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicKeyShareMaterial": transported_public_key_share_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_material",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    let coefficients_hex = package["publicKeyShareMaterial"]["shareMaterialRecords"][0]
        ["shareCoefficientVectorsByLimb"][0]["coefficientsLeHex"]
        .as_str()
        .expect("coefficient hex");
    let replacement_prefix = if coefficients_hex.starts_with("00") {
        "01"
    } else {
        "00"
    };
    let tampered_hex = format!("{replacement_prefix}{}", &coefficients_hex[2..]);
    package["publicKeyShareMaterial"]["shareMaterialRecords"][0]["shareCoefficientVectorsByLimb"]
        [0]["coefficientsLeHex"] = serde_json::json!(tampered_hex);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proofs",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["proofBytesHash"] =
        serde_json::json!(valid_hash('a'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_statement_hash()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_statement_hash",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["statementHash"] =
        serde_json::json!(valid_hash('f'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("statementHash")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_same_secret_proofs_before_public_key_succinct_proofs()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_same_secret_proofs_before_public_key_succinct_proofs",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package")
        .remove("sameSecretProofs");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(result["currentPhase"], "proofVerification");
    assert_eq!(
        result["missingObjects"][0],
        serde_json::json!("sameSecretProofs")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_proof_set_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_proof_set_drift",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["sameSecretProofSetRoot"] =
        serde_json::json!(valid_hash('b'));
    rebind_collective_public_key_succinct_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofSetBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_family_root_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_family_root_drift",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('d'));
    rebind_collective_public_key_succinct_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofSetBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_proof_root_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_proof_root_drift",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["sameSecretProofRoot"] =
        serde_json::json!(valid_hash('c'));
    rebind_collective_public_key_succinct_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_family_record_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_same_secret_family_record_drift",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["sameSecretProofFamilyBindingRoot"] =
        serde_json::json!(valid_hash('e'));
    rebind_collective_public_key_succinct_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proof_byte_content()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proof_byte_content",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    let proof_bytes_hex = package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["proofBytesHex"]
        .as_str()
        .expect("public-key proof bytes hex");
    let mut proof_bytes = decode_hex(proof_bytes_hex).expect("proof bytes");
    let last_byte = proof_bytes.last_mut().expect("proof bytes are non-empty");
    *last_byte ^= 1;
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["proofBytesHex"] =
        serde_json::json!(to_hex(&proof_bytes));
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["proofBytesHash"] = serde_json::json!(
        crate::bgv::setup::trustee_evaluation_key_proof::public_key_share_succinct_proof_bytes_hash(
            &proof_bytes
        )
    );
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["proofSizeBytes"] =
        serde_json::json!(proof_bytes.len());
    rebind_collective_public_key_succinct_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_collective_public_key_from_succinct_proof_bearing_shares()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_collective_public_key_from_succinct_proof_bearing_shares",
    );
    let package = collective_public_key_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_collective_public_key_aggregate()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_collective_public_key_aggregate",
    );
    let mut package = collective_public_key_bearing_collective_setup_package();
    let coefficients_hex =
        package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientsLeHex"]
            .as_str()
            .expect("aggregate coefficients");
    let mut coefficients = coefficient_vector_from_le_hex(
        coefficients_hex,
        same_secret_constant_commitments_from_fixture_package(&package, 0)[0].ring_degree,
        "aggregate coefficient width",
    )
    .expect("aggregate coefficients decode");
    coefficients[0] = add_mod(coefficients[0], 1, DATA_PRIMES[0]).expect("tamper coefficient");
    package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientsLeHex"] =
        serde_json::json!(coefficient_vector_le_hex(&coefficients));
    package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientVectorHash512"] =
        serde_json::json!(public_key_share_coefficient_vector_hash(&coefficients));
    rebind_collective_public_key_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "collectivePublicKeyVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_key_loader_refuses_reduced_ring_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_key_loader_refuses_reduced_ring_material",
    );
    let package = collective_public_key_bearing_collective_setup_package();

    let error = match accepted_setup_collective_public_key_from_package(&package) {
        Ok(_) => panic!("reduced-ring material must not become a runtime public key"),
        Err(error) => error,
    };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring aggregate coefficients")
    );
}

#[test]
fn collective_setup_verifier_refuses_public_key_material_before_proof_verification() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_public_key_material_before_proof_verification",
    );
    let mut package = minimal_collective_setup_package();
    package["collectivePublicKeyRoot"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_package_root()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_package_root",
    );
    let base_package = collective_public_key_bearing_collective_setup_package();

    let mut missing_object_package = base_package.clone();
    missing_object_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKey");
    rebind_collective_setup_package_hash(&mut missing_object_package);

    let missing_object_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": missing_object_package,
        }))
        .expect("verification response");

    assert_eq!(missing_object_result["verifierStatus"], "refused");
    assert_eq!(
        missing_object_result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
    assert_eq!(
        missing_object_result["refusedObjects"][0]["objectPath"],
        "setupPackage.collectivePublicKey"
    );

    let mut missing_root_package = base_package;
    missing_root_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKeyRoot");
    rebind_collective_setup_package_hash(&mut missing_root_package);

    let missing_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": missing_root_package,
        }))
        .expect("verification response");

    assert_eq!(missing_root_result["verifierStatus"], "refused");
    assert_eq!(
        missing_root_result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
    assert_eq!(
        missing_root_result["refusedObjects"][0]["objectPath"],
        "setupPackage.collectivePublicKeyRoot"
    );
}
