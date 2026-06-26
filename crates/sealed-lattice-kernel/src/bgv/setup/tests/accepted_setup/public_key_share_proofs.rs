use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_public_key_share_statements() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_public_key_share_statements",
    );
    assert_minimal_collective_setup_package_refused(
        "wrong public-key share public-a polynomial root",
        |package| {
            package["publicKeyShares"]["shareRecords"][0]["publicAPolynomialRoot"] =
                serde_json::json!(valid_hash('8'));
            rebind_collective_public_key_share_roots(package);
        },
        "publicKeyShareCommonBindingMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong public-key share proof same-secret statement binding",
        |package| {
            package["publicKeyShareProofs"]["proofRecords"][0]["sameSecretStatementRoot"] =
                serde_json::json!(valid_hash('9'));
            rebind_collective_public_key_share_proof_roots(package);
        },
        "publicKeyShareProofBindingMismatch",
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_missing_dependent_public_key_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_missing_dependent_public_key_proofs",
    );

    let mut missing_statement_proofs_package =
        public_key_share_succinct_proof_bearing_collective_setup_package();
    missing_statement_proofs_package
        .as_object_mut()
        .expect("setup package")
        .remove("publicKeyShareProofs");
    rebind_collective_setup_package_hash(&mut missing_statement_proofs_package);

    let missing_statement_proofs_result = verify_collective_bgv_setup_package(
        &missing_statement_proofs_package,
        &serde_json::json!({}),
    )
    .expect("verification response");

    assert_eq!(missing_statement_proofs_result["verifierStatus"], "refused");
    assert_eq!(
        missing_statement_proofs_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareProofsMissing"
    );
    assert!(missing_statement_proofs_result["acceptedSetupHandoff"].is_null());

    let mut missing_succinct_proofs_package =
        collective_public_key_bearing_collective_setup_package();
    missing_succinct_proofs_package
        .as_object_mut()
        .expect("setup package")
        .remove("publicKeyShareSuccinctProofs");
    rebind_collective_setup_package_hash(&mut missing_succinct_proofs_package);

    let missing_succinct_proofs_result = verify_collective_bgv_setup_package(
        &missing_succinct_proofs_package,
        &serde_json::json!({}),
    )
    .expect("verification response");

    assert_eq!(missing_succinct_proofs_result["verifierStatus"], "refused");
    assert_eq!(
        missing_succinct_proofs_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofsMissing"
    );
    assert!(missing_succinct_proofs_result["acceptedSetupHandoff"].is_null());
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_proof_containers() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_proof_containers",
    );

    for (proof_set_name, field_name, reason_code) in [
        (
            "publicKeyShareProofs",
            "proofRecords",
            "publicKeyShareProofRecordsMissing",
        ),
        (
            "publicKeyShareProofs",
            "publicKeyShareProofSetRoot",
            "publicKeyShareProofSetRootMissing",
        ),
        (
            "publicKeyShareSuccinctProofs",
            "proofRecords",
            "publicKeyShareSuccinctProofRecordsMissing",
        ),
        (
            "publicKeyShareSuccinctProofs",
            "publicKeyShareSuccinctProofSetRoot",
            "publicKeyShareSuccinctProofSetRootMissing",
        ),
    ] {
        let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
        package[proof_set_name]
            .as_object_mut()
            .expect("public-key proof set")
            .remove(field_name);
        rebind_collective_setup_package_hash(&mut package);

        let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
            .expect("verification response");

        assert_eq!(result["verifierStatus"], "refused");
        assert_eq!(result["refusedObjects"][0]["reasonCode"], reason_code);
        assert_eq!(
            result["refusedObjects"][0]["objectPath"],
            format!("setupPackage.{proof_set_name}.{field_name}")
        );
        assert!(result["acceptedSetupHandoff"].is_null());
    }
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_extra_and_duplicate_public_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_extra_and_duplicate_public_proofs",
    );

    let mut extra_same_secret_proof_package = same_secret_proof_bearing_collective_setup_package();
    let duplicate_same_secret_proof_record =
        extra_same_secret_proof_package["sameSecretProofs"]["proofRecords"][0].clone();
    extra_same_secret_proof_package["sameSecretProofs"]["proofRecords"]
        .as_array_mut()
        .expect("same-secret proof records")
        .push(duplicate_same_secret_proof_record);
    rebind_collective_same_secret_proof_roots(&mut extra_same_secret_proof_package);
    rebind_collective_same_secret_proof_set_root(&mut extra_same_secret_proof_package);
    rebind_collective_setup_package_hash(&mut extra_same_secret_proof_package);
    assert_refuses_proof_object_variant(
        extra_same_secret_proof_package,
        "sameSecretProofCountMismatch",
        "setupPackage.sameSecretProofs.proofRecords",
        None,
    );

    let mut duplicate_same_secret_proof_package =
        same_secret_proof_bearing_collective_setup_package();
    duplicate_same_secret_proof_package["sameSecretProofs"]["proofRecords"][1] =
        duplicate_same_secret_proof_package["sameSecretProofs"]["proofRecords"][0].clone();
    rebind_same_secret_proof_record_root(&mut duplicate_same_secret_proof_package, 1);
    rebind_collective_same_secret_proof_roots(&mut duplicate_same_secret_proof_package);
    rebind_collective_same_secret_proof_set_root(&mut duplicate_same_secret_proof_package);
    rebind_collective_setup_package_hash(&mut duplicate_same_secret_proof_package);
    assert_refuses_proof_object_variant(
        duplicate_same_secret_proof_package,
        "sameSecretProofVerificationFailed",
        "setupPackage.sameSecretProofs.proofRecords",
        Some("distinct trustee roster positions"),
    );

    let mut extra_public_key_statement_proof_package =
        public_key_share_succinct_proof_bearing_collective_setup_package();
    let duplicate_public_key_statement_proof_record =
        extra_public_key_statement_proof_package["publicKeyShareProofs"]["proofRecords"][0].clone();
    extra_public_key_statement_proof_package["publicKeyShareProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key statement proof records")
        .push(duplicate_public_key_statement_proof_record);
    rebind_collective_public_key_share_proof_roots(&mut extra_public_key_statement_proof_package);
    rebind_collective_setup_package_hash(&mut extra_public_key_statement_proof_package);
    assert_refuses_proof_object_variant(
        extra_public_key_statement_proof_package,
        "publicKeyShareProofCountMismatch",
        "setupPackage.publicKeyShareProofs.proofRecords",
        None,
    );

    let mut duplicate_public_key_statement_proof_package =
        public_key_share_succinct_proof_bearing_collective_setup_package();
    duplicate_public_key_statement_proof_package["publicKeyShareProofs"]["proofRecords"][1] =
        duplicate_public_key_statement_proof_package["publicKeyShareProofs"]["proofRecords"][0]
            .clone();
    rebind_collective_public_key_share_proof_roots(
        &mut duplicate_public_key_statement_proof_package,
    );
    rebind_collective_setup_package_hash(&mut duplicate_public_key_statement_proof_package);
    assert_refuses_proof_object_variant(
        duplicate_public_key_statement_proof_package,
        "publicKeyShareProofDuplicate",
        "setupPackage.publicKeyShareProofs.proofRecords",
        Some("distinct trustee roster positions"),
    );

    let mut extra_public_key_succinct_proof_package =
        public_key_share_succinct_proof_bearing_collective_setup_package();
    let duplicate_public_key_succinct_proof_record =
        extra_public_key_succinct_proof_package["publicKeyShareSuccinctProofs"]["proofRecords"][0]
            .clone();
    extra_public_key_succinct_proof_package["publicKeyShareSuccinctProofs"]["proofRecords"]
        .as_array_mut()
        .expect("public-key succinct proof records")
        .push(duplicate_public_key_succinct_proof_record);
    rebind_collective_public_key_succinct_proof_roots(&mut extra_public_key_succinct_proof_package);
    rebind_collective_setup_package_hash(&mut extra_public_key_succinct_proof_package);
    assert_refuses_proof_object_variant(
        extra_public_key_succinct_proof_package,
        "publicKeyShareSuccinctProofCountMismatch",
        "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
        None,
    );

    let mut duplicate_public_key_succinct_proof_package =
        public_key_share_succinct_proof_bearing_collective_setup_package();
    duplicate_public_key_succinct_proof_package["publicKeyShareSuccinctProofs"]["proofRecords"]
        [1] =
        duplicate_public_key_succinct_proof_package["publicKeyShareSuccinctProofs"]["proofRecords"]
            [0]
        .clone();
    rebind_collective_public_key_succinct_proof_roots(
        &mut duplicate_public_key_succinct_proof_package,
    );
    rebind_collective_setup_package_hash(&mut duplicate_public_key_succinct_proof_package);
    assert_refuses_proof_object_variant(
        duplicate_public_key_succinct_proof_package,
        "publicKeyShareSuccinctProofVerificationFailed",
        "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
        Some("distinct trustee roster positions"),
    );
}

fn assert_refuses_proof_object_variant(
    package: serde_json::Value,
    reason_code: &str,
    object_path: &str,
    message_fragment: Option<&str>,
) {
    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(result["refusedObjects"][0]["reasonCode"], reason_code);
    assert_eq!(result["refusedObjects"][0]["objectPath"], object_path);
    if let Some(message_fragment) = message_fragment {
        assert!(
            result["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message")
                .contains(message_fragment)
        );
    }
    assert!(result["acceptedSetupHandoff"].is_null());
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
    append_transport_certificate_entries_from_material_set(
        &mut package,
        &transported_proof_material,
        "proofMaterials",
        "proofMaterialRoot",
        "publicKeyShareProofMaterial",
        "public-key-share-proof-material",
        DIRECT_TRANSPORT_CERTIFICATE_FIELDS,
    );
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedPublicKeyShareProofMaterial": transported_proof_material,
        }),
    )
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

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedPublicKeyShareProofMaterial": transported_proof_material,
        }),
    )
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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
    let public_key_share_material_set_root =
        package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"]
            .as_str()
            .expect("public-key share material set root")
            .to_string();
    append_setup_transport_certificate_object(
        &mut package,
        SetupTransportCertificateObjectFixture {
            object_name: "publicKeyShareMaterial",
            object_role: "public-key-share-material",
            object_root: public_key_share_material_set_root,
            byte_length: transported_public_key_share_material["totalByteLength"]
                .as_u64()
                .expect("transported material byte length"),
            full_object_hash: transported_public_key_share_material["fullObjectHash"]
                .as_str()
                .expect("transported material full object hash")
                .to_string(),
            chunk_root: transported_public_key_share_material["chunkRoot"]
                .as_str()
                .expect("transported material chunk root")
                .to_string(),
            chunk_hashes: transported_public_key_share_material["chunkHashes"]
                .as_array()
                .expect("transported material chunk hashes")
                .iter()
                .map(|chunk_hash| {
                    chunk_hash
                        .as_str()
                        .expect("transported material chunk hash")
                        .to_string()
                })
                .collect(),
        },
    );
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedPublicKeyShareMaterial": transported_public_key_share_material,
        }),
    )
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

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedPublicKeyShareMaterial": transported_public_key_share_material,
        }),
    )
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_material()
 {
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proofs()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proofs",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["proofBytesHash"] =
        serde_json::json!(valid_hash('a'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofsMissing"
    );
    assert_eq!(
        result["refusedObjects"][0]["objectPath"],
        "setupPackage.sameSecretProofs"
    );
    assert!(result["acceptedSetupHandoff"].is_null());
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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
    let proof_bytes_hex =
        package["publicKeyShareSuccinctProofs"]["proofRecords"][0]["proofBytesHex"]
            .as_str()
            .expect("public-key proof bytes hex");
    let mut proof_bytes = decode_hex(proof_bytes_hex).expect("proof bytes");
    set_first_masked_consistency_claim_to_noncanonical_modulus(&mut proof_bytes);
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_low_degree_shape_with_rebound_roots()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_public_key_succinct_low_degree_shape_with_rebound_roots",
    );
    let mut package = public_key_share_succinct_proof_bearing_collective_setup_package();
    let proof_record = &mut package["publicKeyShareSuccinctProofs"]["proofRecords"][0];
    let mut proof_bytes = decode_hex(
        proof_record["proofBytesHex"]
            .as_str()
            .expect("embedded public-key succinct proof bytes"),
    )
    .expect("public-key succinct proof bytes");
    let ring_degree = proof_record["ringDegree"].as_u64().expect("ring degree") as usize;
    set_first_limb_low_degree_fold_count_to_wrong_value(
        &mut proof_bytes,
        FirstLimbProofCodecLayout::public_key_share(ring_degree),
    );
    proof_record["proofBytesHex"] = serde_json::json!(to_hex(&proof_bytes));
    proof_record["proofBytesHash"] =
        serde_json::json!(public_key_share_succinct_proof_bytes_hash(&proof_bytes));
    proof_record["proofSizeBytes"] = serde_json::json!(proof_bytes.len());
    rebind_collective_public_key_succinct_proof_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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
            .contains("low-degree committed fold count does not match the statement")
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_collective_public_key_from_succinct_proof_bearing_shares()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_collective_public_key_from_succinct_proof_bearing_shares",
    );
    let package = collective_public_key_bearing_collective_setup_package();

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideAcceptedParameters");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideAcceptedRing"
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

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
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
            .contains("requires full-ring aggregate coefficients")
    );
}

#[test]
fn collective_setup_verifier_refuses_public_key_material_before_proof_verification() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_public_key_material_before_proof_verification",
    );
    assert_minimal_collective_setup_package_refused(
        "collective public-key root present before proof verification",
        |package| {
            package["collectivePublicKeyRoot"] = serde_json::json!(valid_hash('8'));
        },
        "publicKeyMaterialBeforeProofVerification",
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_package_root()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_package_root",
    );
    let mut missing_object_package = collective_public_key_bearing_collective_setup_package();
    missing_object_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKey");
    rebind_collective_setup_package_hash(&mut missing_object_package);

    let missing_object_result =
        verify_collective_bgv_setup_package(&missing_object_package, &serde_json::json!({}))
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

    let mut missing_root_package = collective_public_key_bearing_collective_setup_package();
    missing_root_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKeyRoot");
    rebind_collective_setup_package_hash(&mut missing_root_package);

    let missing_root_result =
        verify_collective_bgv_setup_package(&missing_root_package, &serde_json::json!({}))
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
