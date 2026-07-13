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
        "wrong public-key share proof share-root binding",
        |package| {
            package["publicKeyShareProofs"]["proofRecords"][0]["publicKeyShareRoot"] =
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
    let fixture = public_key_share_succinct_proof_bearing_collective_setup_fixture();

    let result = fixture.verify().expect("verification response");

    assert_eq!(result["isValid"], false);
    let refused_objects = result["refusedObjects"]
        .as_array()
        .expect("missing public-key objects must be typed refusals");
    assert_eq!(refused_objects.len(), 2);
    assert!(refused_objects.iter().all(|refusal| {
        refusal["reasonCode"] == "setupObjectMissing"
            && matches!(
                refusal["objectPath"].as_str(),
                Some("setupPackage.collectivePublicKey")
                    | Some("setupPackage.collectivePublicKeyRoot")
            )
    }));
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_missing_dependent_public_key_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_missing_dependent_public_key_proofs",
    );

    let missing_statement_proofs_fixture =
        public_key_share_succinct_proof_bearing_collective_setup_fixture();
    let mut missing_statement_proofs_package = missing_statement_proofs_fixture.package.clone();
    missing_statement_proofs_package
        .as_object_mut()
        .expect("setup package")
        .remove("publicKeyShareProofs");
    rebind_collective_setup_package_hash(&mut missing_statement_proofs_package);

    let missing_statement_proofs_result = missing_statement_proofs_fixture
        .verify_values(
            &missing_statement_proofs_package,
            &missing_statement_proofs_fixture.verification_request,
        )
        .expect("verification response");

    assert_eq!(missing_statement_proofs_result["isValid"], false);
    assert_eq!(
        missing_statement_proofs_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareProofsMissing"
    );
    let mut missing_succinct_proofs_fixture =
        collective_public_key_bearing_collective_setup_fixture();
    let mut missing_succinct_proofs_package = missing_succinct_proofs_fixture.package.clone();
    missing_succinct_proofs_package
        .as_object_mut()
        .expect("setup package")
        .remove("publicKeyShareSuccinctProofs");
    remove_public_key_share_proof_transport(
        &mut missing_succinct_proofs_package,
        &mut missing_succinct_proofs_fixture.verification_request,
    );
    rebind_collective_setup_package_hash(&mut missing_succinct_proofs_package);

    let missing_succinct_proofs_result = missing_succinct_proofs_fixture
        .verify_values(
            &missing_succinct_proofs_package,
            &missing_succinct_proofs_fixture.verification_request,
        )
        .expect("verification response");

    assert_eq!(missing_succinct_proofs_result["isValid"], false);
    assert_eq!(
        missing_succinct_proofs_result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareSuccinctProofsMissing"
    );
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
        let fixture = public_key_share_succinct_proof_bearing_collective_setup_fixture();
        let mut package = fixture.package.clone();
        package[proof_set_name]
            .as_object_mut()
            .expect("public-key proof set")
            .remove(field_name);
        let mut verification_request = fixture.verification_request.clone();
        if proof_set_name == "publicKeyShareSuccinctProofs" && field_name == "proofRecords" {
            remove_public_key_share_proof_transport(&mut package, &mut verification_request);
        }
        rebind_collective_setup_package_hash(&mut package);

        let result = fixture
            .verify_values(&package, &verification_request)
            .expect("verification response");

        assert_eq!(result["isValid"], false);
        assert_eq!(result["refusedObjects"][0]["reasonCode"], reason_code);
        assert_eq!(
            result["refusedObjects"][0]["objectPath"],
            format!("setupPackage.{proof_set_name}.{field_name}")
        );
    }
}

fn remove_public_key_share_proof_transport(
    package: &mut serde_json::Value,
    verification_request: &mut serde_json::Value,
) {
    verification_request
        .as_object_mut()
        .expect("setup verification request")
        .remove("transportedPublicKeyShareProofMaterial");
    replace_setup_proof_material_transport_certificate_objects(
        package,
        &serde_json::json!({ "proofMaterials": [] }),
        PUBLIC_KEY_SHARE_PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_material",
    );
    let fixture = public_key_share_succinct_proof_bearing_collective_setup_fixture();
    let mut package = fixture.package.clone();
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

    let result = fixture
        .verify_values(&package, &fixture.verification_request)
        .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicKeyShareMaterialVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proof_byte_content()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proof_byte_content",
    );
    let fixture = public_key_share_succinct_proof_bearing_collective_setup_fixture();
    let mut package = fixture.package.clone();
    let mut verification_request = fixture.verification_request.clone();
    // The descriptor, hashes, certificate, and package roots below are rebound,
    // so these deliberately malformed proof bytes reach the semantic decoder.
    // The fixture itself retains only opaque verifier bindings, never a second
    // copy of every trustee's proof merely to support this negative test.
    let proof_bytes = vec![0x53, 0x4c, 0x50, 0x4b, 0x01, 0xff, 0x00];
    let proof_bytes_hash =
        crate::bgv::setup::trustee_evaluation_key_proof::public_key_share_succinct_proof_bytes_hash(
            &proof_bytes,
        );
    let proof_record = &mut package["publicKeyShareSuccinctProofs"]["proofRecords"][0];
    proof_record["proofBytesHash"] = serde_json::json!(&proof_bytes_hash);
    let proof_material_root =
        crate::bgv::setup::accepted_setup::public_key_share_succinct_proof_material_root(
            proof_record,
        )
        .expect("tampered public-key proof material root");
    proof_record["proofMaterialRoot"] = serde_json::json!(&proof_material_root);
    rebind_collective_public_key_succinct_proof_roots(&mut package);

    let transport_hashes = canonical_setup_proof_material_transport_accounting(
        crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY,
        &proof_bytes,
    )
    .expect("tampered public-key proof transport hashes");
    let transported_proof_material =
        &mut verification_request["transportedPublicKeyShareProofMaterial"]["proofMaterials"][0];
    transported_proof_material["proofMaterialRoot"] = serde_json::json!(&proof_material_root);
    transported_proof_material["chunkCount"] =
        serde_json::json!(transport_hashes.chunk_hashes.len());
    transported_proof_material["totalByteLength"] =
        serde_json::json!(transport_hashes.total_byte_length);
    transported_proof_material["fullObjectHash"] =
        serde_json::json!(transport_hashes.full_object_hash);
    transported_proof_material["chunkRoot"] = serde_json::json!(transport_hashes.chunk_root);
    transported_proof_material["chunkHashes"] = serde_json::json!(transport_hashes.chunk_hashes);
    authenticate_setup_proof_material_stream_for_test(
        crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY,
        &proof_material_root,
        &proof_bytes,
    )
    .expect("authenticate tampered public-key proof material stream");
    replace_setup_proof_material_transport_certificate_objects(
        &mut package,
        &verification_request["transportedPublicKeyShareProofMaterial"],
        PUBLIC_KEY_SHARE_PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    );
    rebind_collective_setup_package_hash(&mut package);

    let result = fixture
        .verify_values(&package, &verification_request)
        .expect("verification response");

    assert_eq!(result["isValid"], false);
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
    let fixture = collective_public_key_bearing_collective_setup_fixture();

    let result = fixture.verify().expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupMaterialOutsideAcceptedRing"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_collective_public_key_aggregate()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_collective_public_key_aggregate",
    );
    let fixture = collective_public_key_bearing_collective_setup_fixture();
    let mut package = fixture.package.clone();
    let coefficients_hex =
        package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientsLeHex"]
            .as_str()
            .expect("aggregate coefficients");
    let mut coefficients = coefficient_vector_from_le_hex(
        coefficients_hex,
        public_coefficient_commitment_ring_degree_from_fixture_package(&package),
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

    let result = fixture
        .verify_values(&package, &fixture.verification_request)
        .expect("verification response");

    assert_eq!(result["isValid"], false);
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
    let fixture = collective_public_key_bearing_collective_setup_fixture();

    let error = match accepted_setup_collective_public_key_from_package(&fixture.package) {
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
    let missing_object_fixture = collective_public_key_bearing_collective_setup_fixture();
    let mut missing_object_package = missing_object_fixture.package.clone();
    missing_object_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKey");
    rebind_collective_setup_package_hash(&mut missing_object_package);

    let missing_object_result = missing_object_fixture
        .verify_values(
            &missing_object_package,
            &missing_object_fixture.verification_request,
        )
        .expect("verification response");

    assert_eq!(missing_object_result["isValid"], false);
    assert_eq!(
        missing_object_result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
    assert_eq!(
        missing_object_result["refusedObjects"][0]["objectPath"],
        "setupPackage.collectivePublicKey"
    );

    let missing_root_fixture = collective_public_key_bearing_collective_setup_fixture();
    let mut missing_root_package = missing_root_fixture.package.clone();
    missing_root_package
        .as_object_mut()
        .expect("setup package")
        .remove("collectivePublicKeyRoot");
    rebind_collective_setup_package_hash(&mut missing_root_package);

    let missing_root_result = missing_root_fixture
        .verify_values(
            &missing_root_package,
            &missing_root_fixture.verification_request,
        )
        .expect("verification response");

    assert_eq!(missing_root_result["isValid"], false);
    assert_eq!(
        missing_root_result["refusedObjects"][0]["reasonCode"],
        "publicKeyMaterialBeforeProofVerification"
    );
    assert_eq!(
        missing_root_result["refusedObjects"][0]["objectPath"],
        "setupPackage.collectivePublicKeyRoot"
    );
}
