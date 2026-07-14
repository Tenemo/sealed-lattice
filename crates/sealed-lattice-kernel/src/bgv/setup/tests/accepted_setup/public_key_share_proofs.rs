use super::*;

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
    assert_eq!(result["refusalReason"], "missingPrerequisite");
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_missing_succinct_public_key_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_missing_succinct_public_key_proofs",
    );
    let missing_succinct_proofs_fixture = collective_public_key_bearing_collective_setup_fixture();
    let mut missing_succinct_proofs_package = missing_succinct_proofs_fixture.package.clone();
    missing_succinct_proofs_package
        .as_object_mut()
        .expect("setup package")
        .remove("publicKeyShareSuccinctProofs");
    rebind_collective_setup_package_hash(&mut missing_succinct_proofs_package);

    let missing_succinct_proofs_result = missing_succinct_proofs_fixture
        .verify_values(
            &missing_succinct_proofs_package,
            &missing_succinct_proofs_fixture.verification_request,
        )
        .expect("verification response");

    assert_eq!(missing_succinct_proofs_result["isValid"], false);
    assert_eq!(
        missing_succinct_proofs_result["refusalReason"],
        "invalidProof"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_proof_containers() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_public_key_proof_containers",
    );

    for (proof_set_name, field_name) in [
        ("publicKeyShareSuccinctProofs", "proofRecords"),
        (
            "publicKeyShareSuccinctProofs",
            "publicKeyShareSuccinctProofSetRoot",
        ),
    ] {
        let fixture = public_key_share_succinct_proof_bearing_collective_setup_fixture();
        let mut package = fixture.package.clone();
        package[proof_set_name]
            .as_object_mut()
            .expect("public-key proof set")
            .remove(field_name);
        let verification_request = fixture.verification_request.clone();
        rebind_collective_setup_package_hash(&mut package);

        let result = fixture
            .verify_values(&package, &verification_request)
            .expect("verification response");

        assert_eq!(result["isValid"], false);
        assert_eq!(result["refusalReason"], "invalidProof");
    }
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
    assert_eq!(result["refusalReason"], "malformedEncoding");
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proof_byte_content()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_key_share_succinct_proof_byte_content",
    );
    let fixture = public_key_share_succinct_proof_bearing_collective_setup_fixture();
    let proof_binding_session = fixture.begin_proof_binding_session();
    let mut package = fixture.package.clone();
    let verification_request = fixture.verification_request.clone();
    // The descriptor, hashes, and package roots below are rebound,
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

    authenticate_setup_proof_material_stream_in_session_for_test(
        crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY,
        &proof_material_root,
        &proof_bytes,
        proof_binding_session,
    )
    .expect("authenticate tampered public-key proof material stream");
    rebind_collective_setup_package_hash(&mut package);

    let result = fixture
        .verify_values_in_session(&package, &verification_request, proof_binding_session)
        .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(result["refusalReason"], "invalidProof");
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
    assert_eq!(result["refusalReason"], "missingPrerequisite");
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
        vss_commitment_ring_degree_from_fixture_package(&package),
        "aggregate coefficient width",
    )
    .expect("aggregate coefficients decode");
    coefficients[0] = add_mod(coefficients[0], 1, DATA_PRIMES[0]).expect("tamper coefficient");
    package["collectivePublicKey"]["aggregateCoefficientVectorsByLimb"][0]["coefficientsLeHex"] =
        serde_json::json!(coefficient_vector_le_hex(&coefficients));
    rebind_collective_public_key_root(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = fixture
        .verify_values(&package, &fixture.verification_request)
        .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(result["refusalReason"], "malformedEncoding");
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_nested_root() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_collective_public_key_and_nested_root",
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
        missing_object_result["refusalReason"],
        "missingPrerequisite"
    );

    let missing_root_fixture = collective_public_key_bearing_collective_setup_fixture();
    let mut missing_root_package = missing_root_fixture.package.clone();
    missing_root_package["collectivePublicKey"]
        .as_object_mut()
        .expect("collective public key")
        .remove("collectivePublicKeyRoot");
    rebind_collective_setup_package_hash(&mut missing_root_package);

    let missing_root_result = missing_root_fixture
        .verify_values(
            &missing_root_package,
            &missing_root_fixture.verification_request,
        )
        .expect("verification response");

    assert_eq!(missing_root_result["isValid"], false);
    assert_eq!(missing_root_result["refusalReason"], "missingPrerequisite");
}
