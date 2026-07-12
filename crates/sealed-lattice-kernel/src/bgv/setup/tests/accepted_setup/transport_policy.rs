use super::*;

#[test]
fn terminal_full_ring_gate_refuses_reduced_public_key_material() {
    let package = serde_json::json!({
        "vssPublicCoefficientCommitmentSet": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "publicKeyShareMaterial": {
            "ringDegree": 8,
        },
    });

    let response = verify_full_ring_material(&package)
        .expect("full-ring verification")
        .expect("reduced public-key material refusal");

    assert_eq!(response["isValid"], false);
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "setupMaterialOutsideAcceptedRing"
    );
    assert_eq!(
        response["refusedObjects"][0]["objectPath"],
        "setupPackage.publicKeyShareMaterial.ringDegree"
    );
}

#[test]
fn terminal_full_ring_gate_refuses_reduced_evaluation_key_records() {
    let package = serde_json::json!({
        "vssPublicCoefficientCommitmentSet": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "publicKeyShareMaterial": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "publicKeyShareSuccinctProofs": {
            "proofRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
        },
        "collectivePublicKey": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "relinearizationKeyShareRounds": {
            "roundOneRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
            "roundTwoRecords": [
                { "ringDegree": 8 }
            ],
        },
        "galoisKeyShareBatches": [
            {
                "galoisKeyShareMaterialRecords": [
                    { "ringDegree": POLYNOMIAL_DEGREE }
                ]
            }
        ],
    });

    let response = verify_full_ring_material(&package)
        .expect("full-ring verification")
        .expect("reduced evaluation-key proof refusal");

    assert_eq!(response["isValid"], false);
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "setupMaterialOutsideAcceptedRing"
    );
    assert_eq!(
        response["refusedObjects"][0]["objectPath"],
        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords.ringDegree"
    );
}

#[test]
fn terminal_transport_policy_accepts_binary_key_material_references() {
    let package = terminal_transport_policy_package_with_material_encodings(
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
        SETUP_PROOF_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    );

    let response = verify_terminal_setup_transport_policy(&package, &serde_json::json!({}))
        .expect("terminal transport policy");

    assert!(response.is_none());
}

#[test]
fn terminal_transport_policy_refuses_embedded_key_switch_component_vectors() {
    let mut package = terminal_transport_policy_package_with_material_encodings(
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
        SETUP_PROOF_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    );
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["keySwitchComponentVectors"] =
        serde_json::json!([]);

    let response = verify_terminal_setup_transport_policy(&package, &serde_json::json!({}))
        .expect("terminal transport policy")
        .expect("embedded key-switch component vector refusal");

    assert_eq!(response["isValid"], false);
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "terminalKeySwitchMaterialTransportRequired"
    );
}

fn terminal_transport_policy_package_with_material_encodings(
    public_key_share_material_encoding: &str,
    proof_material_encoding: &str,
    key_switch_material_encoding: &str,
) -> serde_json::Value {
    let proof_record = serde_json::json!({
        "proofBytesEncoding": proof_material_encoding,
    });
    let key_switch_record = serde_json::json!({
        "keySwitchMaterialEncoding": key_switch_material_encoding,
    });

    serde_json::json!({
        "publicKeyShareMaterial": {
            "materialEncoding": public_key_share_material_encoding,
        },
        "publicKeyShareSuccinctProofs": {
            "proofRecords": [
                proof_record.clone()
            ],
        },
        "trusteeEvaluationKeyProofs": {
            "proofRecords": [
                proof_record
            ],
        },
        "relinearizationKeyShareRounds": {
            "roundOneRecords": [
                key_switch_record.clone()
            ],
            "roundTwoRecords": [
                key_switch_record.clone()
            ],
        },
        "galoisKeyShareBatches": [
            {
                "galoisKeyShareMaterialRecords": [
                    key_switch_record
                ],
            }
        ],
        "evaluationKeys": {
            "publicEvaluationKeyMaterialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "publicEvaluationKeyMaterialRoot": valid_hash('1'),
        },
    })
}

#[test]
fn collective_setup_verifier_refuses_non_binary_setup_transport() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_non_binary_setup_transport");
    assert_minimal_collective_setup_package_refused(
        "non-binary setup transport encoding",
        |package| {
            package["setupTransportCertificate"]["largeObjectEncoding"] = serde_json::json!("json");
        },
        "transportEncodingMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_vss_transport_missing_certificate_object() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_vss_transport_missing_certificate_object",
    );
    let mut fixture = descriptor_backed_vss_collective_setup_fixture();
    replace_setup_proof_material_transport_certificate_objects(
        &mut fixture.package,
        &serde_json::json!({ "proofMaterials": [] }),
        VSS_SHARE_LINKAGE_PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    );
    rebind_collective_setup_package_hash(&mut fixture.package);

    let result =
        verify_collective_bgv_setup_package(&fixture.package, &fixture.verification_request)
            .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportedObjectBindingMissing"
    );
}

#[test]
fn terminal_full_ring_gate_refuses_reduced_vss_material() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("terminal_full_ring_gate_refuses_reduced_vss_material");
    let package = serde_json::json!({
        "vssPublicCoefficientCommitmentSet": {
            "ringDegree": 8,
        },
    });

    let response = verify_full_ring_material(&package)
        .expect("full-ring verification")
        .expect("reduced VSS material refusal");

    assert_eq!(response["isValid"], false);
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "setupMaterialOutsideAcceptedRing"
    );
    assert_eq!(
        response["refusedObjects"][0]["objectPath"],
        "setupPackage.vssPublicCoefficientCommitmentSet.ringDegree"
    );
}
