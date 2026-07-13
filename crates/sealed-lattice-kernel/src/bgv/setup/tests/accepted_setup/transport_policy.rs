use super::*;

#[test]
fn terminal_full_ring_gate_refuses_every_reduced_material_family() {
    for (package, expected_object_path) in [
        (
            serde_json::json!({
                "vssPublicCoefficientCommitmentSet": { "ringDegree": POLYNOMIAL_DEGREE },
                "publicKeyShareMaterial": { "ringDegree": 8 },
            }),
            "setupPackage.publicKeyShareMaterial.ringDegree",
        ),
        (
            serde_json::json!({
                "vssPublicCoefficientCommitmentSet": { "ringDegree": POLYNOMIAL_DEGREE },
                "publicKeyShareMaterial": { "ringDegree": POLYNOMIAL_DEGREE },
                "publicKeyShareSuccinctProofs": {
                    "proofRecords": [{ "ringDegree": POLYNOMIAL_DEGREE }],
                },
                "collectivePublicKey": { "ringDegree": POLYNOMIAL_DEGREE },
                "relinearizationKeyShareRounds": {
                    "roundOneRecords": [{ "ringDegree": POLYNOMIAL_DEGREE }],
                    "roundTwoRecords": [{ "ringDegree": 8 }],
                },
                "galoisKeyShareBatches": [{
                    "galoisKeyShareMaterialRecords": [{ "ringDegree": POLYNOMIAL_DEGREE }],
                }],
            }),
            "setupPackage.relinearizationKeyShareRounds.roundTwoRecords.ringDegree",
        ),
        (
            serde_json::json!({
                "vssPublicCoefficientCommitmentSet": { "ringDegree": 8 },
            }),
            "setupPackage.vssPublicCoefficientCommitmentSet.ringDegree",
        ),
    ] {
        let response = verify_full_ring_material(&package)
            .expect("full-ring verification")
            .expect("reduced material refusal");

        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            "setupMaterialOutsideAcceptedRing"
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            expected_object_path
        );
    }
}

#[test]
fn terminal_transport_policy_accepts_references_and_rejects_embedded_vectors() {
    let mut package = terminal_transport_policy_package_with_material_encodings(
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    );

    let response = verify_terminal_setup_transport_policy(&package, &serde_json::json!({}))
        .expect("terminal transport policy");

    assert!(response.is_none());
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
    key_switch_material_encoding: &str,
) -> serde_json::Value {
    let key_switch_record = serde_json::json!({
        "keySwitchMaterialEncoding": key_switch_material_encoding,
    });

    serde_json::json!({
        "publicKeyShareMaterial": {
            "materialEncoding": public_key_share_material_encoding,
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
            "publicEvaluationKeyMaterialRoot": valid_hash('1'),
        },
    })
}

#[test]
fn collective_setup_verifier_refuses_invalid_transport_certificates() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_invalid_transport_certificates",
    );
    assert_minimal_collective_setup_package_refused(
        "non-binary setup transport encoding",
        |package| {
            package["setupTransportCertificate"]["largeObjectEncoding"] = serde_json::json!("json");
        },
        "transportEncodingMismatch",
    );

    let mut fixture = descriptor_backed_vss_collective_setup_fixture();
    replace_setup_proof_material_transport_certificate_objects(
        &mut fixture.package,
        &serde_json::json!({ "proofMaterials": [] }),
        VSS_SHARE_LINKAGE_PROOF_TRANSPORT_CERTIFICATE_FIELDS,
    );
    rebind_collective_setup_package_hash(&mut fixture.package);

    let result = fixture.verify().expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportedObjectBindingMissing"
    );
}
