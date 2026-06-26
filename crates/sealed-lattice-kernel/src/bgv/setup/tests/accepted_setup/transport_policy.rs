use super::*;

#[test]
fn terminal_profile_ring_gate_refuses_reduced_public_key_material() {
    let package = serde_json::json!({
        "vssCoefficientCommitmentMaterial": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "sameSecretProofs": {
            "proofRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
        },
        "publicKeyShareMaterial": {
            "ringDegree": 8,
        },
    });

    let response = verify_profile_ring_material(&package)
        .expect("profile-ring verification")
        .expect("reduced public-key material refusal");

    assert_eq!(response["verifierStatus"], "outsideProfile");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    assert_eq!(
        response["refusedObjects"][0]["objectPath"],
        "setupPackage.publicKeyShareMaterial.ringDegree"
    );
}

#[test]
fn terminal_profile_ring_gate_refuses_reduced_evaluation_key_records() {
    let package = serde_json::json!({
        "vssCoefficientCommitmentMaterial": {
            "ringDegree": POLYNOMIAL_DEGREE,
        },
        "sameSecretProofs": {
            "proofRecords": [
                { "ringDegree": POLYNOMIAL_DEGREE }
            ],
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

    let response = verify_profile_ring_material(&package)
        .expect("profile-ring verification")
        .expect("reduced evaluation-key proof refusal");

    assert_eq!(response["verifierStatus"], "outsideProfile");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    assert_eq!(
        response["refusedObjects"][0]["objectPath"],
        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords.ringDegree"
    );
}

#[test]
fn terminal_transport_policy_refuses_embedded_setup_material() {
    let package = terminal_transport_policy_package_with_material_encodings(
        "full-public-setup-commitment-values",
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
        SETUP_PROOF_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    );

    let response = verify_terminal_setup_transport_policy(&package, &serde_json::json!({}))
        .expect("terminal transport policy")
        .expect("embedded VSS material refusal");

    assert_eq!(response["verifierStatus"], "refused");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "terminalVssMaterialTransportRequired"
    );
}

#[test]
fn terminal_transport_policy_accepts_binary_setup_and_key_material_references() {
    let package = terminal_transport_policy_package_with_material_encodings(
        "binary-chunked-full-public-setup-commitment-values",
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
        SETUP_PROOF_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    );
    let request = serde_json::json!({
        "transportedVssCoefficientCommitmentMaterial": {
            "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
            "objectVersion": 1,
            "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
            "chunkSizeBytes": 1_048_576,
            "chunkCount": 1,
            "totalByteLength": 64,
            "fullObjectHash": valid_hash('5'),
            "chunkHashes": [valid_hash('6')],
            "chunkRoot": valid_hash('7'),
        },
        "verifiedVssCoefficientCommitmentMaterial": {
            "objectType": "VerifiedVssCoefficientCommitmentMaterial",
            "objectVersion": 1,
            "verifiedMaterialId": "terminal-policy-test-material",
        },
    });

    let response = verify_terminal_setup_transport_policy(&package, &request)
        .expect("terminal transport policy");

    assert!(response.is_none());
}

#[test]
fn terminal_transport_policy_refuses_raw_vss_chunk_sidecar() {
    let package = terminal_transport_policy_package_with_material_encodings(
        "binary-chunked-full-public-setup-commitment-values",
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
        SETUP_PROOF_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    );
    let request = serde_json::json!({
        "transportedVssCoefficientCommitmentMaterial": {
            "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
            "objectVersion": 1,
            "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
            "chunkSizeBytes": 1_048_576,
            "chunkCount": 1,
            "totalByteLength": 64,
            "fullObjectHash": valid_hash('5'),
            "chunkHashes": [valid_hash('6')],
            "chunkRoot": valid_hash('7'),
            "chunks": [
                {
                    "chunkIndex": 0,
                    "bytesHex": "00",
                }
            ],
        },
        "verifiedVssCoefficientCommitmentMaterial": {
            "objectType": "VerifiedVssCoefficientCommitmentMaterial",
            "objectVersion": 1,
            "verifiedMaterialId": "terminal-policy-test-material",
        },
    });

    let response = verify_terminal_setup_transport_policy(&package, &request)
        .expect("terminal transport policy")
        .expect("raw VSS chunk sidecar refusal");

    assert_eq!(response["verifierStatus"], "refused");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "terminalVssMaterialHandleRequired"
    );
}

#[test]
fn terminal_transport_policy_reports_missing_stream_verified_vss_handle() {
    let package = terminal_transport_policy_package_with_material_encodings(
        "binary-chunked-full-public-setup-commitment-values",
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
        SETUP_PROOF_MATERIAL_ENCODING,
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
    );
    let request = serde_json::json!({
        "transportedVssCoefficientCommitmentMaterial": {
            "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
            "objectVersion": 1,
            "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
            "chunkSizeBytes": 1_048_576,
            "chunkCount": 1,
            "totalByteLength": 64,
            "fullObjectHash": valid_hash('5'),
            "chunkHashes": [valid_hash('6')],
            "chunkRoot": valid_hash('7'),
        },
    });

    let response = verify_terminal_setup_transport_policy(&package, &request)
        .expect("terminal transport policy")
        .expect("missing stream-verified VSS handle response");

    assert_eq!(response["verifierStatus"], "pending");
    assert_eq!(
        response["missingObjects"],
        serde_json::json!(["verifiedVssCoefficientCommitmentMaterial"])
    );
}

fn terminal_transport_policy_package_with_material_encodings(
    vss_material_encoding: &str,
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
        "vssCoefficientCommitmentMaterial": {
            "materialEncoding": vss_material_encoding,
        },
        "sameSecretProofs": {
            "proofRecords": [
                proof_record.clone()
            ],
        },
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
            "publicEvaluationKeyMaterialChunkSizeBytes": 1_048_576,
            "publicEvaluationKeyMaterialChunkCount": 1,
            "publicEvaluationKeyMaterialTotalByteLength": 64,
            "publicEvaluationKeyMaterialFullObjectHash": valid_hash('2'),
            "publicEvaluationKeyMaterialChunkRoot": valid_hash('3'),
            "publicEvaluationKeyMaterialChunkHashes": [
                valid_hash('4')
            ],
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
fn collective_setup_verifier_refuses_malformed_setup_transport_manifest() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_setup_transport_manifest",
    );
    assert_minimal_collective_setup_package_refused(
        "setup transport manifest with a missing chunk hash",
        |package| {
            package["setupTransportCertificate"]["chunkHashes"]
                .as_array_mut()
                .expect("chunk hashes")
                .pop();
        },
        "transportChunkHashCountMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "setup transport manifest with a wrong chunk root",
        |package| {
            package["setupTransportCertificate"]["chunkRoot"] = serde_json::json!(valid_hash('8'));
        },
        "transportChunkRootMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_duplicate_setup_transport_object_root() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_duplicate_setup_transport_object_root",
    );
    assert_minimal_collective_setup_package_refused(
        "setup transport manifest with a duplicate transported object root",
        |package| {
            let duplicate_object =
                package["setupTransportCertificate"]["transportedObjects"][0].clone();
            package["setupTransportCertificate"]["transportedObjects"]
                .as_array_mut()
                .expect("transported objects")
                .push(duplicate_object);
        },
        "transportedObjectRootDuplicate",
    );
}

#[test]
fn collective_setup_verifier_refuses_public_key_share_transport_missing_certificate_object() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_public_key_share_transport_missing_certificate_object",
    );
    let package = minimal_collective_setup_package();

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedPublicKeyShareMaterial": {
                "totalByteLength": 1_u64,
                "fullObjectHash": valid_hash('1'),
                "chunkRoot": valid_hash('2'),
                "chunkHashes": [valid_hash('3')],
            },
        }),
    )
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(result["currentPhase"], "setupPackageVerification");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportedObjectBindingMissing"
    );
}

#[test]
fn collective_setup_verifier_refuses_unrequested_setup_transport_object() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_unrequested_setup_transport_object",
    );
    let mut package = minimal_collective_setup_package();
    append_unrequested_setup_transport_object(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_setup_package(&package);

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(result["currentPhase"], "setupPackageVerification");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportedObjectUnexpected"
    );
}

#[test]
fn collective_setup_verifier_refuses_unreferenced_setup_transport_sidecar() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_unreferenced_setup_transport_sidecar",
    );
    let mut package = minimal_collective_setup_package();
    let transported_same_secret_proof_material =
        append_unreferenced_same_secret_transport_sidecar(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedSameSecretProofMaterial": transported_same_secret_proof_material,
        }),
    )
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(result["currentPhase"], "setupPackageVerification");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportedObjectUnreferenced"
    );
}

#[test]
fn collective_setup_verifier_refuses_unreferenced_setup_transport_material_sidecar() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_unreferenced_setup_transport_material_sidecar",
    );
    let mut package = minimal_collective_setup_package();
    let transported_evaluation_key_component_material =
        append_unreferenced_evaluation_key_component_transport_sidecar(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedEvaluationKeyShareComponentMaterial": transported_evaluation_key_component_material,
        }),
    )
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(result["currentPhase"], "setupPackageVerification");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "transportedObjectUnreferenced"
    );
}

#[test]
fn terminal_profile_ring_gate_refuses_reduced_vss_material() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("terminal_profile_ring_gate_refuses_reduced_vss_material");
    let package = serde_json::json!({
        "vssCoefficientCommitmentMaterial": {
            "ringDegree": 8,
        },
    });

    let response = verify_profile_ring_material(&package)
        .expect("profile-ring verification")
        .expect("reduced VSS material refusal");

    assert_eq!(response["ok"], false);
    assert_eq!(response["verifierStatus"], "outsideProfile");
    assert_eq!(
        response["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}
