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

        let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
            .expect("verification response");

        assert_eq!(result["isValid"], false);
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
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");
    let setup_transport_certificate = setup_transport_certificate_fixture(
        &setup_parameters,
        &package["vssCoefficientCommitmentMaterial"],
    );
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedVssCoefficientCommitmentMaterial": transported_material,
        }),
    )
    .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["isValid"], false,
        "unexpected verifier result: {result}"
    );
    // The fixture transport certificate (setup_transport_certificate_fixture)
    // declares a roster-and-ring-derived byte length that matches the transported
    // material's actual dimensions but a placeholder full-object hash that never
    // matches it, so the transported-material reference mismatch is caught on the
    // content hash. The numeric-metadata check runs and passes first; it still
    // refuses a genuine dimension mismatch.
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], "vssMaterialTransportReferenceHashMismatch",
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
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedSameSecretProofMaterial": transported_proof_material,
        }),
    )
    .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["isValid"], false,
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

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedSameSecretProofMaterial": transported_proof_material,
        }),
    )
    .expect("verification response");

    assert_eq!(result["isValid"], false);
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
    let mut noncanonical_claim_package = same_secret_proof_bearing_collective_setup_package();
    mutate_first_same_secret_proof_bytes_and_rebind(
        &mut noncanonical_claim_package,
        |proof_bytes| {
            set_first_masked_consistency_claim_to_noncanonical_modulus(proof_bytes);
        },
    );
    let noncanonical_claim_result =
        verify_collective_bgv_setup_package(&noncanonical_claim_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(noncanonical_claim_result["isValid"], false);
    assert_eq!(
        noncanonical_claim_result["refusedObjects"][0]["reasonCode"],
        "sameSecretProofVerificationFailed"
    );

    let mut low_degree_shape_package = same_secret_proof_bearing_collective_setup_package();
    let ring_degree = low_degree_shape_package["sameSecretProofs"]["proofRecords"][0]["ringDegree"]
        .as_u64()
        .expect("same-secret proof ring degree") as usize;
    let same_secret_linkage_commitment_count = DATA_PRIMES.len();
    mutate_first_same_secret_proof_bytes_and_rebind(&mut low_degree_shape_package, |proof_bytes| {
        set_first_limb_low_degree_fold_count_to_wrong_value(
            proof_bytes,
            FirstLimbProofCodecLayout::same_secret_anchor(
                ring_degree,
                same_secret_linkage_commitment_count,
            ),
        );
    });
    let low_degree_shape_result =
        verify_collective_bgv_setup_package(&low_degree_shape_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(low_degree_shape_result["isValid"], false);
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
    rebind_same_secret_proof_record_root(package, 0);
    rebind_collective_same_secret_proof_set_root(package);
    rebind_collective_setup_package_hash(package);
}
