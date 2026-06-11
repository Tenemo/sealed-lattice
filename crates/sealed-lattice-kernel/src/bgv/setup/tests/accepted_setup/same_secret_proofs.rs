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
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_before_public_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_before_public_key_material",
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_same_secret_lnp_proofs_before_missing_terminal_objects()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_same_secret_lnp_proofs_before_missing_terminal_objects",
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
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_material",
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
    package["sameSecretProofs"]["vssCoefficientCommitmentMaterialRoot"] =
        package["vssCoefficientCommitmentMaterial"]["vssCoefficientCommitmentMaterialRoot"].clone();
    rebind_collective_same_secret_proof_set_root(&mut package);
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
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssMaterialTransportReferenceMetadataMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_same_secret_lnp_proofs_from_transported_proof_material",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    let transported_proof_material = move_same_secret_proof_bytes_to_transport(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedSameSecretProofMaterial": transported_proof_material,
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_lnp_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_lnp_proofs",
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_row_metadata() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_row_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["z34ChallengeZ3RowSetHash"] =
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_tail_metadata() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_tail_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["z34ChallengeTailHash"] =
        serde_json::json!(valid_hash('9'));
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_tbox_lower_challenge_metadata()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_tbox_lower_challenge_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["tboxLowerProtocolChallengeHash"] =
        serde_json::json!(valid_hash('8'));
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_check_window_metadata()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_same_secret_z34_check_window_metadata",
    );
    let mut package = same_secret_proof_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["z34Z3CheckWindowHash"] =
        serde_json::json!(valid_hash('8'));
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
fn same_secret_lnp_verifier_refuses_unbound_tbox_prefix() {
    let package = minimal_collective_setup_package();
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_record = &package["sameSecretConsistency"]["statementRecords"][0];
    let constant_commitments = same_secret_constant_commitments_from_fixture_package(&package, 0);
    let ring_degree = constant_commitments
        .first()
        .expect("constant commitment")
        .ring_degree;
    let witness = SameSecretLnpProofWitness {
        secret_coefficients: (0..ring_degree)
            .map(|coefficient_position| {
                accepted_vss_secret_coefficient_fixture(0, coefficient_position)
            })
            .collect(),
        opening_randomness_by_limb: (0..DATA_PRIMES.len())
            .map(|rns_limb_index| {
                accepted_vss_randomness_fixture(0, rns_limb_index, 0, ring_degree)
            })
            .collect(),
    };
    let proof_randomness_seed_hex = derive_protocol_hash(
        "SameSecretProofRoot",
        &serde_json::json!({
            "fixture": "same-secret-unbound-prefix-test",
            "trusteeRosterPosition": 0_u64,
        }),
    )
    .expect("same-secret proof randomness seed");
    let mut proof_bytes = generate_same_secret_lnp_relation_proof(
        public_matrix_seed_hash,
        statement_record,
        &constant_commitments,
        &setup_proof_binding_for_test_package(&package),
        &witness,
        &proof_randomness_seed_hex,
    )
    .expect("same-secret proof bytes");
    let tbox_prefix_offset = 8 + 64 + 64 + 8 + 8;
    proof_bytes[tbox_prefix_offset] ^= 1;

    let error = verify_same_secret_lnp_relation_proof(
        public_matrix_seed_hash,
        statement_record,
        &constant_commitments,
        &setup_proof_binding_for_test_package(&package),
        &proof_bytes,
    )
    .expect_err("unbound tbox prefix must be refused");

    assert!(
        error
            .message
            .contains("tbox commitment prefix is not bound")
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
fn heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_setup_proof_challenge_domain_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_same_secret_setup_proof_challenge_domain_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["sameSecretProofs"]["proofRecords"][0]["setupProofBinding"]["challengeDomainHash"] =
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
        "sameSecretProofVerificationFailed"
    );
}
