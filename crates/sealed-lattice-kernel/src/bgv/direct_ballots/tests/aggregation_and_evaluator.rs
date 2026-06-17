use super::*;

#[test]
fn direct_ballot_aggregation_matches_plaintext_oracle_for_multiple_ballots() {
    let setup_package = setup_package();
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        DIRECT_BALLOT_TEST_SETUP_SEED,
    )
    .expect("evaluator key");
    let public_key = public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
    let first_ballot = encrypt_direct_ballot(&setup_package, &public_key, valid_ballot_input())
        .expect("first encrypted ballot");
    let mut second_input = valid_ballot_input();
    second_input.voter_identity = "voter-aggregation-second".to_string();
    second_input.scores = vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10];
    let second_ballot = encrypt_direct_ballot(&setup_package, &public_key, second_input)
        .expect("second encrypted ballot");

    let aggregation_report =
        verify_direct_ballot_aggregation(&evaluator_key, &[first_ballot, second_ballot])
            .expect("aggregation report");

    assert_eq!(aggregation_report.report["ballotCount"].as_u64(), Some(2));
    assert!(aggregation_report.report.get("aggregateScores").is_none());
    assert!(
        aggregation_report
            .report
            .get("plaintextOracleScores")
            .is_none()
    );
    assert_eq!(
        aggregation_report.report["privateCorrectnessCheck"].as_str(),
        Some("aggregate score slots matched the plaintext oracle")
    );
}

#[test]
fn direct_ballot_public_aggregation_sums_verified_ciphertexts_and_binds_certificate() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);
    let first_ballot = encrypt_direct_ballot(
        &public_material_fixture.accepted_public_key_material,
        &public_material_fixture.public_key,
        valid_ballot_input(),
    )
    .expect("first encrypted ballot");
    let mut second_input = valid_ballot_input();
    second_input.voter_identity = "voter-verified-aggregation-second".to_string();
    second_input.voter_roster_position = 1;
    second_input.encryption_seed_hex =
        direct_ballot_test_randomness_hex("verified-aggregation-ballot-encryption", 1);
    second_input.scores = vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10];
    let second_ballot = encrypt_direct_ballot(
        &public_material_fixture.accepted_public_key_material,
        &public_material_fixture.public_key,
        second_input,
    )
    .expect("second encrypted ballot");
    let expected_aggregate_ciphertext =
        ciphertext_add(&first_ballot.ciphertext, &second_ballot.ciphertext)
            .expect("expected aggregate ciphertext");
    let expected_aggregate_ciphertext_root = ciphertext_object_root(&expected_aggregate_ciphertext)
        .expect("expected aggregate ciphertext root");

    let accepted_setup_handoff_root = required_string_field(
        &public_material_fixture.accepted_setup_handoff,
        "acceptedSetupHandoffRoot",
    )
    .expect("accepted setup handoff root")
    .to_string();
    let package_verifications = vec![
        direct_ballot_test_verified_package(
            &accepted_setup_handoff_root,
            "verified aggregation first",
            first_ballot,
        ),
        direct_ballot_test_verified_package(
            &accepted_setup_handoff_root,
            "verified aggregation second",
            second_ballot,
        ),
    ];
    let package_roots = package_verifications
        .iter()
        .map(|verification| verification.package_root.clone())
        .collect::<Vec<_>>();
    let first_valid_order_hash = direct_ballot_test_hash("verified aggregation first-valid order");
    let first_valid_binding = optional_direct_ballot_first_valid_binding(
        &json!({
            "firstValidOrderHash": first_valid_order_hash,
            "firstValidPackageRoots": package_roots,
        }),
        &package_verifications,
    )
    .expect("first-valid binding should validate")
    .expect("first-valid binding should be present");

    let result = aggregate_verified_direct_ballot_packages(
        &public_material_fixture.accepted_public_key_material,
        &accepted_setup_handoff_root,
        package_verifications,
        Some(first_valid_binding),
    )
    .expect("verified package aggregation succeeds");

    assert_eq!(
        result["operation"].as_str(),
        Some(DIRECT_BALLOT_PUBLIC_AGGREGATE_OPERATION)
    );
    assert_eq!(result["ballotCount"].as_u64(), Some(2));
    assert_eq!(
        result["aggregateCiphertextRoot"].as_str(),
        Some(expected_aggregate_ciphertext_root.as_str())
    );
    assert_eq!(
        result["firstValidOrderHash"].as_str(),
        Some(first_valid_order_hash.as_str())
    );
    assert!(result.get("aggregateScores").is_none());
    assert!(result.get("plaintextOracleScores").is_none());

    let aggregate_certificate = &result["aggregateCertificate"];
    assert_eq!(
        aggregate_certificate["objectType"].as_str(),
        Some("DirectEncryptedBallotAggregateCertificate")
    );
    assert_eq!(
        aggregate_certificate["aggregateCiphertextRoot"].as_str(),
        Some(expected_aggregate_ciphertext_root.as_str())
    );
    assert_eq!(
        aggregate_certificate["aggregateCertificateHash"],
        result["aggregateCertificateHash"]
    );
    let mut certificate_hash_input = aggregate_certificate.clone();
    certificate_hash_input
        .as_object_mut()
        .expect("aggregate certificate object")
        .remove("aggregateCertificateHash");
    let expected_certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotAggregateCertificateHash",
        &certificate_hash_input,
    )
    .expect("aggregate certificate hash");
    assert_eq!(
        result["aggregateCertificateHash"].as_str(),
        Some(expected_certificate_hash.as_str())
    );

    let mut tampered_certificate_hash_input = aggregate_certificate.clone();
    tampered_certificate_hash_input["ballotCount"] = json!(3);
    tampered_certificate_hash_input
        .as_object_mut()
        .expect("tampered aggregate certificate object")
        .remove("aggregateCertificateHash");
    let tampered_certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotAggregateCertificateHash",
        &tampered_certificate_hash_input,
    )
    .expect("tampered aggregate certificate hash");
    assert_ne!(
        result["aggregateCertificateHash"].as_str(),
        Some(tampered_certificate_hash.as_str())
    );
}

#[test]
fn direct_ballot_public_aggregation_rejects_duplicate_verified_package_replay() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);
    let accepted_setup_handoff_root = required_string_field(
        &public_material_fixture.accepted_setup_handoff,
        "acceptedSetupHandoffRoot",
    )
    .expect("accepted setup handoff root");
    let first_ballot = encrypt_direct_ballot(
        &public_material_fixture.accepted_public_key_material,
        &public_material_fixture.public_key,
        valid_ballot_input(),
    )
    .expect("first encrypted ballot");
    let mut second_input = valid_ballot_input();
    second_input.voter_identity = "voter-duplicate-package-replay-second".to_string();
    second_input.voter_roster_position = 1;
    second_input.encryption_seed_hex =
        direct_ballot_test_randomness_hex("duplicate-package-replay-ballot-encryption", 1);
    let second_ballot = encrypt_direct_ballot(
        &public_material_fixture.accepted_public_key_material,
        &public_material_fixture.public_key,
        second_input,
    )
    .expect("second encrypted ballot");
    let first_verification = direct_ballot_test_verified_package(
        accepted_setup_handoff_root,
        "duplicate package replay first",
        first_ballot,
    );
    let mut second_verification = direct_ballot_test_verified_package(
        accepted_setup_handoff_root,
        "duplicate package replay second",
        second_ballot,
    );
    second_verification.package_root = first_verification.package_root.clone();

    let error = aggregate_verified_direct_ballot_packages(
        &public_material_fixture.accepted_public_key_material,
        accepted_setup_handoff_root,
        vec![first_verification, second_verification],
        None,
    )
    .expect_err("duplicate package replay must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("duplicates a package root"));
}

#[test]
fn direct_ballot_public_aggregation_rejects_duplicate_verified_voter() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);
    let accepted_setup_handoff_root = required_string_field(
        &public_material_fixture.accepted_setup_handoff,
        "acceptedSetupHandoffRoot",
    )
    .expect("accepted setup handoff root");
    let first_ballot = encrypt_direct_ballot(
        &public_material_fixture.accepted_public_key_material,
        &public_material_fixture.public_key,
        valid_ballot_input(),
    )
    .expect("first encrypted ballot");
    let mut second_input = valid_ballot_input();
    second_input.voter_identity = "voter-duplicate-verified-voter-second".to_string();
    second_input.voter_roster_position = 1;
    second_input.encryption_seed_hex =
        direct_ballot_test_randomness_hex("duplicate-verified-voter-ballot-encryption", 1);
    let second_ballot = encrypt_direct_ballot(
        &public_material_fixture.accepted_public_key_material,
        &public_material_fixture.public_key,
        second_input,
    )
    .expect("second encrypted ballot");
    let first_verification = direct_ballot_test_verified_package(
        accepted_setup_handoff_root,
        "duplicate verified voter first",
        first_ballot,
    );
    let mut second_verification = direct_ballot_test_verified_package(
        accepted_setup_handoff_root,
        "duplicate verified voter second",
        second_ballot,
    );
    second_verification.voter_identity = first_verification.voter_identity.clone();

    let error = aggregate_verified_direct_ballot_packages(
        &public_material_fixture.accepted_public_key_material,
        accepted_setup_handoff_root,
        vec![first_verification, second_verification],
        None,
    )
    .expect_err("duplicate verified voter must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("duplicate voter identity"));
}

#[test]
fn direct_ballot_public_aggregation_rejects_first_valid_package_root_mismatch() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);
    let accepted_setup_handoff_root = required_string_field(
        &public_material_fixture.accepted_setup_handoff,
        "acceptedSetupHandoffRoot",
    )
    .expect("accepted setup handoff root");
    let ballot = encrypt_direct_ballot(
        &public_material_fixture.accepted_public_key_material,
        &public_material_fixture.public_key,
        valid_ballot_input(),
    )
    .expect("encrypted ballot");
    let package_verifications = vec![direct_ballot_test_verified_package(
        accepted_setup_handoff_root,
        "first-valid mismatch",
        ballot,
    )];

    let error = optional_direct_ballot_first_valid_binding(
        &json!({
            "firstValidOrderHash": direct_ballot_test_hash("mismatched first-valid order hash"),
            "firstValidPackageRoots": ["0".repeat(128)],
        }),
        &package_verifications,
    )
    .expect_err("first-valid package roots must match verified package roots");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("firstValidPackageRoots must exactly match")
    );
}

#[test]
fn direct_ballot_top_counts_reject_duplicates_before_evaluator_replay() {
    let error = optional_direct_ballot_top_count_request(&json!({
        "topCounts": [1, 1]
    }))
    .expect_err("duplicate top counts must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("topCounts must not contain duplicates")
    );
}

fn direct_ballot_test_verified_package(
    accepted_setup_handoff_root: &str,
    package_label: &str,
    ballot: DirectEncryptedBallot,
) -> DirectBallotPackageVerification {
    let package_root = direct_ballot_test_hash(&format!("{package_label} package root"));
    let proof_statement_hash =
        direct_ballot_test_hash(&format!("{package_label} proof statement hash"));
    let proof_chunk_root = direct_ballot_test_hash(&format!("{package_label} proof chunk root"));
    let package_verification_certificate_hash = direct_ballot_test_hash(&format!(
        "{package_label} package verification certificate hash"
    ));
    let signature_hash = direct_ballot_test_hash(&format!("{package_label} signature hash"));
    let ciphertext_root = ballot.ciphertext_root.clone();
    let voter_identity = ballot.input.voter_identity.clone();
    let voter_roster_position = ballot.input.voter_roster_position;

    DirectBallotPackageVerification {
        report: json!({
            "fixture": "verified package aggregation test record",
            "packageRoot": package_root,
        }),
        accepted_setup_handoff_root: accepted_setup_handoff_root.to_string(),
        package_root: package_root.clone(),
        ciphertext_root: ciphertext_root.clone(),
        proof_statement_hash: proof_statement_hash.clone(),
        proof_chunk_root: proof_chunk_root.clone(),
        package_verification_certificate_hash: package_verification_certificate_hash.clone(),
        public_aggregation_input: json!({
            "packageRoot": package_root,
            "ciphertextRoot": ciphertext_root,
            "proofStatementHash": proof_statement_hash,
            "proofChunkRoot": proof_chunk_root,
            "acceptedSetupHandoffRoot": accepted_setup_handoff_root,
            "verifierCertificateHash": direct_ballot_verifier_certificate_hash()
                .expect("verifier certificate hash"),
        }),
        voter_identity,
        voter_roster_position,
        signature_hash,
        ballot,
    }
}
