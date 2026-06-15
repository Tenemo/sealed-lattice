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
