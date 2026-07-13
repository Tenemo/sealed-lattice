use super::*;

#[test]
fn direct_ballot_aggregation_matches_plaintext_oracle_for_multiple_ballots() {
    let setup_package = setup_package();
    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(&setup_package, TEST_SETUP_SEED)
            .expect("evaluator key");
    let first_input = valid_ballot_input();
    let first_ballot = encrypt_direct_ballot(&setup_package, &evaluator_key, first_input.clone())
        .expect("first encrypted ballot");
    let mut second_input = valid_ballot_input();
    second_input.voter_identity = "voter-aggregation-second".to_string();
    second_input.scores = vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10];
    let expected_scores = first_input
        .scores
        .iter()
        .zip(second_input.scores.iter())
        .map(|(first_score, second_score)| first_score + second_score)
        .collect::<Vec<_>>();
    let second_ballot = encrypt_direct_ballot(&setup_package, &evaluator_key, second_input)
        .expect("second encrypted ballot");

    let aggregation_result = verify_direct_ballot_aggregation(&[first_ballot, second_ballot])
        .expect("aggregation report");
    let aggregate_slots = evaluator_key
        .decrypt_to_slots(&aggregation_result.aggregate_ciphertext)
        .expect("test-only aggregate decryption");

    assert_eq!(&aggregate_slots[..OPTION_COUNT], expected_scores.as_slice());
    assert!(
        aggregate_slots[OPTION_COUNT..]
            .iter()
            .all(|slot| *slot == 0)
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
