use super::*;

#[test]
fn direct_ballot_aggregation_matches_plaintext_oracle_for_multiple_ballots() {
    let evaluator_key = DevelopmentBgvKey::generate(TEST_SETUP_SEED).expect("evaluator key");
    let first_input = valid_ballot_input();
    let first_ballot =
        encrypt_direct_ballot(&evaluator_key, first_input.clone()).expect("first encrypted ballot");
    let mut second_input = valid_ballot_input();
    second_input.scores = vec![1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10];
    let expected_scores = first_input
        .scores
        .iter()
        .zip(second_input.scores.iter())
        .map(|(first_score, second_score)| first_score + second_score)
        .collect::<Vec<_>>();
    let second_ballot =
        encrypt_direct_ballot(&evaluator_key, second_input).expect("second encrypted ballot");

    let aggregate_ciphertext = aggregate_direct_encrypted_ballots(&[first_ballot, second_ballot])
        .expect("aggregate ciphertext");
    let aggregate_slots = evaluator_key
        .decrypt_to_slots(&aggregate_ciphertext)
        .expect("test-only aggregate decryption");

    assert_eq!(&aggregate_slots[..OPTION_COUNT], expected_scores.as_slice());
    assert!(
        aggregate_slots[OPTION_COUNT..]
            .iter()
            .all(|slot| *slot == 0)
    );
}
