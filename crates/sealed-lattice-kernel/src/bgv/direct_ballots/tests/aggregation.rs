use super::*;

#[test]
fn direct_ballot_aggregation_matches_all_pair_difference_lanes_for_ten_ballots() {
    let evaluator_key = DevelopmentBgvKey::generate(TEST_SETUP_SEED).expect("evaluator key");
    let mut encrypted_ballots = Vec::with_capacity(10);
    let mut expected_pair_differences = vec![0_u64; POLYNOMIAL_DEGREE];
    for ballot_ordinal in 0..10 {
        let mut ballot = valid_ballot_input();
        ballot.scores = (0..OPTION_COUNT)
            .map(|option_ordinal| {
                u64::try_from((option_ordinal * 3 + ballot_ordinal) % 10 + 1)
                    .expect("score fits u64")
            })
            .collect();
        ballot.encryption_seed_hex =
            direct_ballot_test_randomness_hex("aggregate-ballot-encryption", ballot_ordinal);
        let ballot_pair_differences =
            direct_ballot_slots(&ballot.scores, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE)
                .expect("ballot pair differences derive");
        for (aggregate, difference) in expected_pair_differences
            .iter_mut()
            .zip(ballot_pair_differences)
        {
            *aggregate = (*aggregate + difference) % PLAINTEXT_MODULUS;
        }
        encrypted_ballots
            .push(encrypt_direct_ballot(&evaluator_key, ballot).expect("direct ballot encrypts"));
    }

    let aggregate_ciphertext =
        aggregate_direct_encrypted_ballots(&encrypted_ballots).expect("aggregate ciphertext");
    let aggregate_slots = evaluator_key
        .decrypt_to_slots(&aggregate_ciphertext)
        .expect("test-only aggregate decryption");

    assert_eq!(
        &aggregate_slots[..PAIR_COUNT],
        &expected_pair_differences[..PAIR_COUNT]
    );
    assert!(aggregate_slots[PAIR_COUNT..].iter().all(|slot| *slot == 0));
}
