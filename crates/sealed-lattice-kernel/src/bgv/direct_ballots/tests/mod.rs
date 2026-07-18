mod aggregation;

use super::*;

const TEST_SETUP_SEED: &str = "direct-encrypted-ballot-test-setup-seed";

fn direct_ballot_test_randomness_hex(label: &str, index: usize) -> String {
    hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/test-randomness",
        &[
            TEST_SETUP_SEED.as_bytes(),
            label.as_bytes(),
            index.to_string().as_bytes(),
        ],
    )
}

fn valid_ballot_input() -> DirectBallotInput {
    DirectBallotInput {
        scores: vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        one_hot_witnesses: None,
        encryption_seed_hex: direct_ballot_test_randomness_hex("ballot-encryption", 0),
    }
}

fn one_hot_witnesses_for_scores(scores: &[u64]) -> Vec<Vec<u64>> {
    scores
        .iter()
        .map(|score| {
            let mut row = vec![0_u64; 10];
            row[usize::try_from(score - 1).expect("score index fits usize")] = 1;
            row
        })
        .collect()
}

#[test]
fn direct_ballot_input_rejects_wrong_score_counts_and_out_of_range_scores() {
    for scores in [vec![1; OPTION_COUNT - 1], vec![1; OPTION_COUNT + 1]] {
        let mut ballot = valid_ballot_input();
        ballot.scores = scores;
        let error = validate_direct_ballot_input(&ballot)
            .expect_err("the ballot must contain exactly one score per option");
        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    for (option_index, invalid_score) in [
        (0, MINIMUM_SCORE - 1),
        (OPTION_COUNT - 1, MAXIMUM_SCORE + 1),
    ] {
        let mut ballot = valid_ballot_input();
        ballot.scores[option_index] = invalid_score;
        let error = validate_direct_ballot_input(&ballot)
            .expect_err("scores outside the ballot domain must be rejected");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains(&format!("option {option_index}")));
    }
}

#[test]
fn direct_ballot_input_rejects_malformed_or_mismatched_one_hot_witnesses() {
    let ballot = valid_ballot_input();
    let valid_witnesses = one_hot_witnesses_for_scores(&ballot.scores);

    let error = validate_one_hot_witnesses(&ballot.scores[..OPTION_COUNT - 1], &valid_witnesses)
        .expect_err("a witness without one score per option must be rejected");
    assert_eq!(error.code, CanonicalErrorCode::MalformedLength);

    for witness_row_count in [OPTION_COUNT - 1, OPTION_COUNT + 1] {
        let witnesses = vec![vec![1; SCORE_BUCKET_COUNT]; witness_row_count];
        let error = validate_one_hot_witnesses(&ballot.scores, &witnesses)
            .expect_err("a witness must contain one row per option");
        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    for witness_column_count in [SCORE_BUCKET_COUNT - 1, SCORE_BUCKET_COUNT + 1] {
        let mut witnesses = valid_witnesses.clone();
        witnesses[0] = vec![0; witness_column_count];
        let error = validate_one_hot_witnesses(&ballot.scores, &witnesses)
            .expect_err("each witness row must cover the complete score domain");
        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    let mut non_binary = valid_witnesses.clone();
    non_binary[0][0] = 2;
    let error = validate_one_hot_witnesses(&ballot.scores, &non_binary)
        .expect_err("non-binary witness entries must be rejected");
    assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);

    for selected_bucket_count in [0, 2] {
        let mut wrong_weight = valid_witnesses.clone();
        wrong_weight[0].fill(0);
        for bucket in wrong_weight[0].iter_mut().take(selected_bucket_count) {
            *bucket = 1;
        }
        let error = validate_one_hot_witnesses(&ballot.scores, &wrong_weight)
            .expect_err("each witness row must select exactly one score");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
    }

    let mut mismatched = valid_witnesses;
    mismatched[0].fill(0);
    mismatched[0][0] = 1;
    let error = validate_one_hot_witnesses(&ballot.scores, &mismatched)
        .expect_err("the selected bucket must match the scalar score");
    assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
}
