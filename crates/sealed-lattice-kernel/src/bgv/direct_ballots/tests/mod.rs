use std::sync::OnceLock;

mod aggregation_and_evaluator;
mod relation_proof_checks;

use serde_json::json;

use crate::hashing::derive_canonical_object_hash;

use super::*;

const TEST_SETUP_SEED: &str = "direct-encrypted-ballot-test-setup-seed";

struct DirectBallotRelationProofFixture {
    setup_package: Value,
    evaluator_key: DevelopmentBgvKey,
    encrypted_ballot: DirectEncryptedBallot,
    proof_generation: DirectBallotRelationProofGeneration,
}

fn direct_ballot_relation_proof_fixture() -> &'static DirectBallotRelationProofFixture {
    static FIXTURE: OnceLock<DirectBallotRelationProofFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let evaluator_key = DevelopmentBgvKey::generate(TEST_SETUP_SEED).expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&evaluator_key, valid_ballot_input()).expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(TEST_SETUP_SEED, &encrypted_ballot);
        let setup_package = setup_package();
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        DirectBallotRelationProofFixture {
            setup_package,
            evaluator_key,
            encrypted_ballot,
            proof_generation,
        }
    })
}

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
        voter_identity: "voter-validation".to_string(),
        action_context_hash: "a".repeat(128),
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

fn direct_ballot_relation_response_offset(proof_bytes: &[u8]) -> usize {
    proof_bytes.len() - super::relation_proof::direct_ballot_relation_response_bytes()
}

fn direct_ballot_relation_commitment_offset(proof_bytes: &[u8]) -> usize {
    direct_ballot_relation_response_offset(proof_bytes)
        - super::relation_proof::direct_ballot_relation_commitment_bytes()
}

fn direct_ballot_response_coefficient_bytes() -> usize {
    super::relation_proof::direct_ballot_relation_response_bytes()
        / super::relation_proof::direct_ballot_relation_response_scalar_count()
}

fn direct_ballot_score_response_offset(proof_bytes: &[u8]) -> usize {
    direct_ballot_relation_response_offset(proof_bytes)
        + 4 * POLYNOMIAL_DEGREE * direct_ballot_response_coefficient_bytes()
}

fn setup_package() -> Value {
    static SETUP_PACKAGE: OnceLock<Value> = OnceLock::new();
    SETUP_PACKAGE
        .get_or_init(|| setup_package_with_seed(TEST_SETUP_SEED))
        .clone()
}

fn setup_package_with_seed(setup_seed: &str) -> Value {
    json!({
        "objectType": "SetupPackage",
        "setupContext": {
            "ceremonyId": "direct-encrypted-ballot-test-ceremony",
            "manifestHash": derive_canonical_object_hash(
                &json!({ "objectType": "ElectionManifestHash", "manifest": "direct encrypted ballot test" }),
            ).expect("manifest hash"),
            "rosterHash": derive_canonical_object_hash(
                &json!({ "objectType": "RosterHash", "roster": "direct encrypted ballot test" }),
            ).expect("roster hash"),
            "setupParametersHash": derive_canonical_object_hash(
                &json!({ "objectType": "ThresholdParametersHash", "threshold": "direct encrypted ballot test" }),
            ).expect("threshold hash"),
            "testBinding": setup_seed,
        }
    })
}
