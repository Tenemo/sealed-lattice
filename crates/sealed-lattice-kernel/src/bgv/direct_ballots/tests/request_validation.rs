use super::*;

#[test]
fn direct_encrypted_ballot_command_rejects_more_than_twenty_ballots() {
    let setup_package = setup_package_not_reached();
    let ballots = (0..=MAXIMUM_PROTOTYPE_BALLOTS)
        .map(|ballot_index| {
            json!({
                "voterIdentity": format!("voter-{}", ballot_index + 1),
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash",
                        "action": "direct encrypted ballot max batch test",
                        "ballotIndex": ballot_index
                    }),
                ).expect("action hash"),
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            })
        })
        .collect::<Vec<_>>();

    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(MAXIMUM_PROTOTYPE_BALLOTS + 1),
        "ballots": ballots
    }))
    .expect_err("oversized direct ballot batch must reject before encryption");

    assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    assert!(error.message.contains("supports at most twenty ballots"));
}

#[test]
fn direct_encrypted_ballot_command_rejects_missing_ballot_encryption_randomness() {
    let setup_package = setup_package_not_reached();
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-missing-encryption-randomness",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot missing encryption randomness test" }),
                ).expect("action hash"),
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            }
        ]
    }))
    .expect_err("missing direct ballot encryption randomness must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("ballotEncryptionRandomness"));
}

#[test]
fn direct_encrypted_ballot_command_rejects_ballot_embedded_encryption_seed() {
    let setup_package = setup_package_not_reached();
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-embedded-encryption-seed",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot embedded encryption seed test" }),
                ).expect("action hash"),
                "encryptionSeedHex": direct_ballot_test_randomness_hex("embedded-ballot-seed", 0),
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            }
        ]
    }))
    .expect_err("ballot-embedded encryption seed must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("must be supplied through ballotEncryptionRandomness")
    );
}

#[test]
fn direct_encrypted_ballot_command_rejects_reused_encryption_randomness() {
    let setup_package = setup_package_not_reached();
    let reused_randomness = direct_ballot_test_randomness_hex("reused-encryption", 0);
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": {
            "source": ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "encryptionSeedHexes": [
                reused_randomness,
                reused_randomness
            ]
        },
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(2),
        "ballots": [
            direct_ballot_test_ballot_json("voter-randomness-1", 0),
            direct_ballot_test_ballot_json("voter-randomness-2", 1)
        ]
    }))
    .expect_err("reused ballot encryption randomness must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("repeats direct ballot randomness"));
}

#[test]
fn direct_encrypted_ballot_command_rejects_reused_proof_randomness() {
    let setup_package = setup_package();
    let reused_randomness = direct_ballot_test_randomness_hex("reused-proof", 0);
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
        "proofMaskRandomness": {
            "source": PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "ballotProofRandomnessHexes": [
                reused_randomness,
                reused_randomness
            ]
        },
        "ballots": [
            direct_ballot_test_ballot_json("voter-randomness-1", 0),
            direct_ballot_test_ballot_json("voter-randomness-2", 1)
        ]
    }))
    .expect_err("reused proof-mask randomness must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("repeats direct ballot randomness"));
}

#[test]
fn direct_encrypted_ballot_command_rejects_proof_and_encryption_randomness_overlap() {
    let setup_package = setup_package();
    let reused_randomness = direct_ballot_test_randomness_hex("cross-purpose-randomness", 0);
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": {
            "source": ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "encryptionSeedHexes": [reused_randomness]
        },
        "proofMaskRandomness": {
            "source": PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "ballotProofRandomnessHexes": [reused_randomness]
        },
        "ballots": [
            direct_ballot_test_ballot_json("voter-randomness-1", 0)
        ]
    }))
    .expect_err("proof-mask randomness must not reuse ballot encryption randomness");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("must not reuse ballot encryption randomness")
    );
}

#[test]
fn direct_encrypted_ballot_command_rejects_duplicate_voter_identity() {
    let setup_package = setup_package_not_reached();
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
        "ballots": [
            {
                "voterIdentity": "duplicate-voter",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot duplicate test", "ballotIndex": 0 }),
                ).expect("action hash"),
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            },
            {
                "voterIdentity": "duplicate-voter",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot duplicate test", "ballotIndex": 1 }),
                ).expect("action hash"),
                "scores": [
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10,
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1
                ]
            }
        ]
    }))
    .expect_err("duplicate direct ballot voter identity must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("duplicate voter identity"));
}

#[test]
fn direct_encrypted_ballot_command_rejects_wrong_voter_order() {
    let setup_package = setup_package_not_reached();
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
        "ballots": [
            {
                "voterIdentity": "voter-b",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot order test", "ballotIndex": 0 }),
                ).expect("action hash"),
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            },
            {
                "voterIdentity": "voter-a",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot order test", "ballotIndex": 1 }),
                ).expect("action hash"),
                "scores": [
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10,
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1
                ]
            }
        ]
    }))
    .expect_err("out-of-order direct ballot batch must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("deterministic voter identity order"));
}

#[test]
fn direct_encrypted_ballot_command_rejects_invalid_score_before_proof_generation() {
    let setup_package = setup_package_not_reached();
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-invalid-score",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot invalid score test" }),
                ).expect("action hash"),
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 11, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            }
        ]
    }))
    .expect_err("invalid direct ballot score must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("score at option 8"));
}

#[test]
fn direct_encrypted_ballot_command_rejects_wrong_setup_seed() {
    let setup_package = setup_package();
    let error = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": "direct-encrypted-ballot-wrong-setup-seed"
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-wrong-key",
                "actionContextHash": derive_canonical_object_hash(
                    &json!({
                        "objectType": "ActionContextHash", "action": "direct encrypted ballot wrong key test" }),
                ).expect("action hash"),
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            }
        ]
    }))
    .expect_err("wrong setup seed must reject before direct ballot encryption");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(
        error
            .message
            .contains("private setup witness seed commitment")
    );
}

#[test]
fn direct_ballot_validation_rejects_out_of_range_scores() {
    let mut ballot = valid_ballot_input();
    ballot.scores[7] = 11;

    let error = validate_direct_ballot_input(&ballot).expect_err("score is out of range");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("direct encrypted ballot score at option 7")
    );
}

#[test]
fn direct_ballot_validation_rejects_mismatched_one_hot_witness() {
    let mut ballot = valid_ballot_input();
    let mut witnesses = ballot
        .scores
        .iter()
        .map(|score| {
            let mut row = vec![0_u64; 10];
            row[usize::try_from(score - 1).expect("score index fits usize")] = 1;
            row
        })
        .collect::<Vec<_>>();
    witnesses[3] = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    ballot.one_hot_witnesses = Some(witnesses);

    let error = validate_direct_ballot_input(&ballot).expect_err("witness is inconsistent");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("one-hot witness does not match its scalar score")
    );
}
