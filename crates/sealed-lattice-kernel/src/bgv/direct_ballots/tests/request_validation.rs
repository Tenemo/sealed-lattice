use super::*;

#[test]
fn direct_encrypted_ballot_command_rejects_more_than_twenty_ballots() {
    let setup_package = setup_package_not_reached();
    let ballots = (0..=DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS)
        .map(|ballot_index| {
            json!({
                "voterIdentity": format!("voter-{}", ballot_index + 1),
                "voterRosterPosition": ballot_index,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({
                        "action": "direct encrypted ballot max batch test",
                        "ballotIndex": ballot_index
                    }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS + 1),
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-missing-encryption-randomness",
                "voterRosterPosition": 0,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot missing encryption randomness test" }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-embedded-encryption-seed",
                "voterRosterPosition": 0,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot embedded encryption seed test" }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "encryptionSeedHex": direct_ballot_test_randomness_hex("legacy-ballot-seed", 0),
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": {
            "source": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
        "proofMaskRandomness": {
            "source": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": {
            "source": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
            "encryptionSeedHexes": [reused_randomness]
        },
        "proofMaskRandomness": {
            "source": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
        "ballots": [
            {
                "voterIdentity": "duplicate-voter",
                "voterRosterPosition": 0,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot duplicate test", "ballotIndex": 0 }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            },
            {
                "voterIdentity": "duplicate-voter",
                "voterRosterPosition": 1,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot duplicate test", "ballotIndex": 1 }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(2),
        "ballots": [
            {
                "voterIdentity": "voter-b",
                "voterRosterPosition": 1,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot order test", "ballotIndex": 0 }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            },
            {
                "voterIdentity": "voter-a",
                "voterRosterPosition": 0,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot order test", "ballotIndex": 1 }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
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
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-invalid-score",
                "voterRosterPosition": 0,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot invalid score test" }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
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
                "voterRosterPosition": 0,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot wrong key test" }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
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

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("private setup witness seed commitment")
    );
}

#[test]
fn direct_encrypted_ballot_public_package_command_rejects_private_development_fields() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);
    for field_name in [
        "setupPrivateWitness",
        "topCount",
        "topCounts",
        "publicEvaluationKeyMaterial",
        "targetFinalityPolicyHash",
    ] {
        let mut request = json!({
            "acceptedPublicKeyMaterial": public_material_fixture.accepted_public_key_material.clone(),
            "acceptedSetupHandoff": public_material_fixture.accepted_setup_handoff.clone(),
            "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
            "ballots": [
                direct_ballot_test_ballot_json("voter-public-package-rejection", 0)
            ]
        });
        request[field_name] = match field_name {
            "setupPrivateWitness" => json!({ "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED }),
            "topCount" => json!(1),
            "topCounts" => json!([1, 2]),
            "publicEvaluationKeyMaterial" => json!({ "material": "not accepted here" }),
            "targetFinalityPolicyHash" => json!("a".repeat(128)),
            _ => unreachable!("all public package rejection fields are covered"),
        };

        let error = create_direct_encrypted_ballot_packages(&request)
            .expect_err("public package command must reject private development field");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains(&format!("does not accept {field_name}")),
            "unexpected error message: {}",
            error.message
        );
    }
}

#[test]
fn direct_encrypted_ballot_public_package_command_rejects_raw_setup_package_field() {
    let error = create_direct_encrypted_ballot_packages(&json!({
        "setupPackage": setup_package_not_reached(),
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            direct_ballot_test_ballot_json("voter-public-package-raw-setup-rejection", 0)
        ]
    }))
    .expect_err("public package command must reject raw setupPackage field");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("acceptedPublicKeyMaterial"));
    assert!(error.message.contains("acceptedSetupHandoff"));
}

#[test]
fn direct_encrypted_ballot_public_package_command_rejects_passive_setup_material_field() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);

    let error = create_direct_encrypted_ballot_packages(&json!({
        "setupPublicMaterial": setup_package,
        "acceptedPublicKeyMaterial": public_material_fixture.accepted_public_key_material,
        "acceptedSetupHandoff": public_material_fixture.accepted_setup_handoff,
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            direct_ballot_test_ballot_json("voter-public-package-passive-setup-rejection", 0)
        ]
    }))
    .expect_err("public package command must reject passive setupPublicMaterial");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("setupPublicMaterial"));
    assert!(error.message.contains("acceptedPublicKeyMaterial"));
}

#[test]
fn direct_encrypted_ballot_public_package_command_rejects_fixture_encryption_randomness() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);

    let error = create_direct_encrypted_ballot_packages(&json!({
        "acceptedPublicKeyMaterial": public_material_fixture.accepted_public_key_material,
        "acceptedSetupHandoff": public_material_fixture.accepted_setup_handoff,
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_fresh_labelled_proof_mask_randomness(1),
        "ballots": [
            direct_ballot_test_ballot_json("voter-public-package-fixture-encryption-rejection", 0)
        ]
    }))
    .expect_err("public package command must reject fixture encryption randomness");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("ballotEncryptionRandomness.source"));
    assert!(error.message.contains("fresh-csprng"));
    assert!(
        error
            .message
            .contains("accepted only by runDirectEncryptedBallot")
    );
}

#[test]
fn direct_encrypted_ballot_public_package_command_rejects_fixture_proof_randomness() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);

    let error = create_direct_encrypted_ballot_packages(&json!({
        "acceptedPublicKeyMaterial": public_material_fixture.accepted_public_key_material,
        "acceptedSetupHandoff": public_material_fixture.accepted_setup_handoff,
        "ballotEncryptionRandomness": direct_ballot_test_fresh_labelled_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            direct_ballot_test_ballot_json("voter-public-package-fixture-proof-rejection", 0)
        ]
    }))
    .expect_err("public package command must reject fixture proof randomness");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("proofMaskRandomness.source"));
    assert!(error.message.contains("fresh-csprng"));
    assert!(
        error
            .message
            .contains("accepted only by runDirectEncryptedBallot")
    );
}

#[test]
fn direct_encrypted_ballot_public_package_command_rejects_mismatched_handoff_root() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);
    let mut accepted_setup_handoff = public_material_fixture.accepted_setup_handoff;
    accepted_setup_handoff["directBallotEncryptionHandoff"]["bgvPublicKeyRoot"] =
        json!("0".repeat(128));

    let error = create_direct_encrypted_ballot_packages(&json!({
        "acceptedPublicKeyMaterial": public_material_fixture.accepted_public_key_material,
        "acceptedSetupHandoff": accepted_setup_handoff,
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            direct_ballot_test_ballot_json("voter-public-package-handoff-rejection", 0)
        ]
    }))
    .expect_err("public package command must reject mismatched handoff roots");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("acceptedSetupHandoffRoot"));
}

#[test]
fn direct_encrypted_ballot_public_aggregation_rejects_private_development_fields() {
    for field_name in [
        "setupPackage",
        "setupPublicMaterial",
        "setupPrivateWitness",
        "ballots",
        "scores",
        "ballotEncryptionRandomness",
        "proofMaskRandomness",
        "topCount",
        "topCounts",
        "publicEvaluationKeyMaterial",
        "targetFinalityPolicyHash",
    ] {
        let mut request = json!({});
        request[field_name] = match field_name {
            "setupPackage" | "setupPublicMaterial" => setup_package_not_reached(),
            "setupPrivateWitness" => json!({ "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED }),
            "ballots" => json!([direct_ballot_test_ballot_json(
                "voter-public-aggregation-rejection",
                0
            )]),
            "scores" | "topCounts" => json!([1, 2]),
            "ballotEncryptionRandomness" => direct_ballot_test_ballot_encryption_randomness(1),
            "proofMaskRandomness" => direct_ballot_test_proof_mask_randomness(1),
            "topCount" => json!(1),
            "publicEvaluationKeyMaterial" => json!({ "material": "not accepted here" }),
            "targetFinalityPolicyHash" => json!("a".repeat(128)),
            _ => unreachable!("all public aggregation rejection fields are covered"),
        };

        let error = aggregate_direct_encrypted_ballot_packages(&request)
            .expect_err("public aggregation command must reject private development field");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error
                .message
                .contains(&format!("does not accept {field_name}")),
            "unexpected error message: {}",
            error.message
        );
    }
}

#[test]
fn direct_encrypted_ballot_public_aggregation_rejects_incomplete_first_valid_binding_early() {
    let error = aggregate_direct_encrypted_ballot_packages(&json!({
        "firstValidOrderHash": "0".repeat(128)
    }))
    .expect_err("incomplete first-valid binding must reject before package verification");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires firstValidOrderHash and firstValidPackageRoots together")
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
