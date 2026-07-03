use super::*;

#[test]
fn collective_setup_verifier_refuses_generic_key_switch_material_by_default() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_generic_key_switch_material_by_default",
    );
    assert_minimal_collective_setup_package_refused(
        "generic key-switch keys present by default",
        |package| {
            package["genericKeySwitchKeys"] = serde_json::json!({ "keyRoot": valid_hash('4') });
        },
        "genericKeySwitchOutsideParameters",
    );
}

#[test]
fn collective_setup_verifier_refuses_evaluator_schedule_drift() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_evaluator_schedule_drift");
    assert_minimal_collective_setup_package_refused(
        "drifted evaluator key schedule required Galois set hash",
        |package| {
            package["evaluatorKeySchedule"]["requiredGaloisSetHash"] =
                serde_json::json!(valid_hash('8'));
        },
        "requiredGaloisSetHashMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_evaluation_key_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_evaluation_key_material",
    );
    assert_minimal_collective_setup_package_refused(
        "relinearization key-share rounds replaced with a malformed object",
        |package| {
            let evaluator_key_schedule_root =
                package["evaluatorKeySchedule"]["evaluatorKeyScheduleRoot"].clone();
            package["relinearizationKeyShareRounds"] = serde_json::json!({
                "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
            });
        },
        "relinearizationKeyShareRoundsTypeMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "evaluation keys replaced with a malformed object",
        |package| {
            package["evaluationKeys"] = serde_json::json!({
                "evaluationKeyRoot": valid_hash('9'),
            });
        },
        "evaluationKeysTypeMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records",
    );
    assert_minimal_collective_setup_package_refused(
        "trustee evaluation-key proofs object without share records",
        |package| {
            package["trusteeEvaluationKeyProofs"] = serde_json::json!({
                "objectType": "TrusteeEvaluationKeyProofSet",
            });
        },
        "trusteeEvaluationKeyProofsWithoutShareRecords",
    );
}
