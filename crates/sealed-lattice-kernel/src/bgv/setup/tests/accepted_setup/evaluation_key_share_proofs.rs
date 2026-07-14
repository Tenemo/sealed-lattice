use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_evaluation_key_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_evaluation_key_material",
    );
    assert_collective_public_key_bearing_setup_package_refused(
        "relinearization key-share rounds replaced with a malformed object",
        |package| {
            let evaluator_key_schedule_root =
                package["evaluatorKeySchedule"]["evaluatorKeyScheduleRoot"].clone();
            package["relinearizationKeyShareRounds"] = serde_json::json!({
                "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
            });
        },
        "wrongTypeOrLength",
    );
}

#[test]
fn collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records",
    );
    assert_collective_public_key_bearing_setup_package_refused(
        "trustee evaluation-key proofs object without share records",
        |package| {
            package["trusteeEvaluationKeyProofs"] = serde_json::json!({
                "objectType": "TrusteeEvaluationKeyProofSet",
            });
        },
        "invalidProof",
    );
}
