use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_same_secret_statements() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_same_secret_statements",
    );
    assert_minimal_collective_setup_package_refused(
        "wrong same-secret constant coefficient commitment root",
        |package| {
            package["sameSecretConsistency"]["statementRecords"][0]["constantCoefficientCommitmentRoots"]
                [0]["commitmentRoot"] = serde_json::json!(valid_hash('4'));
            rebind_collective_same_secret_statement_roots(package);
        },
        "sameSecretConstantCommitmentRootMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong same-secret statement root",
        |package| {
            package["sameSecretConsistency"]["statementRecords"][0]["sameSecretStatementRoot"] =
                serde_json::json!(valid_hash('5'));
            rebind_collective_same_secret_consistency_root(package);
        },
        "sameSecretStatementRootMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong same-secret proof family binding root",
        |package| {
            package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"] =
                serde_json::json!(valid_hash('6'));
            rebind_collective_same_secret_consistency_root(package);
        },
        "sameSecretProofFamilyBindingRootMismatch",
    );
}
