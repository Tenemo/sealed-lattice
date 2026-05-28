use super::vector_case::LinearProofVectorCase;
use crate::ballot_privacy::linear_proof::parameters::linear_proof_claim_boundary_status_labels;
use crate::ballot_privacy::{BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE, describe_proof_backend};
use crate::encoding::{CanonicalError, CanonicalErrorCode};
use serde_json::{Value, json};
pub fn verify_linear_proof_vector_case_value(vector_case: &Value) -> Value {
    let parsed_case: LinearProofVectorCase = match serde_json::from_value(vector_case.clone()) {
        Ok(parsed_case) => parsed_case,
        Err(error) => {
            return invalid_fixture_value(format!("linear proof vector shape is invalid: {error}"));
        }
    };

    if let Err(error) = parsed_case.validate_and_verify() {
        return error_value_for_case(error, &parsed_case);
    }

    if !parsed_case.upstream_vector_available {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": parsed_case.case_name,
            "vectorAvailable": false,
            "expectedOutcome": parsed_case.expected_outcome,
            "statusLabels": [],
            "acceptedHashes": [],
            "refusedObjects": [
                {
                    "code": "OperationUnavailable",
                    "message": "Upstream linear proof bytes for this vector case have not been generated in the current environment."
                }
            ],
            "unresolvedReason": "OperationUnavailable"
        });
    }

    let mut verified_status_labels = vec![
        "LinearProofCanonicalBytesVerified",
        "LinearProofNormBoundsChecked",
        "AbdlopPublicParametersExpanded",
        "AbdlopLinearOpeningRecovered",
        "TboxZ34ChallengeUpdated",
        "TboxGeneratorChallengeUpdated",
        "QuadraticAccumulatorHelpersChecked",
        "TboxRelationBuildersChecked",
        "TboxResponseRelationBuildersChecked",
        "ManyQuadraticEquationsFolded",
        "QuadraticChallengeRecomputed",
    ];
    if let Some(proof_encoding) = parsed_case.proof_encoding.as_ref() {
        verified_status_labels.extend(linear_proof_claim_boundary_status_labels(proof_encoding));
    }

    if parsed_case.expected_outcome == "reject" {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": parsed_case.case_name,
            "vectorAvailable": true,
            "expectedOutcome": parsed_case.expected_outcome,
            "statusLabels": verified_status_labels,
            "acceptedHashes": [],
            "refusedObjects": [
                {
                    "code": "FixtureMismatch",
                    "message": "Reject vector unexpectedly verified as a valid linear lattice proof."
                }
            ],
            "unresolvedReason": "FixtureMismatch"
        });
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "caseName": parsed_case.case_name,
        "vectorAvailable": true,
        "expectedOutcome": parsed_case.expected_outcome,
        "statusLabels": verified_status_labels,
        "acceptedHashes": [],
        "refusedObjects": [],
        "unresolvedReason": null
    })
}

pub(super) fn invalid_fixture_value(message: impl Into<String>) -> Value {
    error_value(invalid_vector(message))
}

pub(super) fn error_value(error: CanonicalError) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "statusLabels": [],
        "acceptedHashes": [],
        "refusedObjects": [
            {
                "code": error.code.as_str(),
                "message": error.message
            }
        ],
        "unresolvedReason": error.code.as_str()
    })
}

pub(super) fn error_value_for_case(
    error: CanonicalError,
    parsed_case: &LinearProofVectorCase,
) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "caseName": parsed_case.case_name,
        "vectorAvailable": parsed_case.upstream_vector_available,
        "expectedOutcome": parsed_case.expected_outcome,
        "statusLabels": [],
        "acceptedHashes": [],
        "refusedObjects": [
            {
                "code": error.code.as_str(),
                "message": error.message
            }
        ],
        "unresolvedReason": error.code.as_str()
    })
}

pub(super) fn invalid_vector(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use crate::ballot_privacy::linear_proof::profile_constants::{
        DEMO_GENERATED_PARAMETER_CONTRACT, DEMO_GENERATED_PROFILE,
    };
    use serde_json::Value;
    use serde_json::json;

    use super::verify_linear_proof_vector_case_value;

    fn integer_property(value: &Value, field_name: &str) -> usize {
        value
            .get(field_name)
            .and_then(Value::as_u64)
            .and_then(|field_value| usize::try_from(field_value).ok())
            .unwrap_or_else(|| panic!("{field_name} should be a usize-compatible integer"))
    }

    fn apply_statement_matrix_patch(statement_matrix: &mut Value, patch: &Value) {
        let row_index = integer_property(patch, "rowIndex");
        let column_index = integer_property(patch, "columnIndex");
        let coefficient_index = integer_property(patch, "coefficientIndex");
        let coefficient = patch
            .get("coefficient")
            .cloned()
            .expect("statement matrix patch coefficient should exist");

        statement_matrix[row_index][column_index][coefficient_index] = coefficient;
    }

    fn apply_target_vector_patch(target_vector: &mut Value, patch: &Value) {
        let row_index = integer_property(patch, "rowIndex");
        let coefficient_index = integer_property(patch, "coefficientIndex");
        let coefficient = patch
            .get("coefficient")
            .cloned()
            .expect("target vector patch coefficient should exist");

        target_vector[row_index][coefficient_index] = coefficient;
    }

    fn expand_encoded_score_field_vector_case(vectors: &Value, compact_case: &Value) -> Value {
        let mut statement_matrix =
            vectors["linearStatement"]["statementMatrixCoefficients"].clone();
        let mut target_vector = vectors["linearStatement"]["targetVectorCoefficients"].clone();
        if let Some(statement_matrix_patch) = compact_case.get("statementMatrixPatch") {
            apply_statement_matrix_patch(&mut statement_matrix, statement_matrix_patch);
        }
        if let Some(target_vector_patch) = compact_case.get("targetVectorPatch") {
            apply_target_vector_patch(&mut target_vector, target_vector_patch);
        }

        json!({
            "caseName": compact_case["caseName"],
            "description": compact_case["description"],
            "mutation": compact_case["mutation"],
            "expectedOutcome": compact_case["expectedOutcome"],
            "upstreamVectorAvailable": compact_case["upstreamVectorAvailable"],
            "parameterSet": vectors["parameterSet"],
            "proofEncoding": vectors["proofEncoding"],
            "publicRandomnessHex": compact_case
                .get("publicRandomnessHex")
                .cloned()
                .unwrap_or_else(|| vectors["publicRandomnessHex"].clone()),
            "statementMatrixCoefficients": statement_matrix,
            "matrixCoefficientRepresentation": vectors
                .get("matrixCoefficientRepresentation")
                .cloned()
                .expect(
                    "encoded-score field vectors should define matrixCoefficientRepresentation",
                ),
            "targetVectorCoefficients": target_vector,
            "targetCoefficientRepresentation": vectors["targetCoefficientRepresentation"],
            "proofHex": compact_case
                .get("proofHex")
                .cloned()
                .unwrap_or_else(|| vectors["proofHex"].clone()),
            "expectedProofSizeBytes": vectors["expectedProofSizeBytes"],
            "trace": compact_case["trace"]
        })
    }

    #[test]
    fn pending_upstream_vector_fails_closed() {
        let verification = verify_linear_proof_vector_case_value(&json!({
            "caseName": "valid-small-linear-proof",
            "description": "Valid proof bytes are generated from the upstream oracle in a compatible environment.",
            "mutation": "none",
            "expectedOutcome": "pending-upstream-generation",
            "upstreamVectorAvailable": false,
            "parameterSet": null,
            "publicRandomnessHex": null,
            "proofHex": null,
            "expectedProofSizeBytes": null
        }));

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["vectorAvailable"], false);
        assert_eq!(verification["unresolvedReason"], "OperationUnavailable");
    }

    #[test]
    fn pending_upstream_vector_with_available_bytes_is_invalid() {
        let verification = verify_linear_proof_vector_case_value(&json!({
            "caseName": "bad-pending-with-bytes",
            "description": "Malformed vector shape used by the schema test.",
            "mutation": "none",
            "expectedOutcome": "pending-upstream-generation",
            "upstreamVectorAvailable": true
        }));

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["unresolvedReason"], "InvalidFixture");
        assert!(
            verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("message should be a string")
                .contains("must not include available proof bytes")
        );
    }

    #[test]
    fn available_vector_shape_rejects_bad_public_randomness_length() {
        let verification = verify_linear_proof_vector_case_value(&json!({
            "caseName": "bad-public-randomness",
            "description": "Malformed vector shape used by the schema test.",
            "mutation": "wrong-public-randomness",
            "expectedOutcome": "reject",
            "upstreamVectorAvailable": true,
            "parameterSet": {
                "profileId": "demo-linear-proof-parameter-v1",
                "source": "sealed-lattice/linear-proof/demo-parameters-v1",
                "relation": "A*w + t = 0",
                "ringDegree": DEMO_GENERATED_PARAMETER_CONTRACT.source_ring_degree,
                "proofSystemRingDegree": DEMO_GENERATED_PARAMETER_CONTRACT.proof_system_ring_degree,
                "coefficientModulus": DEMO_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus,
                "statementRows": DEMO_GENERATED_PARAMETER_CONTRACT.statement_rows,
                "statementColumns": DEMO_GENERATED_PARAMETER_CONTRACT.statement_columns,
                "witnessL2BoundSquared": DEMO_GENERATED_PROFILE.exact_norm_bound_squared,
                "expectedProofSizeBytes": 2
            },
            "publicRandomnessHex": "00",
            "proofHex": "0001",
            "expectedProofSizeBytes": 2
        }));

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["unresolvedReason"], "InvalidFixture");
        assert!(
            verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("message should be a string")
                .contains("32 bytes")
        );
    }

    #[test]
    fn decoder_error_reject_vectors_are_valid_negative_fixtures() {
        let linear_vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        )))
        .expect("generated vector file should parse");
        let receiver_key_vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
        )))
        .expect("receiver-key linear vector file should parse");
        let encoded_score_field_vectors: serde_json::Value =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
            )))
            .expect("encoded-score field vector file should parse");

        for (vectors, case_name) in [
            (&linear_vectors, "truncated-proof"),
            (&linear_vectors, "extended-proof"),
            (&receiver_key_vectors, "truncated-receiver-key-proof"),
            (&receiver_key_vectors, "extended-receiver-key-proof"),
        ] {
            let vector_case = vectors["cases"]
                .as_array()
                .expect("generated vector file should contain cases")
                .iter()
                .find(|vector_case| vector_case["caseName"] == case_name)
                .unwrap_or_else(|| panic!("{case_name} should exist"));
            let verification = verify_linear_proof_vector_case_value(vector_case);

            assert_eq!(verification["ok"], false);
            assert_eq!(verification["caseName"], case_name);
            assert_eq!(verification["vectorAvailable"], true);
            assert_eq!(verification["unresolvedReason"], "FixtureMismatch");
        }

        for case_name in [
            "truncated-encoded-score-field-proof",
            "extended-encoded-score-field-proof",
        ] {
            let compact_case = encoded_score_field_vectors["cases"]
                .as_array()
                .expect("encoded-score field vector file should contain cases")
                .iter()
                .find(|vector_case| vector_case["caseName"] == case_name)
                .unwrap_or_else(|| panic!("{case_name} should exist"));
            let vector_case =
                expand_encoded_score_field_vector_case(&encoded_score_field_vectors, compact_case);
            let verification = verify_linear_proof_vector_case_value(&vector_case);

            assert_eq!(verification["ok"], false);
            assert_eq!(verification["caseName"], case_name);
            assert_eq!(verification["vectorAvailable"], true);
            assert_eq!(verification["unresolvedReason"], "FixtureMismatch");
        }
    }

    #[test]
    fn generated_upstream_vector_verifies() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        )))
        .expect("generated vector file should parse");
        let vector_case = vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-small-linear-proof")
            .expect("valid generated vector should exist");

        let verification = verify_linear_proof_vector_case_value(vector_case);

        assert_eq!(
            verification["ok"], true,
            "receiver-key vector verification failed: {verification}"
        );
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["unresolvedReason"], serde_json::Value::Null);
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("QuadraticChallengeRecomputed"))
        );
    }

    #[test]
    fn generated_upstream_mutations_fail_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        )))
        .expect("generated vector file should parse");

        for vector_case in vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .filter(|vector_case| vector_case["expectedOutcome"] == "reject")
        {
            let verification = verify_linear_proof_vector_case_value(vector_case);

            assert_eq!(
                verification["ok"], false,
                "{} should fail closed",
                vector_case["caseName"]
            );
            assert_eq!(verification["caseName"], vector_case["caseName"]);
            assert_eq!(verification["vectorAvailable"], true);
            assert!(
                verification["refusedObjects"][0]["message"]
                    .as_str()
                    .expect("refusal message should be a string")
                    .len()
                    > 8
            );
        }
    }

    #[test]
    fn generated_receiver_key_vector_verifies() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
        )))
        .expect("receiver-key linear vector file should parse");
        let vector_case = vectors["cases"]
            .as_array()
            .expect("receiver-key vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-receiver-key-linear-proof")
            .expect("valid receiver-key vector should exist");

        let verification = verify_linear_proof_vector_case_value(vector_case);

        assert_eq!(
            verification["ok"], true,
            "receiver-key vector verification failed: {verification}"
        );
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["unresolvedReason"], serde_json::Value::Null);
    }

    #[test]
    fn generated_receiver_key_mutations_fail_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
        )))
        .expect("receiver-key linear vector file should parse");

        for vector_case in vectors["cases"]
            .as_array()
            .expect("receiver-key vector file should contain cases")
            .iter()
            .filter(|vector_case| vector_case["expectedOutcome"] == "reject")
        {
            let verification = verify_linear_proof_vector_case_value(vector_case);

            assert_eq!(
                verification["ok"], false,
                "{} should fail closed",
                vector_case["caseName"]
            );
            assert_eq!(verification["caseName"], vector_case["caseName"]);
            assert_eq!(verification["vectorAvailable"], true);
            assert!(
                verification["refusedObjects"][0]["message"]
                    .as_str()
                    .expect("refusal message should be a string")
                    .len()
                    > 8
            );
        }
    }

    #[test]
    fn generated_encoded_score_field_vector_verifies() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
        )))
        .expect("encoded-score field vector file should parse");
        let compact_case = vectors["cases"]
            .as_array()
            .expect("encoded-score field vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-encoded-score-field-linear-proof")
            .expect("valid encoded-score field vector should exist");
        let vector_case = expand_encoded_score_field_vector_case(&vectors, compact_case);

        let verification = verify_linear_proof_vector_case_value(&vector_case);

        assert_eq!(
            verification["ok"], true,
            "encoded-score field vector verification failed: {verification}"
        );
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["backendAvailable"], true);
        assert_eq!(verification["unresolvedReason"], serde_json::Value::Null);
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("QuadraticChallengeRecomputed"))
        );
    }

    #[test]
    fn generated_encoded_score_field_mutations_fail_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
        )))
        .expect("encoded-score field vector file should parse");

        for compact_case in vectors["cases"]
            .as_array()
            .expect("encoded-score field vector file should contain cases")
            .iter()
            .filter(|vector_case| vector_case["expectedOutcome"] == "reject")
        {
            let vector_case = expand_encoded_score_field_vector_case(&vectors, compact_case);
            let verification = verify_linear_proof_vector_case_value(&vector_case);

            assert_eq!(
                verification["ok"], false,
                "{} should fail closed",
                compact_case["caseName"]
            );
            assert_eq!(verification["caseName"], compact_case["caseName"]);
            assert_eq!(verification["vectorAvailable"], true);
            assert! {
                verification["refusedObjects"][0]["message"]
                    .as_str()
                    .expect("refusal message should be a string")
                    .len()
                    > 8
            };
        }
    }
}
