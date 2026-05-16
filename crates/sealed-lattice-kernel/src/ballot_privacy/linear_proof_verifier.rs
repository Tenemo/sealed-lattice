use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    transcript_core::decode_hex,
};

use super::{
    BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE, describe_proof_backend,
    linear_proof_parameters::{LazerDemoProofEncoding, LinearProofParameterSet},
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    proof_coder::{LinearProofBytes, decode_lazer_demo_linear_proof_fields},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofVectorCase {
    pub case_name: String,
    pub description: String,
    pub mutation: String,
    pub expected_outcome: String,
    pub upstream_vector_available: bool,
    pub parameter_set: Option<LinearProofParameterSet>,
    pub proof_encoding: Option<LazerDemoProofEncoding>,
    pub public_randomness_hex: Option<String>,
    pub statement_matrix_coefficients: Option<Vec<Vec<Vec<u64>>>>,
    pub target_vector_coefficients: Option<Vec<Vec<u64>>>,
    pub proof_hex: Option<String>,
    pub expected_proof_size_bytes: Option<usize>,
    pub trace: Option<LinearProofVectorTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofVectorTrace {
    pub decoded_proof_field_lengths: Option<Value>,
}

impl LinearProofVectorCase {
    pub fn validate_shape(&self) -> CanonicalResult<()> {
        if self.case_name.is_empty() {
            return Err(invalid_vector("caseName must not be empty"));
        }
        if self.description.is_empty() {
            return Err(invalid_vector("description must not be empty"));
        }
        if !matches!(
            self.expected_outcome.as_str(),
            "accept" | "reject" | "pending-upstream-generation"
        ) {
            return Err(invalid_vector(
                "expectedOutcome must be accept, reject, or pending-upstream-generation",
            ));
        }
        if self.upstream_vector_available {
            self.parameter_set
                .as_ref()
                .ok_or_else(|| invalid_vector("available vectors require parameterSet"))?
                .validate()?;
            let parameter_set = self
                .parameter_set
                .as_ref()
                .ok_or_else(|| invalid_vector("available vectors require parameterSet"))?;
            let public_randomness_hex = self
                .public_randomness_hex
                .as_deref()
                .ok_or_else(|| invalid_vector("available vectors require publicRandomnessHex"))?;
            let public_randomness = decode_hex(public_randomness_hex)?;
            if public_randomness.len() != 32 {
                return Err(invalid_vector(
                    "publicRandomnessHex must encode exactly 32 bytes",
                ));
            }
            let proof_hex = self
                .proof_hex
                .as_deref()
                .ok_or_else(|| invalid_vector("available vectors require proofHex"))?;
            let proof_bytes =
                LinearProofBytes::from_hex(proof_hex, self.expected_proof_size_bytes)?;
            if let Some(proof_encoding) = self.proof_encoding.as_ref() {
                proof_encoding.validate()?;
                let decoded_field_lengths =
                    decode_lazer_demo_linear_proof_fields(proof_bytes.bytes(), proof_encoding)?;
                if let Some(expected_field_lengths) = self
                    .trace
                    .as_ref()
                    .and_then(|trace| trace.decoded_proof_field_lengths.as_ref())
                    && expected_field_lengths.get("decoderError").is_none()
                    && *expected_field_lengths
                        != serde_json::to_value(decoded_field_lengths).map_err(|error| {
                            invalid_vector(format!(
                                "decoded proof field lengths could not be serialized: {error}"
                            ))
                        })?
                {
                    return Err(invalid_vector(
                        "decoded proof field lengths do not match the upstream trace",
                    ));
                }
            }
            let statement_matrix_coefficients = self
                .statement_matrix_coefficients
                .as_deref()
                .ok_or_else(|| {
                    invalid_vector("available vectors require statementMatrixCoefficients")
                })?;
            decode_statement_matrix(parameter_set, statement_matrix_coefficients)?;
            let target_vector_coefficients =
                self.target_vector_coefficients.as_deref().ok_or_else(|| {
                    invalid_vector("available vectors require targetVectorCoefficients")
                })?;
            decode_target_vector(parameter_set, target_vector_coefficients)?;
        }

        Ok(())
    }
}

fn decode_statement_matrix(
    parameter_set: &LinearProofParameterSet,
    coefficients: &[Vec<Vec<u64>>],
) -> CanonicalResult<PolynomialMatrix> {
    if coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_vector(format!(
            "statementMatrixCoefficients must contain {} rows",
            parameter_set.statement_rows
        )));
    }

    let ring = PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
    let mut entries =
        Vec::with_capacity(parameter_set.statement_rows * parameter_set.statement_columns);
    for row in coefficients {
        if row.len() != parameter_set.statement_columns {
            return Err(invalid_vector(format!(
                "each statementMatrixCoefficients row must contain {} columns",
                parameter_set.statement_columns
            )));
        }
        for polynomial_coefficients in row {
            entries.push(polynomial_coefficients.clone());
        }
    }

    PolynomialMatrix::new(
        ring,
        parameter_set.statement_rows,
        parameter_set.statement_columns,
        entries,
    )
}

fn decode_target_vector(
    parameter_set: &LinearProofParameterSet,
    coefficients: &[Vec<u64>],
) -> CanonicalResult<PolynomialVector> {
    if coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_vector(format!(
            "targetVectorCoefficients must contain {} entries",
            parameter_set.statement_rows
        )));
    }

    let ring = PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
    PolynomialVector::new(ring, coefficients.to_vec())
}

pub fn verify_linear_proof_vector_case_value(vector_case: &Value) -> Value {
    let parsed_case: LinearProofVectorCase = match serde_json::from_value(vector_case.clone()) {
        Ok(parsed_case) => parsed_case,
        Err(error) => {
            return invalid_fixture_value(format!("linear proof vector shape is invalid: {error}"));
        }
    };

    if let Err(error) = parsed_case.validate_shape() {
        return error_value(error);
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
            "acceptedDigests": [],
            "refusedObjects": [
                {
                    "code": "OperationUnavailable",
                    "message": "Upstream LaZer proof bytes for this vector case have not been generated in the current environment."
                }
            ],
            "unresolvedReason": "OperationUnavailable"
        });
    }

    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "caseName": parsed_case.case_name,
        "vectorAvailable": true,
        "expectedOutcome": parsed_case.expected_outcome,
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": [
            {
                "code": "OperationUnavailable",
                "message": "Portable LaZer-style linear proof verification is not implemented in this build."
            }
        ],
        "unresolvedReason": "OperationUnavailable"
    })
}

fn invalid_fixture_value(message: impl Into<String>) -> Value {
    error_value(invalid_vector(message))
}

fn error_value(error: CanonicalError) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": [
            {
                "code": error.code.as_str(),
                "message": error.message
            }
        ],
        "unresolvedReason": error.code.as_str()
    })
}

fn invalid_vector(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::verify_linear_proof_vector_case_value;

    #[test]
    fn pending_upstream_vector_fails_closed() {
        let verification = verify_linear_proof_vector_case_value(&json!({
            "caseName": "valid-small-linear-proof",
            "description": "Valid proof bytes are generated from upstream LaZer in a compatible environment.",
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
    fn available_vector_shape_rejects_bad_public_randomness_length() {
        let verification = verify_linear_proof_vector_case_value(&json!({
            "caseName": "bad-public-randomness",
            "description": "Malformed vector shape used by the schema test.",
            "mutation": "wrong-public-randomness",
            "expectedOutcome": "reject",
            "upstreamVectorAvailable": true,
            "parameterSet": {
                "profileId": "lazer-linear-demo-compatibility-v1",
                "source": "temp/lazer/python/demo/demo_params.h",
                "relation": "A*w + t = 0",
                "ringDegree": 256,
                "proofSystemRingDegree": 64,
                "coefficientModulus": 4294962689_u64,
                "statementRows": 4,
                "statementColumns": 8,
                "witnessL2BoundSquared": 2048_u64,
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
    fn generated_upstream_vector_decodes_and_fails_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("generated vector file should parse");
        let vector_case = vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-small-linear-proof")
            .expect("valid generated vector should exist");

        let verification = verify_linear_proof_vector_case_value(vector_case);

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["unresolvedReason"], "OperationUnavailable");
    }
}
