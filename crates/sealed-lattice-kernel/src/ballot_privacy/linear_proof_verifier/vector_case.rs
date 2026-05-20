use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::vector_case_verifier::invalid_vector;
use crate::{
    ballot_privacy::{
        linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
        linear_proof_statement::{
            LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
        },
    },
    encoding::CanonicalResult,
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
    pub proof_encoding: Option<LinearProofEncoding>,
    pub public_randomness_hex: Option<String>,
    pub statement_matrix_coefficients: Option<Vec<Vec<Vec<u64>>>>,
    pub target_vector_coefficients: Option<Vec<Vec<u64>>>,
    pub matrix_coefficient_representation: Option<LinearProofMatrixCoefficientRepresentation>,
    pub target_coefficient_representation: Option<LinearProofTargetCoefficientRepresentation>,
    pub proof_hex: Option<String>,
    pub expected_proof_size_bytes: Option<usize>,
    pub trace: Option<LinearProofVectorTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofVectorTrace {
    pub decoded_proof_field_lengths: Option<Value>,
    pub sealed_lattice_preflight_transcript: Option<Value>,
}

impl LinearProofVectorCase {
    pub(super) fn expected_decoded_proof_field_lengths(&self) -> Option<&Value> {
        self.trace
            .as_ref()
            .and_then(|trace| trace.decoded_proof_field_lengths.as_ref())
    }

    pub(super) fn expected_decoder_error(&self) -> CanonicalResult<Option<&str>> {
        match self
            .expected_decoded_proof_field_lengths()
            .and_then(|field_lengths| field_lengths.get("decoderError"))
        {
            Some(Value::String(decoder_error)) => Ok(Some(decoder_error.as_str())),
            Some(_) => Err(invalid_vector(
                "trace decodedProofFieldLengths.decoderError must be a string",
            )),
            None => Ok(None),
        }
    }

    pub(super) fn validate_case_metadata(&self) -> CanonicalResult<()> {
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
        if self.expected_outcome == "pending-upstream-generation" && self.upstream_vector_available
        {
            return Err(invalid_vector(
                "pending-upstream-generation vectors must not include available proof bytes",
            ));
        }

        Ok(())
    }
}
