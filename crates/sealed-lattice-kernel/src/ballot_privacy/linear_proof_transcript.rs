use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    encoding::CanonicalResult,
    hashing::{canonical_json, to_hex},
};

pub const LINEAR_PROOF_PREFLIGHT_DOMAIN: &str = "sealed.vote/internal/linear-proof-preflight-v1";
pub const LINEAR_PROOF_PREFLIGHT_HASH_NAME: &str = "SHAKE128-256";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearProofPreflightTranscriptInput<'input> {
    pub parameter_set: &'input Value,
    pub statement_matrix_coefficients: &'input Value,
    pub target_vector_coefficients: &'input Value,
    pub public_randomness: &'input [u8],
    pub proof_bytes: &'input [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofPreflightTranscript {
    pub domain: String,
    pub hash: String,
    pub parameter_digest: String,
    pub statement_digest: String,
    pub target_digest: String,
    pub proof_digest: String,
    pub public_randomness_digest: String,
    pub preflight_transcript_digest: String,
}

pub fn shake128_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake128::default();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 32];
    reader.read(&mut output);

    output
}

pub fn shake128_64(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Shake128::default();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);

    output
}

pub fn shake128_96(parts: &[&[u8]]) -> [u8; 96] {
    let mut hasher = Shake128::default();
    for part in parts {
        hasher.update(part);
    }
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 96];
    reader.read(&mut output);

    output
}

pub fn shake128_32_hex(parts: &[&[u8]]) -> String {
    to_hex(&shake128_32(parts))
}

pub fn canonical_json_shake128_32_hex(value: &Value) -> CanonicalResult<String> {
    let canonical = canonical_json(value)?;

    Ok(shake128_32_hex(&[canonical.as_bytes()]))
}

pub fn compute_linear_proof_preflight_transcript(
    input: LinearProofPreflightTranscriptInput<'_>,
) -> CanonicalResult<LinearProofPreflightTranscript> {
    let parameter_set_canonical = canonical_json(input.parameter_set)?;
    let statement_matrix_canonical = canonical_json(input.statement_matrix_coefficients)?;
    let target_vector_canonical = canonical_json(input.target_vector_coefficients)?;

    let parameter_digest = shake128_32_hex(&[parameter_set_canonical.as_bytes()]);
    let statement_digest = shake128_32_hex(&[statement_matrix_canonical.as_bytes()]);
    let target_digest = shake128_32_hex(&[target_vector_canonical.as_bytes()]);
    let proof_digest = shake128_32_hex(&[input.proof_bytes]);
    let public_randomness_digest = shake128_32_hex(&[input.public_randomness]);
    let preflight_transcript_digest = shake128_32_hex(&[
        LINEAR_PROOF_PREFLIGHT_DOMAIN.as_bytes(),
        parameter_set_canonical.as_bytes(),
        statement_matrix_canonical.as_bytes(),
        target_vector_canonical.as_bytes(),
        input.public_randomness,
        input.proof_bytes,
    ]);

    Ok(LinearProofPreflightTranscript {
        domain: LINEAR_PROOF_PREFLIGHT_DOMAIN.to_string(),
        hash: LINEAR_PROOF_PREFLIGHT_HASH_NAME.to_string(),
        parameter_digest,
        statement_digest,
        target_digest,
        proof_digest,
        public_randomness_digest,
        preflight_transcript_digest,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        LinearProofPreflightTranscriptInput, canonical_json_shake128_32_hex,
        compute_linear_proof_preflight_transcript, shake128_32_hex,
    };

    fn generated_vector_case(case_name: &str) -> serde_json::Value {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("generated vector file should parse");

        vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == case_name)
            .unwrap_or_else(|| panic!("generated vector case {case_name} should exist"))
            .clone()
    }

    fn decode_lower_hex(hex_value: &str) -> Vec<u8> {
        crate::transcript_core::decode_hex(hex_value).expect("hex should decode")
    }

    #[test]
    fn shake128_empty_input_matches_known_answer() {
        assert_eq!(
            shake128_32_hex(&[b""]),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn canonical_json_digest_is_order_independent() {
        let left = canonical_json_shake128_32_hex(&json!({
            "parameter": 17,
            "profile": "demo"
        }))
        .expect("digest should compute");
        let right = canonical_json_shake128_32_hex(&json!({
            "profile": "demo",
            "parameter": 17
        }))
        .expect("digest should compute");

        assert_eq!(left, right);
    }

    #[test]
    fn preflight_transcript_binds_each_public_component() {
        let valid_case = generated_vector_case("valid-small-linear-proof");
        let mutated_statement_case = generated_vector_case("mutated-statement-matrix");
        let mutated_target_case = generated_vector_case("mutated-target-vector");
        let mutated_proof_case = generated_vector_case("mutated-proof-byte");
        let wrong_randomness_case = generated_vector_case("wrong-public-randomness");

        let compute_digest = |vector_case: &serde_json::Value| {
            let public_randomness = decode_lower_hex(
                vector_case["publicRandomnessHex"]
                    .as_str()
                    .expect("public randomness should be present"),
            );
            let proof_bytes = decode_lower_hex(
                vector_case["proofHex"]
                    .as_str()
                    .expect("proof bytes should be present"),
            );

            compute_linear_proof_preflight_transcript(LinearProofPreflightTranscriptInput {
                parameter_set: &vector_case["parameterSet"],
                statement_matrix_coefficients: &vector_case["statementMatrixCoefficients"],
                target_vector_coefficients: &vector_case["targetVectorCoefficients"],
                public_randomness: &public_randomness,
                proof_bytes: &proof_bytes,
            })
            .expect("preflight transcript should compute")
            .preflight_transcript_digest
        };

        let valid_digest = compute_digest(&valid_case);

        assert_ne!(valid_digest, compute_digest(&mutated_statement_case));
        assert_ne!(valid_digest, compute_digest(&mutated_target_case));
        assert_ne!(valid_digest, compute_digest(&mutated_proof_case));
        assert_ne!(valid_digest, compute_digest(&wrong_randomness_case));
    }
}
