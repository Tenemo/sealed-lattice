use serde_json::Value;

use super::{
    json_helpers::object_map, protocol_constants::BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION,
};

pub(crate) const FULL_BALLOT_PROOF_PROJECTION_COVERAGE: &str = "full-encoded-score-ballot-relation";
pub(crate) const FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID: &str =
    "full-encoded-score-ballot-linear-compatibility-v1";
pub(crate) const FULL_BALLOT_PROOF_ENCODING_PROFILE_ID: &str =
    "full-encoded-score-ballot-linear-proof-encoding-v1";
pub(crate) const RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID: &str =
    "receiver-key-linear-module-lwe-v1";
pub(crate) const RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID: &str =
    "receiver-key-linear-proof-encoding-v1";
pub(crate) const COMPONENT_BUNDLE_INCOMPLETE_COVERAGE: &str = "component-bundle-incomplete";
pub(crate) const REQUIRED_BALLOT_PROOF_COMPONENT_IDS: &[&str] = &[
    "score-and-shamir-field-component",
    "payload-plaintext-field-component",
    "share-commitment-component",
    "receiver-encryption-component",
    "receiver-key-binding-component",
];
pub(crate) const ALLOWED_BALLOT_PROOF_COMPONENT_STATEMENT_FORMATS: &[&str] = &[
    "dense-polynomial-matrix-linear-proof-v1",
    "sparse-polynomial-matrix-linear-proof-v1",
    "structured-module-sis-share-commitment-v1",
    "structured-module-lwe-linear-proof-v1",
    "public-zero-witness-binding-check-v1",
];
pub(crate) const DENSE_COMPONENT_PROOF_STATEMENT_FORMAT: &str =
    "dense-polynomial-matrix-linear-proof-v1";
pub(crate) const SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT: &str =
    "sparse-polynomial-matrix-linear-proof-v1";
pub(crate) const STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT: &str =
    "structured-module-sis-share-commitment-v1";
pub(crate) const STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT: &str =
    "structured-module-lwe-linear-proof-v1";
pub(crate) const PUBLIC_ZERO_PROOF_STATEMENT_FORMAT: &str = "public-zero-witness-binding-check-v1";
pub(crate) const MAX_GENERIC_SPARSE_COMPONENT_SHORT_RESPONSE_VECTOR_LENGTH: usize = 4_096;
pub(crate) const AVAILABLE_DENSE_PROOF_BYTES: &str = "available-for-small-dense-oracle";
pub(crate) const REQUIRES_SPARSE_PROOF_STATEMENT: &str = "requires-sparse-proof-statement";
pub(crate) const REQUIRES_STRUCTURED_PROOF_STATEMENT: &str = "requires-structured-proof-statement";
pub(crate) const PUBLIC_ZERO_WITNESS_BINDING_CHECK: &str = "public-zero-witness-binding-check";
pub(crate) const SHARE_COMMITMENT_MODULE_RANK: usize = 4;
pub(crate) const SHARE_COMMITMENT_MODULE_DEGREE: usize = 256;
pub(crate) const SHARE_COMMITMENT_OPENING_DIMENSION: usize = 64;

pub(crate) fn encoded_share_vector_width(statement: &Value) -> Option<u64> {
    object_map(statement)
        .and_then(|object| object.get("optionCount"))
        .and_then(Value::as_u64)
        .and_then(|option_count| {
            option_count.checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION)
        })
}

pub(crate) fn expected_component_proof_statement_format(
    component_id: &str,
) -> Option<&'static str> {
    match component_id {
        "score-and-shamir-field-component" => Some(DENSE_COMPONENT_PROOF_STATEMENT_FORMAT),
        "payload-plaintext-field-component" | "share-commitment-component" => {
            Some(SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT)
        }
        "receiver-encryption-component" => {
            Some(STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT)
        }
        "receiver-key-binding-component" => Some(PUBLIC_ZERO_PROOF_STATEMENT_FORMAT),
        _ => None,
    }
}

pub(crate) fn component_proof_statement_format_is_expected(
    component_id: &str,
    proof_statement_format: &str,
) -> bool {
    match component_id {
        "score-and-shamir-field-component" => matches!(
            proof_statement_format,
            DENSE_COMPONENT_PROOF_STATEMENT_FORMAT | SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT
        ),
        "payload-plaintext-field-component" => {
            proof_statement_format == SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT
        }
        "share-commitment-component" => matches!(
            proof_statement_format,
            SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT
                | STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT
        ),
        "receiver-encryption-component" => {
            proof_statement_format == STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT
        }
        "receiver-key-binding-component" => {
            proof_statement_format == PUBLIC_ZERO_PROOF_STATEMENT_FORMAT
        }
        _ => false,
    }
}

pub(crate) fn expected_component_proof_statement_format_label(component_id: &str) -> &'static str {
    match component_id {
        "score-and-shamir-field-component" => {
            "dense-polynomial-matrix-linear-proof-v1 or sparse-polynomial-matrix-linear-proof-v1"
        }
        "share-commitment-component" => {
            "sparse-polynomial-matrix-linear-proof-v1 or structured-module-sis-share-commitment-v1"
        }
        _ => expected_component_proof_statement_format(component_id).unwrap_or("unknown"),
    }
}

pub(crate) fn component_proof_bytes_availability_is_expected(
    component_id: &str,
    proof_statement_format: &str,
    proof_bytes_availability: &str,
) -> bool {
    let expected_availability = match proof_statement_format {
        DENSE_COMPONENT_PROOF_STATEMENT_FORMAT => AVAILABLE_DENSE_PROOF_BYTES,
        SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT
        | STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT => REQUIRES_SPARSE_PROOF_STATEMENT,
        STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT => {
            REQUIRES_STRUCTURED_PROOF_STATEMENT
        }
        PUBLIC_ZERO_PROOF_STATEMENT_FORMAT => PUBLIC_ZERO_WITNESS_BINDING_CHECK,
        _ => return false,
    };

    component_proof_statement_format_is_expected(component_id, proof_statement_format)
        && proof_bytes_availability == expected_availability
}

pub(crate) fn component_proof_bytes_must_be_empty(component_id: &str) -> bool {
    component_id == "receiver-key-binding-component"
}

#[cfg(test)]
mod tests {
    use super::encoded_share_vector_width;

    #[test]
    fn encoded_share_vector_width_uses_checked_arithmetic() {
        assert_eq!(
            encoded_share_vector_width(&serde_json::json!({ "optionCount": 3 })),
            Some(33)
        );
        assert_eq!(
            encoded_share_vector_width(&serde_json::json!({ "optionCount": u64::MAX })),
            None
        );
    }
}
