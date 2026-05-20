pub mod abdlop_commitment;
pub mod encoded_relation_vectors;
pub mod linear_proof_abdlop;
pub mod linear_proof_norms;
pub mod linear_proof_parameters;
pub(crate) mod linear_proof_profile_constants;
pub(crate) mod linear_proof_prover;
pub mod linear_proof_public_parameters;
pub mod linear_proof_rng;
pub mod linear_proof_statement;
pub mod linear_proof_tbox;
pub mod linear_proof_transcript;
pub mod linear_proof_verifier;
pub(crate) mod many_quadratic;
pub mod polynomial_matrix;
pub mod polynomial_ring;
pub mod polynomial_vector;
pub mod proof_coder;
pub(crate) mod protocol_constants;
pub(crate) mod quadratic_challenge;
pub(crate) mod quadratic_equation;
pub mod receiver_key_vectors;
pub mod sparse_linear_proof_statement;
pub mod sparse_polynomial_matrix;
pub mod sparse_polynomial_vector;
pub(crate) mod tbox_relations;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::{
    hashing::{canonical_json, derive_protocol_digest, hash512, to_hex},
    transcript_core::decode_hex,
};

use self::{
    linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
    linear_proof_prover::{
        LinearProverCommitmentInput, LinearProverProofInput, LinearProverWitnessInput,
        SparseLinearProverProofInput, StreamedLinearProverProofInput, generate_linear_proof,
        generate_receiver_key_linear_proof, generate_sparse_linear_proof,
        generate_streamed_linear_proof, prepare_linear_prover_commitment,
        prepare_linear_prover_witness,
    },
    linear_proof_statement::{
        LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
        StreamedLinearProofStatement,
        derive_linear_statement_transcript_with_matrix_coefficient_representation,
        source_polynomial_split_factor, transform_target_vector_to_proof_ring,
    },
    linear_proof_transcript::shake128_32,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    protocol_constants::{BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION, SHARE_COMMITMENT_MODULUS},
    receiver_key_vectors::{
        RECEIVER_ENCRYPTION_MODULE_DEGREE, RECEIVER_ENCRYPTION_MODULE_RANK,
        RECEIVER_ENCRYPTION_MODULUS, derive_receiver_encryption_public_matrix,
    },
    sparse_linear_proof_statement::transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
};

pub const MODULE_MARKER: &str = "ballot-privacy";
pub const BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE: bool = true;

const BACKEND_NAME: &str = "linear lattice proof backend";
const FULL_BALLOT_PROOF_PROJECTION_COVERAGE: &str = "full-encoded-score-ballot-relation";
const FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID: &str =
    "full-encoded-score-ballot-linear-compatibility-v1";
const FULL_BALLOT_PROOF_ENCODING_PROFILE_ID: &str =
    "full-encoded-score-ballot-linear-proof-encoding-v1";
const RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID: &str = "receiver-key-linear-module-lwe-v1";
const RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID: &str = "receiver-key-linear-proof-encoding-v1";
const COMPONENT_BUNDLE_INCOMPLETE_COVERAGE: &str = "component-bundle-incomplete";
const REQUIRED_BALLOT_PROOF_COMPONENT_IDS: &[&str] = &[
    "score-and-shamir-field-component",
    "payload-plaintext-field-component",
    "share-commitment-component",
    "receiver-encryption-component",
    "receiver-key-binding-component",
];
const ALLOWED_BALLOT_PROOF_COMPONENT_STATEMENT_FORMATS: &[&str] = &[
    "dense-polynomial-matrix-linear-proof-v1",
    "sparse-polynomial-matrix-linear-proof-v1",
    "structured-module-sis-share-commitment-v1",
    "structured-module-lwe-linear-proof-v1",
    "public-zero-witness-binding-check-v1",
];
const DENSE_COMPONENT_PROOF_STATEMENT_FORMAT: &str = "dense-polynomial-matrix-linear-proof-v1";
const SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT: &str = "sparse-polynomial-matrix-linear-proof-v1";
const STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT: &str =
    "structured-module-sis-share-commitment-v1";
const STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT: &str =
    "structured-module-lwe-linear-proof-v1";
const PUBLIC_ZERO_PROOF_STATEMENT_FORMAT: &str = "public-zero-witness-binding-check-v1";
const MAX_GENERIC_SPARSE_COMPONENT_SHORT_RESPONSE_VECTOR_LENGTH: usize = 4_096;
const AVAILABLE_DENSE_PROOF_BYTES: &str = "available-for-small-dense-oracle";
const REQUIRES_SPARSE_PROOF_STATEMENT: &str = "requires-sparse-proof-statement";
const REQUIRES_STRUCTURED_PROOF_STATEMENT: &str = "requires-structured-proof-statement";
const PUBLIC_ZERO_WITNESS_BINDING_CHECK: &str = "public-zero-witness-binding-check";
const SHARE_COMMITMENT_MODULE_RANK: usize = 4;
const SHARE_COMMITMENT_MODULE_DEGREE: usize = 256;
const SHARE_COMMITMENT_OPENING_DIMENSION: usize = 64;

fn encoded_share_vector_width(statement: &Value) -> Option<u64> {
    object_map(statement)
        .and_then(|object| object.get("optionCount"))
        .and_then(Value::as_u64)
        .map(|option_count| {
            option_count.saturating_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION)
        })
}

pub fn describe_proof_backend() -> Value {
    json!({
        "backendName": BACKEND_NAME,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "portableRustWasmPortRequired": false,
        "requiredComponents": [],
        "blockedReason": Value::Null
    })
}

fn structural_rejection(operation: &str, refused_objects: Vec<Value>) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": refused_objects,
        "unresolvedReason": "BallotPackageInvalid"
    })
}

fn structural_refusal(message: impl Into<String>, object_digest: Option<&str>) -> Value {
    let message = message.into();
    match object_digest {
        Some(object_digest) => json!({
            "code": "BallotPackageInvalid",
            "message": message,
            "objectDigest": object_digest
        }),
        None => json!({
            "code": "BallotPackageInvalid",
            "message": message
        }),
    }
}

fn object_map(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn string_field<'value>(value: &'value Value, field_name: &str) -> Option<&'value str> {
    object_map(value)?.get(field_name)?.as_str()
}

fn array_field<'value>(value: &'value Value, field_name: &str) -> Option<&'value Vec<Value>> {
    object_map(value)?.get(field_name)?.as_array()
}

fn is_protocol_digest(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unsigned_decimal_string(value: &str) -> bool {
    value == "0" || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn expected_component_proof_statement_format(component_id: &str) -> Option<&'static str> {
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

fn component_proof_statement_format_is_expected(
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

fn expected_component_proof_statement_format_label(component_id: &str) -> &'static str {
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

fn component_proof_bytes_availability_is_expected(
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

fn component_proof_bytes_must_be_empty(component_id: &str) -> bool {
    component_id == "receiver-key-binding-component"
}

fn positive_roster_position(value: &Value, field_name: &str) -> Option<u64> {
    let roster_position = object_map(value)?.get(field_name)?.as_u64()?;
    if roster_position == 0 {
        None
    } else {
        Some(roster_position)
    }
}

fn value_without_field(value: &Value, field_name: &str) -> Option<Value> {
    let object = object_map(value)?;
    let mut copied_object = object.clone();
    copied_object.remove(field_name);

    Some(Value::Object(copied_object))
}

fn value_without_fields(value: &Value, field_names: &[&str]) -> Option<Value> {
    let object = object_map(value)?;
    let mut copied_object = object.clone();
    for field_name in field_names {
        copied_object.remove(*field_name);
    }

    Some(Value::Object(copied_object))
}

fn derive_digest(namespace: &str, value: &Value) -> Option<String> {
    derive_protocol_digest(namespace, value).ok()
}

fn receiver_reference_key(value: &Value) -> Option<String> {
    let receiver_identity = string_field(value, "receiverIdentity")?;
    if receiver_identity.is_empty() {
        return None;
    }

    Some(format!(
        "{}:{}",
        positive_roster_position(value, "receiverRosterPosition")?,
        receiver_identity,
    ))
}

fn collect_receiver_reference_refusals(
    references: Option<&Vec<Value>>,
    object_digest: Option<&str>,
    label: &str,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let mut seen_receiver_references = BTreeSet::new();
    let Some(references) = references else {
        refused_objects.push(structural_refusal(
            format!("{label} must be an array."),
            object_digest,
        ));

        return refused_objects;
    };

    for receiver_reference in references {
        let Some(receiver_reference_key) = receiver_reference_key(receiver_reference) else {
            refused_objects.push(structural_refusal(
                format!("{label} contains an invalid receiver identity or roster position."),
                object_digest,
            ));
            continue;
        };
        if !seen_receiver_references.insert(receiver_reference_key) {
            refused_objects.push(structural_refusal(
                format!("{label} contains a duplicate receiver reference."),
                object_digest,
            ));
        }
    }

    refused_objects
}

mod ballot_linear_verifier;
mod ballot_package_verifier;
mod ballot_proof_digest_helpers;
mod ballot_proof_generation_core;
mod ballot_proof_record_generation;
mod ballot_proof_refusals;
mod component_backend_sparse;
mod component_bundle_validation;
mod component_linear_proof_verification;
mod linear_proof_contract_validation;
mod proof_binding_digests;
mod proof_preflight_parsing;
mod receiver_key_package_refusals;
mod receiver_key_proof;
mod receiver_polynomial_helpers;
mod share_commitment_backend_helpers;
mod structured_receiver_encryption_statement;
mod structured_share_commitment_statement;

pub(crate) use ballot_linear_verifier::*;
pub(crate) use ballot_proof_digest_helpers::*;
pub(crate) use ballot_proof_generation_core::{
    generate_ballot_component_proof_inner, generate_ballot_proof_inner,
};
pub(crate) use ballot_proof_refusals::*;
pub(crate) use component_backend_sparse::*;
pub(crate) use component_bundle_validation::*;
pub(crate) use component_linear_proof_verification::*;
pub(crate) use linear_proof_contract_validation::*;
pub(crate) use proof_binding_digests::*;
pub(crate) use proof_preflight_parsing::*;
pub(crate) use receiver_key_package_refusals::*;
pub(crate) use receiver_polynomial_helpers::*;
pub(crate) use share_commitment_backend_helpers::*;
pub(crate) use structured_receiver_encryption_statement::*;
pub(crate) use structured_share_commitment_statement::*;

pub use ballot_package_verifier::{
    verify_claim_bearing_ballot_package, verify_encoded_relation_vector_case,
    verify_linear_proof_vector_case, verify_receiver_key_vector_case,
};
pub use ballot_proof_generation_core::{generate_ballot_component_proof, generate_ballot_proof};
pub use ballot_proof_record_generation::{
    BallotProofRecordGenerationInput, generate_ballot_proof_record,
};
pub use receiver_key_proof::{
    generate_receiver_key_proof, prepare_receiver_key_proof_generation, verify_receiver_key_proof,
};

#[cfg(test)]
mod tests;
