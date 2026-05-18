pub mod abdlop_commitment;
pub mod encoded_relation_vectors;
pub mod linear_proof_abdlop;
pub mod linear_proof_norms;
pub mod linear_proof_parameters;
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
pub(crate) mod quadratic_challenge;
pub(crate) mod quadratic_equation;
pub mod receiver_key_vectors;
pub mod sparse_linear_proof_statement;
pub mod sparse_polynomial_matrix;
pub mod sparse_polynomial_vector;
pub(crate) mod tbox_relations;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::{hashing::derive_protocol_digest, transcript_core::decode_hex};

use self::{
    linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
    linear_proof_prover::{
        LinearProverCommitmentInput, LinearProverProofInput, LinearProverWitnessInput,
        SparseLinearProverProofInput, generate_linear_proof, generate_receiver_key_linear_proof,
        generate_sparse_linear_proof, prepare_linear_prover_commitment,
        prepare_linear_prover_witness,
    },
    linear_proof_statement::{
        LinearProofTargetCoefficientRepresentation, derive_linear_statement_transcript,
    },
    polynomial_ring::PolynomialRing,
    receiver_key_vectors::{
        RECEIVER_ENCRYPTION_MODULE_DEGREE, RECEIVER_ENCRYPTION_MODULE_RANK,
        RECEIVER_ENCRYPTION_MODULUS, derive_receiver_encryption_public_matrix,
    },
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
};

pub const MODULE_MARKER: &str = "ballot-privacy";
pub const BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE: bool = false;

const UNAVAILABLE_BACKEND_MESSAGE: &str = "Ballot privacy proof verification requires the frozen linear lattice proof backend, which is not implemented in this build.";
const BACKEND_NAME: &str = "linear lattice proof backend";
const ENCODED_COORDINATES_PER_OPTION: u64 = 11;
const FULL_BALLOT_PROOF_PROJECTION_COVERAGE: &str = "full-encoded-score-ballot-relation";
const FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID: &str =
    "full-encoded-score-ballot-linear-compatibility-v1";
const FULL_BALLOT_PROOF_ENCODING_PROFILE_ID: &str =
    "full-encoded-score-ballot-linear-proof-encoding-v1";
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
    "structured-module-lwe-linear-proof-v1",
    "public-zero-witness-binding-check-v1",
];
const DENSE_COMPONENT_PROOF_STATEMENT_FORMAT: &str = "dense-polynomial-matrix-linear-proof-v1";
const SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT: &str = "sparse-polynomial-matrix-linear-proof-v1";
const STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT: &str =
    "structured-module-lwe-linear-proof-v1";
const PUBLIC_ZERO_PROOF_STATEMENT_FORMAT: &str = "public-zero-witness-binding-check-v1";
const AVAILABLE_DENSE_PROOF_BYTES: &str = "available-for-small-dense-oracle";
const REQUIRES_SPARSE_PROOF_STATEMENT: &str = "requires-sparse-proof-statement";
const REQUIRES_STRUCTURED_PROOF_STATEMENT: &str = "requires-structured-proof-statement";
const PUBLIC_ZERO_WITNESS_BINDING_CHECK: &str = "public-zero-witness-binding-check";

pub const REQUIRED_PORTABLE_BACKEND_COMPONENTS: &[&str] = &[
    "generated linear proof parameters from lin-codegen.sage",
    "portable polynomial ring arithmetic for Z_q[X]/(X^d + 1)",
    "portable polynomial vector and matrix arithmetic",
    "sparse polynomial vector and matrix arithmetic",
    "ABDLop commitment key generation, commitment, and commitment hashing",
    "linear relation statement mapping for A*w + t = 0",
    "linear witness decomposition into short and message coordinates",
    "tbox proof generation and verification",
    "quadratic-to-linear helper relations used by the tbox backend",
    "proof byte coder and decoder",
    "SHAKE128 transcript and expansion path",
    "rejection sampling and bounded short-vector checks",
    "browser-safe prover randomness source",
];

fn encoded_share_vector_width(statement: &Value) -> Option<u64> {
    object_map(statement)
        .and_then(|object| object.get("optionCount"))
        .and_then(Value::as_u64)
        .map(|option_count| option_count.saturating_mul(ENCODED_COORDINATES_PER_OPTION))
}

pub fn describe_proof_backend() -> Value {
    json!({
        "backendName": BACKEND_NAME,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "portableRustWasmPortRequired": true,
        "requiredComponents": REQUIRED_PORTABLE_BACKEND_COMPONENTS,
        "blockedReason": UNAVAILABLE_BACKEND_MESSAGE
    })
}

fn fail_closed(operation: &str) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": [
            {
                "code": "OperationUnavailable",
                "message": format!("{operation}: {UNAVAILABLE_BACKEND_MESSAGE}")
            }
        ],
        "unresolvedReason": "OperationUnavailable"
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

fn expected_component_proof_bytes_availability(component_id: &str) -> Option<&'static str> {
    match component_id {
        "score-and-shamir-field-component" => Some(AVAILABLE_DENSE_PROOF_BYTES),
        "payload-plaintext-field-component" | "share-commitment-component" => {
            Some(REQUIRES_SPARSE_PROOF_STATEMENT)
        }
        "receiver-encryption-component" => Some(REQUIRES_STRUCTURED_PROOF_STATEMENT),
        "receiver-key-binding-component" => Some(PUBLIC_ZERO_WITNESS_BINDING_CHECK),
        _ => None,
    }
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

fn collect_receiver_key_proof_refusals(
    receiver_key_proof: &Value,
    proof_bytes_hex: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let object_digest = string_field(receiver_key_proof, "receiverKeyProofRoot");
    let expected_digest = value_without_field(receiver_key_proof, "receiverKeyProofRoot")
        .and_then(|payload| derive_digest("ReceiverKeyProofRoot", &payload));
    let proof_size_bytes = object_map(receiver_key_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64);

    if string_field(receiver_key_proof, "objectType") != Some("ReceiverKeyProof")
        || object_map(receiver_key_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(receiver_key_proof, "proofBackend") != Some("LocalLinearLatticeRelation")
        || string_field(receiver_key_proof, "proofRoot")
            .is_none_or(|proof_root| !is_protocol_digest(proof_root))
        || string_field(receiver_key_proof, "backendStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "linearStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "proofBytesDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "proofEncodingProfileDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "proofParameterSetDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(receiver_key_proof, "publicRandomnessDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || proof_size_bytes.is_some_and(|size| size == 0)
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof shell has an invalid canonical shape.",
            object_digest,
        ));
    }
    let proof_metadata_field_count = [
        string_field(receiver_key_proof, "linearStatementDigest").is_some(),
        string_field(receiver_key_proof, "proofBytesDigest").is_some(),
        string_field(receiver_key_proof, "proofEncodingProfileDigest").is_some(),
        string_field(receiver_key_proof, "proofParameterSetDigest").is_some(),
        string_field(receiver_key_proof, "publicRandomnessDigest").is_some(),
        proof_size_bytes.is_some(),
    ]
    .iter()
    .filter(|field_present| **field_present)
    .count();
    if proof_metadata_field_count > 0 && proof_metadata_field_count != 6 {
        refused_objects.push(structural_refusal(
            "Receiver key proof byte metadata must be complete when any proof-byte field is present.",
            object_digest,
        ));
    }
    if proof_bytes_hex.is_some() && string_field(receiver_key_proof, "proofBytesDigest").is_none() {
        refused_objects.push(structural_refusal(
            "Receiver key proof bytes require a proof-byte-bearing receiver key proof record.",
            object_digest,
        ));
    }
    refused_objects.extend(collect_proof_bytes_refusals(
        proof_bytes_hex,
        string_field(receiver_key_proof, "proofBytesDigest"),
        proof_size_bytes,
        object_digest,
        "Receiver key",
        false,
    ));
    if expected_digest.as_deref() != object_digest {
        refused_objects.push(structural_refusal(
            "Receiver key proof root does not match its canonical payload.",
            object_digest,
        ));
    }

    refused_objects
}

fn insert_optional_digest_field(
    payload: &mut Map<String, Value>,
    source: &Value,
    field_name: &str,
) {
    if let Some(digest_value) = string_field(source, field_name) {
        payload.insert(field_name.to_string(), json!(digest_value));
    }
}

fn derive_ballot_proof_challenge_digest(statement: &Value, ballot_proof: &Value) -> Option<String> {
    let mut challenge_payload = Map::new();
    challenge_payload.insert(
        "ballotProofStatementDigest".to_string(),
        json!(string_field(statement, "ballotProofStatementDigest")?),
    );
    challenge_payload.insert(
        "challengeDomainDigest".to_string(),
        json!(string_field(statement, "challengeDomainDigest")?),
    );
    challenge_payload.insert(
        "proofBytesDigest".to_string(),
        json!(string_field(ballot_proof, "proofBytesDigest")?),
    );
    challenge_payload.insert(
        "proofRoot".to_string(),
        json!(string_field(ballot_proof, "proofRoot")?),
    );
    challenge_payload.insert(
        "relationStatementDigest".to_string(),
        json!(string_field(ballot_proof, "relationStatementDigest")?),
    );
    for field_name in [
        "backendStatementDigest",
        "componentBundleStatementDigest",
        "componentProofBundleDigest",
        "linearStatementDigest",
        "proofEncodingProfileDigest",
        "proofParameterSetDigest",
        "publicRandomnessDigest",
        "statementMatrixDigest",
        "targetVectorDigest",
    ] {
        insert_optional_digest_field(&mut challenge_payload, ballot_proof, field_name);
    }

    derive_digest("ChallengeDomainDigest", &Value::Object(challenge_payload))
}

fn derive_ballot_component_statement_digest(component_statement: &Value) -> Option<String> {
    let statement_payload = value_without_field(component_statement, "componentStatementDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-statement-v1"
        }),
    )
}

fn derive_ballot_component_bundle_statement_digest(component_bundle: &Value) -> Option<String> {
    let statement_payload =
        value_without_field(component_bundle, "componentBundleStatementDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-bundle-statement-v1"
        }),
    )
}

fn derive_ballot_component_proof_record_digest(component_proof: &Value) -> Option<String> {
    let proof_payload = value_without_field(component_proof, "componentProofRecordDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": proof_payload,
            "purpose": "ballot-proof-component-proof-record-v1"
        }),
    )
}

fn derive_ballot_component_proof_bundle_digest(component_proof_bundle: &Value) -> Option<String> {
    let proof_bundle_payload =
        value_without_field(component_proof_bundle, "componentProofBundleDigest")?;

    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": proof_bundle_payload,
            "purpose": "ballot-proof-component-proof-bundle-v1"
        }),
    )
}

fn derive_ballot_component_proof_root(
    component_proof: &Value,
    proof_input: &Value,
    expected_component_id: &str,
) -> Option<String> {
    let mut proof_root_payload = Map::new();
    proof_root_payload.insert("componentId".to_string(), json!(expected_component_id));
    if let Some(component_proof_statement_digest) =
        string_field(proof_input, "componentProofStatementDigest")
    {
        proof_root_payload.insert(
            "componentProofStatementDigest".to_string(),
            json!(component_proof_statement_digest),
        );
    }
    proof_root_payload.insert(
        "componentStatementDigest".to_string(),
        json!(string_field(component_proof, "componentStatementDigest")?),
    );
    proof_root_payload.insert(
        "proofBytesDigest".to_string(),
        json!(string_field(component_proof, "proofBytesDigest")?),
    );
    proof_root_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(string_field(component_proof, "proofEncodingProfileDigest")?),
    );
    proof_root_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(string_field(component_proof, "proofParameterSetDigest")?),
    );
    proof_root_payload.insert(
        "proofStatementFormat".to_string(),
        json!(string_field(proof_input, "proofStatementFormat")?),
    );
    proof_root_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(string_field(component_proof, "publicRandomnessDigest")?),
    );
    proof_root_payload.insert(
        "purpose".to_string(),
        json!("ballot-proof-component-proof-root-v1"),
    );
    proof_root_payload.insert(
        "statementDigest".to_string(),
        json!(string_field(proof_input, "statementDigest")?),
    );

    derive_digest("ChallengeDomainDigest", &Value::Object(proof_root_payload))
}

fn collect_ballot_proof_refusals(statement: &Value, ballot_proof: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let statement_digest = string_field(statement, "ballotProofStatementDigest");
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let proof_size_bytes = object_map(ballot_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64);
    let expected_statement_digest = value_without_field(statement, "ballotProofStatementDigest")
        .and_then(|payload| derive_digest("BallotProofStatementDigest", &payload));
    let expected_proof_record_digest = value_without_field(ballot_proof, "ballotProofRecordDigest")
        .and_then(|payload| derive_digest("BallotProofRecordDigest", &payload));
    let expected_challenge_digest = derive_ballot_proof_challenge_digest(statement, ballot_proof);

    if string_field(statement, "objectType") != Some("BallotProofStatement")
        || object_map(statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || object_map(statement)
            .and_then(|object| object.get("shareVectorWidth"))
            .and_then(Value::as_u64)
            != encoded_share_vector_width(statement)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof statement has an invalid canonical shape.",
            statement_digest,
        ));
    }
    if expected_statement_digest.as_deref() != statement_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof statement digest does not match its canonical payload.",
            statement_digest,
        ));
    }

    let receiver_public_keys = object_map(statement)
        .and_then(|object| object.get("receiverPublicKeys"))
        .and_then(Value::as_array);
    let receiver_payloads = object_map(statement)
        .and_then(|object| object.get("receiverPayloads"))
        .and_then(Value::as_array);
    let share_commitments = object_map(statement)
        .and_then(|object| object.get("shareCommitments"))
        .and_then(Value::as_array);
    refused_objects.extend(collect_receiver_reference_refusals(
        receiver_public_keys,
        statement_digest,
        "Ballot proof receiver-key references",
    ));
    refused_objects.extend(collect_receiver_reference_refusals(
        receiver_payloads,
        statement_digest,
        "Ballot proof receiver-payload references",
    ));
    refused_objects.extend(collect_receiver_reference_refusals(
        share_commitments,
        statement_digest,
        "Ballot proof share-commitment references",
    ));
    if receiver_public_keys.is_none_or(Vec::is_empty)
        || receiver_public_keys.map(Vec::len) != receiver_payloads.map(Vec::len)
        || receiver_public_keys.map(Vec::len) != share_commitments.map(Vec::len)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof statement must bind the same non-empty receiver set across keys, payloads, and commitments.",
            statement_digest,
        ));
    }

    if string_field(ballot_proof, "objectType") != Some("BallotProofRecord")
        || object_map(ballot_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(ballot_proof, "proofBackend") != Some("LocalLinearLatticeRelation")
        || string_field(ballot_proof, "backendStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "componentBundleStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "componentProofBundleDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "relationStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "linearStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "statementMatrixDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "targetVectorDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofRoot").is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofBytesDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofEncodingProfileDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "proofParameterSetDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(ballot_proof, "publicRandomnessDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || proof_size_bytes.is_none_or(|proof_size_bytes| proof_size_bytes == 0)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record has an invalid canonical shape.",
            proof_record_digest,
        ));
    }
    let proof_backend_metadata_field_count = [
        string_field(ballot_proof, "backendStatementDigest").is_some(),
        string_field(ballot_proof, "linearStatementDigest").is_some(),
        string_field(ballot_proof, "statementMatrixDigest").is_some(),
        string_field(ballot_proof, "targetVectorDigest").is_some(),
        string_field(ballot_proof, "proofEncodingProfileDigest").is_some(),
        string_field(ballot_proof, "proofParameterSetDigest").is_some(),
        string_field(ballot_proof, "publicRandomnessDigest").is_some(),
    ]
    .iter()
    .filter(|field_present| **field_present)
    .count();
    if proof_backend_metadata_field_count > 0 && proof_backend_metadata_field_count != 7 {
        refused_objects.push(structural_refusal(
            "Ballot proof backend metadata must be complete when any backend proof field is present.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "ballotProofStatementDigest") != statement_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied statement.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "ballotProofProfileDigest")
        != string_field(statement, "ballotProofProfileDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the statement proof profile.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "challengeDigest") != expected_challenge_digest.as_deref() {
        refused_objects.push(structural_refusal(
            "Ballot proof challenge digest does not match the statement and proof roots.",
            proof_record_digest,
        ));
    }
    if expected_proof_record_digest.as_deref() != proof_record_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record digest does not match its canonical payload.",
            proof_record_digest,
        ));
    }

    refused_objects
}

fn collect_proof_bytes_refusals(
    proof_bytes_hex: Option<&str>,
    expected_proof_bytes_digest: Option<&str>,
    expected_proof_size_bytes: Option<u64>,
    proof_record_digest: Option<&str>,
    proof_label: &str,
    allow_empty_proof_bytes: bool,
) -> Vec<Value> {
    let Some(proof_bytes_hex) = proof_bytes_hex else {
        return Vec::new();
    };
    let mut refused_objects = Vec::new();
    let proof_bytes = match decode_hex(proof_bytes_hex) {
        Ok(proof_bytes) if allow_empty_proof_bytes || !proof_bytes.is_empty() => proof_bytes,
        _ => {
            let required_shape = if allow_empty_proof_bytes {
                "lowercase hexadecimal bytes"
            } else {
                "non-empty lowercase hexadecimal bytes"
            };
            refused_objects.push(structural_refusal(
                format!("{proof_label} proof bytes must be {required_shape}."),
                proof_record_digest,
            ));

            return refused_objects;
        }
    };
    let proof_size_bytes = proof_bytes.len() as u64;
    let proof_bytes_digest = derive_digest(
        "ProofBytesDigest",
        &json!({
            "objectType": "ProofBytes",
            "objectVersion": 1,
            "proofBytesHex": proof_bytes_hex,
            "proofSizeBytes": proof_size_bytes,
        }),
    );

    if Some(proof_size_bytes) != expected_proof_size_bytes {
        refused_objects.push(structural_refusal(
            format!("{proof_label} proof byte length does not match the proof record."),
            proof_record_digest,
        ));
    }
    if proof_bytes_digest.as_deref() != expected_proof_bytes_digest {
        refused_objects.push(structural_refusal(
            format!("{proof_label} proof bytes do not match the proof record digest."),
            proof_record_digest,
        ));
    }

    refused_objects
}

fn collect_receiver_payload_refusals(receiver_payload: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let payload_digest = string_field(receiver_payload, "receiverPayloadDigest");
    let expected_ciphertext_root = match (
        string_field(receiver_payload, "ceremonyId"),
        string_field(receiver_payload, "manifestDigest"),
        string_field(receiver_payload, "payloadContextDigest"),
        string_field(receiver_payload, "receiverEncryptionProfileDigest"),
        string_field(receiver_payload, "receiverIdentity"),
        string_field(receiver_payload, "receiverPublicKeyDigest"),
        positive_roster_position(receiver_payload, "receiverRosterPosition"),
        string_field(receiver_payload, "ciphertextBodyDigest"),
    ) {
        (
            Some(ceremony_id),
            Some(manifest_digest),
            Some(payload_context_digest),
            Some(receiver_encryption_profile_digest),
            Some(receiver_identity),
            Some(receiver_public_key_digest),
            Some(receiver_roster_position),
            Some(ciphertext_body_digest),
        ) => derive_digest(
            "ReceiverPayloadCiphertextRoot",
            &json!({
                "ceremonyId": ceremony_id,
                "ciphertextBodyDigest": ciphertext_body_digest,
                "manifestDigest": manifest_digest,
                "payloadContextDigest": payload_context_digest,
                "receiverEncryptionProfileDigest": receiver_encryption_profile_digest,
                "receiverIdentity": receiver_identity,
                "receiverPublicKeyDigest": receiver_public_key_digest,
                "receiverRosterPosition": receiver_roster_position,
            }),
        ),
        _ => None,
    };
    let expected_payload_digest = value_without_field(receiver_payload, "receiverPayloadDigest")
        .and_then(|payload| derive_digest("ReceiverPayloadDigest", &payload));

    if string_field(receiver_payload, "objectType") != Some("ReceiverPayload")
        || object_map(receiver_payload)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(receiver_payload, "receiverPayloadCiphertextRoot")
            != expected_ciphertext_root.as_deref()
        || payload_digest != expected_payload_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver payload shell digest or shape is invalid.",
            payload_digest,
        ));
    }
    for forbidden_field in [
        "receiverShareVector",
        "shareCommitmentOpening",
        "receiverEncryptionRandomness",
        "receiverEncryptionNoise",
        "proofWitness",
    ] {
        if object_map(receiver_payload).is_some_and(|object| object.contains_key(forbidden_field)) {
            refused_objects.push(structural_refusal(
                "Receiver payload shell must not expose witness material.",
                payload_digest,
            ));
            break;
        }
    }

    refused_objects
}

fn collect_share_commitment_refusals(share_commitment: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let share_commitment_digest = string_field(share_commitment, "shareCommitmentDigest");
    let expected_digest = value_without_field(share_commitment, "shareCommitmentDigest")
        .and_then(|payload| derive_digest("ShareCommitmentDigest", &payload));

    if string_field(share_commitment, "objectType") != Some("ShareCommitment")
        || object_map(share_commitment)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || object_map(share_commitment)
            .and_then(|object| object.get("shareVectorWidth"))
            .and_then(Value::as_u64)
            .is_none_or(|share_vector_width| share_vector_width == 0)
        || share_commitment_digest != expected_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Share commitment shell digest or shape is invalid.",
            share_commitment_digest,
        ));
    }
    for forbidden_field in ["openingRandomness", "receiverShareVector", "proofWitness"] {
        if object_map(share_commitment).is_some_and(|object| object.contains_key(forbidden_field)) {
            refused_objects.push(structural_refusal(
                "Share commitment shell must not expose witness material.",
                share_commitment_digest,
            ));
            break;
        }
    }

    refused_objects
}

fn reference_map(references: Option<&Vec<Value>>) -> BTreeMap<String, &Value> {
    let mut mapped_references = BTreeMap::new();
    if let Some(references) = references {
        for reference in references {
            if let Some(reference_key) = receiver_reference_key(reference) {
                mapped_references.insert(reference_key, reference);
            }
        }
    }

    mapped_references
}

fn collect_claim_bearing_package_refusals(ballot_package: &Value) -> Vec<Value> {
    let Some(package_object) = object_map(ballot_package) else {
        return vec![structural_refusal(
            "Claim-bearing ballot package shell digest or shape is invalid.",
            None,
        )];
    };
    let statement = package_object
        .get("ballotProofStatement")
        .unwrap_or(&Value::Null);
    let ballot_proof = package_object.get("ballotProof").unwrap_or(&Value::Null);
    let mut refused_objects = collect_ballot_proof_refusals(statement, ballot_proof);
    refused_objects.extend(collect_proof_bytes_refusals(
        package_object.get("proofBytesHex").and_then(Value::as_str),
        string_field(ballot_proof, "proofBytesDigest"),
        object_map(ballot_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64),
        string_field(ballot_proof, "ballotProofRecordDigest"),
        "Ballot",
        false,
    ));
    refused_objects.extend(collect_ballot_component_proof_bundle_refusals(
        statement,
        ballot_proof,
        None,
        package_object.get("componentProofBundle"),
        package_object.get("componentProofInputs"),
    ));
    let package_digest = string_field(ballot_package, "ballotPackageDigest");

    if string_field(ballot_package, "objectType") != Some("ClaimBearingBallotPackage")
        || package_object.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || package_digest != string_field(statement, "ballotPackageDigest")
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package shell digest or shape is invalid.",
            package_digest,
        ));
    }
    if package_object.contains_key("componentProofBundle")
        && !package_object.contains_key("proofBytesHex")
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package verification requires the public ballot proof bytes when a component proof bundle is supplied.",
            package_digest,
        ));
    }

    let statement_receiver_key_references = reference_map(
        object_map(statement)
            .and_then(|object| object.get("receiverPublicKeys"))
            .and_then(Value::as_array),
    );
    let statement_payload_references = reference_map(
        object_map(statement)
            .and_then(|object| object.get("receiverPayloads"))
            .and_then(Value::as_array),
    );
    let statement_commitment_references = reference_map(
        object_map(statement)
            .and_then(|object| object.get("shareCommitments"))
            .and_then(Value::as_array),
    );
    let receiver_payloads = package_object
        .get("receiverPayloads")
        .and_then(Value::as_array);
    let share_commitments = package_object
        .get("shareCommitments")
        .and_then(Value::as_array);

    if receiver_payloads.map(Vec::len)
        != object_map(statement)
            .and_then(|object| object.get("receiverPayloads"))
            .and_then(Value::as_array)
            .map(Vec::len)
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package must include every receiver payload referenced by the statement.",
            package_digest,
        ));
    }
    if share_commitments.map(Vec::len)
        != object_map(statement)
            .and_then(|object| object.get("shareCommitments"))
            .and_then(Value::as_array)
            .map(Vec::len)
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package must include every share commitment referenced by the statement.",
            package_digest,
        ));
    }

    for receiver_payload in receiver_payloads.into_iter().flatten() {
        refused_objects.extend(collect_receiver_payload_refusals(receiver_payload));
        let receiver_reference_key = receiver_reference_key(receiver_payload);
        let payload_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_payload_references.get(key).copied());
        let receiver_key_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_receiver_key_references.get(key).copied());

        if payload_reference.and_then(|reference| string_field(reference, "receiverPayloadDigest"))
            != string_field(receiver_payload, "receiverPayloadDigest")
            || payload_reference
                .and_then(|reference| string_field(reference, "receiverPayloadCiphertextRoot"))
                != string_field(receiver_payload, "receiverPayloadCiphertextRoot")
        {
            refused_objects.push(structural_refusal(
                "Receiver payload shell is not bound to the ballot proof statement reference.",
                string_field(receiver_payload, "receiverPayloadDigest"),
            ));
        }
        if receiver_key_reference
            .and_then(|reference| string_field(reference, "receiverPublicKeyDigest"))
            != string_field(receiver_payload, "receiverPublicKeyDigest")
            || string_field(receiver_payload, "ceremonyId") != string_field(statement, "ceremonyId")
            || string_field(receiver_payload, "manifestDigest")
                != string_field(statement, "manifestDigest")
            || string_field(receiver_payload, "rosterDigest")
                != string_field(statement, "rosterDigest")
            || string_field(receiver_payload, "pollSpecDigest")
                != string_field(statement, "pollSpecDigest")
            || string_field(receiver_payload, "voterIdentityDigest")
                != string_field(statement, "voterIdentityDigest")
            || string_field(receiver_payload, "receiverEncryptionProfileDigest")
                != string_field(statement, "receiverEncryptionProfileDigest")
        {
            refused_objects.push(structural_refusal(
                "Receiver payload shell is not bound to the statement context or receiver key.",
                string_field(receiver_payload, "receiverPayloadDigest"),
            ));
        }
    }

    for share_commitment in share_commitments.into_iter().flatten() {
        refused_objects.extend(collect_share_commitment_refusals(share_commitment));
        let receiver_reference_key = receiver_reference_key(share_commitment);
        let commitment_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_commitment_references.get(key).copied());
        let receiver_key_reference = receiver_reference_key
            .as_ref()
            .and_then(|key| statement_receiver_key_references.get(key).copied());

        if commitment_reference
            .and_then(|reference| string_field(reference, "shareCommitmentDigest"))
            != string_field(share_commitment, "shareCommitmentDigest")
        {
            refused_objects.push(structural_refusal(
                "Share commitment shell is not bound to the ballot proof statement reference.",
                string_field(share_commitment, "shareCommitmentDigest"),
            ));
        }
        if receiver_key_reference.and_then(|reference| string_field(reference, "receiverIdentity"))
            != string_field(share_commitment, "receiverIdentity")
            || receiver_key_reference
                .and_then(|reference| positive_roster_position(reference, "receiverRosterPosition"))
                != positive_roster_position(share_commitment, "receiverRosterPosition")
            || string_field(share_commitment, "ceremonyId") != string_field(statement, "ceremonyId")
            || string_field(share_commitment, "manifestDigest")
                != string_field(statement, "manifestDigest")
            || string_field(share_commitment, "rosterDigest")
                != string_field(statement, "rosterDigest")
            || object_map(share_commitment)
                .and_then(|object| object.get("shareVectorWidth"))
                .and_then(Value::as_u64)
                != object_map(statement)
                    .and_then(|object| object.get("shareVectorWidth"))
                    .and_then(Value::as_u64)
            || string_field(share_commitment, "shareCommitmentProfileDigest")
                != string_field(statement, "shareCommitmentProfileDigest")
        {
            refused_objects.push(structural_refusal(
                "Share commitment shell is not bound to the statement context or receiver set.",
                string_field(share_commitment, "shareCommitmentDigest"),
            ));
        }
    }

    refused_objects
}

fn derive_receiver_key_proof_encoding_profile_digest(proof_encoding: &Value) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "proofEncoding": proof_encoding,
            "purpose": "receiver-key-linear-proof-encoding-profile-v1"
        }),
    )
}

fn derive_receiver_key_proof_parameter_set_digest(parameter_set: &Value) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "parameterSet": parameter_set,
            "purpose": "receiver-key-linear-proof-parameter-set-v1"
        }),
    )
}

fn derive_receiver_key_public_randomness_digest(public_randomness_hex: &str) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "publicRandomnessHex": public_randomness_hex,
            "purpose": "receiver-key-linear-proof-public-randomness-v1"
        }),
    )
}

fn derive_receiver_key_linear_statement_digest(linear_statement: &Value) -> Option<String> {
    let statement_payload = value_without_field(linear_statement, "statementDigest")?;
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "receiver-key-linear-proof-statement-v1"
        }),
    )
}

fn derive_ballot_proof_encoding_profile_digest(proof_encoding: &Value) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "proofEncoding": proof_encoding,
            "purpose": "ballot-proof-linear-proof-encoding-profile-v1"
        }),
    )
}

fn derive_ballot_proof_parameter_set_digest(parameter_set: &Value) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "parameterSet": parameter_set,
            "purpose": "ballot-proof-linear-proof-parameter-set-v1"
        }),
    )
}

fn derive_ballot_proof_public_randomness_digest(public_randomness_hex: &str) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "publicRandomnessHex": public_randomness_hex,
            "purpose": "ballot-proof-linear-proof-public-randomness-v1"
        }),
    )
}

fn derive_ballot_proof_linear_statement_digest(linear_statement: &Value) -> Option<String> {
    let statement_payload = value_without_field(linear_statement, "statementDigest")?;
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-linear-proof-statement-v1"
        }),
    )
}

fn derive_ballot_sparse_linear_statement_digest(sparse_statement: &Value) -> Option<String> {
    let statement_payload = value_without_field(sparse_statement, "statementDigest")?;
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-sparse-linear-proof-statement-v1"
        }),
    )
}

fn derive_ballot_structured_receiver_encryption_statement_digest(
    structured_statement: &Value,
) -> Option<String> {
    let statement_payload = value_without_field(structured_statement, "statementDigest")?;
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-structured-receiver-encryption-proof-statement-v1"
        }),
    )
}

fn derive_ballot_component_proof_statement_plan_digest(plan: &Value) -> Option<String> {
    let statement_payload = value_without_field(plan, "componentProofStatementDigest")?;
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "ballot-proof-component-proof-statement-plan-v1"
        }),
    )
}

fn verify_receiver_key_linear_proof_bytes(
    receiver_key_proof: &Value,
    linear_statement: &Value,
    proof_bytes_hex: &str,
    public_randomness_hex: &str,
    parameter_set: &Value,
    proof_encoding: &Value,
) -> Value {
    let mut refused_objects = Vec::new();
    let receiver_key_proof_root = string_field(receiver_key_proof, "receiverKeyProofRoot");
    let linear_statement_digest = string_field(linear_statement, "statementDigest");
    let expected_proof_encoding_digest =
        derive_receiver_key_proof_encoding_profile_digest(proof_encoding);
    let expected_parameter_set_digest =
        derive_receiver_key_proof_parameter_set_digest(parameter_set);
    let expected_public_randomness_digest =
        derive_receiver_key_public_randomness_digest(public_randomness_hex);
    let expected_linear_statement_digest =
        derive_receiver_key_linear_statement_digest(linear_statement);
    let proof_size_bytes = object_map(receiver_key_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size_bytes| usize::try_from(proof_size_bytes).ok());

    if linear_statement_digest != expected_linear_statement_digest.as_deref() {
        refused_objects.push(structural_refusal(
            "Receiver key linear statement digest does not match its canonical payload.",
            receiver_key_proof_root,
        ));
    }

    if string_field(receiver_key_proof, "linearStatementDigest") != linear_statement_digest {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied linear statement.",
            receiver_key_proof_root,
        ));
    }
    if string_field(receiver_key_proof, "proofEncodingProfileDigest")
        != expected_proof_encoding_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied proof encoding profile.",
            receiver_key_proof_root,
        ));
    }
    if string_field(receiver_key_proof, "proofParameterSetDigest")
        != expected_parameter_set_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied proof parameter set.",
            receiver_key_proof_root,
        ));
    }
    if string_field(receiver_key_proof, "publicRandomnessDigest")
        != expected_public_randomness_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied public randomness.",
            receiver_key_proof_root,
        ));
    }
    match serde_json::from_value::<LinearProofParameterSet>(parameter_set.clone()) {
        Ok(parameter_contract)
            if parameter_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                "Receiver key proof parameter set is not bound to the proof record byte length.",
                receiver_key_proof_root,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!("Receiver key proof parameter set is malformed: {error}"),
            receiver_key_proof_root,
        )),
    }
    match serde_json::from_value::<LinearProofEncoding>(proof_encoding.clone()) {
        Ok(proof_encoding_contract)
            if proof_encoding_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                "Receiver key proof encoding is not bound to the proof record byte length.",
                receiver_key_proof_root,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!("Receiver key proof encoding is malformed: {error}"),
            receiver_key_proof_root,
        )),
    }
    if !refused_objects.is_empty() {
        return structural_rejection("verifyReceiverKeyProof", refused_objects);
    }

    let vector_case = json!({
        "caseName": "receiver-key-proof-record",
        "description": "Receiver-key proof record verification through the internal linear proof backend.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("statementMatrixCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetVectorCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("targetVectorCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetCoefficientRepresentation": object_map(linear_statement)
            .and_then(|object| object.get("targetCoefficientRepresentation"))
            .cloned()
            .unwrap_or(Value::Null),
        "proofHex": proof_bytes_hex,
        "expectedProofSizeBytes": object_map(receiver_key_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .cloned()
            .unwrap_or(Value::Null)
    });
    let proof_verification =
        linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if proof_verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "verifyReceiverKeyProof",
            "statusLabels": [],
            "acceptedDigests": [],
            "refusedObjects": proof_verification
                .as_object()
                .and_then(|object| object.get("refusedObjects"))
                .cloned()
                .unwrap_or_else(|| json!([
                    {
                        "code": "InvalidFixture",
                        "message": "Receiver key proof backend verification failed without a structured refusal."
                    }
                ])),
            "unresolvedReason": proof_verification
                .as_object()
                .and_then(|object| object.get("unresolvedReason"))
                .cloned()
                .unwrap_or_else(|| json!("InvalidFixture"))
        });
    }

    let mut status_labels = vec![
        json!("ReceiverKeyProofRootRecomputed"),
        json!("ReceiverKeyProofBytesDigestChecked"),
        json!("ReceiverKeyLinearStatementBound"),
        json!("ReceiverKeyLinearProofVerified"),
    ];
    if let Some(proof_status_labels) = proof_verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(proof_status_labels.iter().cloned());
    }
    let accepted_digests = [
        receiver_key_proof_root,
        string_field(receiver_key_proof, "proofBytesDigest"),
        string_field(receiver_key_proof, "proofParameterSetDigest"),
        linear_statement_digest,
    ]
    .into_iter()
    .flatten()
    .map(Value::from)
    .collect::<Vec<_>>();

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "verifyReceiverKeyProof",
        "statusLabels": status_labels,
        "acceptedDigests": accepted_digests,
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

pub fn verify_receiver_key_proof(
    receiver_key_proof: &Value,
    linear_statement: Option<&Value>,
    proof_bytes_hex: Option<&str>,
    public_randomness_hex: Option<&str>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
) -> Value {
    let refused_objects = collect_receiver_key_proof_refusals(receiver_key_proof, proof_bytes_hex);
    if !refused_objects.is_empty() {
        return structural_rejection("verifyReceiverKeyProof", refused_objects);
    }

    match (
        linear_statement,
        proof_bytes_hex,
        public_randomness_hex,
        parameter_set,
        proof_encoding,
    ) {
        (None, None, None, None, None) => {}
        (
            Some(linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(parameter_set),
            Some(proof_encoding),
        ) => {
            return verify_receiver_key_linear_proof_bytes(
                receiver_key_proof,
                linear_statement,
                proof_bytes_hex,
                public_randomness_hex,
                parameter_set,
                proof_encoding,
            );
        }
        _ => {
            return structural_rejection(
                "verifyReceiverKeyProof",
                vec![structural_refusal(
                    "Receiver key proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement together.",
                    string_field(receiver_key_proof, "receiverKeyProofRoot"),
                )],
            );
        }
    }

    fail_closed("verifyReceiverKeyProof")
}

pub fn prepare_receiver_key_proof_generation(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match prepare_receiver_key_proof_generation_inner(
        linear_statement,
        parameter_set,
        proof_encoding,
        public_randomness_hex,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "prepareReceiverKeyProofGeneration",
            vec![error.to_json_value()],
        ),
    }
}

fn prepare_receiver_key_proof_generation_inner(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = linear_statement.ok_or_else(|| {
        invalid_preflight("linearStatement is required for receiver-key proof preparation")
    })?;
    let parameter_set = parameter_set.ok_or_else(|| {
        invalid_preflight("parameterSet is required for receiver-key proof preparation")
    })?;
    let proof_encoding = proof_encoding.ok_or_else(|| {
        invalid_preflight("proofEncoding is required for receiver-key proof preparation")
    })?;
    let public_randomness_hex = public_randomness_hex.ok_or_else(|| {
        invalid_preflight("publicRandomnessHex is required for receiver-key proof preparation")
    })?;
    let secret_state = secret_state.ok_or_else(|| {
        invalid_preflight("secretState is required for receiver-key proof preparation")
    })?;

    let parameter_set_value = parameter_set;
    let proof_encoding_value = proof_encoding;
    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "parameterSet is malformed for receiver-key proof preparation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofEncoding is malformed for receiver-key proof preparation: {error}"
            ))
        })?;
    let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> = required_json_field(
        linear_statement,
        "statementMatrixCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.statementMatrixCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_vector_coefficients: Vec<Vec<u64>> = required_json_field(
        linear_statement,
        "targetVectorCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.targetVectorCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        required_json_field(
            linear_statement,
            "targetCoefficientRepresentation",
            "linearStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "linearStatement.targetCoefficientRepresentation is malformed: {error}"
                ))
            })
        })?;
    let source_witness_coefficients = receiver_key_source_witness_coefficients(secret_state)?;
    let public_randomness = decode_hex(public_randomness_hex)?;
    if public_randomness.len() != 32 {
        return Err(invalid_preflight(
            "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
        ));
    }
    let public_randomness_array: [u8; 32] = public_randomness
        .as_slice()
        .try_into()
        .map_err(|_| {
            invalid_preflight(
                "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
            )
        })?;

    let preparation = prepare_linear_prover_witness(LinearProverWitnessInput {
        parameter_set: &parameter_set,
        proof_encoding: &proof_encoding,
        statement_matrix_coefficients: &statement_matrix_coefficients,
        target_vector_coefficients: &target_vector_coefficients,
        target_coefficient_representation,
        source_witness_coefficients: &source_witness_coefficients,
        public_randomness: &public_randomness,
    })?;
    let summary = preparation.summary();
    let commitment_preparation = match prover_randomness_hex {
        Some(prover_randomness_hex) => {
            let prover_randomness = decode_hex(prover_randomness_hex)?;
            if prover_randomness.len() != 32 {
                return Err(invalid_preflight(
                    "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
                ));
            }
            let prover_randomness_array: [u8; 32] = prover_randomness
                .as_slice()
                .try_into()
                .map_err(|_| {
                    invalid_preflight(
                        "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
                    )
                })?;
            let statement_transcript = derive_linear_statement_transcript(
                &parameter_set,
                &proof_encoding,
                &statement_matrix_coefficients,
                &target_vector_coefficients,
                target_coefficient_representation,
                &public_randomness,
            )?;
            Some(prepare_linear_prover_commitment(
                LinearProverCommitmentInput {
                    proof_encoding: &proof_encoding,
                    public_randomness: &public_randomness_array,
                    statement_transcript_hash: &statement_transcript
                        .public_parameters_and_statement_hash,
                    witness_preparation: &preparation,
                    prover_randomness: &prover_randomness_array,
                },
            )?)
        }
        None => None,
    };
    let accepted_digests = [
        derive_receiver_key_linear_statement_digest(linear_statement),
        derive_receiver_key_proof_parameter_set_digest(parameter_set_value),
        derive_receiver_key_proof_encoding_profile_digest(proof_encoding_value),
        derive_receiver_key_public_randomness_digest(public_randomness_hex),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let mut status_labels = vec![
        "ReceiverKeySourceWitnessChecked",
        "ReceiverKeyProofRingWitnessPrepared",
        "ReceiverKeyNormSlackPrepared",
    ];
    if commitment_preparation.is_some() {
        status_labels.push("ReceiverKeyAbdlopCommitmentPrepared");
    }
    let commitment_summary = commitment_preparation.as_ref().map(|commitment| {
        let summary = commitment.summary();
        json!({
            "compressedCommitmentPolynomialCount": commitment.compressed_commitment_polynomial_count(),
            "openingRandomnessPolynomialCount": summary.opening_randomness_polynomial_count,
            "openingRemainderPolynomialCount": summary.opening_remainder_polynomial_count,
            "proverRandomnessSeedBytes": summary.prover_randomness_seed_bytes,
            "subprotocolSeedBytes": summary.subprotocol_seed_bytes,
            "abdlopCommitmentHash": summary.abdlop_commitment_hash_hex
        })
    });

    Ok(json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "prepareReceiverKeyProofGeneration",
        "statusLabels": status_labels,
        "acceptedDigests": accepted_digests,
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": false,
        "summary": {
            "relationWitnessPolynomialCount": summary.relation_witness_polynomial_count,
            "shortWitnessPolynomialCount": summary.short_witness_polynomial_count,
            "preparedShortWitnessPolynomialCount": preparation.short_witness_polynomial_count(),
            "witnessL2Squared": summary.witness_l2_squared.to_string(),
            "witnessL2BoundSquared": summary.witness_l2_bound_squared.to_string(),
            "normSlack": summary.norm_slack.to_string(),
            "abdlopCommitment": commitment_summary
        }
    }))
}

pub fn generate_receiver_key_proof(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match generate_receiver_key_proof_inner(
        linear_statement,
        parameter_set,
        proof_encoding,
        public_randomness_hex,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => structural_rejection("generateReceiverKeyProof", vec![error.to_json_value()]),
    }
}

fn generate_receiver_key_proof_inner(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = linear_statement.ok_or_else(|| {
        invalid_preflight("linearStatement is required for receiver-key proof generation")
    })?;
    let parameter_set_value = parameter_set.ok_or_else(|| {
        invalid_preflight("parameterSet is required for receiver-key proof generation")
    })?;
    let proof_encoding_value = proof_encoding.ok_or_else(|| {
        invalid_preflight("proofEncoding is required for receiver-key proof generation")
    })?;
    let public_randomness_hex = public_randomness_hex.ok_or_else(|| {
        invalid_preflight("publicRandomnessHex is required for receiver-key proof generation")
    })?;
    let secret_state = secret_state.ok_or_else(|| {
        invalid_preflight("secretState is required for receiver-key proof generation")
    })?;
    let prover_randomness_hex = prover_randomness_hex.ok_or_else(|| {
        invalid_preflight("proverRandomnessHex is required for receiver-key proof generation")
    })?;

    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "parameterSet is malformed for receiver-key proof generation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofEncoding is malformed for receiver-key proof generation: {error}"
            ))
        })?;
    let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> = required_json_field(
        linear_statement,
        "statementMatrixCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.statementMatrixCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_vector_coefficients: Vec<Vec<u64>> = required_json_field(
        linear_statement,
        "targetVectorCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.targetVectorCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        required_json_field(
            linear_statement,
            "targetCoefficientRepresentation",
            "linearStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "linearStatement.targetCoefficientRepresentation is malformed: {error}"
                ))
            })
        })?;
    let source_witness_coefficients = receiver_key_source_witness_coefficients(secret_state)?;
    let public_randomness = decode_hex(public_randomness_hex)?;
    if public_randomness.len() != 32 {
        return Err(invalid_preflight(
            "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        ));
    }
    let public_randomness_array: [u8; 32] = public_randomness.as_slice().try_into().map_err(|_| {
        invalid_preflight(
            "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        )
    })?;
    let prover_randomness = decode_hex(prover_randomness_hex)?;
    if prover_randomness.len() != 32 {
        return Err(invalid_preflight(
            "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        ));
    }
    let prover_randomness_array: [u8; 32] = prover_randomness.as_slice().try_into().map_err(|_| {
        invalid_preflight(
            "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        )
    })?;

    let generation = generate_receiver_key_linear_proof(LinearProverProofInput {
        parameter_set: &parameter_set,
        proof_encoding: &proof_encoding,
        statement_matrix_coefficients: &statement_matrix_coefficients,
        target_vector_coefficients: &target_vector_coefficients,
        target_coefficient_representation,
        source_witness_coefficients: &source_witness_coefficients,
        public_randomness: &public_randomness_array,
        prover_randomness: &prover_randomness_array,
    })?;
    let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
    let vector_case = json!({
        "caseName": "generated-receiver-key-proof",
        "description": "Receiver-key linear proof generated by the internal Rust prover.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set_value,
        "proofEncoding": proof_encoding_value,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": statement_matrix_coefficients,
        "targetVectorCoefficients": target_vector_coefficients,
        "targetCoefficientRepresentation": target_coefficient_representation,
        "proofHex": proof_hex,
        "expectedProofSizeBytes": generation.summary.proof_size_bytes
    });
    let verification = linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(
            "generated receiver-key proof did not verify against its public statement",
        ));
    }
    let accepted_digests = [
        derive_receiver_key_linear_statement_digest(linear_statement),
        derive_receiver_key_proof_parameter_set_digest(parameter_set_value),
        derive_receiver_key_proof_encoding_profile_digest(proof_encoding_value),
        derive_receiver_key_public_randomness_digest(public_randomness_hex),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    Ok(json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "generateReceiverKeyProof",
        "statusLabels": [
            "ReceiverKeySourceWitnessChecked",
            "ReceiverKeyProofRingWitnessPrepared",
            "ReceiverKeyAbdlopCommitmentPrepared",
            "ReceiverKeyTboxResponsesGenerated",
            "ReceiverKeyQuadraticChallengeGenerated",
            "ReceiverKeyProofBytesGenerated",
            "ReceiverKeyGeneratedProofVerified"
        ],
        "acceptedDigests": accepted_digests,
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": true,
        "proofBytesHex": proof_hex,
        "proofSizeBytes": generation.summary.proof_size_bytes,
        "summary": {
            "abdlopCommitmentHash": generation.summary.abdlop_commitment_hash_hex,
            "z34ChallengeHash": generation.summary.z34_challenge_hash_hex,
            "generatorChallengeHash": generation.summary.generator_challenge_hash_hex,
            "quadraticChallengeHash": generation.summary.quadratic_challenge_hash_hex
        }
    }))
}

pub fn generate_ballot_proof(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match generate_ballot_proof_inner(
        linear_statement,
        parameter_set,
        proof_encoding,
        public_randomness_hex,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => structural_rejection("generateBallotProof", vec![error.to_json_value()]),
    }
}

fn generate_ballot_proof_inner(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = linear_statement.ok_or_else(|| {
        invalid_preflight("linearStatement is required for ballot proof generation")
    })?;
    if string_field(linear_statement, "projectionCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        return Err(invalid_preflight(
            "ballot proof generation requires a full encoded-score relation statement",
        ));
    }
    let parameter_set_value = parameter_set
        .ok_or_else(|| invalid_preflight("parameterSet is required for ballot proof generation"))?;
    let proof_encoding_value = proof_encoding.ok_or_else(|| {
        invalid_preflight("proofEncoding is required for ballot proof generation")
    })?;
    if string_field(parameter_set_value, "profileId")
        != Some(FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID)
    {
        return Err(invalid_preflight(
            "ballot proof generation requires the full-relation parameter profile",
        ));
    }
    if string_field(proof_encoding_value, "profileId")
        != Some(FULL_BALLOT_PROOF_ENCODING_PROFILE_ID)
    {
        return Err(invalid_preflight(
            "ballot proof generation requires the full-relation proof encoding profile",
        ));
    }
    let public_randomness_hex = public_randomness_hex.ok_or_else(|| {
        invalid_preflight("publicRandomnessHex is required for ballot proof generation")
    })?;
    let secret_state = secret_state
        .ok_or_else(|| invalid_preflight("secretState is required for ballot proof generation"))?;
    let prover_randomness_hex = prover_randomness_hex.ok_or_else(|| {
        invalid_preflight("proverRandomnessHex is required for ballot proof generation")
    })?;

    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "parameterSet is malformed for ballot proof generation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofEncoding is malformed for ballot proof generation: {error}"
            ))
        })?;
    let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> = required_json_field(
        linear_statement,
        "statementMatrixCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.statementMatrixCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_vector_coefficients: Vec<Vec<u64>> = required_json_field(
        linear_statement,
        "targetVectorCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.targetVectorCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        required_json_field(
            linear_statement,
            "targetCoefficientRepresentation",
            "linearStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "linearStatement.targetCoefficientRepresentation is malformed: {error}"
                ))
            })
        })?;
    let source_witness_coefficients = source_witness_coefficients(secret_state)?;
    let public_randomness_array = decode_32_byte_hex(public_randomness_hex, "publicRandomnessHex")?;
    let prover_randomness_array = decode_32_byte_hex(prover_randomness_hex, "proverRandomnessHex")?;

    let generation = generate_linear_proof(LinearProverProofInput {
        parameter_set: &parameter_set,
        proof_encoding: &proof_encoding,
        statement_matrix_coefficients: &statement_matrix_coefficients,
        target_vector_coefficients: &target_vector_coefficients,
        target_coefficient_representation,
        source_witness_coefficients: &source_witness_coefficients,
        public_randomness: &public_randomness_array,
        prover_randomness: &prover_randomness_array,
    })?;
    let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
    let vector_case = json!({
        "caseName": "generated-ballot-proof",
        "description": "Ballot linear proof generated by the internal Rust prover.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set_value,
        "proofEncoding": proof_encoding_value,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": statement_matrix_coefficients,
        "targetVectorCoefficients": target_vector_coefficients,
        "targetCoefficientRepresentation": target_coefficient_representation,
        "proofHex": proof_hex,
        "expectedProofSizeBytes": generation.summary.proof_size_bytes
    });
    let verification = linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(
            "generated ballot proof did not verify against its public statement",
        ));
    }

    Ok(generated_proof_success(
        "generateBallotProof",
        "BallotGeneratedProofVerified",
        proof_hex,
        generation.summary,
    ))
}

pub fn generate_ballot_component_proof(
    component_id: Option<&str>,
    proof_input: Option<&Value>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match generate_ballot_component_proof_inner(
        component_id,
        proof_input,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => {
            structural_rejection("generateBallotComponentProof", vec![error.to_json_value()])
        }
    }
}

fn generate_ballot_component_proof_inner(
    component_id: Option<&str>,
    proof_input: Option<&Value>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let component_id = component_id.ok_or_else(|| {
        invalid_preflight("componentId is required for component proof generation")
    })?;
    let proof_input = proof_input.ok_or_else(|| {
        invalid_preflight("proofInput is required for component proof generation")
    })?;
    let secret_state = secret_state.ok_or_else(|| {
        invalid_preflight("secretState is required for component proof generation")
    })?;
    let prover_randomness_hex = prover_randomness_hex.ok_or_else(|| {
        invalid_preflight("proverRandomnessHex is required for component proof generation")
    })?;
    if string_field(proof_input, "componentId") != Some(component_id) {
        return Err(invalid_preflight(
            "component proof input is not bound to the requested component",
        ));
    }

    let proof_statement_format =
        string_field(proof_input, "proofStatementFormat").ok_or_else(|| {
            invalid_preflight(
                "proofInput.proofStatementFormat is required for component proof generation",
            )
        })?;
    if proof_statement_format == PUBLIC_ZERO_PROOF_STATEMENT_FORMAT {
        if component_id != "receiver-key-binding-component" {
            return Err(invalid_preflight(
                "public-zero component proof generation is only valid for the receiver-key binding component",
            ));
        }
        return Ok(json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "generateBallotComponentProof",
            "componentId": component_id,
            "statusLabels": [
                "BallotComponentPublicZeroProofBytesGenerated"
            ],
            "acceptedDigests": [],
            "refusedObjects": [],
            "unresolvedReason": Value::Null,
            "generatedProofBytes": true,
            "proofBytesHex": "",
            "proofSizeBytes": 0
        }));
    }

    let proof_statement = required_json_field(proof_input, "proofStatement", "proofInput")?;
    let parameter_set_value = required_json_field(proof_input, "proofParameterSet", "proofInput")?;
    let proof_encoding_value = required_json_field(proof_input, "proofEncoding", "proofInput")?;
    let public_randomness_hex =
        string_field(proof_input, "publicRandomnessHex").ok_or_else(|| {
            invalid_preflight(
                "proofInput.publicRandomnessHex is required for component proof generation",
            )
        })?;
    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "proofInput.proofParameterSet is malformed for component proof generation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofInput.proofEncoding is malformed for component proof generation: {error}"
            ))
        })?;
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        required_json_field(
            proof_statement,
            "targetCoefficientRepresentation",
            "proofInput.proofStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "proofInput.proofStatement.targetCoefficientRepresentation is malformed: {error}"
                ))
            })
        })?;
    let source_witness_coefficients = source_witness_coefficients(secret_state)?;
    let public_randomness_array =
        decode_32_byte_hex(public_randomness_hex, "proofInput.publicRandomnessHex")?;
    let prover_randomness_array = decode_32_byte_hex(prover_randomness_hex, "proverRandomnessHex")?;

    let generation = match proof_statement_format {
        DENSE_COMPONENT_PROOF_STATEMENT_FORMAT => {
            let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> = required_json_field(
                proof_statement,
                "statementMatrixCoefficients",
                "proofInput.proofStatement",
            )
            .and_then(|value| {
                serde_json::from_value(value.clone()).map_err(|error| {
                    invalid_preflight(format!(
                        "proofInput.proofStatement.statementMatrixCoefficients is malformed: {error}"
                    ))
                })
            })?;
            let target_vector_coefficients: Vec<Vec<u64>> = required_json_field(
                proof_statement,
                "targetVectorCoefficients",
                "proofInput.proofStatement",
            )
            .and_then(|value| {
                serde_json::from_value(value.clone()).map_err(|error| {
                    invalid_preflight(format!(
                        "proofInput.proofStatement.targetVectorCoefficients is malformed: {error}"
                    ))
                })
            })?;
            let generation = generate_linear_proof(LinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                statement_matrix_coefficients: &statement_matrix_coefficients,
                target_vector_coefficients: &target_vector_coefficients,
                target_coefficient_representation,
                source_witness_coefficients: &source_witness_coefficients,
                public_randomness: &public_randomness_array,
                prover_randomness: &prover_randomness_array,
            })?;
            let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
            let vector_case = json!({
                "caseName": format!("{component_id}-generated-component-proof"),
                "description": "Ballot component proof generated by the internal Rust prover.",
                "mutation": "none",
                "expectedOutcome": "accept",
                "upstreamVectorAvailable": true,
                "parameterSet": parameter_set_value,
                "proofEncoding": proof_encoding_value,
                "publicRandomnessHex": public_randomness_hex,
                "statementMatrixCoefficients": statement_matrix_coefficients,
                "targetVectorCoefficients": target_vector_coefficients,
                "targetCoefficientRepresentation": target_coefficient_representation,
                "proofHex": proof_hex,
                "expectedProofSizeBytes": generation.summary.proof_size_bytes
            });
            let verification =
                linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
            if verification
                .as_object()
                .and_then(|object| object.get("ok"))
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Err(invalid_preflight(
                    "generated dense component proof did not verify against its public statement",
                ));
            }

            generation
        }
        SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT => {
            let parsed_sparse_statement =
                sparse_matrix_from_sparse_component_statement(proof_statement)
                    .map_err(|error| invalid_preflight(error.message))?;
            let generation = generate_sparse_linear_proof(SparseLinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
                target_coefficient_representation,
                source_witness_coefficients: &source_witness_coefficients,
                public_randomness: &public_randomness_array,
                prover_randomness: &prover_randomness_array,
            })?;
            verify_generated_sparse_component_proof(GeneratedSparseComponentProofCheck {
                component_id,
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex,
                source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
                target_coefficient_representation,
                generation: &generation,
            })?;

            generation
        }
        STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT => {
            let parsed_structured_statement =
                structured_receiver_encryption_statement_as_sparse(proof_statement)
                    .map_err(|error| invalid_preflight(error.message))?;
            let generation = generate_sparse_linear_proof(SparseLinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                source_statement_matrix: &parsed_structured_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_structured_statement.target_vector_coefficients,
                target_coefficient_representation,
                source_witness_coefficients: &source_witness_coefficients,
                public_randomness: &public_randomness_array,
                prover_randomness: &prover_randomness_array,
            })?;
            verify_generated_sparse_component_proof(GeneratedSparseComponentProofCheck {
                component_id,
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex,
                source_statement_matrix: &parsed_structured_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_structured_statement.target_vector_coefficients,
                target_coefficient_representation,
                generation: &generation,
            })?;

            generation
        }
        _ => {
            return Err(invalid_preflight(
                "component proof statement format is not supported for proof generation",
            ));
        }
    };

    let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
    Ok(generated_proof_success(
        "generateBallotComponentProof",
        "BallotComponentGeneratedProofVerified",
        proof_hex,
        generation.summary,
    ))
}

struct GeneratedSparseComponentProofCheck<'a> {
    component_id: &'a str,
    parameter_set: &'a LinearProofParameterSet,
    proof_encoding: &'a LinearProofEncoding,
    public_randomness_hex: &'a str,
    source_statement_matrix: &'a SparsePolynomialMatrix,
    target_vector_coefficients: &'a [Vec<u64>],
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    generation: &'a linear_proof_prover::LinearProverProofGeneration,
}

fn verify_generated_sparse_component_proof(
    input: GeneratedSparseComponentProofCheck<'_>,
) -> crate::encoding::CanonicalResult<()> {
    let proof_hex = crate::hashing::to_hex(&input.generation.proof_bytes);
    let verification = linear_proof_verifier::verify_sparse_linear_proof_components(
        linear_proof_verifier::SparseLinearProofVerificationInput {
            case_name: &format!("{}-generated-component-proof", input.component_id),
            parameter_set: input.parameter_set,
            proof_encoding: input.proof_encoding,
            public_randomness_hex: input.public_randomness_hex,
            source_statement_matrix: input.source_statement_matrix,
            target_vector_coefficients: input.target_vector_coefficients,
            target_coefficient_representation: input.target_coefficient_representation,
            proof_hex: &proof_hex,
            expected_proof_size_bytes: Some(input.generation.summary.proof_size_bytes),
        },
    );
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(
            "generated sparse component proof did not verify against its public statement",
        ));
    }

    Ok(())
}

fn generated_proof_success(
    operation: &str,
    verified_status_label: &str,
    proof_hex: String,
    summary: linear_proof_prover::LinearProverProofSummary,
) -> Value {
    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": [
            "LinearProofSourceWitnessChecked",
            "LinearProofRingWitnessPrepared",
            "LinearProofAbdlopCommitmentPrepared",
            "LinearProofTboxResponsesGenerated",
            "LinearProofQuadraticChallengeGenerated",
            "LinearProofBytesGenerated",
            verified_status_label
        ],
        "acceptedDigests": [],
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": true,
        "proofBytesHex": proof_hex,
        "proofSizeBytes": summary.proof_size_bytes,
        "summary": {
            "abdlopCommitmentHash": summary.abdlop_commitment_hash_hex,
            "z34ChallengeHash": summary.z34_challenge_hash_hex,
            "generatorChallengeHash": summary.generator_challenge_hash_hex,
            "quadraticChallengeHash": summary.quadratic_challenge_hash_hex
        }
    })
}

pub struct BallotProofRecordGenerationInput<'a> {
    pub statement: Option<&'a Value>,
    pub linear_statement: Option<&'a Value>,
    pub parameter_set: Option<&'a Value>,
    pub proof_encoding: Option<&'a Value>,
    pub public_randomness_hex: Option<&'a str>,
    pub component_bundle_statement: Option<&'a Value>,
    pub component_proof_inputs: Option<&'a Value>,
    pub secret_state: Option<&'a Value>,
    pub prover_randomness_hex: Option<&'a str>,
    pub component_prover_randomness_hexes: Option<&'a Value>,
    pub component_secret_states: Option<&'a Value>,
}

pub fn generate_ballot_proof_record(input: BallotProofRecordGenerationInput<'_>) -> Value {
    match generate_ballot_proof_record_inner(input) {
        Ok(value) => value,
        Err(error) => {
            structural_rejection("generateBallotProofRecord", vec![error.to_json_value()])
        }
    }
}

fn generate_ballot_proof_record_inner(
    input: BallotProofRecordGenerationInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let statement = input.statement.ok_or_else(|| {
        invalid_preflight("statement is required for ballot proof record generation")
    })?;
    let linear_statement = input.linear_statement.ok_or_else(|| {
        invalid_preflight("linearStatement is required for ballot proof record generation")
    })?;
    let parameter_set = input.parameter_set.ok_or_else(|| {
        invalid_preflight("parameterSet is required for ballot proof record generation")
    })?;
    let proof_encoding = input.proof_encoding.ok_or_else(|| {
        invalid_preflight("proofEncoding is required for ballot proof record generation")
    })?;
    let public_randomness_hex = input.public_randomness_hex.ok_or_else(|| {
        invalid_preflight("publicRandomnessHex is required for ballot proof record generation")
    })?;
    let component_bundle_statement = input.component_bundle_statement.ok_or_else(|| {
        invalid_preflight("componentBundleStatement is required for ballot proof record generation")
    })?;
    let component_proof_inputs = input.component_proof_inputs.ok_or_else(|| {
        invalid_preflight("componentProofInputs is required for ballot proof record generation")
    })?;
    let secret_state = input.secret_state.ok_or_else(|| {
        invalid_preflight("secretState is required for ballot proof record generation")
    })?;
    let prover_randomness_hex = input.prover_randomness_hex.ok_or_else(|| {
        invalid_preflight("proverRandomnessHex is required for ballot proof record generation")
    })?;
    let component_prover_randomness_hexes =
        input.component_prover_randomness_hexes.ok_or_else(|| {
            invalid_preflight(
                "componentProverRandomnessHexes is required for ballot proof record generation",
            )
        })?;
    let component_secret_states = input.component_secret_states;

    if string_field(linear_statement, "projectionCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        return Err(invalid_preflight(
            "ballot proof record generation requires a full encoded-score linear statement",
        ));
    }
    if string_field(component_bundle_statement, "bundleCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        return Err(invalid_preflight(
            "ballot proof record generation requires a full component bundle statement",
        ));
    }

    let component_inputs_array = component_proof_inputs.as_array().ok_or_else(|| {
        invalid_preflight("componentProofInputs must be an array for ballot proof generation")
    })?;
    if component_inputs_array.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        return Err(invalid_preflight(
            "componentProofInputs must contain exactly the required ballot proof components",
        ));
    }
    let mut component_inputs_by_id = BTreeMap::new();
    for component_input in component_inputs_array {
        let component_id = string_field(component_input, "componentId")
            .ok_or_else(|| invalid_preflight("component proof input is missing componentId"))?;
        if object_map(component_input).is_some_and(|object| object.contains_key("proofBytesHex")) {
            return Err(invalid_preflight(
                "component proof inputs for generation must not pre-supply proofBytesHex",
            ));
        }
        if component_inputs_by_id
            .insert(component_id.to_string(), component_input)
            .is_some()
        {
            return Err(invalid_preflight(
                "component proof inputs contain a duplicate component",
            ));
        }
    }

    let mut generated_component_proofs = Vec::new();
    let mut generated_component_inputs = Vec::new();
    for component_id in REQUIRED_BALLOT_PROOF_COMPONENT_IDS {
        let proof_input = component_inputs_by_id.get(*component_id).ok_or_else(|| {
            invalid_preflight(format!(
                "component proof input for {component_id} is missing"
            ))
        })?;
        let component_prover_randomness_hex =
            component_generation_randomness_hex(component_id, component_prover_randomness_hexes)?;
        let component_secret_state =
            component_generation_secret_state(component_id, secret_state, component_secret_states)?;
        let component_generation = generate_ballot_component_proof_inner(
            Some(component_id),
            Some(proof_input),
            Some(component_secret_state),
            Some(&component_prover_randomness_hex),
        )
        .map_err(|error| {
            invalid_preflight(format!(
                "component proof generation failed for {component_id}: {}",
                error.message
            ))
        })?;
        let component_proof_bytes_hex = string_field(&component_generation, "proofBytesHex")
            .ok_or_else(|| {
                invalid_preflight(format!(
                    "generated component proof for {component_id} did not return proofBytesHex"
                ))
            })?
            .to_string();
        let component_proof_size_bytes = object_map(&component_generation)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64)
            .and_then(|proof_size| usize::try_from(proof_size).ok())
            .ok_or_else(|| {
                invalid_preflight(format!(
                    "generated component proof for {component_id} did not return proofSizeBytes"
                ))
            })?;
        let generated_component_input = generated_component_proof_input(
            proof_input,
            &component_proof_bytes_hex,
            component_proof_size_bytes,
        )?;
        let component_proof = generated_component_proof_record(
            component_id,
            statement,
            component_bundle_statement,
            &generated_component_input,
            &component_proof_bytes_hex,
            component_proof_size_bytes,
        )?;
        generated_component_inputs.push(generated_component_input);
        generated_component_proofs.push(component_proof);
    }
    let component_proof_bundle =
        generated_component_proof_bundle(component_bundle_statement, generated_component_proofs)?;

    let ballot_generation = generate_ballot_proof_inner(
        Some(linear_statement),
        Some(parameter_set),
        Some(proof_encoding),
        Some(public_randomness_hex),
        Some(secret_state),
        Some(prover_randomness_hex),
    )
    .map_err(|error| {
        invalid_preflight(format!(
            "full ballot proof generation failed: {}",
            error.message
        ))
    })?;
    let proof_bytes_hex = string_field(&ballot_generation, "proofBytesHex")
        .ok_or_else(|| invalid_preflight("generated ballot proof did not return proofBytesHex"))?
        .to_string();
    let proof_size_bytes = object_map(&ballot_generation)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size| usize::try_from(proof_size).ok())
        .ok_or_else(|| invalid_preflight("generated ballot proof did not return proofSizeBytes"))?;
    let bound_parameter_set =
        proof_contract_with_expected_size(parameter_set, proof_size_bytes, "parameterSet")?;
    let bound_proof_encoding =
        proof_contract_with_expected_size(proof_encoding, proof_size_bytes, "proofEncoding")?;
    let ballot_proof = generated_ballot_proof_record(GeneratedBallotProofRecordInput {
        statement,
        linear_statement,
        parameter_set: &bound_parameter_set,
        proof_encoding: &bound_proof_encoding,
        public_randomness_hex,
        component_bundle_statement,
        component_proof_bundle: &component_proof_bundle,
        proof_bytes_hex: &proof_bytes_hex,
        proof_size_bytes,
    })?;
    let component_proof_inputs = Value::Array(generated_component_inputs);
    let verification = verify_ballot_proof(
        statement,
        &ballot_proof,
        BallotProofVerificationInputs {
            component_bundle_statement: Some(component_bundle_statement),
            component_proof_bundle: Some(&component_proof_bundle),
            component_proof_inputs: Some(&component_proof_inputs),
            linear_statement: Some(linear_statement),
            parameter_set: Some(&bound_parameter_set),
            proof_bytes_hex: Some(&proof_bytes_hex),
            proof_encoding: Some(&bound_proof_encoding),
            public_randomness_hex: Some(public_randomness_hex),
        },
    );
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(format!(
            "generated ballot proof record did not verify: {verification}"
        )));
    }

    Ok(json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "generateBallotProofRecord",
        "statusLabels": [
            "BallotGeneratedProofVerified",
            "BallotComponentProofBundleGenerated",
            "BallotProofRecordGenerated",
            "BallotProofRecordGeneratedProofVerified"
        ],
        "acceptedDigests": [
            string_field(&ballot_proof, "ballotProofRecordDigest"),
            string_field(&component_proof_bundle, "componentProofBundleDigest"),
            string_field(&ballot_proof, "proofBytesDigest")
        ],
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": true,
        "proofBytesHex": proof_bytes_hex,
        "proofSizeBytes": proof_size_bytes,
        "parameterSet": bound_parameter_set,
        "proofEncoding": bound_proof_encoding,
        "ballotProof": ballot_proof,
        "componentProofBundle": component_proof_bundle,
        "componentProofInputs": component_proof_inputs,
        "verification": verification
    }))
}

fn component_generation_randomness_hex(
    component_id: &str,
    component_prover_randomness_hexes: &Value,
) -> crate::encoding::CanonicalResult<String> {
    if component_proof_bytes_must_be_empty(component_id) {
        return Ok("00".repeat(32));
    }
    object_map(component_prover_randomness_hexes)
        .and_then(|object| object.get(component_id))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            invalid_preflight(format!(
                "componentProverRandomnessHexes.{component_id} is required for proof generation"
            ))
        })
}

fn component_generation_secret_state<'a>(
    component_id: &str,
    default_secret_state: &'a Value,
    component_secret_states: Option<&'a Value>,
) -> crate::encoding::CanonicalResult<&'a Value> {
    let Some(component_secret_states) = component_secret_states else {
        return Ok(default_secret_state);
    };
    let component_secret_states = object_map(component_secret_states).ok_or_else(|| {
        invalid_preflight("componentSecretStates must be an object for ballot proof generation")
    })?;

    Ok(component_secret_states
        .get(component_id)
        .unwrap_or(default_secret_state))
}

fn proof_contract_with_expected_size(
    proof_contract: &Value,
    proof_size_bytes: usize,
    field_name: &str,
) -> crate::encoding::CanonicalResult<Value> {
    let mut proof_contract = object_map(proof_contract)
        .ok_or_else(|| invalid_preflight(format!("{field_name} must be an object")))?
        .clone();
    proof_contract.insert(
        "expectedProofSizeBytes".to_string(),
        json!(proof_size_bytes),
    );

    Ok(Value::Object(proof_contract))
}

fn proof_bytes_digest(
    proof_bytes_hex: &str,
    allow_empty: bool,
) -> crate::encoding::CanonicalResult<String> {
    let proof_bytes = decode_hex(proof_bytes_hex).map_err(|_| {
        invalid_preflight("generated proof bytes must be lowercase hexadecimal bytes")
    })?;
    if !allow_empty && proof_bytes.is_empty() {
        return Err(invalid_preflight(
            "generated proof bytes must be non-empty for this proof record",
        ));
    }
    derive_digest(
        "ProofBytesDigest",
        &json!({
            "objectType": "ProofBytes",
            "objectVersion": 1,
            "proofBytesHex": proof_bytes_hex,
            "proofSizeBytes": proof_bytes.len(),
        }),
    )
    .ok_or_else(|| invalid_preflight("generated proof bytes digest could not be derived"))
}

fn generated_component_proof_input(
    proof_input: &Value,
    proof_bytes_hex: &str,
    proof_size_bytes: usize,
) -> crate::encoding::CanonicalResult<Value> {
    let mut proof_input = object_map(proof_input)
        .ok_or_else(|| invalid_preflight("component proof input must be an object"))?
        .clone();
    let parameter_set = proof_input
        .get("proofParameterSet")
        .cloned()
        .ok_or_else(|| invalid_preflight("component proof input is missing proofParameterSet"))?;
    let proof_encoding = proof_input
        .get("proofEncoding")
        .cloned()
        .ok_or_else(|| invalid_preflight("component proof input is missing proofEncoding"))?;
    proof_input.insert(
        "proofParameterSet".to_string(),
        proof_contract_with_expected_size(
            &parameter_set,
            proof_size_bytes,
            "component proof parameter set",
        )?,
    );
    proof_input.insert(
        "proofEncoding".to_string(),
        proof_contract_with_expected_size(
            &proof_encoding,
            proof_size_bytes,
            "component proof encoding",
        )?,
    );
    if !proof_input.contains_key("componentProofStatementDigest") {
        let proof_statement = proof_input
            .get("proofStatement")
            .ok_or_else(|| invalid_preflight("component proof input is missing proofStatement"))?;
        let proof_statement_format = proof_input
            .get("proofStatementFormat")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_preflight("component proof input is missing proofStatementFormat")
            })?;
        if let (Some(component_proof_statement_digest), _) =
            supplied_component_proof_statement_digest(proof_statement, proof_statement_format)
        {
            proof_input.insert(
                "componentProofStatementDigest".to_string(),
                json!(component_proof_statement_digest),
            );
        }
    }
    proof_input.insert("proofBytesHex".to_string(), json!(proof_bytes_hex));

    Ok(Value::Object(proof_input))
}

fn generated_component_proof_record(
    component_id: &str,
    statement: &Value,
    component_bundle_statement: &Value,
    component_proof_input: &Value,
    proof_bytes_hex: &str,
    proof_size_bytes: usize,
) -> crate::encoding::CanonicalResult<Value> {
    let allow_empty_proof_bytes = component_proof_bytes_must_be_empty(component_id);
    let proof_bytes_digest = proof_bytes_digest(proof_bytes_hex, allow_empty_proof_bytes)?;
    let proof_encoding = required_json_field(
        component_proof_input,
        "proofEncoding",
        "componentProofInput",
    )?;
    let proof_parameter_set = required_json_field(
        component_proof_input,
        "proofParameterSet",
        "componentProofInput",
    )?;
    let public_randomness_hex = string_field(component_proof_input, "publicRandomnessHex")
        .ok_or_else(|| invalid_preflight("component proof input is missing publicRandomnessHex"))?;
    let proof_encoding_profile_digest = derive_ballot_proof_encoding_profile_digest(proof_encoding)
        .ok_or_else(|| invalid_preflight("component proof encoding digest could not be derived"))?;
    let proof_parameter_set_digest = derive_ballot_proof_parameter_set_digest(proof_parameter_set)
        .ok_or_else(|| {
            invalid_preflight("component proof parameter-set digest could not be derived")
        })?;
    let public_randomness_digest =
        derive_ballot_proof_public_randomness_digest(public_randomness_hex).ok_or_else(|| {
            invalid_preflight("component proof public randomness digest could not be derived")
        })?;
    let component_statement_digest = string_field(component_proof_input, "statementDigest")
        .ok_or_else(|| invalid_preflight("component proof input is missing statementDigest"))?;

    let mut proof_root_payload = Map::new();
    proof_root_payload.insert("componentId".to_string(), json!(component_id));
    if let Some(component_proof_statement_digest) =
        string_field(component_proof_input, "componentProofStatementDigest")
    {
        proof_root_payload.insert(
            "componentProofStatementDigest".to_string(),
            json!(component_proof_statement_digest),
        );
    }
    proof_root_payload.insert(
        "componentStatementDigest".to_string(),
        json!(component_statement_digest),
    );
    proof_root_payload.insert("proofBytesDigest".to_string(), json!(proof_bytes_digest));
    proof_root_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(proof_encoding_profile_digest),
    );
    proof_root_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(proof_parameter_set_digest),
    );
    proof_root_payload.insert(
        "proofStatementFormat".to_string(),
        json!(
            string_field(component_proof_input, "proofStatementFormat").ok_or_else(|| {
                invalid_preflight("component proof input is missing proofStatementFormat")
            })?
        ),
    );
    proof_root_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(public_randomness_digest),
    );
    proof_root_payload.insert(
        "purpose".to_string(),
        json!("ballot-proof-component-proof-root-v1"),
    );
    proof_root_payload.insert(
        "statementDigest".to_string(),
        json!(component_statement_digest),
    );
    let proof_root = derive_digest("ChallengeDomainDigest", &Value::Object(proof_root_payload))
        .ok_or_else(|| invalid_preflight("component proof root could not be derived"))?;

    let mut component_proof_payload = Map::new();
    component_proof_payload.insert(
        "backendStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "backendStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing backendStatementDigest"
                )
            )?
        ),
    );
    if let Some(ballot_proof_statement_digest) =
        string_field(statement, "ballotProofStatementDigest")
    {
        component_proof_payload.insert(
            "ballotProofStatementDigest".to_string(),
            json!(ballot_proof_statement_digest),
        );
    }
    component_proof_payload.insert("componentId".to_string(), json!(component_id));
    if let Some(component_proof_statement_digest) =
        string_field(component_proof_input, "componentProofStatementDigest")
    {
        component_proof_payload.insert(
            "componentProofStatementDigest".to_string(),
            json!(component_proof_statement_digest),
        );
    }
    component_proof_payload.insert(
        "componentStatementDigest".to_string(),
        json!(component_statement_digest),
    );
    component_proof_payload.insert(
        "objectType".to_string(),
        json!("BallotProofComponentProofRecord"),
    );
    component_proof_payload.insert("objectVersion".to_string(), json!(1));
    component_proof_payload.insert(
        "proofBackend".to_string(),
        json!("LocalLinearLatticeRelation"),
    );
    component_proof_payload.insert("proofBytesDigest".to_string(), json!(proof_bytes_digest));
    component_proof_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(proof_encoding_profile_digest),
    );
    component_proof_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(proof_parameter_set_digest),
    );
    component_proof_payload.insert("proofRoot".to_string(), json!(proof_root));
    component_proof_payload.insert("proofSizeBytes".to_string(), json!(proof_size_bytes));
    component_proof_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(public_randomness_digest),
    );
    component_proof_payload.insert(
        "relationStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "relationStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing relationStatementDigest"
                )
            )?
        ),
    );
    let component_proof_payload_value = Value::Object(component_proof_payload.clone());
    let component_proof_record_digest = derive_ballot_component_proof_record_digest(
        &component_proof_payload_value,
    )
    .ok_or_else(|| invalid_preflight("component proof record digest could not be derived"))?;
    component_proof_payload.insert(
        "componentProofRecordDigest".to_string(),
        json!(component_proof_record_digest),
    );

    Ok(Value::Object(component_proof_payload))
}

fn generated_component_proof_bundle(
    component_bundle_statement: &Value,
    component_proofs: Vec<Value>,
) -> crate::encoding::CanonicalResult<Value> {
    let mut component_proof_bundle_payload = Map::new();
    component_proof_bundle_payload.insert(
        "backendStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "backendStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing backendStatementDigest"
                )
            )?
        ),
    );
    if let Some(ballot_proof_statement_digest) =
        string_field(component_bundle_statement, "ballotProofStatementDigest")
    {
        component_proof_bundle_payload.insert(
            "ballotProofStatementDigest".to_string(),
            json!(ballot_proof_statement_digest),
        );
    }
    component_proof_bundle_payload.insert(
        "bundleCoverage".to_string(),
        json!(FULL_BALLOT_PROOF_PROJECTION_COVERAGE),
    );
    component_proof_bundle_payload.insert(
        "componentBundleStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "componentBundleStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing componentBundleStatementDigest"
                )
            )?
        ),
    );
    component_proof_bundle_payload.insert("componentProofs".to_string(), json!(component_proofs));
    component_proof_bundle_payload.insert(
        "objectType".to_string(),
        json!("BallotProofComponentProofBundle"),
    );
    component_proof_bundle_payload.insert("objectVersion".to_string(), json!(1));
    component_proof_bundle_payload.insert(
        "relationStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "relationStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing relationStatementDigest"
                )
            )?
        ),
    );
    component_proof_bundle_payload.insert(
        "requiredComponentIds".to_string(),
        json!(REQUIRED_BALLOT_PROOF_COMPONENT_IDS),
    );
    let component_proof_bundle_value = Value::Object(component_proof_bundle_payload.clone());
    let component_proof_bundle_digest = derive_ballot_component_proof_bundle_digest(
        &component_proof_bundle_value,
    )
    .ok_or_else(|| invalid_preflight("component proof bundle digest could not be derived"))?;
    component_proof_bundle_payload.insert(
        "componentProofBundleDigest".to_string(),
        json!(component_proof_bundle_digest),
    );

    Ok(Value::Object(component_proof_bundle_payload))
}

struct GeneratedBallotProofRecordInput<'a> {
    statement: &'a Value,
    linear_statement: &'a Value,
    parameter_set: &'a Value,
    proof_encoding: &'a Value,
    public_randomness_hex: &'a str,
    component_bundle_statement: &'a Value,
    component_proof_bundle: &'a Value,
    proof_bytes_hex: &'a str,
    proof_size_bytes: usize,
}

fn generated_ballot_proof_record(
    input: GeneratedBallotProofRecordInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let statement = input.statement;
    let linear_statement = input.linear_statement;
    let parameter_set = input.parameter_set;
    let proof_encoding = input.proof_encoding;
    let public_randomness_hex = input.public_randomness_hex;
    let component_bundle_statement = input.component_bundle_statement;
    let component_proof_bundle = input.component_proof_bundle;
    let proof_bytes_hex = input.proof_bytes_hex;
    let proof_size_bytes = input.proof_size_bytes;
    let proof_bytes_digest = proof_bytes_digest(proof_bytes_hex, false)?;
    let proof_encoding_profile_digest = derive_ballot_proof_encoding_profile_digest(proof_encoding)
        .ok_or_else(|| invalid_preflight("ballot proof encoding digest could not be derived"))?;
    let proof_parameter_set_digest = derive_ballot_proof_parameter_set_digest(parameter_set)
        .ok_or_else(|| {
            invalid_preflight("ballot proof parameter-set digest could not be derived")
        })?;
    let public_randomness_digest =
        derive_ballot_proof_public_randomness_digest(public_randomness_hex).ok_or_else(|| {
            invalid_preflight("ballot proof public randomness digest could not be derived")
        })?;
    let linear_statement_digest = string_field(linear_statement, "statementDigest")
        .ok_or_else(|| invalid_preflight("linear statement is missing statementDigest"))?;
    let proof_root = derive_digest(
        "BallotProofRecordDigest",
        &json!({
            "linearStatementDigest": linear_statement_digest,
            "proofBytesDigest": proof_bytes_digest,
            "proofEncodingProfileDigest": proof_encoding_profile_digest,
            "proofParameterSetDigest": proof_parameter_set_digest,
            "publicRandomnessDigest": public_randomness_digest,
            "purpose": "ballot-proof-linear-proof-record-root-v1",
        }),
    )
    .ok_or_else(|| invalid_preflight("ballot proof root could not be derived"))?;

    let mut proof_payload = Map::new();
    proof_payload.insert(
        "backendStatementDigest".to_string(),
        json!(
            string_field(linear_statement, "backendStatementDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing backendStatementDigest")
            })?
        ),
    );
    proof_payload.insert(
        "ballotProofProfileDigest".to_string(),
        json!(
            string_field(statement, "ballotProofProfileDigest").ok_or_else(|| {
                invalid_preflight("statement is missing ballotProofProfileDigest")
            })?
        ),
    );
    proof_payload.insert(
        "ballotProofStatementDigest".to_string(),
        json!(
            string_field(statement, "ballotProofStatementDigest").ok_or_else(|| {
                invalid_preflight("statement is missing ballotProofStatementDigest")
            })?
        ),
    );
    proof_payload.insert(
        "componentBundleStatementDigest".to_string(),
        json!(
            string_field(component_bundle_statement, "componentBundleStatementDigest").ok_or_else(
                || invalid_preflight(
                    "component bundle statement is missing componentBundleStatementDigest"
                )
            )?
        ),
    );
    proof_payload.insert(
        "componentProofBundleDigest".to_string(),
        json!(
            string_field(component_proof_bundle, "componentProofBundleDigest").ok_or_else(
                || invalid_preflight(
                    "component proof bundle is missing componentProofBundleDigest"
                )
            )?
        ),
    );
    proof_payload.insert(
        "linearStatementDigest".to_string(),
        json!(linear_statement_digest),
    );
    proof_payload.insert("objectType".to_string(), json!("BallotProofRecord"));
    proof_payload.insert("objectVersion".to_string(), json!(1));
    proof_payload.insert(
        "proofBackend".to_string(),
        json!("LocalLinearLatticeRelation"),
    );
    proof_payload.insert("proofBytesDigest".to_string(), json!(proof_bytes_digest));
    proof_payload.insert(
        "proofEncodingProfileDigest".to_string(),
        json!(proof_encoding_profile_digest),
    );
    proof_payload.insert(
        "proofParameterSetDigest".to_string(),
        json!(proof_parameter_set_digest),
    );
    proof_payload.insert("proofRoot".to_string(), json!(proof_root));
    proof_payload.insert("proofSizeBytes".to_string(), json!(proof_size_bytes));
    proof_payload.insert(
        "publicRandomnessDigest".to_string(),
        json!(public_randomness_digest),
    );
    proof_payload.insert(
        "relationStatementDigest".to_string(),
        json!(
            string_field(linear_statement, "relationStatementDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing relationStatementDigest")
            })?
        ),
    );
    proof_payload.insert(
        "statementMatrixDigest".to_string(),
        json!(
            string_field(linear_statement, "statementMatrixDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing statementMatrixDigest")
            })?
        ),
    );
    proof_payload.insert(
        "targetVectorDigest".to_string(),
        json!(
            string_field(linear_statement, "targetVectorDigest").ok_or_else(|| {
                invalid_preflight("linear statement is missing targetVectorDigest")
            })?
        ),
    );
    let challenge_digest =
        derive_ballot_proof_challenge_digest(statement, &Value::Object(proof_payload.clone()))
            .ok_or_else(|| {
                invalid_preflight("ballot proof challenge digest could not be derived")
            })?;
    proof_payload.insert("challengeDigest".to_string(), json!(challenge_digest));
    let proof_payload_value = Value::Object(proof_payload.clone());
    let ballot_proof_record_digest = derive_digest("BallotProofRecordDigest", &proof_payload_value)
        .ok_or_else(|| invalid_preflight("ballot proof record digest could not be derived"))?;
    proof_payload.insert(
        "ballotProofRecordDigest".to_string(),
        json!(ballot_proof_record_digest),
    );

    Ok(Value::Object(proof_payload))
}

fn required_json_field<'value>(
    value: &'value Value,
    field_name: &str,
    object_name: &str,
) -> crate::encoding::CanonicalResult<&'value Value> {
    object_map(value)
        .and_then(|object| object.get(field_name))
        .ok_or_else(|| invalid_preflight(format!("{object_name}.{field_name} is required")))
}

fn decode_32_byte_hex(
    hex_value: &str,
    field_name: &str,
) -> crate::encoding::CanonicalResult<[u8; 32]> {
    let bytes = decode_hex(hex_value)?;
    if bytes.len() != 32 {
        return Err(invalid_preflight(format!(
            "{field_name} must encode exactly 32 bytes"
        )));
    }

    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_preflight(format!("{field_name} must encode exactly 32 bytes")))
}

fn source_witness_coefficients(
    secret_state: &Value,
) -> crate::encoding::CanonicalResult<Vec<Vec<i64>>> {
    let secret_state = object_map(secret_state)
        .ok_or_else(|| invalid_preflight("secretState must be an object"))?;
    signed_polynomial_vector_field(secret_state, "sourceWitnessCoefficients")
}

fn receiver_key_source_witness_coefficients(
    secret_state: &Value,
) -> crate::encoding::CanonicalResult<Vec<Vec<i64>>> {
    let secret_state = object_map(secret_state)
        .ok_or_else(|| invalid_preflight("secretState must be an object"))?;
    let mut source_witness_coefficients =
        signed_polynomial_vector_field(secret_state, "secretVector")?;
    source_witness_coefficients
        .extend(signed_polynomial_vector_field(secret_state, "errorVector")?);

    Ok(source_witness_coefficients)
}

fn signed_polynomial_vector_field(
    object: &Map<String, Value>,
    field_name: &str,
) -> crate::encoding::CanonicalResult<Vec<Vec<i64>>> {
    let vector = object
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_preflight(format!("secretState.{field_name} must be an array")))?;

    vector
        .iter()
        .enumerate()
        .map(|(polynomial_index, polynomial)| {
            let coefficients = polynomial.as_array().ok_or_else(|| {
                invalid_preflight(format!(
                    "secretState.{field_name}[{polynomial_index}] must be an array"
                ))
            })?;

            coefficients
                .iter()
                .enumerate()
                .map(|(coefficient_index, coefficient)| {
                    coefficient.as_i64().ok_or_else(|| {
                        invalid_preflight(format!(
                            "secretState.{field_name}[{polynomial_index}][{coefficient_index}] must be a signed integer"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

fn invalid_preflight(message: impl Into<String>) -> crate::encoding::CanonicalError {
    crate::encoding::CanonicalError::new(
        crate::encoding::CanonicalErrorCode::InvalidFixture,
        message,
    )
}

fn string_array_matches_expected(
    value: &Value,
    field_name: &str,
    expected_values: &[&str],
) -> bool {
    let Some(values) = array_field(value, field_name) else {
        return false;
    };

    values.len() == expected_values.len()
        && values
            .iter()
            .zip(expected_values.iter())
            .all(|(actual_value, expected_value)| actual_value.as_str() == Some(*expected_value))
}

fn string_array_length(value: &Value, field_name: &str) -> Option<usize> {
    Some(
        array_field(value, field_name)?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?
            .len(),
    )
}

fn collect_component_bundle_component_refusals(
    component_statement: &Value,
    expected_component_id: &str,
    bundle_digest: Option<&str>,
    statement: &Value,
    linear_statement: &Value,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let component_statement_digest = string_field(component_statement, "componentStatementDigest");
    let expected_component_statement_digest =
        derive_ballot_component_statement_digest(component_statement);
    let row_batch_name_count = string_array_length(component_statement, "rowBatchNames");
    let row_batch_matrix_digest_count =
        string_array_length(component_statement, "rowBatchMatrixDigests");
    let row_batch_target_vector_digest_count =
        string_array_length(component_statement, "rowBatchTargetVectorDigests");
    let variable_column_count = object_map(component_statement)
        .and_then(|object| object.get("variableColumnCount"))
        .and_then(Value::as_u64);
    let variable_column_indices_count = array_field(component_statement, "variableColumnIndices")
        .map(Vec::len)
        .and_then(|count| u64::try_from(count).ok());
    let row_count = object_map(component_statement)
        .and_then(|object| object.get("rowCount"))
        .and_then(Value::as_u64);
    let row_kinds_are_present =
        array_field(component_statement, "rowKinds").is_some_and(|values| {
            !values.is_empty() && values.iter().all(|value| value.as_str().is_some())
        });

    if string_field(component_statement, "objectType") != Some("BallotProofComponentStatement")
        || object_map(component_statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_statement, "componentId") != Some(expected_component_id)
        || string_field(component_statement, "coefficientModulus").is_none_or(str::is_empty)
        || string_field(component_statement, "componentDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || component_statement_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_statement, "matrixDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_statement, "targetVectorDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || row_count.is_none_or(|count| count == 0)
        || !row_kinds_are_present
        || variable_column_count != variable_column_indices_count
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} has an invalid canonical shape."
            ),
            bundle_digest,
        ));
    }
    if expected_component_statement_digest.as_deref() != component_statement_digest {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement digest for {expected_component_id} does not match its canonical payload."
            ),
            bundle_digest,
        ));
    }
    if string_field(component_statement, "backendStatementDigest")
        != string_field(linear_statement, "backendStatementDigest")
        || string_field(component_statement, "relationStatementDigest")
            != string_field(linear_statement, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not bound to the supplied relation and backend statement."
            ),
            bundle_digest,
        ));
    }
    if string_field(component_statement, "ballotProofStatementDigest").is_some()
        && string_field(component_statement, "ballotProofStatementDigest")
            != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not bound to the supplied ballot proof statement."
            ),
            bundle_digest,
        ));
    }
    if string_field(component_statement, "proofLoweringStatus") != Some("explicitRowsAvailable") {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} is not fully lowered into explicit proof rows."
            ),
            bundle_digest,
        ));
    }
    if row_batch_name_count.is_none()
        || row_batch_matrix_digest_count.is_none()
        || row_batch_target_vector_digest_count.is_none()
        || row_batch_name_count != row_batch_matrix_digest_count
        || row_batch_name_count != row_batch_target_vector_digest_count
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} has inconsistent row-batch digest lists."
            ),
            bundle_digest,
        ));
    }
    if array_field(component_statement, "rowBatchMatrixDigests").is_some_and(|digests| {
        digests.iter().any(|digest| {
            digest
                .as_str()
                .is_none_or(|value| !is_protocol_digest(value))
        })
    }) || array_field(component_statement, "rowBatchTargetVectorDigests").is_some_and(
        |digests| {
            digests.iter().any(|digest| {
                digest
                    .as_str()
                    .is_none_or(|value| !is_protocol_digest(value))
            })
        },
    ) {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component statement for {expected_component_id} contains a non-digest row-batch reference."
            ),
            bundle_digest,
        ));
    }

    refused_objects
}

fn collect_ballot_component_bundle_refusals(
    statement: &Value,
    ballot_proof: &Value,
    linear_statement: &Value,
    component_bundle_statement: Option<&Value>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let projection_coverage = string_field(linear_statement, "projectionCoverage");

    let Some(component_bundle_statement) = component_bundle_statement else {
        if projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
            || string_field(ballot_proof, "componentBundleStatementDigest").is_some()
        {
            refused_objects.push(structural_refusal(
                "Full encoded-score ballot proof verification requires a public component bundle statement.",
                proof_record_digest,
            ));
        }

        return refused_objects;
    };

    let bundle_digest = string_field(component_bundle_statement, "componentBundleStatementDigest");
    let expected_bundle_digest =
        derive_ballot_component_bundle_statement_digest(component_bundle_statement);

    if string_field(component_bundle_statement, "objectType")
        != Some("BallotProofComponentBundleStatement")
        || object_map(component_bundle_statement)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_bundle_statement, "relationLabel")
            != Some("BallotPrivacyPvssRelation")
        || bundle_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || !string_array_matches_expected(
            component_bundle_statement,
            "requiredComponentIds",
            REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        )
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle statement has an invalid canonical shape.",
            proof_record_digest,
        ));
    }
    if expected_bundle_digest.as_deref() != bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle digest does not match its canonical payload.",
            proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "componentBundleStatementDigest") != bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied component bundle statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_bundle_statement, "backendStatementDigest")
        != string_field(linear_statement, "backendStatementDigest")
        || string_field(component_bundle_statement, "relationStatementDigest")
            != string_field(linear_statement, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is not bound to the supplied relation and backend statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_bundle_statement, "ballotProofStatementDigest").is_some()
        && string_field(component_bundle_statement, "ballotProofStatementDigest")
            != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is not bound to the supplied ballot proof statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_bundle_statement, "bundleCoverage")
        == Some(COMPONENT_BUNDLE_INCOMPLETE_COVERAGE)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle is still incomplete.",
            proof_record_digest,
        ));
    } else if string_field(component_bundle_statement, "bundleCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle has an unknown coverage label.",
            proof_record_digest,
        ));
    }

    let Some(component_statements) = array_field(component_bundle_statement, "componentStatements")
    else {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle must contain component statements.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    if component_statements.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component bundle must contain exactly the required component statements.",
            proof_record_digest,
        ));
    }

    let mut seen_component_ids = BTreeSet::new();
    for (component_index, expected_component_id) in
        REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter().enumerate()
    {
        let Some(component_statement) = component_statements.get(component_index) else {
            continue;
        };
        if let Some(component_id) = string_field(component_statement, "componentId")
            && !seen_component_ids.insert(component_id.to_string())
        {
            refused_objects.push(structural_refusal(
                "Ballot proof component bundle contains a duplicate component statement.",
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_component_bundle_component_refusals(
            component_statement,
            expected_component_id,
            proof_record_digest,
            statement,
            linear_statement,
        ));
    }

    refused_objects
}

fn collect_component_proof_record_refusals(
    component_proof: &Value,
    expected_component_id: &str,
    proof_record_digest: Option<&str>,
    statement: &Value,
    component_proof_bundle: &Value,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let component_proof_record_digest = string_field(component_proof, "componentProofRecordDigest");
    let expected_component_proof_record_digest =
        derive_ballot_component_proof_record_digest(component_proof);
    let proof_size_bytes = object_map(component_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64);
    let proof_size_bytes_is_valid = proof_size_bytes.is_some_and(|proof_size_bytes| {
        if component_proof_bytes_must_be_empty(expected_component_id) {
            proof_size_bytes == 0
        } else {
            proof_size_bytes > 0
        }
    });

    if string_field(component_proof, "objectType") != Some("BallotProofComponentProofRecord")
        || object_map(component_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_proof, "componentId") != Some(expected_component_id)
        || string_field(component_proof, "proofBackend") != Some("LocalLinearLatticeRelation")
        || component_proof_record_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "componentStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "backendStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "relationStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofRoot")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofBytesDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofEncodingProfileDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "proofParameterSetDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "publicRandomnessDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "componentProofStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || string_field(component_proof, "ballotProofStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || !proof_size_bytes_is_valid
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} has an invalid canonical shape."
            ),
            proof_record_digest,
        ));
    }
    if expected_component_proof_record_digest.as_deref() != component_proof_record_digest {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof digest for {expected_component_id} does not match its canonical payload."
            ),
            proof_record_digest,
        ));
    }
    if string_field(component_proof, "backendStatementDigest")
        != string_field(component_proof_bundle, "backendStatementDigest")
        || string_field(component_proof, "relationStatementDigest")
            != string_field(component_proof_bundle, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} is not bound to the supplied relation and backend statement."
            ),
            proof_record_digest,
        ));
    }
    if string_field(component_proof, "ballotProofStatementDigest").is_some()
        && string_field(component_proof, "ballotProofStatementDigest")
            != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof for {expected_component_id} is not bound to the supplied ballot proof statement."
            ),
            proof_record_digest,
        ));
    }

    refused_objects
}

fn collect_ballot_component_proof_bundle_refusals(
    statement: &Value,
    ballot_proof: &Value,
    component_bundle_statement: Option<&Value>,
    component_proof_bundle: Option<&Value>,
    component_proof_inputs: Option<&Value>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let ballot_proof_component_bundle_digest =
        string_field(ballot_proof, "componentProofBundleDigest");

    if ballot_proof_component_bundle_digest.is_some() && component_proof_bundle.is_none() {
        refused_objects.push(structural_refusal(
            "Ballot proof record references a component proof bundle that was not supplied.",
            proof_record_digest,
        ));

        return refused_objects;
    }
    if component_proof_bundle.is_some() && ballot_proof_component_bundle_digest.is_none() {
        refused_objects.push(structural_refusal(
            "Supplied component proof bundle is not bound by the ballot proof record.",
            proof_record_digest,
        ));
    }
    if component_bundle_statement.is_some_and(|bundle_statement| {
        string_field(bundle_statement, "bundleCoverage")
            == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    }) && component_proof_bundle.is_none()
    {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot proof verification requires a component proof bundle.",
            proof_record_digest,
        ));
    }
    let Some(component_proof_bundle) = component_proof_bundle else {
        return refused_objects;
    };
    refused_objects.extend(collect_ballot_component_proof_input_refusals(
        ballot_proof,
        component_proof_bundle,
        component_proof_inputs,
    ));

    let component_proof_bundle_digest =
        string_field(component_proof_bundle, "componentProofBundleDigest");
    let expected_component_proof_bundle_digest =
        derive_ballot_component_proof_bundle_digest(component_proof_bundle);

    if string_field(component_proof_bundle, "objectType") != Some("BallotProofComponentProofBundle")
        || object_map(component_proof_bundle)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(component_proof_bundle, "bundleCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        || component_proof_bundle_digest.is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "componentBundleStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "backendStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "relationStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || string_field(component_proof_bundle, "ballotProofStatementDigest")
            .is_some_and(|digest| !is_protocol_digest(digest))
        || !string_array_matches_expected(
            component_proof_bundle,
            "requiredComponentIds",
            REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        )
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle has an invalid canonical shape.",
            proof_record_digest,
        ));
    }
    if expected_component_proof_bundle_digest.as_deref() != component_proof_bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle digest does not match its canonical payload.",
            proof_record_digest,
        ));
    }
    if ballot_proof_component_bundle_digest != component_proof_bundle_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied component proof bundle.",
            proof_record_digest,
        ));
    }
    if string_field(component_proof_bundle, "componentBundleStatementDigest")
        != string_field(ballot_proof, "componentBundleStatementDigest")
        || string_field(component_proof_bundle, "backendStatementDigest")
            != string_field(ballot_proof, "backendStatementDigest")
        || string_field(component_proof_bundle, "relationStatementDigest")
            != string_field(ballot_proof, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied proof statement roots.",
            proof_record_digest,
        ));
    }
    if let Some(component_bundle_statement) = component_bundle_statement
        && string_field(component_proof_bundle, "componentBundleStatementDigest")
            != string_field(component_bundle_statement, "componentBundleStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied component bundle statement.",
            proof_record_digest,
        ));
    }
    if string_field(component_proof_bundle, "ballotProofStatementDigest").is_some()
        && string_field(component_proof_bundle, "ballotProofStatementDigest")
            != string_field(statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle is not bound to the supplied ballot proof statement.",
            proof_record_digest,
        ));
    }

    let Some(component_proofs) = array_field(component_proof_bundle, "componentProofs") else {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle must contain component proofs.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    if component_proofs.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof bundle must contain exactly the required component proofs.",
            proof_record_digest,
        ));
    }

    let mut seen_component_ids = BTreeSet::new();
    for (component_index, expected_component_id) in
        REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter().enumerate()
    {
        let Some(component_proof) = component_proofs.get(component_index) else {
            continue;
        };
        if let Some(component_id) = string_field(component_proof, "componentId")
            && !seen_component_ids.insert(component_id.to_string())
        {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof bundle contains a duplicate component proof.",
                proof_record_digest,
            ));
        }
        if let Some(component_bundle_statement) = component_bundle_statement
            && let Some(component_statement) =
                array_field(component_bundle_statement, "componentStatements")
                    .and_then(|component_statements| component_statements.get(component_index))
            && string_field(component_proof, "componentStatementDigest")
                != string_field(component_statement, "componentStatementDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof for {expected_component_id} is not bound to the supplied component statement."
                ),
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_component_proof_record_refusals(
            component_proof,
            expected_component_id,
            proof_record_digest,
            statement,
            component_proof_bundle,
        ));
    }

    refused_objects
}

fn supplied_component_proof_statement_digest<'a>(
    proof_statement: &'a Value,
    proof_statement_format: &str,
) -> (Option<String>, Option<&'a str>) {
    match (
        string_field(proof_statement, "objectType"),
        proof_statement_format,
    ) {
        (Some("BallotProofLinearProofStatement"), "dense-polynomial-matrix-linear-proof-v1") => (
            derive_ballot_proof_linear_statement_digest(proof_statement),
            Some("statementDigest"),
        ),
        (
            Some("BallotProofSparseComponentLinearProofStatement"),
            "sparse-polynomial-matrix-linear-proof-v1",
        ) => (
            derive_ballot_sparse_linear_statement_digest(proof_statement),
            Some("statementDigest"),
        ),
        (
            Some("BallotProofComponentProofStatementPlan"),
            "structured-module-lwe-linear-proof-v1" | "public-zero-witness-binding-check-v1",
        ) => (
            derive_ballot_component_proof_statement_plan_digest(proof_statement),
            Some("componentProofStatementDigest"),
        ),
        (
            Some("BallotProofStructuredReceiverEncryptionProofStatement"),
            "structured-module-lwe-linear-proof-v1",
        ) => (
            derive_ballot_structured_receiver_encryption_statement_digest(proof_statement),
            Some("statementDigest"),
        ),
        _ => (None, None),
    }
}

fn protocol_digest_field(value: &Value, field_name: &str) -> bool {
    string_field(value, field_name).is_some_and(is_protocol_digest)
}

fn unsigned_decimal_string_field(value: &Value, field_name: &str) -> bool {
    string_field(value, field_name).is_some_and(unsigned_decimal_string)
}

fn non_negative_u64_field(value: &Value, field_name: &str) -> Option<u64> {
    object_map(value)?.get(field_name)?.as_u64()
}

fn string_array_field<'value>(value: &'value Value, field_name: &str) -> Option<Vec<&'value str>> {
    array_field(value, field_name)?
        .iter()
        .map(Value::as_str)
        .collect()
}

fn digest_array_field_is_valid(value: &Value, field_name: &str) -> bool {
    array_field(value, field_name).is_some_and(|values| {
        values
            .iter()
            .all(|entry| entry.as_str().is_some_and(is_protocol_digest))
    })
}

fn u64_array_field_is_valid(value: &Value, field_name: &str) -> bool {
    array_field(value, field_name)
        .is_some_and(|values| values.iter().all(|entry| entry.as_u64().is_some()))
}

fn null_field(value: &Value, field_name: &str) -> bool {
    object_map(value)
        .and_then(|object| object.get(field_name))
        .is_some_and(Value::is_null)
}

fn collect_component_proof_statement_plan_shape_refusals(
    proof_statement: &Value,
    expected_component_id: &str,
    proof_record_digest: Option<&str>,
) -> Vec<Value> {
    if string_field(proof_statement, "objectType") != Some("BallotProofComponentProofStatementPlan")
    {
        return Vec::new();
    }

    let row_batch_names = string_array_field(proof_statement, "rowBatchNames");
    let row_batch_term_counts = string_array_field(proof_statement, "rowBatchTermCounts");
    let row_batch_count = row_batch_names
        .as_ref()
        .filter(|names| !names.is_empty())
        .map(Vec::len);
    let row_batch_lengths_match = row_batch_count.is_some_and(|row_batch_count| {
        array_field(proof_statement, "rowBatchMatrixDigests")
            .is_some_and(|digests| digests.len() == row_batch_count)
            && array_field(proof_statement, "rowBatchTargetVectorDigests")
                .is_some_and(|digests| digests.len() == row_batch_count)
            && row_batch_term_counts
                .as_ref()
                .is_some_and(|counts| counts.len() == row_batch_count)
    });
    let variable_column_indices =
        array_field(proof_statement, "variableColumnIndices").map(Vec::len);
    let variable_column_count = non_negative_u64_field(proof_statement, "variableColumnCount");

    let common_shape_is_valid = object_map(proof_statement)
        .and_then(|object| object.get("objectVersion"))
        .and_then(Value::as_u64)
        == Some(1)
        && string_field(proof_statement, "componentId") == Some(expected_component_id)
        && string_field(proof_statement, "proofStatementFormat")
            == expected_component_proof_statement_format(expected_component_id)
        && string_field(proof_statement, "proofBytesAvailability")
            == expected_component_proof_bytes_availability(expected_component_id)
        && string_field(proof_statement, "proofLoweringStatus") == Some("explicitRowsAvailable")
        && string_field(proof_statement, "relation") == Some("A*w + t = 0")
        && unsigned_decimal_string_field(proof_statement, "coefficientModulus")
        && protocol_digest_field(proof_statement, "backendStatementDigest")
        && protocol_digest_field(proof_statement, "componentProofStatementDigest")
        && protocol_digest_field(proof_statement, "componentStatementDigest")
        && protocol_digest_field(proof_statement, "matrixDigest")
        && protocol_digest_field(proof_statement, "relationStatementDigest")
        && protocol_digest_field(proof_statement, "targetVectorDigest")
        && digest_array_field_is_valid(proof_statement, "rowBatchMatrixDigests")
        && row_batch_names.is_some()
        && digest_array_field_is_valid(proof_statement, "rowBatchTargetVectorDigests")
        && row_batch_term_counts.as_ref().is_some_and(|term_counts| {
            term_counts
                .iter()
                .all(|term_count| unsigned_decimal_string(term_count))
        })
        && row_batch_lengths_match
        && non_negative_u64_field(proof_statement, "rowCount")
            .is_some_and(|row_count| row_count > 0)
        && variable_column_count.is_some()
        && u64_array_field_is_valid(proof_statement, "variableColumnIndices");

    let component_specific_shape_is_valid = match expected_component_id {
        "receiver-encryption-component" => {
            object_map(proof_statement)
                .and_then(|object| object.get("sourceRingDegree"))
                .and_then(Value::as_u64)
                == Some(256)
                && object_map(proof_statement)
                    .and_then(|object| object.get("proofSystemRingDegree"))
                    .and_then(Value::as_u64)
                    == Some(64)
                && unsigned_decimal_string_field(proof_statement, "denseCoefficientCount")
                && null_field(proof_statement, "sparseTermCount")
                && non_negative_u64_field(proof_statement, "structuredCiphertextChunkCount")
                    .is_some_and(|count| count > 0)
                && non_negative_u64_field(proof_statement, "structuredReceiverCount")
                    .is_some_and(|count| count > 0)
                && string_field(proof_statement, "structuredWitnessTermCount")
                    .is_some_and(|count| unsigned_decimal_string(count) && count != "0")
                && variable_column_count.is_some_and(|count| count > 0)
                && variable_column_indices
                    .zip(variable_column_count)
                    .is_some_and(|(indices_len, column_count)| indices_len as u64 == column_count)
        }
        "receiver-key-binding-component" => {
            null_field(proof_statement, "sourceRingDegree")
                && null_field(proof_statement, "proofSystemRingDegree")
                && null_field(proof_statement, "denseCoefficientCount")
                && null_field(proof_statement, "sparseTermCount")
                && null_field(proof_statement, "structuredCiphertextChunkCount")
                && null_field(proof_statement, "structuredReceiverCount")
                && null_field(proof_statement, "structuredWitnessTermCount")
                && variable_column_count == Some(0)
                && variable_column_indices == Some(0)
                && row_batch_term_counts.as_ref().is_some_and(|term_counts| {
                    term_counts.iter().all(|term_count| *term_count == "0")
                })
        }
        _ => true,
    };

    if common_shape_is_valid && component_specific_shape_is_valid {
        Vec::new()
    } else {
        vec![structural_refusal(
            format!(
                "Ballot proof component proof statement plan for {expected_component_id} has an invalid canonical shape."
            ),
            proof_record_digest,
        )]
    }
}

fn collect_supplied_component_proof_statement_refusals(
    component_proof: &Value,
    expected_component_id: &str,
    proof_input: &Value,
    proof_record_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(proof_statement) =
        object_map(proof_input).and_then(|object| object.get("proofStatement"))
    else {
        return refused_objects;
    };
    if object_map(proof_statement).is_none() {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement object for {expected_component_id} is malformed."
            ),
            proof_record_digest,
        ));
        return refused_objects;
    }

    let proof_statement_format = string_field(proof_input, "proofStatementFormat").unwrap_or("");
    refused_objects.extend(collect_component_proof_statement_plan_shape_refusals(
        proof_statement,
        expected_component_id,
        proof_record_digest,
    ));
    let (expected_statement_digest, digest_field_name) =
        supplied_component_proof_statement_digest(proof_statement, proof_statement_format);
    if expected_statement_digest.is_none() || digest_field_name.is_none() {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement object for {expected_component_id} does not match its declared statement format."
            ),
            proof_record_digest,
        ));
    }
    if string_field(proof_statement, "proofStatementFormat")
        .is_some_and(|supplied_format| supplied_format != proof_statement_format)
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement format for {expected_component_id} does not match the supplied proof input."
            ),
            proof_record_digest,
        ));
    }
    if string_field(proof_statement, "componentId")
        .is_some_and(|component_id| component_id != expected_component_id)
    {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} is bound to the wrong component."
            ),
            proof_record_digest,
        ));
    }
    if string_field(proof_statement, "componentStatementDigest").is_some_and(
        |component_statement_digest| {
            Some(component_statement_digest)
                != string_field(component_proof, "componentStatementDigest")
        },
    ) {
        refused_objects.push(structural_refusal(
            format!(
                "Ballot proof component proof statement for {expected_component_id} is not bound to the component statement."
            ),
            proof_record_digest,
        ));
    }
    match digest_field_name {
        Some("statementDigest") => {
            if string_field(proof_statement, "statementDigest")
                != expected_statement_digest.as_deref()
            {
                refused_objects.push(structural_refusal(
                    format!(
                        "Ballot proof component proof statement digest for {expected_component_id} does not match its canonical payload."
                    ),
                    proof_record_digest,
                ));
            }
        }
        Some("componentProofStatementDigest") => {
            if string_field(proof_statement, "componentProofStatementDigest")
                != expected_statement_digest.as_deref()
            {
                refused_objects.push(structural_refusal(
                    format!(
                        "Ballot proof component proof statement digest for {expected_component_id} does not match its canonical payload."
                    ),
                    proof_record_digest,
                ));
            }
            if string_field(component_proof, "componentProofStatementDigest").is_some()
                && string_field(proof_statement, "componentProofStatementDigest")
                    != string_field(component_proof, "componentProofStatementDigest")
            {
                refused_objects.push(structural_refusal(
                    format!(
                        "Ballot proof component proof statement for {expected_component_id} does not match the proof record digest."
                    ),
                    proof_record_digest,
                ));
            }
        }
        _ => {}
    }

    refused_objects
}

fn collect_ballot_component_proof_input_refusals(
    ballot_proof: &Value,
    component_proof_bundle: &Value,
    component_proof_inputs: Option<&Value>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let Some(component_proof_inputs) = component_proof_inputs else {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot proof verification requires public proof inputs for every component proof.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    let Some(component_proof_inputs_array) = component_proof_inputs.as_array() else {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof inputs must be an array.",
            proof_record_digest,
        ));

        return refused_objects;
    };
    if component_proof_inputs_array.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
        refused_objects.push(structural_refusal(
            "Ballot proof component proof inputs must contain exactly the required components.",
            proof_record_digest,
        ));
    }

    let mut proof_inputs_by_component = BTreeMap::new();
    for proof_input in component_proof_inputs_array {
        let Some(component_id) = string_field(proof_input, "componentId") else {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof input is missing its component id.",
                proof_record_digest,
            ));
            continue;
        };
        if proof_inputs_by_component
            .insert(component_id.to_string(), proof_input)
            .is_some()
        {
            refused_objects.push(structural_refusal(
                "Ballot proof component proof inputs contain a duplicate component.",
                proof_record_digest,
            ));
        }
    }

    let component_proofs = array_field(component_proof_bundle, "componentProofs")
        .map(|values| values.as_slice())
        .unwrap_or(&[]);
    for (component_index, expected_component_id) in
        REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter().enumerate()
    {
        let Some(component_proof) = component_proofs.get(component_index) else {
            continue;
        };
        let Some(proof_input) = proof_inputs_by_component.get(*expected_component_id) else {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is missing."
                ),
                proof_record_digest,
            ));
            continue;
        };
        if string_field(proof_input, "componentId") != string_field(component_proof, "componentId")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is not bound to the matching proof record."
                ),
                proof_record_digest,
            ));
        }
        if string_field(component_proof, "componentProofStatementDigest").is_some()
            && string_field(proof_input, "componentProofStatementDigest")
                != string_field(component_proof, "componentProofStatementDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        if string_field(proof_input, "proofStatementFormat").is_none_or(|proof_statement_format| {
            !ALLOWED_BALLOT_PROOF_COMPONENT_STATEMENT_FORMATS.contains(&proof_statement_format)
        }) {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement format for {expected_component_id} is not supported."
                ),
                proof_record_digest,
            ));
        }
        if string_field(proof_input, "proofStatementFormat")
            != expected_component_proof_statement_format(expected_component_id)
        {
            let expected_format = expected_component_proof_statement_format(expected_component_id)
                .unwrap_or("unknown");
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof statement format for {expected_component_id} must be {expected_format}."
                ),
                proof_record_digest,
            ));
        }
        if component_proof_bytes_must_be_empty(expected_component_id)
            && string_field(proof_input, "proofBytesHex")
                .is_some_and(|proof_bytes_hex| !proof_bytes_hex.is_empty())
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof bytes for {expected_component_id} must be empty for the public-zero witness binding check."
                ),
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_proof_bytes_refusals(
            string_field(proof_input, "proofBytesHex"),
            string_field(component_proof, "proofBytesDigest"),
            object_map(component_proof)
                .and_then(|object| object.get("proofSizeBytes"))
                .and_then(Value::as_u64),
            proof_record_digest,
            "Ballot proof component",
            component_proof_bytes_must_be_empty(expected_component_id),
        ));
        let expected_proof_encoding_digest = object_map(proof_input)
            .and_then(|object| object.get("proofEncoding"))
            .and_then(derive_ballot_proof_encoding_profile_digest);
        if expected_proof_encoding_digest.as_deref()
            != string_field(component_proof, "proofEncodingProfileDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof encoding for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        let expected_parameter_set_digest = object_map(proof_input)
            .and_then(|object| object.get("proofParameterSet"))
            .and_then(derive_ballot_proof_parameter_set_digest);
        if expected_parameter_set_digest.as_deref()
            != string_field(component_proof, "proofParameterSetDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof parameter set for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        let expected_public_randomness_digest = string_field(proof_input, "publicRandomnessHex")
            .and_then(derive_ballot_proof_public_randomness_digest);
        if expected_public_randomness_digest.as_deref()
            != string_field(component_proof, "publicRandomnessDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component public randomness for {expected_component_id} does not match the proof record."
                ),
                proof_record_digest,
            ));
        }
        if string_field(proof_input, "statementDigest")
            != string_field(component_proof, "componentStatementDigest")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} is not bound to the component statement."
                ),
                proof_record_digest,
            ));
        }
        if object_map(proof_input)
            .and_then(|object| object.get("proofStatement"))
            .is_none()
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof input for {expected_component_id} must supply its public proof statement object."
                ),
                proof_record_digest,
            ));
        }
        if derive_ballot_component_proof_root(component_proof, proof_input, expected_component_id)
            .as_deref()
            != string_field(component_proof, "proofRoot")
        {
            refused_objects.push(structural_refusal(
                format!(
                    "Ballot proof component proof root for {expected_component_id} does not match the supplied public proof input."
                ),
                proof_record_digest,
            ));
        }
        refused_objects.extend(collect_supplied_component_proof_statement_refusals(
            component_proof,
            expected_component_id,
            proof_input,
            proof_record_digest,
        ));
    }

    refused_objects
}

fn component_proof_bundle_unavailable_result(
    operation: &str,
    accepted_object_digest: Option<&str>,
    component_proof_bundle: &Value,
) -> Value {
    let mut status_labels = vec![
        json!("BallotProofRecordDigestRecomputed"),
        json!("BallotProofBytesDigestChecked"),
        json!("BallotProofComponentBundleBound"),
        json!("BallotProofComponentProofInputsBound"),
        json!("BallotProofComponentProofRootsVerified"),
    ];
    if operation == "verifyClaimBearingBallotPackage" {
        status_labels.push(json!("ClaimBearingBallotPackageDigestRecomputed"));
    }
    let mut accepted_digests = accepted_object_digest
        .into_iter()
        .map(Value::from)
        .collect::<Vec<_>>();
    if let Some(component_proof_bundle_digest) =
        string_field(component_proof_bundle, "componentProofBundleDigest")
    {
        accepted_digests.push(json!(component_proof_bundle_digest));
    }
    if let Some(component_proofs) = array_field(component_proof_bundle, "componentProofs") {
        accepted_digests.extend(
            component_proofs
                .iter()
                .filter_map(|component_proof| {
                    string_field(component_proof, "componentProofRecordDigest")
                })
                .map(Value::from),
        );
    }

    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": status_labels,
        "acceptedDigests": accepted_digests,
        "refusedObjects": [
            {
                "code": "OperationUnavailable",
                "message": format!("{operation}: component proof bundle preflight succeeded, but proof-byte verification for every ballot component format is not complete."),
                "objectDigest": accepted_object_digest
            }
        ],
        "unresolvedReason": "OperationUnavailable"
    })
}

fn component_proof_backend_rejection(
    operation: &str,
    component_id: &str,
    refused_objects: Vec<Value>,
    unresolved_reason: Value,
) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": refused_objects,
        "componentId": component_id,
        "unresolvedReason": unresolved_reason
    })
}

fn integer_value(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text)
            if text == "0"
                || (!text.starts_with('0') && text.bytes().all(|byte| byte.is_ascii_digit())) =>
        {
            text.parse::<u64>().ok()
        }
        _ => None,
    }
}

fn usize_object_field(value: &Value, field_name: &str) -> Option<usize> {
    object_map(value)?
        .get(field_name)
        .and_then(integer_value)
        .and_then(|field_value| usize::try_from(field_value).ok())
}

fn u64_object_field(value: &Value, field_name: &str) -> Option<u64> {
    object_map(value)?.get(field_name).and_then(integer_value)
}

fn derive_sparse_statement_matrix_digest(matrix_entries: &Value) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "purpose": "ballot-proof-sparse-linear-statement-matrix-v1",
            "sparseStatementMatrixEntries": matrix_entries
        }),
    )
}

fn derive_sparse_target_vector_digest(target_entries: &Value) -> Option<String> {
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "purpose": "ballot-proof-sparse-linear-target-vector-v1",
            "targetVectorEntries": target_entries
        }),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComponentProofBackendError {
    code: &'static str,
    message: String,
}

impl ComponentProofBackendError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "BallotPackageInvalid",
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: "OperationUnavailable",
            message: message.into(),
        }
    }
}

struct ParsedSparseComponentProofStatement {
    source_statement_matrix: SparsePolynomialMatrix,
    target_vector_coefficients: Vec<Vec<u64>>,
}

fn parse_sparse_polynomial_entry(
    entry: &Value,
    constant_field_name: &str,
    polynomial_field_name: &str,
    source_ring_degree: usize,
    coefficient_modulus: u64,
    entry_label: &str,
) -> Result<Vec<u64>, ComponentProofBackendError> {
    let entry_object = object_map(entry).ok_or_else(|| {
        ComponentProofBackendError::invalid(format!("{entry_label} must be an object."))
    })?;
    let constant_coefficient = entry_object
        .get(constant_field_name)
        .and_then(integer_value);
    let polynomial_coefficients = entry_object.get(polynomial_field_name);

    match (constant_coefficient, polynomial_coefficients) {
        (Some(coefficient), None) => {
            if coefficient >= coefficient_modulus {
                return Err(ComponentProofBackendError::invalid(format!(
                    "{entry_label} coefficient is not canonical."
                )));
            }
            let mut coefficients = vec![0_u64; source_ring_degree];
            coefficients[0] = coefficient;

            Ok(coefficients)
        }
        (None, Some(polynomial_value)) => {
            let polynomial_array = polynomial_value.as_array().ok_or_else(|| {
                ComponentProofBackendError::invalid(format!(
                    "{entry_label} polynomial coefficients must be an array."
                ))
            })?;
            if polynomial_array.len() != source_ring_degree {
                return Err(ComponentProofBackendError::invalid(format!(
                    "{entry_label} polynomial degree does not match sourceRingDegree."
                )));
            }
            let mut coefficients = Vec::with_capacity(source_ring_degree);
            for coefficient_value in polynomial_array {
                let coefficient = integer_value(coefficient_value).ok_or_else(|| {
                    ComponentProofBackendError::invalid(format!(
                        "{entry_label} polynomial coefficient is not a canonical integer."
                    ))
                })?;
                if coefficient >= coefficient_modulus {
                    return Err(ComponentProofBackendError::invalid(format!(
                        "{entry_label} polynomial coefficient is not canonical."
                    )));
                }
                coefficients.push(coefficient);
            }

            Ok(coefficients)
        }
        (Some(_), Some(_)) => Err(ComponentProofBackendError::invalid(format!(
            "{entry_label} must use either {constant_field_name} or {polynomial_field_name}, not both."
        ))),
        (None, None) => Err(ComponentProofBackendError::invalid(format!(
            "{entry_label} is missing {constant_field_name} or {polynomial_field_name}."
        ))),
    }
}

fn polynomial_is_zero(coefficients: &[u64]) -> bool {
    coefficients.iter().all(|coefficient| *coefficient == 0)
}

fn sparse_matrix_from_sparse_component_statement(
    sparse_statement: &Value,
) -> Result<ParsedSparseComponentProofStatement, ComponentProofBackendError> {
    let statement_rows =
        usize_object_field(sparse_statement, "statementRows").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing statementRows.",
            )
        })?;
    let statement_columns =
        usize_object_field(sparse_statement, "statementColumns").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing statementColumns.",
            )
        })?;
    let source_ring_degree =
        usize_object_field(sparse_statement, "sourceRingDegree").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing sourceRingDegree.",
            )
        })?;
    let coefficient_modulus =
        u64_object_field(sparse_statement, "coefficientModulus").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing coefficientModulus.",
            )
        })?;
    let matrix_entries_value = object_map(sparse_statement)
        .and_then(|object| object.get("sparseStatementMatrixEntries"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing sparseStatementMatrixEntries.",
            )
        })?;
    let matrix_entries = matrix_entries_value.as_array().ok_or_else(|| {
        ComponentProofBackendError::invalid(
            "Sparse component proof statement matrix entries must be an array.",
        )
    })?;
    let target_entries_value = object_map(sparse_statement)
        .and_then(|object| object.get("targetVectorEntries"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Sparse component proof statement is missing targetVectorEntries.",
            )
        })?;
    let target_entries = target_entries_value.as_array().ok_or_else(|| {
        ComponentProofBackendError::invalid(
            "Sparse component proof statement target entries must be an array.",
        )
    })?;

    if usize_object_field(sparse_statement, "sparseStatementTermCount")
        != Some(matrix_entries.len())
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement matrix term count does not match entries."
                .to_string(),
        ));
    }
    if usize_object_field(sparse_statement, "targetVectorEntryCount") != Some(target_entries.len())
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement target entry count does not match entries."
                .to_string(),
        ));
    }
    if string_field(sparse_statement, "sparseStatementMatrixDigest")
        != derive_sparse_statement_matrix_digest(matrix_entries_value).as_deref()
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement matrix digest does not match entries.",
        ));
    }
    if string_field(sparse_statement, "targetVectorDigest")
        != derive_sparse_target_vector_digest(target_entries_value).as_deref()
    {
        return Err(ComponentProofBackendError::invalid(
            "Sparse component proof statement target vector digest does not match entries."
                .to_string(),
        ));
    }

    let source_ring =
        PolynomialRing::new(source_ring_degree, coefficient_modulus).map_err(|error| {
            ComponentProofBackendError::invalid(format!(
                "Sparse component proof statement ring is invalid: {}",
                error.message
            ))
        })?;
    let mut sparse_matrix_entries = Vec::with_capacity(matrix_entries.len());
    let mut seen_matrix_positions = BTreeSet::new();
    for matrix_entry in matrix_entries {
        let row_index = usize_object_field(matrix_entry, "rowIndex").ok_or_else(|| {
            ComponentProofBackendError::invalid("Sparse matrix entry is missing rowIndex.")
        })?;
        let column_index = usize_object_field(matrix_entry, "columnIndex").ok_or_else(|| {
            ComponentProofBackendError::invalid("Sparse matrix entry is missing columnIndex.")
        })?;
        let coefficients = parse_sparse_polynomial_entry(
            matrix_entry,
            "constantCoefficient",
            "polynomialCoefficients",
            source_ring_degree,
            coefficient_modulus,
            "Sparse matrix entry",
        )?;
        if row_index >= statement_rows || column_index >= statement_columns {
            return Err(ComponentProofBackendError::invalid(
                "Sparse matrix entry index is outside the statement shape.",
            ));
        }
        if polynomial_is_zero(&coefficients) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse matrix entries must not store zero polynomials.",
            ));
        }
        if !seen_matrix_positions.insert((row_index, column_index)) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse matrix entries contain a duplicate position.",
            ));
        }
        sparse_matrix_entries.push(SparsePolynomialMatrixEntry::new(
            row_index,
            column_index,
            coefficients,
        ));
    }
    sparse_matrix_entries.sort_by_key(|entry| (entry.row_index(), entry.column_index()));
    let source_statement_matrix = SparsePolynomialMatrix::new(
        source_ring,
        statement_rows,
        statement_columns,
        sparse_matrix_entries,
    )
    .map_err(|error| {
        ComponentProofBackendError::invalid(format!(
            "Sparse component proof statement matrix is invalid: {}",
            error.message
        ))
    })?;

    let mut target_vector_coefficients = vec![vec![0_u64; source_ring_degree]; statement_rows];
    let mut seen_target_positions = BTreeSet::new();
    for target_entry in target_entries {
        let row_index = usize_object_field(target_entry, "rowIndex").ok_or_else(|| {
            ComponentProofBackendError::invalid("Sparse target entry is missing rowIndex.")
        })?;
        let coefficients = parse_sparse_polynomial_entry(
            target_entry,
            "constantCoefficient",
            "polynomialCoefficients",
            source_ring_degree,
            coefficient_modulus,
            "Sparse target entry",
        )?;
        if row_index >= statement_rows {
            return Err(ComponentProofBackendError::invalid(
                "Sparse target entry index is outside the statement shape.",
            ));
        }
        if polynomial_is_zero(&coefficients) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse target entries must not store zero polynomials.",
            ));
        }
        if !seen_target_positions.insert(row_index) {
            return Err(ComponentProofBackendError::invalid(
                "Sparse target entries contain a duplicate position.",
            ));
        }
        target_vector_coefficients[row_index] = coefficients;
    }

    Ok(ParsedSparseComponentProofStatement {
        source_statement_matrix,
        target_vector_coefficients,
    })
}

#[cfg(test)]
fn dense_matrix_from_sparse_component_statement(
    sparse_statement: &Value,
) -> Result<(Value, Value), ComponentProofBackendError> {
    let parsed_sparse_statement = sparse_matrix_from_sparse_component_statement(sparse_statement)?;
    Ok((
        json!(
            parsed_sparse_statement
                .source_statement_matrix
                .to_dense()
                .map_err(|error| ComponentProofBackendError::invalid(format!(
                    "Sparse component proof statement could not be densified for test compatibility: {}",
                    error.message
                )))?
                .entries_by_row()
        ),
        json!(parsed_sparse_statement.target_vector_coefficients),
    ))
}

fn structured_receiver_encryption_statement_as_sparse(
    structured_statement: &Value,
) -> Result<ParsedSparseComponentProofStatement, ComponentProofBackendError> {
    if string_field(structured_statement, "objectType")
        != Some("BallotProofStructuredReceiverEncryptionProofStatement")
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement must use the structured public statement object.",
        ));
    }
    if string_field(structured_statement, "proofStatementFormat")
        != Some(STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement format is invalid.",
        ));
    }
    if string_field(structured_statement, "componentId") != Some("receiver-encryption-component") {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement is bound to the wrong component.",
        ));
    }
    if u64_object_field(structured_statement, "objectVersion") != Some(1) {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement objectVersion must be 1.",
        ));
    }
    if usize_object_field(structured_statement, "sourceRingDegree")
        != Some(RECEIVER_ENCRYPTION_MODULE_DEGREE as usize)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement sourceRingDegree is not supported.",
        ));
    }
    if u64_object_field(structured_statement, "coefficientModulus")
        != Some(RECEIVER_ENCRYPTION_MODULUS)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement modulus is not supported.",
        ));
    }
    let statement_rows =
        usize_object_field(structured_statement, "statementRows").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption proof statement is missing statementRows.",
            )
        })?;
    let statement_columns = usize_object_field(structured_statement, "statementColumns")
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption proof statement is missing statementColumns.",
            )
        })?;
    let receiver_encryption_profile_digest = string_field(
        structured_statement,
        "receiverEncryptionProfileDigest",
    )
    .ok_or_else(|| {
        ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement is missing receiverEncryptionProfileDigest.",
        )
    })?;
    let receiver_rows = object_map(structured_statement)
        .and_then(|object| object.get("receiverRows"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption proof statement receiverRows must be an array.",
            )
        })?;
    if receiver_rows.is_empty() {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement must contain receiver rows.",
        ));
    }

    let source_ring = PolynomialRing::new(
        RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
        RECEIVER_ENCRYPTION_MODULUS,
    )
    .map_err(|error| {
        ComponentProofBackendError::invalid(format!(
            "Structured receiver-encryption source ring is invalid: {}",
            error.message
        ))
    })?;
    let mut matrix_coefficients_by_position: BTreeMap<(usize, usize), u64> = BTreeMap::new();
    let mut target_vector_coefficients =
        vec![vec![0_u64; RECEIVER_ENCRYPTION_MODULE_DEGREE as usize]; statement_rows];
    let mut covered_row_count = 0_usize;

    for receiver_row in receiver_rows {
        let receiver_object = object_map(receiver_row).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row must be an object.",
            )
        })?;
        let row_offset_within_statement = usize_object_field(
            receiver_row,
            "rowOffsetWithinStatement",
        )
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row is missing rowOffsetWithinStatement.",
            )
        })?;
        let row_count = usize_object_field(receiver_row, "rowCount").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row is missing rowCount.",
            )
        })?;
        let ciphertext_chunks = receiver_object
            .get("ciphertextChunks")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption receiver row ciphertextChunks must be an array.",
                )
            })?;
        let expected_row_count = ciphertext_chunks
            .len()
            .checked_mul(
                (RECEIVER_ENCRYPTION_MODULE_RANK as usize + 1)
                    .checked_mul(RECEIVER_ENCRYPTION_MODULE_DEGREE as usize)
                    .ok_or_else(|| {
                        ComponentProofBackendError::invalid(
                            "Structured receiver-encryption row count overflowed.",
                        )
                    })?,
            )
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption row count overflowed.",
                )
            })?;
        if row_count != expected_row_count {
            return Err(ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row count does not match ciphertext chunks.",
            ));
        }
        if row_offset_within_statement
            .checked_add(row_count)
            .is_none_or(|exclusive_end| exclusive_end > statement_rows)
        {
            return Err(ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver rows exceed the statement shape.",
            ));
        }
        covered_row_count = covered_row_count.checked_add(row_count).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption covered row count overflowed.",
            )
        })?;

        let public_matrix_seed_digest = string_field(receiver_row, "publicMatrixSeedDigest")
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption receiver row is missing publicMatrixSeedDigest.",
                )
            })?;
        let public_key_vector = parse_receiver_polynomial_vector(
            receiver_object.get("publicKeyVector").ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption receiver row is missing publicKeyVector.",
                )
            })?,
            "Structured receiver-encryption public key vector",
        )?;
        let public_matrix = derive_receiver_encryption_public_matrix(
            receiver_encryption_profile_digest,
            public_matrix_seed_digest,
        )
        .map_err(|error| {
            ComponentProofBackendError::invalid(format!(
                "Structured receiver-encryption public matrix could not be derived: {error}"
            ))
        })?;

        for (chunk_position, ciphertext_chunk) in ciphertext_chunks.iter().enumerate() {
            let chunk_object = object_map(ciphertext_chunk).ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption ciphertext chunk must be an object.",
                )
            })?;
            let chunk_index =
                usize_object_field(ciphertext_chunk, "chunkIndex").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing chunkIndex.",
                    )
                })?;
            if chunk_index != chunk_position {
                return Err(ComponentProofBackendError::invalid(
                    "Structured receiver-encryption ciphertext chunks must be in canonical order.",
                ));
            }
            let first_ciphertext_vector = parse_receiver_polynomial_vector(
                chunk_object.get("firstCiphertextVector").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing firstCiphertextVector.",
                    )
                })?,
                "Structured receiver-encryption first ciphertext vector",
            )?;
            let second_ciphertext_polynomial = parse_receiver_polynomial(
                chunk_object.get("secondCiphertextPolynomial").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing secondCiphertextPolynomial.",
                    )
                })?,
                "Structured receiver-encryption second ciphertext polynomial",
            )?;
            let randomness_column_indices = parse_receiver_column_matrix(
                chunk_object.get("randomnessColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing randomnessColumnIndices.",
                    )
                })?,
                statement_columns,
                "Structured receiver-encryption randomness column indices",
            )?;
            let first_noise_column_indices = parse_receiver_column_matrix(
                chunk_object.get("firstNoiseColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing firstNoiseColumnIndices.",
                    )
                })?,
                statement_columns,
                "Structured receiver-encryption first-noise column indices",
            )?;
            let second_noise_column_indices = parse_receiver_column_vector(
                chunk_object.get("secondNoiseColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing secondNoiseColumnIndices.",
                    )
                })?,
                RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                statement_columns,
                "Structured receiver-encryption second-noise column indices",
            )?;
            let plaintext_bit_column_indices = parse_receiver_column_vector_with_max_len(
                chunk_object.get("plaintextBitColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing plaintextBitColumnIndices.",
                    )
                })?,
                RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                statement_columns,
                "Structured receiver-encryption plaintext-bit column indices",
            )?;
            let chunk_row_offset = row_offset_within_statement
                .checked_add(
                    chunk_index
                        .checked_mul(
                            (RECEIVER_ENCRYPTION_MODULE_RANK as usize + 1)
                                * RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                        )
                        .ok_or_else(|| {
                            ComponentProofBackendError::invalid(
                                "Structured receiver-encryption chunk row offset overflowed.",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption chunk row offset overflowed.",
                    )
                })?;

            for ciphertext_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                for output_coefficient_index in 0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize {
                    let row_index = chunk_row_offset
                        + ciphertext_vector_index * RECEIVER_ENCRYPTION_MODULE_DEGREE as usize
                        + output_coefficient_index;
                    target_vector_coefficients[row_index][0] = negate_receiver_coefficient(
                        first_ciphertext_vector[ciphertext_vector_index][output_coefficient_index],
                    );
                    for randomness_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                        for randomness_coefficient_index in
                            0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize
                        {
                            let coefficient = negacyclic_receiver_coefficient(
                                &public_matrix[randomness_vector_index][ciphertext_vector_index],
                                output_coefficient_index,
                                randomness_coefficient_index,
                            );
                            add_structured_constant_entry(
                                &mut matrix_coefficients_by_position,
                                row_index,
                                randomness_column_indices[randomness_vector_index]
                                    [randomness_coefficient_index],
                                coefficient,
                            )?;
                        }
                    }
                    add_structured_constant_entry(
                        &mut matrix_coefficients_by_position,
                        row_index,
                        first_noise_column_indices[ciphertext_vector_index]
                            [output_coefficient_index],
                        1,
                    )?;
                }
            }

            let second_ciphertext_row_offset = chunk_row_offset
                + RECEIVER_ENCRYPTION_MODULE_RANK as usize
                    * RECEIVER_ENCRYPTION_MODULE_DEGREE as usize;
            for output_coefficient_index in 0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize {
                let row_index = second_ciphertext_row_offset + output_coefficient_index;
                target_vector_coefficients[row_index][0] = negate_receiver_coefficient(
                    second_ciphertext_polynomial[output_coefficient_index],
                );
                for randomness_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                    for randomness_coefficient_index in
                        0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize
                    {
                        let coefficient = negacyclic_receiver_coefficient(
                            &public_key_vector[randomness_vector_index],
                            output_coefficient_index,
                            randomness_coefficient_index,
                        );
                        add_structured_constant_entry(
                            &mut matrix_coefficients_by_position,
                            row_index,
                            randomness_column_indices[randomness_vector_index]
                                [randomness_coefficient_index],
                            coefficient,
                        )?;
                    }
                }
                add_structured_constant_entry(
                    &mut matrix_coefficients_by_position,
                    row_index,
                    second_noise_column_indices[output_coefficient_index],
                    1,
                )?;
                if let Some(plaintext_column_index) =
                    plaintext_bit_column_indices.get(output_coefficient_index)
                {
                    add_structured_constant_entry(
                        &mut matrix_coefficients_by_position,
                        row_index,
                        *plaintext_column_index,
                        RECEIVER_ENCRYPTION_MODULUS / 2,
                    )?;
                }
            }
        }
    }
    if covered_row_count != statement_rows {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption receiver rows do not cover the statement row count.",
        ));
    }

    let sparse_matrix_entries = matrix_coefficients_by_position
        .into_iter()
        .filter_map(|((row_index, column_index), coefficient)| {
            if coefficient == 0 {
                None
            } else {
                let mut coefficients = vec![0_u64; RECEIVER_ENCRYPTION_MODULE_DEGREE as usize];
                coefficients[0] = coefficient;
                Some(SparsePolynomialMatrixEntry::new(
                    row_index,
                    column_index,
                    coefficients,
                ))
            }
        })
        .collect::<Vec<_>>();
    let source_statement_matrix = SparsePolynomialMatrix::new(
        source_ring,
        statement_rows,
        statement_columns,
        sparse_matrix_entries,
    )
    .map_err(|error| {
        ComponentProofBackendError::invalid(format!(
            "Structured receiver-encryption sparse statement matrix is invalid: {}",
            error.message
        ))
    })?;

    Ok(ParsedSparseComponentProofStatement {
        source_statement_matrix,
        target_vector_coefficients,
    })
}

fn parse_receiver_polynomial(
    value: &Value,
    label: &str,
) -> Result<Vec<u64>, ComponentProofBackendError> {
    let coefficients = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if coefficients.len() != RECEIVER_ENCRYPTION_MODULE_DEGREE as usize {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen receiver-encryption degree."
        )));
    }
    coefficients
        .iter()
        .map(|coefficient_value| {
            let coefficient = integer_value(coefficient_value).ok_or_else(|| {
                ComponentProofBackendError::invalid(format!(
                    "{label} coefficient is not a canonical integer."
                ))
            })?;
            if coefficient >= RECEIVER_ENCRYPTION_MODULUS {
                return Err(ComponentProofBackendError::invalid(format!(
                    "{label} coefficient is outside the receiver-encryption modulus."
                )));
            }
            Ok(coefficient)
        })
        .collect()
}

fn parse_receiver_polynomial_vector(
    value: &Value,
    label: &str,
) -> Result<Vec<Vec<u64>>, ComponentProofBackendError> {
    let polynomials = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if polynomials.len() != RECEIVER_ENCRYPTION_MODULE_RANK as usize {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen receiver-encryption module rank."
        )));
    }
    polynomials
        .iter()
        .enumerate()
        .map(|(polynomial_index, polynomial)| {
            parse_receiver_polynomial(
                polynomial,
                &format!("{label} polynomial {polynomial_index}"),
            )
        })
        .collect()
}

fn parse_receiver_column_vector(
    value: &Value,
    expected_length: usize,
    statement_columns: usize,
    label: &str,
) -> Result<Vec<usize>, ComponentProofBackendError> {
    let column_indices = parse_receiver_column_vector_with_max_len(
        value,
        expected_length,
        statement_columns,
        label,
    )?;
    if column_indices.len() != expected_length {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} length does not match the expected receiver-encryption dimension."
        )));
    }

    Ok(column_indices)
}

fn parse_receiver_column_vector_with_max_len(
    value: &Value,
    maximum_length: usize,
    statement_columns: usize,
    label: &str,
) -> Result<Vec<usize>, ComponentProofBackendError> {
    let column_values = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if column_values.len() > maximum_length {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} length exceeds the receiver-encryption degree."
        )));
    }
    let mut column_indices = Vec::with_capacity(column_values.len());
    for column_value in column_values {
        let column_index = integer_value(column_value)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(format!(
                    "{label} entry is not a canonical column index."
                ))
            })?;
        if column_index >= statement_columns {
            return Err(ComponentProofBackendError::invalid(format!(
                "{label} entry is outside the statement column range."
            )));
        }
        column_indices.push(column_index);
    }

    Ok(column_indices)
}

fn parse_receiver_column_matrix(
    value: &Value,
    statement_columns: usize,
    label: &str,
) -> Result<Vec<Vec<usize>>, ComponentProofBackendError> {
    let rows = value
        .as_array()
        .ok_or_else(|| ComponentProofBackendError::invalid(format!("{label} must be an array.")))?;
    if rows.len() != RECEIVER_ENCRYPTION_MODULE_RANK as usize {
        return Err(ComponentProofBackendError::invalid(format!(
            "{label} must have the frozen receiver-encryption module rank."
        )));
    }
    rows.iter()
        .enumerate()
        .map(|(row_index, row)| {
            parse_receiver_column_vector(
                row,
                RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                statement_columns,
                &format!("{label} row {row_index}"),
            )
        })
        .collect()
}

fn negacyclic_receiver_coefficient(
    polynomial: &[u64],
    output_coefficient_index: usize,
    witness_coefficient_index: usize,
) -> u64 {
    if output_coefficient_index >= witness_coefficient_index {
        polynomial[output_coefficient_index - witness_coefficient_index]
            % RECEIVER_ENCRYPTION_MODULUS
    } else {
        negate_receiver_coefficient(
            polynomial[RECEIVER_ENCRYPTION_MODULE_DEGREE as usize + output_coefficient_index
                - witness_coefficient_index],
        )
    }
}

fn negate_receiver_coefficient(coefficient: u64) -> u64 {
    if coefficient == 0 {
        0
    } else {
        RECEIVER_ENCRYPTION_MODULUS - coefficient
    }
}

fn add_structured_constant_entry(
    coefficients_by_position: &mut BTreeMap<(usize, usize), u64>,
    row_index: usize,
    column_index: usize,
    coefficient: u64,
) -> Result<(), ComponentProofBackendError> {
    if coefficient >= RECEIVER_ENCRYPTION_MODULUS {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption coefficient is not canonical.",
        ));
    }
    if coefficient == 0 {
        return Ok(());
    }
    let current_coefficient = coefficients_by_position
        .get(&(row_index, column_index))
        .copied()
        .unwrap_or(0);
    let next_coefficient = (current_coefficient + coefficient) % RECEIVER_ENCRYPTION_MODULUS;
    if next_coefficient == 0 {
        coefficients_by_position.remove(&(row_index, column_index));
    } else {
        coefficients_by_position.insert((row_index, column_index), next_coefficient);
    }

    Ok(())
}

fn component_linear_proof_vector_case(
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Result<Value, ComponentProofBackendError> {
    let proof_statement = object_map(proof_input)
        .and_then(|object| object.get("proofStatement"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component proof input for {component_id} has no proof statement."
            ))
        })?;
    let proof_statement_format =
        string_field(proof_input, "proofStatementFormat").ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component proof input for {component_id} has no statement format."
            ))
        })?;
    let (statement_matrix_coefficients, target_vector_coefficients) = match proof_statement_format {
        "dense-polynomial-matrix-linear-proof-v1" => (
            object_map(proof_statement)
                .and_then(|object| object.get("statementMatrixCoefficients"))
                .cloned()
                .ok_or_else(|| {
                    ComponentProofBackendError::invalid(format!(
                        "Dense component proof statement for {component_id} has no statement matrix."
                    ))
                })?,
            object_map(proof_statement)
                .and_then(|object| object.get("targetVectorCoefficients"))
                .cloned()
                .ok_or_else(|| {
                    ComponentProofBackendError::invalid(format!(
                        "Dense component proof statement for {component_id} has no target vector."
                    ))
                })?,
        ),
        "sparse-polynomial-matrix-linear-proof-v1" => {
            return Err(ComponentProofBackendError::unavailable(format!(
                "Sparse component proof statement for {component_id} must be verified through the sparse proof-byte backend."
            )));
        }
        "structured-module-lwe-linear-proof-v1" => {
            return Err(ComponentProofBackendError::unavailable(format!(
                "Structured receiver-encryption proof bytes for {component_id} are not implemented in this backend slice."
            )));
        }
        "public-zero-witness-binding-check-v1" => {
            return Err(ComponentProofBackendError::unavailable(format!(
                "Public-zero witness binding checks for {component_id} are structural only and are not linear proof bytes."
            )));
        }
        _ => {
            return Err(ComponentProofBackendError::invalid(format!(
                "Ballot proof component proof statement format for {component_id} is not supported."
            )));
        }
    };

    let proof_bytes_hex = string_field(proof_input, "proofBytesHex").ok_or_else(|| {
        ComponentProofBackendError::invalid(format!(
            "Ballot proof component {component_id} has no proof bytes."
        ))
    })?;
    let public_randomness_hex =
        string_field(proof_input, "publicRandomnessHex").ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component {component_id} has no public randomness."
            ))
        })?;
    let parameter_set = object_map(proof_input)
        .and_then(|object| object.get("proofParameterSet"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component {component_id} has no parameter set."
            ))
        })?;
    let proof_encoding = object_map(proof_input)
        .and_then(|object| object.get("proofEncoding"))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(format!(
                "Ballot proof component {component_id} has no proof encoding."
            ))
        })?;

    Ok(json!({
        "caseName": format!("{component_id}-component-proof"),
        "description": format!("Ballot proof component {component_id} verification through the internal linear proof backend."),
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": statement_matrix_coefficients,
        "targetVectorCoefficients": target_vector_coefficients,
        "targetCoefficientRepresentation": object_map(proof_statement)
            .and_then(|object| object.get("targetCoefficientRepresentation"))
            .cloned()
            .unwrap_or(Value::Null),
        "proofHex": proof_bytes_hex,
        "expectedProofSizeBytes": object_map(component_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .cloned()
            .unwrap_or(Value::Null)
    }))
}

fn verify_component_linear_proof_bytes(
    operation: &str,
    component_id: &str,
    component_proof: &Value,
    proof_input: &Value,
) -> Value {
    if string_field(proof_input, "proofStatementFormat")
        == Some(STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT)
    {
        let mut refused_objects = Vec::new();
        if component_id != "receiver-encryption-component" {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Structured receiver-encryption proof statements are only valid for receiver-encryption-component, not {component_id}."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        }
        if let Some(proof_statement) =
            object_map(proof_input).and_then(|object| object.get("proofStatement"))
        {
            if string_field(proof_statement, "objectType")
                == Some("BallotProofComponentProofStatementPlan")
            {
                refused_objects.push(json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Structured receiver-encryption proof bytes for {component_id} require a public structured proof statement, not only the proof statement plan."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                }));
            } else if derive_ballot_structured_receiver_encryption_statement_digest(proof_statement)
                .as_deref()
                != string_field(proof_statement, "statementDigest")
            {
                refused_objects.push(json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component proof statement digest for {component_id} does not match its canonical payload."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                }));
            }
            if string_field(proof_statement, "statementDigest")
                != string_field(proof_input, "componentProofStatementDigest")
            {
                refused_objects.push(json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component proof statement for {component_id} is not bound to the supplied proof input."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                }));
            }
        } else {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Ballot proof component proof input for {component_id} must supply its public proof statement object."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        }
        if !refused_objects.is_empty() {
            return component_proof_backend_rejection(
                operation,
                component_id,
                refused_objects,
                json!("BallotPackageInvalid"),
            );
        }

        let proof_statement = object_map(proof_input)
            .and_then(|object| object.get("proofStatement"))
            .expect("structured proof statement presence was checked");
        let parsed_structured_statement = match structured_receiver_encryption_statement_as_sparse(
            proof_statement,
        ) {
            Ok(parsed_structured_statement) => parsed_structured_statement,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": error.code,
                        "message": error.message,
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!(error.code),
                );
            }
        };
        let proof_bytes_hex = match string_field(proof_input, "proofBytesHex") {
            Some(proof_bytes_hex) => proof_bytes_hex,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no proof bytes."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let public_randomness_hex = match string_field(proof_input, "publicRandomnessHex") {
            Some(public_randomness_hex) => public_randomness_hex,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no public randomness."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let parameter_set_value = match object_map(proof_input)
            .and_then(|object| object.get("proofParameterSet"))
        {
            Some(parameter_set_value) => parameter_set_value,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no parameter set."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let proof_encoding_value = match object_map(proof_input)
            .and_then(|object| object.get("proofEncoding"))
        {
            Some(proof_encoding_value) => proof_encoding_value,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no proof encoding."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let parameter_set: LinearProofParameterSet = match serde_json::from_value(
            parameter_set_value.clone(),
        ) {
            Ok(parameter_set) => parameter_set,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} parameter set is invalid: {error}."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let proof_encoding: LinearProofEncoding = match serde_json::from_value(
            proof_encoding_value.clone(),
        ) {
            Ok(proof_encoding) => proof_encoding,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} proof encoding is invalid: {error}."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
            match serde_json::from_value(
                object_map(proof_statement)
                    .and_then(|object| object.get("targetCoefficientRepresentation"))
                    .cloned()
                    .unwrap_or(Value::Null),
            ) {
                Ok(target_coefficient_representation) => target_coefficient_representation,
                Err(error) => {
                    return component_proof_backend_rejection(
                        operation,
                        component_id,
                        vec![json!({
                            "code": "BallotPackageInvalid",
                            "message": format!("Structured receiver-encryption proof statement for {component_id} has invalid targetCoefficientRepresentation: {error}."),
                            "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                        })],
                        json!("BallotPackageInvalid"),
                    );
                }
            };
        let expected_proof_size_bytes = object_map(component_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64)
            .and_then(|proof_size| usize::try_from(proof_size).ok());
        let proof_verification = linear_proof_verifier::verify_sparse_linear_proof_components(
            linear_proof_verifier::SparseLinearProofVerificationInput {
                case_name: &format!("{component_id}-component-proof"),
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex,
                source_statement_matrix: &parsed_structured_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_structured_statement.target_vector_coefficients,
                target_coefficient_representation,
                proof_hex: proof_bytes_hex,
                expected_proof_size_bytes,
            },
        );
        if proof_verification
            .as_object()
            .and_then(|object| object.get("ok"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return component_proof_backend_rejection(
                operation,
                component_id,
                proof_verification
                    .as_object()
                    .and_then(|object| object.get("refusedObjects"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_else(|| {
                        vec![json!({
                            "code": "InvalidFixture",
                            "message": format!("Ballot proof component {component_id} structured proof bytes failed without a structured refusal.")
                        })]
                    }),
                proof_verification
                    .as_object()
                    .and_then(|object| object.get("unresolvedReason"))
                    .cloned()
                    .unwrap_or_else(|| json!("InvalidFixture")),
            );
        }

        let mut status_labels = vec![
            json!("BallotProofComponentProofBytesVerified"),
            json!("BallotProofComponentLinearProofVerified"),
            json!("BallotProofComponentStructuredReceiverEncryptionStatementVerified"),
        ];
        if let Some(proof_status_labels) = proof_verification
            .as_object()
            .and_then(|object| object.get("statusLabels"))
            .and_then(Value::as_array)
        {
            status_labels.extend(proof_status_labels.iter().cloned());
        }

        return json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": operation,
            "componentId": component_id,
            "statusLabels": status_labels,
            "acceptedDigests": [
                string_field(component_proof, "componentProofRecordDigest"),
                string_field(component_proof, "proofBytesDigest"),
                string_field(proof_input, "componentProofStatementDigest"),
                string_field(proof_input, "statementDigest")
            ],
            "refusedObjects": [],
            "unresolvedReason": Value::Null
        });
    }

    if string_field(proof_input, "proofStatementFormat") == Some(PUBLIC_ZERO_PROOF_STATEMENT_FORMAT)
    {
        let mut refused_objects = Vec::new();
        if component_id != "receiver-key-binding-component" {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Public-zero witness binding checks are only valid for receiver-key-binding-component, not {component_id}."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        }
        if string_field(proof_input, "proofBytesHex") != Some("")
            || object_map(component_proof)
                .and_then(|object| object.get("proofSizeBytes"))
                .and_then(Value::as_u64)
                != Some(0)
        {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Ballot proof component proof bytes for {component_id} must be empty for the public-zero witness binding check."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        }
        if let Some(proof_statement) =
            object_map(proof_input).and_then(|object| object.get("proofStatement"))
        {
            refused_objects.extend(collect_component_proof_statement_plan_shape_refusals(
                proof_statement,
                component_id,
                string_field(component_proof, "componentProofRecordDigest"),
            ));
            if derive_ballot_component_proof_statement_plan_digest(proof_statement).as_deref()
                != string_field(proof_statement, "componentProofStatementDigest")
            {
                refused_objects.push(json!({
                    "code": "BallotPackageInvalid",
                    "message": format!("Ballot proof component proof statement digest for {component_id} does not match its canonical payload."),
                    "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                }));
            }
        } else {
            refused_objects.push(json!({
                "code": "BallotPackageInvalid",
                "message": format!("Ballot proof component proof input for {component_id} must supply its public proof statement object."),
                "objectDigest": string_field(component_proof, "componentProofRecordDigest")
            }));
        }
        if !refused_objects.is_empty() {
            return component_proof_backend_rejection(
                operation,
                component_id,
                refused_objects,
                json!("BallotPackageInvalid"),
            );
        }

        return json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": operation,
            "componentId": component_id,
            "statusLabels": [
                "BallotProofComponentProofBytesVerified",
                "BallotProofComponentPublicZeroWitnessBindingChecked"
            ],
            "acceptedDigests": [
                string_field(component_proof, "componentProofRecordDigest"),
                string_field(component_proof, "proofBytesDigest"),
                string_field(proof_input, "componentProofStatementDigest"),
                string_field(proof_input, "statementDigest")
            ],
            "refusedObjects": [],
            "unresolvedReason": Value::Null
        });
    }

    if string_field(proof_input, "proofStatementFormat")
        == Some(SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT)
    {
        let proof_statement = match object_map(proof_input)
            .and_then(|object| object.get("proofStatement"))
        {
            Some(proof_statement) => proof_statement,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component proof input for {component_id} must supply its sparse public proof statement object."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let parsed_sparse_statement = match sparse_matrix_from_sparse_component_statement(
            proof_statement,
        ) {
            Ok(parsed_sparse_statement) => parsed_sparse_statement,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": error.code,
                        "message": error.message,
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!(error.code),
                );
            }
        };
        let proof_bytes_hex = match string_field(proof_input, "proofBytesHex") {
            Some(proof_bytes_hex) => proof_bytes_hex,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no proof bytes."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let public_randomness_hex = match string_field(proof_input, "publicRandomnessHex") {
            Some(public_randomness_hex) => public_randomness_hex,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no public randomness."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let parameter_set_value = match object_map(proof_input)
            .and_then(|object| object.get("proofParameterSet"))
        {
            Some(parameter_set_value) => parameter_set_value,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no parameter set."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let proof_encoding_value = match object_map(proof_input)
            .and_then(|object| object.get("proofEncoding"))
        {
            Some(proof_encoding_value) => proof_encoding_value,
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} has no proof encoding."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let parameter_set: LinearProofParameterSet = match serde_json::from_value(
            parameter_set_value.clone(),
        ) {
            Ok(parameter_set) => parameter_set,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} parameter set is invalid: {error}."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let proof_encoding: LinearProofEncoding = match serde_json::from_value(
            proof_encoding_value.clone(),
        ) {
            Ok(proof_encoding) => proof_encoding,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Ballot proof component {component_id} proof encoding is invalid: {error}."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let target_coefficient_representation_value = match object_map(proof_statement)
            .and_then(|object| object.get("targetCoefficientRepresentation"))
        {
            Some(target_coefficient_representation_value) => {
                target_coefficient_representation_value.clone()
            }
            None => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": "BallotPackageInvalid",
                        "message": format!("Sparse component proof statement for {component_id} is missing targetCoefficientRepresentation."),
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
        let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
            match serde_json::from_value(target_coefficient_representation_value) {
                Ok(target_coefficient_representation) => target_coefficient_representation,
                Err(error) => {
                    return component_proof_backend_rejection(
                        operation,
                        component_id,
                        vec![json!({
                            "code": "BallotPackageInvalid",
                            "message": format!("Sparse component proof statement for {component_id} has invalid targetCoefficientRepresentation: {error}."),
                            "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                        })],
                        json!("BallotPackageInvalid"),
                    );
                }
            };
        let expected_proof_size_bytes = object_map(component_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64)
            .and_then(|proof_size| usize::try_from(proof_size).ok());
        let proof_verification = linear_proof_verifier::verify_sparse_linear_proof_components(
            linear_proof_verifier::SparseLinearProofVerificationInput {
                case_name: &format!("{component_id}-component-proof"),
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex,
                source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
                target_coefficient_representation,
                proof_hex: proof_bytes_hex,
                expected_proof_size_bytes,
            },
        );
        if proof_verification
            .as_object()
            .and_then(|object| object.get("ok"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return component_proof_backend_rejection(
                operation,
                component_id,
                proof_verification
                    .as_object()
                    .and_then(|object| object.get("refusedObjects"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_else(|| {
                        vec![json!({
                            "code": "InvalidFixture",
                            "message": format!("Ballot proof component {component_id} sparse proof bytes failed without a structured refusal.")
                        })]
                    }),
                proof_verification
                    .as_object()
                    .and_then(|object| object.get("unresolvedReason"))
                    .cloned()
                    .unwrap_or_else(|| json!("InvalidFixture")),
            );
        }

        let mut status_labels = vec![
            json!("BallotProofComponentProofBytesVerified"),
            json!("BallotProofComponentLinearProofVerified"),
            json!("BallotProofComponentSparseStatementVerifiedWithoutDenseExpansion"),
        ];
        if let Some(proof_status_labels) = proof_verification
            .as_object()
            .and_then(|object| object.get("statusLabels"))
            .and_then(Value::as_array)
        {
            status_labels.extend(proof_status_labels.iter().cloned());
        }

        return json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": operation,
            "componentId": component_id,
            "statusLabels": status_labels,
            "acceptedDigests": [
                string_field(component_proof, "componentProofRecordDigest"),
                string_field(component_proof, "proofBytesDigest"),
                string_field(proof_input, "componentProofStatementDigest"),
                string_field(proof_input, "statementDigest")
            ],
            "refusedObjects": [],
            "unresolvedReason": Value::Null
        });
    }

    let vector_case =
        match component_linear_proof_vector_case(component_id, component_proof, proof_input) {
            Ok(vector_case) => vector_case,
            Err(error) => {
                return component_proof_backend_rejection(
                    operation,
                    component_id,
                    vec![json!({
                        "code": error.code,
                        "message": error.message,
                        "objectDigest": string_field(component_proof, "componentProofRecordDigest")
                    })],
                    json!(error.code),
                );
            }
        };
    let proof_verification =
        linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if proof_verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return component_proof_backend_rejection(
            operation,
            component_id,
            proof_verification
                .as_object()
                .and_then(|object| object.get("refusedObjects"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| {
                    vec![json!({
                        "code": "InvalidFixture",
                        "message": format!("Ballot proof component {component_id} proof bytes failed without a structured refusal.")
                    })]
                }),
            proof_verification
                .as_object()
                .and_then(|object| object.get("unresolvedReason"))
                .cloned()
                .unwrap_or_else(|| json!("InvalidFixture")),
        );
    }

    let mut status_labels = vec![
        json!("BallotProofComponentProofBytesVerified"),
        json!("BallotProofComponentLinearProofVerified"),
    ];
    if let Some(proof_status_labels) = proof_verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(proof_status_labels.iter().cloned());
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "componentId": component_id,
        "statusLabels": status_labels,
        "acceptedDigests": [
            string_field(component_proof, "componentProofRecordDigest"),
            string_field(component_proof, "proofBytesDigest"),
            string_field(proof_input, "componentProofStatementDigest"),
            string_field(proof_input, "statementDigest")
        ],
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

fn verify_component_proof_bundle_backend(
    operation: &str,
    _accepted_object_digest: Option<&str>,
    component_proof_bundle: &Value,
    component_proof_inputs: Option<&Value>,
) -> Option<Value> {
    let component_proof_inputs = component_proof_inputs?;
    let component_proof_inputs_array = component_proof_inputs.as_array()?;
    let component_proofs = array_field(component_proof_bundle, "componentProofs")?;
    let mut proof_inputs_by_component = BTreeMap::new();
    for proof_input in component_proof_inputs_array {
        if let Some(component_id) = string_field(proof_input, "componentId") {
            proof_inputs_by_component.insert(component_id.to_string(), proof_input);
        }
    }

    for component_proof in component_proofs {
        let Some(component_id) = string_field(component_proof, "componentId") else {
            continue;
        };
        let Some(proof_input) = proof_inputs_by_component.get(component_id) else {
            continue;
        };
        let component_verification = verify_component_linear_proof_bytes(
            operation,
            component_id,
            component_proof,
            proof_input,
        );
        if component_verification
            .as_object()
            .and_then(|object| object.get("ok"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Some(component_verification);
        }
    }

    None
}

struct BallotLinearProofVerificationInputs<'a> {
    component_proof_bundle: Option<&'a Value>,
    component_proof_inputs: Option<&'a Value>,
    linear_statement: &'a Value,
    proof_bytes_hex: &'a str,
    public_randomness_hex: &'a str,
    parameter_set: &'a Value,
    proof_encoding: &'a Value,
    component_bundle_statement: Option<&'a Value>,
}

pub(crate) struct BallotProofVerificationInputs<'a> {
    pub(crate) proof_bytes_hex: Option<&'a str>,
    pub(crate) linear_statement: Option<&'a Value>,
    pub(crate) public_randomness_hex: Option<&'a str>,
    pub(crate) parameter_set: Option<&'a Value>,
    pub(crate) proof_encoding: Option<&'a Value>,
    pub(crate) component_bundle_statement: Option<&'a Value>,
    pub(crate) component_proof_inputs: Option<&'a Value>,
    pub(crate) component_proof_bundle: Option<&'a Value>,
}

fn verify_ballot_linear_proof_bytes(
    statement: &Value,
    ballot_proof: &Value,
    backend_inputs: BallotLinearProofVerificationInputs<'_>,
) -> Value {
    let linear_statement = backend_inputs.linear_statement;
    let proof_bytes_hex = backend_inputs.proof_bytes_hex;
    let public_randomness_hex = backend_inputs.public_randomness_hex;
    let parameter_set = backend_inputs.parameter_set;
    let proof_encoding = backend_inputs.proof_encoding;
    let component_bundle_statement = backend_inputs.component_bundle_statement;
    let component_proof_bundle = backend_inputs.component_proof_bundle;
    let component_proof_inputs = backend_inputs.component_proof_inputs;
    let mut refused_objects = Vec::new();
    let ballot_proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let linear_statement_digest = string_field(linear_statement, "statementDigest");
    let expected_proof_encoding_digest =
        derive_ballot_proof_encoding_profile_digest(proof_encoding);
    let expected_parameter_set_digest = derive_ballot_proof_parameter_set_digest(parameter_set);
    let expected_public_randomness_digest =
        derive_ballot_proof_public_randomness_digest(public_randomness_hex);
    let expected_linear_statement_digest =
        derive_ballot_proof_linear_statement_digest(linear_statement);
    let supplied_parameter_profile_id = string_field(parameter_set, "profileId");
    let supplied_proof_encoding_profile_id = string_field(proof_encoding, "profileId");
    let linear_statement_parameter_profile_id =
        string_field(linear_statement, "parameterProfileId");
    let linear_statement_projection_coverage = string_field(linear_statement, "projectionCoverage");
    let proof_size_bytes = object_map(ballot_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size_bytes| usize::try_from(proof_size_bytes).ok());

    if linear_statement_digest != expected_linear_statement_digest.as_deref() {
        refused_objects.push(structural_refusal(
            "Ballot proof linear statement digest does not match its canonical payload.",
            ballot_proof_record_digest,
        ));
    }
    if linear_statement_parameter_profile_id != supplied_parameter_profile_id {
        refused_objects.push(structural_refusal(
            "Ballot proof linear statement parameter profile does not match the supplied proof parameter set.",
            ballot_proof_record_digest,
        ));
    }
    if linear_statement_projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        && supplied_parameter_profile_id != Some(FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID)
    {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot relation proofs require the dedicated full-relation parameter profile.",
            ballot_proof_record_digest,
        ));
    }
    if linear_statement_projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        && supplied_proof_encoding_profile_id != Some(FULL_BALLOT_PROOF_ENCODING_PROFILE_ID)
    {
        refused_objects.push(structural_refusal(
            "Full encoded-score ballot relation proofs require the dedicated full-relation proof encoding profile.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "linearStatementDigest") != linear_statement_digest {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied linear statement.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "backendStatementDigest")
        != string_field(linear_statement, "backendStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied backend statement.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "statementMatrixDigest")
        != string_field(linear_statement, "statementMatrixDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied statement matrix.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "targetVectorDigest")
        != string_field(linear_statement, "targetVectorDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied target vector.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(linear_statement, "relationStatementDigest").is_some()
        && string_field(ballot_proof, "relationStatementDigest")
            != string_field(linear_statement, "relationStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the relation statement used by the supplied linear statement.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(linear_statement, "ballotProofStatementDigest").is_some()
        && string_field(statement, "ballotProofStatementDigest")
            != string_field(linear_statement, "ballotProofStatementDigest")
    {
        refused_objects.push(structural_refusal(
            "Ballot proof linear statement is not bound to the supplied ballot proof statement.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "proofEncodingProfileDigest")
        != expected_proof_encoding_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied proof encoding profile.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "proofParameterSetDigest")
        != expected_parameter_set_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied proof parameter set.",
            ballot_proof_record_digest,
        ));
    }
    if string_field(ballot_proof, "publicRandomnessDigest")
        != expected_public_randomness_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record is not bound to the supplied public randomness.",
            ballot_proof_record_digest,
        ));
    }
    match serde_json::from_value::<LinearProofParameterSet>(parameter_set.clone()) {
        Ok(parameter_contract)
            if parameter_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                "Ballot proof parameter set is not bound to the proof record byte length.",
                ballot_proof_record_digest,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!("Ballot proof parameter set is malformed: {error}"),
            ballot_proof_record_digest,
        )),
    }
    match serde_json::from_value::<LinearProofEncoding>(proof_encoding.clone()) {
        Ok(proof_encoding_contract)
            if proof_encoding_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                "Ballot proof encoding is not bound to the proof record byte length.",
                ballot_proof_record_digest,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!("Ballot proof encoding is malformed: {error}"),
            ballot_proof_record_digest,
        )),
    }
    refused_objects.extend(collect_ballot_component_bundle_refusals(
        statement,
        ballot_proof,
        linear_statement,
        component_bundle_statement,
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyBallotProof", refused_objects);
    }
    if linear_statement_projection_coverage == Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        && let Some(component_proof_bundle) = component_proof_bundle
        && let Some(component_backend_result) = verify_component_proof_bundle_backend(
            "verifyBallotProof",
            ballot_proof_record_digest,
            component_proof_bundle,
            component_proof_inputs,
        )
    {
        return component_backend_result;
    }

    let vector_case = json!({
        "caseName": "ballot-proof-record",
        "description": "Ballot proof record verification through the internal linear proof backend.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("statementMatrixCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetVectorCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("targetVectorCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetCoefficientRepresentation": object_map(linear_statement)
            .and_then(|object| object.get("targetCoefficientRepresentation"))
            .cloned()
            .unwrap_or(Value::Null),
        "proofHex": proof_bytes_hex,
        "expectedProofSizeBytes": object_map(ballot_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .cloned()
            .unwrap_or(Value::Null)
    });
    let proof_verification =
        linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if proof_verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "verifyBallotProof",
            "statusLabels": [],
            "acceptedDigests": [],
            "refusedObjects": proof_verification
                .as_object()
                .and_then(|object| object.get("refusedObjects"))
                .cloned()
                .unwrap_or_else(|| json!([
                    {
                        "code": "InvalidFixture",
                        "message": "Ballot proof backend verification failed without a structured refusal."
                    }
                ])),
            "unresolvedReason": proof_verification
                .as_object()
                .and_then(|object| object.get("unresolvedReason"))
                .cloned()
                .unwrap_or_else(|| json!("InvalidFixture"))
        });
    }
    if string_field(linear_statement, "projectionCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        return structural_rejection(
            "verifyBallotProof",
            vec![structural_refusal(
                "Ballot proof linear statement does not cover the full encoded-score ballot relation.",
                ballot_proof_record_digest,
            )],
        );
    }
    if let Some(component_proof_bundle) = component_proof_bundle
        && let Some(component_backend_result) = verify_component_proof_bundle_backend(
            "verifyBallotProof",
            ballot_proof_record_digest,
            component_proof_bundle,
            component_proof_inputs,
        )
    {
        return component_backend_result;
    }

    let mut status_labels = vec![
        json!("BallotProofRecordDigestRecomputed"),
        json!("BallotProofBytesDigestChecked"),
        json!("BallotProofLinearStatementBound"),
        json!("BallotProofLinearProofVerified"),
    ];
    if let Some(proof_status_labels) = proof_verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(proof_status_labels.iter().cloned());
    }
    let accepted_digests = [
        ballot_proof_record_digest,
        string_field(ballot_proof, "proofBytesDigest"),
        linear_statement_digest,
        string_field(ballot_proof, "backendStatementDigest"),
    ]
    .into_iter()
    .flatten()
    .map(Value::from)
    .collect::<Vec<_>>();

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "verifyBallotProof",
        "statusLabels": status_labels,
        "acceptedDigests": accepted_digests,
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

pub(crate) fn verify_ballot_proof(
    statement: &Value,
    ballot_proof: &Value,
    backend_inputs: BallotProofVerificationInputs<'_>,
) -> Value {
    let mut refused_objects = collect_ballot_proof_refusals(statement, ballot_proof);
    refused_objects.extend(collect_proof_bytes_refusals(
        backend_inputs.proof_bytes_hex,
        string_field(ballot_proof, "proofBytesDigest"),
        object_map(ballot_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64),
        string_field(ballot_proof, "ballotProofRecordDigest"),
        "Ballot",
        false,
    ));
    refused_objects.extend(collect_ballot_component_proof_bundle_refusals(
        statement,
        ballot_proof,
        backend_inputs.component_bundle_statement,
        backend_inputs.component_proof_bundle,
        backend_inputs.component_proof_inputs,
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyBallotProof", refused_objects);
    }

    match (
        backend_inputs.linear_statement,
        backend_inputs.proof_bytes_hex,
        backend_inputs.public_randomness_hex,
        backend_inputs.parameter_set,
        backend_inputs.proof_encoding,
        backend_inputs.component_bundle_statement,
        backend_inputs.component_proof_bundle,
    ) {
        (None, _, None, None, None, None, None) => {}
        (
            Some(linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(parameter_set),
            Some(proof_encoding),
            component_bundle_statement,
            _component_proof_bundle,
        ) => {
            return verify_ballot_linear_proof_bytes(
                statement,
                ballot_proof,
                BallotLinearProofVerificationInputs {
                    component_bundle_statement,
                    component_proof_bundle: backend_inputs.component_proof_bundle,
                    component_proof_inputs: backend_inputs.component_proof_inputs,
                    linear_statement,
                    parameter_set,
                    proof_bytes_hex,
                    proof_encoding,
                    public_randomness_hex,
                },
            );
        }
        _ => {
            return structural_rejection(
                "verifyBallotProof",
                vec![structural_refusal(
                    "Ballot proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement together.",
                    string_field(ballot_proof, "ballotProofRecordDigest"),
                )],
            );
        }
    }

    fail_closed("verifyBallotProof")
}

pub fn verify_claim_bearing_ballot_package(ballot_package: &Value) -> Value {
    let refused_objects = collect_claim_bearing_package_refusals(ballot_package);
    if !refused_objects.is_empty() {
        return structural_rejection("verifyClaimBearingBallotPackage", refused_objects);
    }
    if let Some(component_proof_bundle) = object_map(ballot_package)
        .and_then(|package_object| package_object.get("componentProofBundle"))
    {
        return component_proof_bundle_unavailable_result(
            "verifyClaimBearingBallotPackage",
            string_field(ballot_package, "ballotPackageDigest"),
            component_proof_bundle,
        );
    }

    fail_closed("verifyClaimBearingBallotPackage")
}

pub fn verify_linear_proof_vector_case(vector_case: &Value) -> Value {
    linear_proof_verifier::verify_linear_proof_vector_case_value(vector_case)
}

pub fn verify_encoded_relation_vector_case(vector_case: &Value) -> Value {
    encoded_relation_vectors::verify_encoded_relation_vector_case_value(vector_case)
}

pub fn verify_receiver_key_vector_case(vector_case: &Value) -> Value {
    receiver_key_vectors::verify_receiver_key_vector_case_value(vector_case)
}

#[cfg(test)]
mod tests {
    use crate::ballot_privacy::{
        linear_proof_parameters::{
            LinearProofParameterSet, encoded_score_field_linear_proof_encoding_contract,
            receiver_key_linear_parameter_contract, receiver_key_linear_proof_encoding_contract,
        },
        polynomial_ring::PolynomialRing,
    };
    use serde_json::{Value, json};

    #[derive(Default)]
    struct BallotProofBackendInputParts<'a> {
        proof_bytes_hex: Option<&'a str>,
        linear_statement: Option<&'a Value>,
        public_randomness_hex: Option<&'a str>,
        parameter_set: Option<&'a Value>,
        proof_encoding: Option<&'a Value>,
        component_bundle_statement: Option<&'a Value>,
        component_proof_bundle: Option<&'a Value>,
        component_proof_inputs: Option<&'a Value>,
    }

    fn ballot_proof_backend_inputs<'a>(
        parts: BallotProofBackendInputParts<'a>,
    ) -> super::BallotProofVerificationInputs<'a> {
        super::BallotProofVerificationInputs {
            component_bundle_statement: parts.component_bundle_statement,
            component_proof_bundle: parts.component_proof_bundle,
            component_proof_inputs: parts.component_proof_inputs,
            linear_statement: parts.linear_statement,
            parameter_set: parts.parameter_set,
            proof_bytes_hex: parts.proof_bytes_hex,
            proof_encoding: parts.proof_encoding,
            public_randomness_hex: parts.public_randomness_hex,
        }
    }

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
    fn ballot_privacy_backend_is_explicitly_unavailable_until_integrated() {
        let statement = json!({
            "objectType": "BallotProofStatement",
            "objectVersion": 1,
            "optionCount": 20,
            "shareVectorWidth": 220,
            "receiverPublicKeys": [],
            "receiverPayloads": [],
            "shareCommitments": []
        });
        let ballot_proof = json!({
            "objectType": "BallotProofRecord",
            "objectVersion": 1,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofSizeBytes": 1024
        });
        let verification = super::verify_ballot_proof(
            &statement,
            &ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts::default()),
        );

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(
            verification["backendStatus"]["portableRustWasmPortRequired"],
            true
        );
        assert!(
            verification["backendStatus"]["requiredComponents"]
                .as_array()
                .expect("backend component list should be an array")
                .contains(&json!(
                    "ABDLop commitment key generation, commitment, and commitment hashing"
                ))
        );
        assert_eq!(verification["unresolvedReason"], "BallotPackageInvalid");
    }

    #[test]
    fn ballot_proof_generation_command_emits_verifying_dense_proof_bytes() {
        let mut proof_encoding = encoded_score_field_linear_proof_encoding_contract();
        proof_encoding.profile_id = super::FULL_BALLOT_PROOF_ENCODING_PROFILE_ID.to_string();
        proof_encoding.source =
            "sealed-lattice/linear-proof/full-encoded-score-ballot-test-encoding-v1".to_string();
        proof_encoding.short_response_vector_length = 2;
        let parameter_set = LinearProofParameterSet {
            profile_id: super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID.to_string(),
            source: "sealed-lattice/linear-proof/full-encoded-score-ballot-test-parameters-v1"
                .to_string(),
            relation: "A*w + t = 0".to_string(),
            ring_degree: 64,
            proof_system_ring_degree: 64,
            coefficient_modulus: 65_537,
            statement_rows: 1,
            statement_columns: 1,
            witness_l2_bound_squared: 65_536,
            expected_proof_size_bytes: None,
        };
        let mut unit_polynomial = vec![0_u64; 64];
        unit_polynomial[0] = 1;
        let mut target_polynomial = vec![0_u64; 64];
        target_polynomial[0] = 65_537 - 5;
        let mut witness_polynomial = vec![0_i64; 64];
        witness_polynomial[0] = 5;
        let linear_statement = json!({
            "objectType": "BallotProofLinearProofStatement",
            "objectVersion": 1,
            "projectionCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
            "parameterProfileId": super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
            "relation": "A*w + t = 0",
            "statementMatrixCoefficients": [[unit_polynomial]],
            "targetVectorCoefficients": [target_polynomial],
            "targetCoefficientRepresentation": "centeredSignedSourceModulus"
        });
        let parameter_set_value =
            serde_json::to_value(&parameter_set).expect("parameter set should serialize");
        let proof_encoding_value =
            serde_json::to_value(&proof_encoding).expect("proof encoding should serialize");
        let public_randomness_hex = "00".repeat(32);
        let prover_randomness_hex = "07".repeat(32);
        let secret_state = json!({
            "sourceWitnessCoefficients": [witness_polynomial]
        });

        let generation = super::generate_ballot_proof(
            Some(&linear_statement),
            Some(&parameter_set_value),
            Some(&proof_encoding_value),
            Some(&public_randomness_hex),
            Some(&secret_state),
            Some(&prover_randomness_hex),
        );

        assert_eq!(
            generation["ok"], true,
            "generated ballot proof should verify: {generation}"
        );
        assert_eq!(generation["generatedProofBytes"], true);
        assert!(
            generation["statusLabels"]
                .as_array()
                .expect("status labels should be present")
                .contains(&json!("BallotGeneratedProofVerified"))
        );
        assert!(
            generation["proofBytesHex"]
                .as_str()
                .expect("proof bytes should be hex")
                .len()
                > 100
        );

        let proof_input = json!({
            "componentId": "score-and-shamir-field-component",
            "proofStatementFormat": "dense-polynomial-matrix-linear-proof-v1",
            "proofStatement": linear_statement,
            "proofParameterSet": parameter_set_value,
            "proofEncoding": proof_encoding_value,
            "publicRandomnessHex": public_randomness_hex
        });
        let component_generation = super::generate_ballot_component_proof(
            Some("score-and-shamir-field-component"),
            Some(&proof_input),
            Some(&secret_state),
            Some(&prover_randomness_hex),
        );

        assert_eq!(
            component_generation["ok"], true,
            "generated dense component proof should verify: {component_generation}"
        );
        assert!(
            component_generation["statusLabels"]
                .as_array()
                .expect("status labels should be present")
                .contains(&json!("BallotComponentGeneratedProofVerified"))
        );
    }

    #[test]
    fn ballot_proof_record_generation_emits_bound_component_bundle() {
        fn proof_encoding_value(
            profile_id: &str,
            source: &str,
            short_response_vector_length: usize,
        ) -> Value {
            let mut proof_encoding = encoded_score_field_linear_proof_encoding_contract();
            proof_encoding.profile_id = profile_id.to_string();
            proof_encoding.source = source.to_string();
            proof_encoding.short_response_vector_length = short_response_vector_length;
            serde_json::to_value(&proof_encoding).expect("proof encoding should serialize")
        }

        fn parameter_set_value(
            profile_id: &str,
            source: &str,
            ring_degree: usize,
            coefficient_modulus: u64,
            statement_rows: usize,
            statement_columns: usize,
            witness_l2_bound_squared: u128,
        ) -> Value {
            json!({
                "profileId": profile_id,
                "source": source,
                "relation": "A*w + t = 0",
                "ringDegree": ring_degree,
                "proofSystemRingDegree": 64,
                "coefficientModulus": coefficient_modulus.to_string(),
                "statementRows": statement_rows,
                "statementColumns": statement_columns,
                "witnessL2BoundSquared": witness_l2_bound_squared,
            })
        }

        fn digest_for_payload(namespace: &str, value: &Value) -> String {
            super::derive_digest(namespace, value).expect("digest should derive")
        }

        fn statement_digest_for_payload(purpose: &str, payload: &Value) -> String {
            digest_for_payload(
                "ChallengeDomainDigest",
                &json!({
                    "payload": payload,
                    "purpose": purpose
                }),
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn component_statement(
            component_id: &str,
            component_statement_digest_label: &str,
            backend_statement_digest: &str,
            relation_statement_digest: &str,
            ballot_proof_statement_digest: &str,
            coefficient_modulus: &str,
            row_count: usize,
            variable_column_count: usize,
        ) -> Value {
            let variable_column_indices = (0..variable_column_count).collect::<Vec<_>>();
            let component_payload = json!({
                "objectType": "BallotProofComponentStatement",
                "objectVersion": 1,
                "backendStatementDigest": backend_statement_digest,
                "ballotProofStatementDigest": ballot_proof_statement_digest,
                "coefficientModulus": coefficient_modulus,
                "componentDigest": test_digest(&format!("{component_id}-component")),
                "componentId": component_id,
                "matrixDigest": test_digest(&format!("{component_id}-matrix")),
                "proofLoweringStatus": "explicitRowsAvailable",
                "relationStatementDigest": relation_statement_digest,
                "rowBatchMatrixDigests": [test_digest(&format!("{component_id}-row-matrix"))],
                "rowBatchNames": [format!("{component_id}-rows")],
                "rowBatchTargetVectorDigests": [test_digest(&format!("{component_id}-row-target"))],
                "rowCount": row_count,
                "rowKinds": [format!("{component_id}-rows")],
                "targetVectorDigest": test_digest(&format!("{component_id}-target")),
                "variableColumnCount": variable_column_count,
                "variableColumnIndices": variable_column_indices,
            });
            let mut component_statement = component_payload;
            component_statement
                .as_object_mut()
                .expect("component statement should be an object")
                .insert(
                    "componentStatementDigest".to_string(),
                    json!(test_digest(component_statement_digest_label)),
                );
            let canonical_digest =
                super::derive_ballot_component_statement_digest(&component_statement)
                    .expect("component statement digest should derive");
            component_statement
                .as_object_mut()
                .expect("component statement should be an object")
                .insert(
                    "componentStatementDigest".to_string(),
                    json!(canonical_digest),
                );
            component_statement
        }

        #[allow(clippy::too_many_arguments)]
        fn dense_linear_statement(
            component_id: &str,
            component_statement_digest: &Value,
            parameter_profile_id: &str,
            backend_statement_digest: &str,
            relation_statement_digest: &str,
            ballot_proof_statement_digest: &str,
            statement_matrix_digest: &str,
            target_vector_digest: &str,
            projection_coverage: &str,
            statement_columns: usize,
        ) -> Value {
            let mut unit_polynomial = vec![0_u64; 64];
            unit_polynomial[0] = 1;
            let mut target_polynomial = vec![0_u64; 64];
            target_polynomial[0] = 65_537 - 5;
            let mut statement_matrix_row = vec![vec![0_u64; 64]; statement_columns];
            statement_matrix_row[0] = unit_polynomial;
            let mut statement_payload = json!({
                "objectType": "BallotProofLinearProofStatement",
                "objectVersion": 1,
                "backendStatementDigest": backend_statement_digest,
                "ballotProofStatementDigest": ballot_proof_statement_digest,
                "coefficientModulus": "65537",
                "componentId": component_id,
                "componentStatementDigest": component_statement_digest,
                "parameterProfileId": parameter_profile_id,
                "projectionCoverage": projection_coverage,
                "relation": "A*w + t = 0",
                "relationStatementDigest": relation_statement_digest,
                "ringDegree": 64,
                "statementColumns": statement_columns,
                "statementMatrixCoefficients": [statement_matrix_row],
                "statementMatrixDigest": statement_matrix_digest,
                "statementRows": 1,
                "targetCoefficientRepresentation": "centeredSignedSourceModulus",
                "targetVectorCoefficients": [target_polynomial],
                "targetVectorDigest": target_vector_digest,
                "witnessL2BoundSquared": "65536",
            });
            let statement_digest = statement_digest_for_payload(
                "ballot-proof-linear-proof-statement-v1",
                &statement_payload,
            );
            statement_payload
                .as_object_mut()
                .expect("linear statement should be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));
            statement_payload
        }

        #[allow(clippy::too_many_arguments)]
        fn sparse_statement(
            component_id: &str,
            component_statement_digest: &Value,
            parameter_profile_id: &str,
            backend_statement_digest: &str,
            relation_statement_digest: &str,
            ballot_proof_statement_digest: &str,
            coefficient_modulus: &str,
            projection_coverage: &str,
            target_constant_coefficient: Option<&str>,
            witness_l2_bound_squared: &str,
        ) -> Value {
            let matrix_entries = json!([
                {
                    "rowIndex": 0,
                    "columnIndex": 0,
                    "constantCoefficient": 1
                }
            ]);
            let target_entries = target_constant_coefficient.map_or_else(
                || json!([]),
                |constant_coefficient| {
                    json!([
                        {
                            "rowIndex": 0,
                            "constantCoefficient": constant_coefficient
                        }
                    ])
                },
            );
            let target_entry_count = if target_constant_coefficient.is_some() {
                1
            } else {
                0
            };
            let mut statement_payload = json!({
                "objectType": "BallotProofSparseComponentLinearProofStatement",
                "objectVersion": 1,
                "backendStatementDigest": backend_statement_digest,
                "ballotProofStatementDigest": ballot_proof_statement_digest,
                "coefficientModulus": coefficient_modulus,
                "componentId": component_id,
                "componentStatementDigest": component_statement_digest,
                "parameterProfileId": parameter_profile_id,
                "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
                "projectionCoverage": projection_coverage,
                "relation": "A*w + t = 0",
                "relationStatementDigest": relation_statement_digest,
                "sourceBackendColumnIndices": [0],
                "sourceRingDegree": 64,
                "sparseStatementMatrixDigest": super::derive_sparse_statement_matrix_digest(&matrix_entries)
                    .expect("sparse matrix digest should derive"),
                "sparseStatementMatrixEntries": matrix_entries,
                "sparseStatementTermCount": 1,
                "statementColumns": 1,
                "statementRows": 1,
                "targetCoefficientRepresentation": "centeredSignedSourceModulus",
                "targetVectorDigest": super::derive_sparse_target_vector_digest(&target_entries)
                    .expect("sparse target digest should derive"),
                "targetVectorEntries": target_entries,
                "targetVectorEntryCount": target_entry_count,
                "witnessL2BoundSquared": witness_l2_bound_squared
            });
            let statement_digest = statement_digest_for_payload(
                "ballot-proof-sparse-linear-proof-statement-v1",
                &statement_payload,
            );
            statement_payload
                .as_object_mut()
                .expect("sparse statement should be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));
            statement_payload
        }

        fn structured_statement(
            component_statement_digest: &Value,
            backend_statement_digest: &str,
            relation_statement_digest: &str,
            ballot_proof_statement_digest: &str,
        ) -> Value {
            let module_degree = 256_usize;
            let module_rank = 4_usize;
            let zero_polynomial = vec![0_u64; module_degree];
            let zero_vector = vec![
                zero_polynomial.clone(),
                zero_polynomial.clone(),
                zero_polynomial.clone(),
                zero_polynomial.clone(),
            ];
            let repeated_column_matrix = vec![vec![0_usize; module_degree]; module_rank];
            let repeated_column_vector = vec![0_usize; module_degree];
            let mut statement_payload = json!({
                "objectType": "BallotProofStructuredReceiverEncryptionProofStatement",
                "objectVersion": 1,
                "backendStatementDigest": backend_statement_digest,
                "ballotProofStatementDigest": ballot_proof_statement_digest,
                "coefficientModulus": "12289",
                "componentId": "receiver-encryption-component",
                "componentStatementDigest": component_statement_digest,
                "matrixDigest": test_digest("receiver-encryption-matrix"),
                "parameterProfileId": "receiver-encryption-test-compatibility-v1",
                "proofStatementFormat": "structured-module-lwe-linear-proof-v1",
                "proofSystemRingDegree": 64,
                "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
                "receiverRows": [
                    {
                        "ciphertextChunkCount": 1,
                        "ciphertextChunks": [
                            {
                                "chunkIndex": 0,
                                "firstCiphertextVector": zero_vector,
                                "firstNoiseColumnIndices": repeated_column_matrix,
                                "plaintextBitColumnIndices": [],
                                "randomnessColumnIndices": repeated_column_matrix,
                                "secondCiphertextPolynomial": zero_polynomial,
                                "secondNoiseColumnIndices": repeated_column_vector
                            }
                        ],
                        "plaintextBitLength": 0,
                        "publicKeyVector": zero_vector,
                        "publicMatrixSeedDigest": test_digest("receiver-public-matrix-seed"),
                        "receiverIdentity": "receiver-1",
                        "receiverPayloadDigest": test_digest("receiver-payload"),
                        "receiverPublicKeyDigest": test_digest("receiver-public-key"),
                        "receiverRosterPosition": 1,
                        "rowCount": 1280,
                        "rowOffsetWithinStatement": 0
                    }
                ],
                "relation": "A*w + t = 0",
                "relationStatementDigest": relation_statement_digest,
                "sourceBackendColumnIndices": [0],
                "sourceRingDegree": 256,
                "statementColumns": 1,
                "statementRows": 1280,
                "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
                "targetVectorDigest": test_digest("receiver-encryption-target"),
                "witnessL2BoundSquared": "65536"
            });
            let statement_digest = statement_digest_for_payload(
                "ballot-proof-structured-receiver-encryption-proof-statement-v1",
                &statement_payload,
            );
            statement_payload
                .as_object_mut()
                .expect("structured statement should be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));
            statement_payload
        }

        let backend_statement_digest = test_digest("generated-backend-statement");
        let relation_statement_digest = test_digest("generated-relation-statement");
        let statement_matrix_digest = test_digest("generated-statement-matrix");
        let target_vector_digest = test_digest("generated-target-vector");
        let ballot_statement_payload = json!({
            "objectType": "BallotProofStatement",
            "objectVersion": 1,
            "actionContextDigest": test_digest("action-context"),
            "aggregateInputEncodingProfileDigest": test_digest("aggregate-input-encoding-profile"),
            "ballotPackageDigest": test_digest("ballot-package"),
            "ballotProofProfileDigest": test_digest("ballot-proof-profile"),
            "ballotScoreEncodingProfileDigest": test_digest("ballot-score-encoding-profile"),
            "ballotShareLayoutProfileDigest": test_digest("ballot-share-layout-profile"),
            "ceremonyId": "ceremony-generated-ballot-proof-record",
            "challengeDomainDigest": test_digest("challenge-domain"),
            "duplicateBallotPolicyDigest": test_digest("duplicate-ballot-policy"),
            "encodedAggregateLayoutDigest": test_digest("encoded-aggregate-layout"),
            "encodedShareVectorLayoutDigest": test_digest("encoded-share-vector-layout"),
            "manifestDigest": test_digest("manifest"),
            "optionCount": 1,
            "pollSpecDigest": test_digest("poll-spec"),
            "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
            "receiverKeyProofRoot": test_digest("receiver-key-proof-root"),
            "receiverKeyRoot": test_digest("receiver-key-root"),
            "receiverPayloads": [
                {
                    "receiverIdentity": "receiver-1",
                    "receiverPayloadCiphertextRoot": test_digest("payload-ciphertext-root"),
                    "receiverPayloadDigest": test_digest("payload"),
                    "receiverRosterPosition": 1
                }
            ],
            "receiverPublicKeys": [
                {
                    "receiverIdentity": "receiver-1",
                    "receiverPublicKeyDigest": test_digest("receiver-public-key"),
                    "receiverRosterPosition": 1
                }
            ],
            "rosterDigest": test_digest("roster"),
            "rosterExternalAcceptanceDigest": test_digest("roster-acceptance"),
            "scoreDomainDigest": test_digest("score-domain"),
            "scoreMembershipProfileDigest": test_digest("score-membership-profile"),
            "shareCommitmentMessageBoundCertDigest": test_digest("share-commitment-bound-cert"),
            "shareCommitmentProfileDigest": test_digest("share-commitment-profile"),
            "shareCommitments": [
                {
                    "receiverIdentity": "receiver-1",
                    "receiverRosterPosition": 1,
                    "shareCommitmentDigest": test_digest("share-commitment")
                }
            ],
            "shareVectorWidth": 11,
            "thresholdProfileDigest": test_digest("threshold-profile"),
            "tiePolicyDigest": test_digest("tie-policy"),
            "topOptionCount": 1,
            "voterIdentityDigest": test_digest("voter-identity"),
            "voterRosterPosition": 1,
            "voterSigningKeyDigest": test_digest("voter-signing-key")
        });
        let mut statement = ballot_statement_payload;
        let ballot_proof_statement_digest =
            digest_for_payload("BallotProofStatementDigest", &statement);
        statement
            .as_object_mut()
            .expect("statement should be an object")
            .insert(
                "ballotProofStatementDigest".to_string(),
                json!(ballot_proof_statement_digest),
            );
        let ballot_proof_statement_digest = statement["ballotProofStatementDigest"]
            .as_str()
            .expect("ballot proof statement digest should be a string")
            .to_string();
        let score_component = component_statement(
            "score-and-shamir-field-component",
            "score-component-statement",
            &backend_statement_digest,
            &relation_statement_digest,
            &ballot_proof_statement_digest,
            "65537",
            1,
            1,
        );
        let payload_component = component_statement(
            "payload-plaintext-field-component",
            "payload-component-statement",
            &backend_statement_digest,
            &relation_statement_digest,
            &ballot_proof_statement_digest,
            "65537",
            1,
            1,
        );
        let share_component = component_statement(
            "share-commitment-component",
            "share-component-statement",
            &backend_statement_digest,
            &relation_statement_digest,
            &ballot_proof_statement_digest,
            "18446744069414584321",
            1,
            1,
        );
        let receiver_encryption_component = component_statement(
            "receiver-encryption-component",
            "receiver-encryption-component-statement",
            &backend_statement_digest,
            &relation_statement_digest,
            &ballot_proof_statement_digest,
            "12289",
            1280,
            1,
        );
        let receiver_key_component = component_statement(
            "receiver-key-binding-component",
            "receiver-key-binding-component-statement",
            &backend_statement_digest,
            &relation_statement_digest,
            &ballot_proof_statement_digest,
            "12289",
            1,
            0,
        );
        let component_statements = vec![
            score_component.clone(),
            payload_component.clone(),
            share_component.clone(),
            receiver_encryption_component.clone(),
            receiver_key_component.clone(),
        ];
        let component_bundle_payload = json!({
            "objectType": "BallotProofComponentBundleStatement",
            "objectVersion": 1,
            "backendStatementDigest": backend_statement_digest,
            "ballotProofStatementDigest": ballot_proof_statement_digest,
            "bundleCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
            "componentStatements": component_statements,
            "relationLabel": "BallotPrivacyPvssRelation",
            "relationStatementDigest": relation_statement_digest,
            "requiredComponentIds": super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        });
        let mut component_bundle_statement = component_bundle_payload;
        let component_bundle_statement_digest =
            super::derive_ballot_component_bundle_statement_digest(&component_bundle_statement)
                .expect("component bundle statement digest should derive");
        component_bundle_statement
            .as_object_mut()
            .expect("component bundle statement should be an object")
            .insert(
                "componentBundleStatementDigest".to_string(),
                json!(component_bundle_statement_digest),
            );
        let linear_statement = dense_linear_statement(
            "full-ballot-proof",
            &Value::Null,
            super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
            &backend_statement_digest,
            &relation_statement_digest,
            &ballot_proof_statement_digest,
            &statement_matrix_digest,
            &target_vector_digest,
            super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
            1,
        );
        let full_parameter_set = parameter_set_value(
            super::FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID,
            "sealed-lattice/linear-proof/generated-full-record-test-parameters-v1",
            64,
            65_537,
            1,
            1,
            65_536,
        );
        let full_proof_encoding = proof_encoding_value(
            super::FULL_BALLOT_PROOF_ENCODING_PROFILE_ID,
            "sealed-lattice/linear-proof/generated-full-record-test-encoding-v1",
            2,
        );
        let score_parameter_set = parameter_set_value(
            "encoded-score-field-linear-compatibility-v1",
            "sealed-lattice/linear-proof/generated-score-test-parameters-v1",
            64,
            65_537,
            1,
            1,
            65_536,
        );
        let payload_parameter_set = parameter_set_value(
            "payload-plaintext-field-linear-compatibility-v1",
            "sealed-lattice/linear-proof/generated-payload-test-parameters-v1",
            64,
            65_537,
            1,
            1,
            65_536,
        );
        let share_parameter_set = parameter_set_value(
            "share-commitment-linear-compatibility-v1",
            "sealed-lattice/linear-proof/generated-share-test-parameters-v1",
            64,
            18_446_744_069_414_584_321,
            1,
            1,
            1_048_576,
        );
        let receiver_encryption_parameter_set = parameter_set_value(
            "receiver-encryption-linear-compatibility-v1",
            "sealed-lattice/linear-proof/generated-receiver-encryption-test-parameters-v1",
            256,
            12_289,
            1280,
            1,
            65_536,
        );
        let component_proof_inputs = json!([
            {
                "componentId": "score-and-shamir-field-component",
                "proofEncoding": proof_encoding_value(
                    "encoded-score-field-linear-proof-encoding-v1",
                    "sealed-lattice/linear-proof/generated-score-component-test-encoding-v1",
                    2
                ),
                "proofParameterSet": score_parameter_set,
                "proofStatement": dense_linear_statement(
                    "score-and-shamir-field-component",
                    &score_component["componentStatementDigest"],
                    "encoded-score-field-linear-compatibility-v1",
                    &backend_statement_digest,
                    &relation_statement_digest,
                    &ballot_proof_statement_digest,
                    &statement_matrix_digest,
                    &target_vector_digest,
                    "encoded-score-field-rows-only",
                    1
                ),
                "proofStatementFormat": "dense-polynomial-matrix-linear-proof-v1",
                "publicRandomnessHex": "11".repeat(32),
                "statementDigest": score_component["componentStatementDigest"],
            },
            {
                "componentId": "payload-plaintext-field-component",
                "proofEncoding": proof_encoding_value(
                    "payload-plaintext-field-linear-proof-encoding-v1",
                    "sealed-lattice/linear-proof/generated-payload-component-test-encoding-v1",
                    2
                ),
                "proofParameterSet": payload_parameter_set,
                "proofStatement": sparse_statement(
                    "payload-plaintext-field-component",
                    &payload_component["componentStatementDigest"],
                    "payload-plaintext-field-linear-compatibility-v1",
                    &backend_statement_digest,
                    &relation_statement_digest,
                    &ballot_proof_statement_digest,
                    "65537",
                    "payload-plaintext-field-rows-only",
                    None,
                    "65536"
                ),
                "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
                "publicRandomnessHex": "22".repeat(32),
                "statementDigest": payload_component["componentStatementDigest"],
            },
            {
                "componentId": "share-commitment-component",
                "proofEncoding": proof_encoding_value(
                    "share-commitment-linear-proof-encoding-v1",
                    "sealed-lattice/linear-proof/generated-share-component-test-encoding-v1",
                    2
                ),
                "proofParameterSet": share_parameter_set,
                "proofStatement": sparse_statement(
                    "share-commitment-component",
                    &share_component["componentStatementDigest"],
                    "share-commitment-linear-compatibility-v1",
                    &backend_statement_digest,
                    &relation_statement_digest,
                    &ballot_proof_statement_digest,
                    "18446744069414584321",
                    "share-commitment-rows-only",
                    Some("18446744069414584316"),
                    "1048576"
                ),
                "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
                "publicRandomnessHex": "00".repeat(32),
                "statementDigest": share_component["componentStatementDigest"],
            },
            {
                "componentId": "receiver-encryption-component",
                "proofEncoding": proof_encoding_value(
                    "receiver-encryption-linear-proof-encoding-v1",
                    "sealed-lattice/linear-proof/generated-receiver-encryption-component-test-encoding-v1",
                    5
                ),
                "proofParameterSet": receiver_encryption_parameter_set,
                "proofStatement": structured_statement(
                    &receiver_encryption_component["componentStatementDigest"],
                    &backend_statement_digest,
                    &relation_statement_digest,
                    &ballot_proof_statement_digest
                ),
                "proofStatementFormat": "structured-module-lwe-linear-proof-v1",
                "publicRandomnessHex": "44".repeat(32),
                "statementDigest": receiver_encryption_component["componentStatementDigest"],
            },
            {
                "componentId": "receiver-key-binding-component",
                "proofEncoding": proof_encoding_value(
                    "receiver-encryption-linear-proof-encoding-v1",
                    "sealed-lattice/linear-proof/generated-receiver-key-binding-component-test-encoding-v1",
                    2
                ),
                "proofParameterSet": parameter_set_value(
                    "receiver-key-binding-linear-compatibility-v1",
                    "sealed-lattice/linear-proof/generated-receiver-key-binding-test-parameters-v1",
                    64,
                    12_289,
                    1,
                    1,
                    65_536
                ),
                "proofStatement": component_proof_statement_for_test(
                    "receiver-key-binding-component",
                    &receiver_key_component["componentStatementDigest"],
                    None,
                    "public-zero-witness-binding-check-v1"
                ),
                "proofStatementFormat": "public-zero-witness-binding-check-v1",
                "publicRandomnessHex": "55".repeat(32),
                "statementDigest": receiver_key_component["componentStatementDigest"],
            }
        ]);
        let mut dense_witness_polynomial = vec![0_i64; 64];
        dense_witness_polynomial[0] = 5;
        let secret_state = json!({
            "sourceWitnessCoefficients": [dense_witness_polynomial.clone()]
        });
        let dense_component_secret_state = json!({
            "sourceWitnessCoefficients": [dense_witness_polynomial]
        });
        let scalar_component_secret_state = json!({
            "sourceWitnessCoefficients": [vec![0_i64; 64]]
        });
        let mut share_witness_polynomial = vec![0_i64; 64];
        share_witness_polynomial[0] = 5;
        let share_component_secret_state = json!({
            "sourceWitnessCoefficients": [share_witness_polynomial]
        });
        let receiver_encryption_component_secret_state = json!({
            "sourceWitnessCoefficients": [vec![0_i64; 256]]
        });
        let component_secret_states = json!({
            "score-and-shamir-field-component": dense_component_secret_state,
            "payload-plaintext-field-component": scalar_component_secret_state.clone(),
            "share-commitment-component": share_component_secret_state,
            "receiver-encryption-component": receiver_encryption_component_secret_state,
        });
        let generation =
            super::generate_ballot_proof_record(super::BallotProofRecordGenerationInput {
                statement: Some(&statement),
                linear_statement: Some(&linear_statement),
                parameter_set: Some(&full_parameter_set),
                proof_encoding: Some(&full_proof_encoding),
                public_randomness_hex: Some(&"00".repeat(32)),
                component_bundle_statement: Some(&component_bundle_statement),
                component_proof_inputs: Some(&component_proof_inputs),
                secret_state: Some(&secret_state),
                prover_randomness_hex: Some(&"07".repeat(32)),
                component_prover_randomness_hexes: Some(&json!({
                    "score-and-shamir-field-component": "07".repeat(32),
                    "payload-plaintext-field-component": "a2".repeat(32),
                    "share-commitment-component": "0c".repeat(32),
                    "receiver-encryption-component": "a4".repeat(32)
                })),
                component_secret_states: Some(&component_secret_states),
            });

        assert_eq!(
            generation["ok"], true,
            "generated ballot proof record should verify: {generation}"
        );
        assert_eq!(generation["verification"]["ok"], true);
        assert_eq!(
            generation["componentProofBundle"]["componentProofs"]
                .as_array()
                .expect("component proofs should be an array")
                .len(),
            super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len()
        );
        assert!(
            generation["componentProofInputs"]
                .as_array()
                .expect("component proof inputs should be an array")
                .iter()
                .all(|component_input| component_input
                    .get("proofBytesHex")
                    .and_then(Value::as_str)
                    .is_some())
        );

        let mut wrong_secret_state = secret_state.clone();
        wrong_secret_state["sourceWitnessCoefficients"][0][0] = json!(1);
        let wrong_generation =
            super::generate_ballot_proof_record(super::BallotProofRecordGenerationInput {
                statement: Some(&statement),
                linear_statement: Some(&linear_statement),
                parameter_set: Some(&full_parameter_set),
                proof_encoding: Some(&full_proof_encoding),
                public_randomness_hex: Some(&"00".repeat(32)),
                component_bundle_statement: Some(&component_bundle_statement),
                component_proof_inputs: Some(&component_proof_inputs),
                secret_state: Some(&wrong_secret_state),
                prover_randomness_hex: Some(&"07".repeat(32)),
                component_prover_randomness_hexes: Some(&json!({
                    "score-and-shamir-field-component": "07".repeat(32),
                    "payload-plaintext-field-component": "a2".repeat(32),
                    "share-commitment-component": "0c".repeat(32),
                    "receiver-encryption-component": "a4".repeat(32)
                })),
                component_secret_states: Some(&component_secret_states),
            });
        assert_eq!(wrong_generation["ok"], false);
        assert_eq!(wrong_generation["unresolvedReason"], "BallotPackageInvalid");
    }

    #[test]
    fn malformed_receiver_key_proof_rejects_before_backend_gate() {
        let verification = super::verify_receiver_key_proof(
            &json!({
                "objectType": "ReceiverKeyProof",
                "objectVersion": 1,
                "proofBackend": "LocalLinearLatticeRelation",
                "receiverKeyProofRoot": "00"
            }),
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["unresolvedReason"], "BallotPackageInvalid");
        assert_eq!(
            verification["refusedObjects"][0]["code"],
            "BallotPackageInvalid"
        );
    }

    fn zero_receiver_key_source_polynomial() -> Vec<u64> {
        vec![0_u64; 256]
    }

    fn zero_receiver_key_witness_polynomial() -> Vec<i64> {
        vec![0_i64; 256]
    }

    fn unit_receiver_key_source_polynomial() -> Vec<u64> {
        let mut polynomial = zero_receiver_key_source_polynomial();
        polynomial[0] = 1;
        polynomial
    }

    fn canonical_receiver_key_witness_polynomial(polynomial: &[i64], modulus: u64) -> Vec<u64> {
        polynomial
            .iter()
            .map(|coefficient| {
                if *coefficient < 0 {
                    modulus - coefficient.unsigned_abs()
                } else {
                    coefficient.unsigned_abs()
                }
            })
            .collect()
    }

    fn receiver_key_prover_preflight_fixture() -> (Value, Value, Value, Value) {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let source_ring =
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
                .expect("source ring should validate");
        let mut witness =
            vec![zero_receiver_key_witness_polynomial(); parameter_set.statement_columns];
        witness[0][0] = 2;
        witness[0][5] = -1;
        witness[1][1] = 1;
        witness[4][0] = -2;
        witness[5][7] = 1;

        let mut statement_matrix =
            vec![
                vec![zero_receiver_key_source_polynomial(); parameter_set.statement_columns];
                parameter_set.statement_rows
            ];
        for (row_index, statement_matrix_row) in statement_matrix
            .iter_mut()
            .enumerate()
            .take(parameter_set.statement_rows)
        {
            statement_matrix_row[row_index] = unit_receiver_key_source_polynomial();
            statement_matrix_row[row_index + 4] = unit_receiver_key_source_polynomial();
        }

        let target_vector = (0..parameter_set.statement_rows)
            .map(|row_index| {
                let secret_polynomial = canonical_receiver_key_witness_polynomial(
                    &witness[row_index],
                    parameter_set.coefficient_modulus,
                );
                let error_polynomial = canonical_receiver_key_witness_polynomial(
                    &witness[row_index + 4],
                    parameter_set.coefficient_modulus,
                );
                let public_key_polynomial = source_ring
                    .add(&secret_polynomial, &error_polynomial)
                    .expect("public key polynomial should add");
                source_ring
                    .neg(&public_key_polynomial)
                    .expect("target polynomial should negate")
            })
            .collect::<Vec<_>>();
        let linear_statement_payload = json!({
            "ceremonyId": "ceremony-receiver-key-prover-preflight",
            "coefficientModulus": "12289",
            "keyMaterialDigest": test_digest("receiver-key-material"),
            "manifestDigest": test_digest("manifest"),
            "objectType": "ReceiverKeyLinearProofStatement",
            "objectVersion": 1,
            "publicMatrixSeedDigest": test_digest("receiver-matrix-seed"),
            "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
            "receiverIdentity": "receiver-1",
            "receiverPublicKeyDigest": test_digest("receiver-public-key"),
            "receiverRosterPosition": 1,
            "recoveryEpoch": 0,
            "relation": "A*w + t = 0",
            "ringDegree": 256,
            "rosterDigest": test_digest("roster"),
            "sourceRing": "Z_q[X]/(X^256 + 1)",
            "statementColumns": 8,
            "statementMatrixCoefficients": statement_matrix,
            "statementMatrixDigest": test_digest("statement-matrix"),
            "statementProfileId": "receiver-key-linear-module-lwe-statement-v1",
            "statementRows": 4,
            "targetCoefficientRepresentation": "centeredSignedSourceModulus",
            "targetVectorCoefficients": target_vector,
            "targetVectorDigest": test_digest("target-vector"),
            "witnessInfinityNormBound": 2,
            "witnessL2BoundSquared": "8192",
            "witnessVectorLayout": [
                "receiver secret polynomial 0",
                "receiver secret polynomial 1",
                "receiver secret polynomial 2",
                "receiver secret polynomial 3",
                "receiver error polynomial 0",
                "receiver error polynomial 1",
                "receiver error polynomial 2",
                "receiver error polynomial 3"
            ]
        });
        let linear_statement_digest =
            super::derive_receiver_key_linear_statement_digest(&linear_statement_payload)
                .expect("linear statement digest should derive");
        let mut linear_statement = linear_statement_payload;
        linear_statement
            .as_object_mut()
            .expect("linear statement should be an object")
            .insert(
                "statementDigest".to_string(),
                json!(linear_statement_digest),
            );
        let secret_state = json!({
            "secretVector": witness[..4].to_vec(),
            "errorVector": witness[4..].to_vec()
        });

        (
            linear_statement,
            json!(parameter_set),
            json!(proof_encoding),
            secret_state,
        )
    }

    #[test]
    fn receiver_key_proof_generation_preflight_checks_source_and_proof_ring_witness() {
        let (linear_statement, parameter_set, proof_encoding, secret_state) =
            receiver_key_prover_preflight_fixture();
        let preparation = super::prepare_receiver_key_proof_generation(
            Some(&linear_statement),
            Some(&parameter_set),
            Some(&proof_encoding),
            Some(&"00".repeat(32)),
            Some(&secret_state),
            Some(&"09".repeat(32)),
        );

        assert_eq!(preparation["ok"], true);
        assert_eq!(
            preparation["operation"],
            "prepareReceiverKeyProofGeneration"
        );
        assert_eq!(preparation["generatedProofBytes"], false);
        assert_eq!(preparation["summary"]["relationWitnessPolynomialCount"], 32);
        assert_eq!(preparation["summary"]["shortWitnessPolynomialCount"], 33);
        assert_eq!(
            preparation["summary"]["preparedShortWitnessPolynomialCount"],
            33
        );
        assert_eq!(preparation["summary"]["witnessL2Squared"], "11");
        assert_eq!(preparation["summary"]["normSlack"], "8181");
        assert!(
            preparation["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("ReceiverKeyProofRingWitnessPrepared"))
        );
        assert!(
            preparation["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("ReceiverKeyAbdlopCommitmentPrepared"))
        );
        assert_eq!(
            preparation["summary"]["abdlopCommitment"]["compressedCommitmentPolynomialCount"],
            json!(19)
        );
        assert_eq!(
            preparation["summary"]["abdlopCommitment"]["openingRandomnessPolynomialCount"],
            json!(55)
        );
        assert_eq!(
            preparation["summary"]["abdlopCommitment"]["abdlopCommitmentHash"]
                .as_str()
                .expect("commitment hash should be present")
                .len(),
            64
        );

        let mut wrong_secret_state = secret_state;
        wrong_secret_state["secretVector"][0][0] = json!(3);
        let rejection = super::prepare_receiver_key_proof_generation(
            Some(&linear_statement),
            Some(&parameter_set),
            Some(&proof_encoding),
            Some(&"00".repeat(32)),
            Some(&wrong_secret_state),
            Some(&"09".repeat(32)),
        );

        assert_eq!(rejection["ok"], false);
        assert_eq!(rejection["unresolvedReason"], json!("BallotPackageInvalid"));
        assert!(
            rejection["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("source witness")
        );
    }

    #[test]
    fn proof_byte_bearing_receiver_key_record_verifies_against_linear_backend() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
        ))
        .expect("receiver-key linear vector file should parse");
        let cases = vectors["cases"]
            .as_array()
            .expect("receiver-key linear vector file should contain cases");
        let valid_case = cases
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-receiver-key-linear-proof")
            .expect("valid receiver-key linear vector should exist");
        let mutated_target_case = cases
            .iter()
            .find(|vector_case| vector_case["caseName"] == "mutated-receiver-key-target-vector")
            .expect("mutated receiver-key target vector should exist");
        let proof_bytes_hex = valid_case["proofHex"]
            .as_str()
            .expect("valid vector proofHex should be a string");
        let public_randomness_hex = valid_case["publicRandomnessHex"]
            .as_str()
            .expect("valid vector publicRandomnessHex should be a string");
        let proof_size_bytes = proof_bytes_hex.len() / 2;
        let test_digest = |label: &str| {
            super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "label": label,
                    "purpose": "receiver-key-proof-record-native-test"
                }),
            )
            .expect("test digest should derive")
        };
        let create_linear_statement = |target_vector_coefficients: Value| {
            let statement_payload = json!({
                "ceremonyId": "ceremony-receiver-key-proof-record",
                "coefficientModulus": "12289",
                "keyMaterialDigest": test_digest("receiver-key-material"),
                "manifestDigest": test_digest("manifest"),
                "objectType": "ReceiverKeyLinearProofStatement",
                "objectVersion": 1,
                "publicMatrixSeedDigest": test_digest("receiver-matrix-seed"),
                "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
                "receiverIdentity": "receiver-1",
                "receiverPublicKeyDigest": test_digest("receiver-public-key"),
                "receiverRosterPosition": 1,
                "recoveryEpoch": 0,
                "relation": "A*w + t = 0",
                "ringDegree": 256,
                "rosterDigest": test_digest("roster"),
                "sourceRing": "Z_q[X]/(X^256 + 1)",
                "statementColumns": 8,
                "statementMatrixCoefficients": valid_case["statementMatrixCoefficients"].clone(),
                "statementMatrixDigest": test_digest("statement-matrix"),
                "statementProfileId": "receiver-key-linear-module-lwe-statement-v1",
                "statementRows": 4,
                "targetCoefficientRepresentation": "centeredSignedSourceModulus",
                "targetVectorCoefficients": target_vector_coefficients,
                "targetVectorDigest": test_digest("target-vector"),
                "witnessInfinityNormBound": 2,
                "witnessL2BoundSquared": "8192",
                "witnessVectorLayout": [
                    "receiver secret polynomial 0",
                    "receiver secret polynomial 1",
                    "receiver secret polynomial 2",
                    "receiver secret polynomial 3",
                    "receiver error polynomial 0",
                    "receiver error polynomial 1",
                    "receiver error polynomial 2",
                    "receiver error polynomial 3"
                ]
            });
            let statement_digest = super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "payload": statement_payload,
                    "purpose": "receiver-key-linear-proof-statement-v1"
                }),
            )
            .expect("linear statement digest should derive");
            let mut statement = statement_payload;
            statement
                .as_object_mut()
                .expect("linear statement should be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));

            statement
        };
        let create_receiver_key_proof =
            |linear_statement: &Value, parameter_set: &Value, proof_encoding: &Value| {
                let proof_bytes_digest = super::derive_digest(
                    "ProofBytesDigest",
                    &json!({
                        "objectType": "ProofBytes",
                        "objectVersion": 1,
                        "proofBytesHex": proof_bytes_hex,
                        "proofSizeBytes": proof_size_bytes
                    }),
                )
                .expect("proof bytes digest should derive");
                let proof_encoding_profile_digest =
                    super::derive_receiver_key_proof_encoding_profile_digest(proof_encoding)
                        .expect("proof encoding profile digest should derive");
                let proof_parameter_set_digest =
                    super::derive_receiver_key_proof_parameter_set_digest(parameter_set)
                        .expect("proof parameter set digest should derive");
                let public_randomness_digest =
                    super::derive_receiver_key_public_randomness_digest(public_randomness_hex)
                        .expect("public randomness digest should derive");
                let linear_statement_digest = linear_statement["statementDigest"]
                    .as_str()
                    .expect("linear statement digest should be a string");
                let proof_root = super::derive_digest(
                    "ReceiverKeyProofRoot",
                    &json!({
                        "linearStatementDigest": linear_statement_digest,
                        "proofBytesDigest": proof_bytes_digest,
                        "proofEncodingProfileDigest": proof_encoding_profile_digest,
                        "proofParameterSetDigest": proof_parameter_set_digest,
                        "publicRandomnessDigest": public_randomness_digest,
                        "purpose": "receiver-key-linear-proof-record-root-v1"
                    }),
                )
                .expect("proof root should derive");
                let proof_payload = json!({
                    "backendStatementDigest": test_digest("backend-statement"),
                    "ceremonyId": "ceremony-receiver-key-proof-record",
                    "linearStatementDigest": linear_statement_digest,
                    "manifestDigest": test_digest("manifest"),
                    "objectType": "ReceiverKeyProof",
                    "objectVersion": 1,
                    "proofBackend": "LocalLinearLatticeRelation",
                    "proofBytesDigest": proof_bytes_digest,
                    "proofEncodingProfileDigest": proof_encoding_profile_digest,
                    "proofParameterSetDigest": proof_parameter_set_digest,
                    "proofRoot": proof_root,
                    "proofSizeBytes": proof_size_bytes,
                    "publicRandomnessDigest": public_randomness_digest,
                    "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
                    "receiverIdentity": "receiver-1",
                    "receiverPublicKeyDigest": test_digest("receiver-public-key"),
                    "receiverRosterPosition": 1,
                    "recoveryEpoch": 0,
                    "rosterDigest": test_digest("roster")
                });
                let receiver_key_proof_root =
                    super::derive_digest("ReceiverKeyProofRoot", &proof_payload)
                        .expect("receiver key proof root should derive");
                let mut receiver_key_proof = proof_payload;
                receiver_key_proof
                    .as_object_mut()
                    .expect("receiver key proof should be an object")
                    .insert(
                        "receiverKeyProofRoot".to_string(),
                        json!(receiver_key_proof_root),
                    );

                receiver_key_proof
            };

        let valid_linear_statement =
            create_linear_statement(valid_case["targetVectorCoefficients"].clone());
        let valid_receiver_key_proof = create_receiver_key_proof(
            &valid_linear_statement,
            &valid_case["parameterSet"],
            &valid_case["proofEncoding"],
        );
        let valid_verification = super::verify_receiver_key_proof(
            &valid_receiver_key_proof,
            Some(&valid_linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(&valid_case["parameterSet"]),
            Some(&valid_case["proofEncoding"]),
        );

        assert_eq!(valid_verification["ok"], true);
        assert_eq!(valid_verification["unresolvedReason"], Value::Null);
        assert!(
            valid_verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("ReceiverKeyLinearProofVerified"))
        );

        let mutated_linear_statement =
            create_linear_statement(mutated_target_case["targetVectorCoefficients"].clone());
        let mutated_receiver_key_proof = create_receiver_key_proof(
            &mutated_linear_statement,
            &valid_case["parameterSet"],
            &valid_case["proofEncoding"],
        );
        let mutated_verification = super::verify_receiver_key_proof(
            &mutated_receiver_key_proof,
            Some(&mutated_linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(&valid_case["parameterSet"]),
            Some(&valid_case["proofEncoding"]),
        );

        assert_eq!(mutated_verification["ok"], false);
        assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");

        let mut wrong_parameter_set = valid_case["parameterSet"].clone();
        wrong_parameter_set
            .as_object_mut()
            .expect("parameter set should be an object")
            .insert(
                "profileId".to_string(),
                json!("receiver-key-linear-module-lwe-wrong-profile"),
            );
        let wrong_parameter_verification = super::verify_receiver_key_proof(
            &valid_receiver_key_proof,
            Some(&valid_linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(&wrong_parameter_set),
            Some(&valid_case["proofEncoding"]),
        );

        assert_eq!(wrong_parameter_verification["ok"], false);
        assert_eq!(
            wrong_parameter_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );

        let mut size_unbound_parameter_set = valid_case["parameterSet"].clone();
        size_unbound_parameter_set
            .as_object_mut()
            .expect("parameter set should be an object")
            .insert(
                "expectedProofSizeBytes".to_string(),
                json!(proof_size_bytes + 1),
            );
        let size_unbound_receiver_key_proof = create_receiver_key_proof(
            &valid_linear_statement,
            &size_unbound_parameter_set,
            &valid_case["proofEncoding"],
        );
        let size_unbound_parameter_verification = super::verify_receiver_key_proof(
            &size_unbound_receiver_key_proof,
            Some(&valid_linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(&size_unbound_parameter_set),
            Some(&valid_case["proofEncoding"]),
        );

        assert_eq!(size_unbound_parameter_verification["ok"], false);
        assert_eq!(
            size_unbound_parameter_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            size_unbound_parameter_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("byte length")
        );

        let mut size_unbound_proof_encoding = valid_case["proofEncoding"].clone();
        size_unbound_proof_encoding
            .as_object_mut()
            .expect("proof encoding should be an object")
            .insert(
                "expectedProofSizeBytes".to_string(),
                json!(proof_size_bytes + 1),
            );
        let size_unbound_encoding_receiver_key_proof = create_receiver_key_proof(
            &valid_linear_statement,
            &valid_case["parameterSet"],
            &size_unbound_proof_encoding,
        );
        let size_unbound_encoding_verification = super::verify_receiver_key_proof(
            &size_unbound_encoding_receiver_key_proof,
            Some(&valid_linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(&valid_case["parameterSet"]),
            Some(&size_unbound_proof_encoding),
        );

        assert_eq!(size_unbound_encoding_verification["ok"], false);
        assert_eq!(
            size_unbound_encoding_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            size_unbound_encoding_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("byte length")
        );
    }

    #[test]
    fn proof_byte_bearing_ballot_record_rejects_without_full_relation_coverage() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("linear proof vector file should parse");
        let cases = vectors["cases"]
            .as_array()
            .expect("linear proof vector file should contain cases");
        let valid_case = cases
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-small-linear-proof")
            .expect("valid linear vector should exist");
        let mutated_target_case = cases
            .iter()
            .find(|vector_case| vector_case["caseName"] == "mutated-target-vector")
            .expect("mutated target vector should exist");
        let proof_bytes_hex = valid_case["proofHex"]
            .as_str()
            .expect("valid vector proofHex should be a string");
        let public_randomness_hex = valid_case["publicRandomnessHex"]
            .as_str()
            .expect("valid vector publicRandomnessHex should be a string");
        let proof_size_bytes = proof_bytes_hex.len() / 2;
        let test_digest = |label: &str| {
            super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "label": label,
                    "purpose": "ballot-proof-record-native-test"
                }),
            )
            .expect("test digest should derive")
        };
        let create_statement = || {
            let statement_payload = json!({
                "actionContextDigest": test_digest("action-context"),
                "aggregateInputEncodingProfileDigest": test_digest("aggregate-input-encoding-profile"),
                "ballotPackageDigest": test_digest("ballot-package"),
                "ballotProofProfileDigest": test_digest("ballot-proof-profile"),
                "ballotScoreEncodingProfileDigest": test_digest("ballot-score-encoding-profile"),
                "ballotShareLayoutProfileDigest": test_digest("ballot-share-layout-profile"),
                "ceremonyId": "ceremony-ballot-proof-record",
                "challengeDomainDigest": test_digest("challenge-domain"),
                "duplicateBallotPolicyDigest": test_digest("duplicate-policy"),
                "encodedAggregateLayoutDigest": test_digest("encoded-aggregate-layout"),
                "encodedShareVectorLayoutDigest": test_digest("encoded-share-vector-layout"),
                "manifestDigest": test_digest("manifest"),
                "objectType": "BallotProofStatement",
                "objectVersion": 1,
                "optionCount": 20,
                "pollSpecDigest": test_digest("poll-spec"),
                "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
                "receiverKeyProofRoot": test_digest("receiver-key-proof-root"),
                "receiverKeyRoot": test_digest("receiver-key-root"),
                "receiverPayloads": [
                    {
                        "receiverIdentity": "receiver-1",
                        "receiverPayloadCiphertextRoot": test_digest("receiver-ciphertext-1"),
                        "receiverPayloadDigest": test_digest("receiver-payload-1"),
                        "receiverRosterPosition": 1
                    }
                ],
                "receiverPublicKeys": [
                    {
                        "receiverIdentity": "receiver-1",
                        "receiverPublicKeyDigest": test_digest("receiver-public-key-1"),
                        "receiverRosterPosition": 1
                    }
                ],
                "rosterDigest": test_digest("roster"),
                "rosterExternalAcceptanceDigest": test_digest("external-acceptance"),
                "scoreDomainDigest": test_digest("score-domain"),
                "scoreMembershipProfileDigest": test_digest("score-membership-profile"),
                "shareCommitmentMessageBoundCertDigest": test_digest("share-commitment-bound-cert"),
                "shareCommitmentProfileDigest": test_digest("share-commitment-profile"),
                "shareCommitments": [
                    {
                        "receiverIdentity": "receiver-1",
                        "receiverRosterPosition": 1,
                        "shareCommitmentDigest": test_digest("share-commitment-1")
                    }
                ],
                "shareVectorWidth": 220,
                "thresholdProfileDigest": test_digest("threshold-profile"),
                "tiePolicyDigest": test_digest("tie-policy"),
                "topOptionCount": 3,
                "voterIdentityDigest": test_digest("voter-1"),
                "voterRosterPosition": 1,
                "voterSigningKeyDigest": test_digest("voter-signing-key")
            });
            let statement_digest =
                super::derive_digest("BallotProofStatementDigest", &statement_payload)
                    .expect("statement digest should derive");
            let mut statement = statement_payload;
            statement
                .as_object_mut()
                .expect("statement should be an object")
                .insert(
                    "ballotProofStatementDigest".to_string(),
                    json!(statement_digest),
                );

            statement
        };
        let create_linear_statement =
            |statement: &Value, parameter_set: &Value, target_vector_coefficients: Value| {
                let backend_statement_digest = test_digest("backend-statement");
                let relation_statement_digest = test_digest("relation-statement");
                let statement_matrix_digest = test_digest("statement-matrix");
                let target_vector_digest = test_digest("target-vector");
                let linear_statement_payload = json!({
                    "backendStatementDigest": backend_statement_digest,
                    "ballotProofStatementDigest": statement["ballotProofStatementDigest"],
                    "coefficientModulus": "4294962689",
                    "objectType": "BallotProofLinearProofStatement",
                    "objectVersion": 1,
                    "parameterProfileId": parameter_set["profileId"],
                    "relation": "A*w + t = 0",
                    "relationStatementDigest": relation_statement_digest,
                    "ringDegree": 256,
                    "statementColumns": 8,
                    "statementMatrixCoefficients": valid_case["statementMatrixCoefficients"].clone(),
                    "statementMatrixDigest": statement_matrix_digest,
                    "statementRows": 4,
                    "targetCoefficientRepresentation": "centeredSignedSourceModulus",
                    "targetVectorCoefficients": target_vector_coefficients,
                    "targetVectorDigest": target_vector_digest,
                    "witnessL2BoundSquared": "2048"
                });
                let statement_digest = super::derive_digest(
                    "ChallengeDomainDigest",
                    &json!({
                        "payload": linear_statement_payload,
                        "purpose": "ballot-proof-linear-proof-statement-v1"
                    }),
                )
                .expect("linear statement digest should derive");
                let mut linear_statement = linear_statement_payload;
                linear_statement
                    .as_object_mut()
                    .expect("linear statement should be an object")
                    .insert("statementDigest".to_string(), json!(statement_digest));

                linear_statement
            };
        let mut valid_parameter_set = valid_case["parameterSet"].clone();
        valid_parameter_set
            .as_object_mut()
            .expect("parameter set should be an object")
            .insert(
                "expectedProofSizeBytes".to_string(),
                json!(proof_size_bytes),
            );
        let mut valid_proof_encoding = valid_case["proofEncoding"].clone();
        valid_proof_encoding
            .as_object_mut()
            .expect("proof encoding should be an object")
            .insert(
                "expectedProofSizeBytes".to_string(),
                json!(proof_size_bytes),
            );
        let create_ballot_proof = |statement: &Value,
                                   linear_statement: &Value,
                                   parameter_set: &Value,
                                   proof_encoding: &Value| {
            let proof_bytes_digest = super::derive_digest(
                "ProofBytesDigest",
                &json!({
                    "objectType": "ProofBytes",
                    "objectVersion": 1,
                    "proofBytesHex": proof_bytes_hex,
                    "proofSizeBytes": proof_size_bytes
                }),
            )
            .expect("proof bytes digest should derive");
            let proof_encoding_profile_digest =
                super::derive_ballot_proof_encoding_profile_digest(proof_encoding)
                    .expect("proof encoding profile digest should derive");
            let proof_parameter_set_digest =
                super::derive_ballot_proof_parameter_set_digest(parameter_set)
                    .expect("proof parameter set digest should derive");
            let public_randomness_digest =
                super::derive_ballot_proof_public_randomness_digest(public_randomness_hex)
                    .expect("public randomness digest should derive");
            let proof_root = super::derive_digest(
                "BallotProofRecordDigest",
                &json!({
                    "linearStatementDigest": linear_statement["statementDigest"],
                    "proofBytesDigest": proof_bytes_digest,
                    "proofEncodingProfileDigest": proof_encoding_profile_digest,
                    "proofParameterSetDigest": proof_parameter_set_digest,
                    "publicRandomnessDigest": public_randomness_digest,
                    "purpose": "ballot-proof-linear-proof-record-root-v1"
                }),
            )
            .expect("proof root should derive");
            let proof_payload = json!({
                "backendStatementDigest": linear_statement["backendStatementDigest"],
                "ballotProofProfileDigest": statement["ballotProofProfileDigest"],
                "ballotProofStatementDigest": statement["ballotProofStatementDigest"],
                "challengeDigest": "",
                "linearStatementDigest": linear_statement["statementDigest"],
                "objectType": "BallotProofRecord",
                "objectVersion": 1,
                "proofBackend": "LocalLinearLatticeRelation",
                "proofBytesDigest": proof_bytes_digest,
                "proofEncodingProfileDigest": proof_encoding_profile_digest,
                "proofParameterSetDigest": proof_parameter_set_digest,
                "proofRoot": proof_root,
                "proofSizeBytes": proof_size_bytes,
                "publicRandomnessDigest": public_randomness_digest,
                "relationStatementDigest": linear_statement["relationStatementDigest"],
                "statementMatrixDigest": linear_statement["statementMatrixDigest"],
                "targetVectorDigest": linear_statement["targetVectorDigest"]
            });
            let challenge_digest =
                super::derive_ballot_proof_challenge_digest(statement, &proof_payload)
                    .expect("challenge digest should derive");
            let mut proof_payload_with_challenge = proof_payload;
            proof_payload_with_challenge
                .as_object_mut()
                .expect("proof payload should be an object")
                .insert("challengeDigest".to_string(), json!(challenge_digest));
            let ballot_proof_record_digest =
                super::derive_digest("BallotProofRecordDigest", &proof_payload_with_challenge)
                    .expect("ballot proof record digest should derive");
            let mut ballot_proof = proof_payload_with_challenge;
            ballot_proof
                .as_object_mut()
                .expect("ballot proof should be an object")
                .insert(
                    "ballotProofRecordDigest".to_string(),
                    json!(ballot_proof_record_digest),
                );

            ballot_proof
        };

        let statement = create_statement();
        let valid_linear_statement = create_linear_statement(
            &statement,
            &valid_parameter_set,
            valid_case["targetVectorCoefficients"].clone(),
        );
        let valid_ballot_proof = create_ballot_proof(
            &statement,
            &valid_linear_statement,
            &valid_parameter_set,
            &valid_proof_encoding,
        );
        let valid_verification = super::verify_ballot_proof(
            &statement,
            &valid_ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts {
                proof_bytes_hex: Some(proof_bytes_hex),
                linear_statement: Some(&valid_linear_statement),
                public_randomness_hex: Some(public_randomness_hex),
                parameter_set: Some(&valid_parameter_set),
                proof_encoding: Some(&valid_proof_encoding),
                ..BallotProofBackendInputParts::default()
            }),
        );

        assert_eq!(valid_verification["ok"], false);
        assert_eq!(
            valid_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            valid_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("full encoded-score ballot relation"),
            "{valid_verification}"
        );
        assert!(
            !valid_verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("BallotProofLinearProofVerified"))
        );

        let mut size_unbound_parameter_set = valid_parameter_set.clone();
        size_unbound_parameter_set
            .as_object_mut()
            .expect("parameter set should be an object")
            .insert(
                "expectedProofSizeBytes".to_string(),
                json!(proof_size_bytes + 1),
            );
        let size_unbound_parameter_ballot_proof = create_ballot_proof(
            &statement,
            &valid_linear_statement,
            &size_unbound_parameter_set,
            &valid_proof_encoding,
        );
        let size_unbound_parameter_verification = super::verify_ballot_proof(
            &statement,
            &size_unbound_parameter_ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts {
                proof_bytes_hex: Some(proof_bytes_hex),
                linear_statement: Some(&valid_linear_statement),
                public_randomness_hex: Some(public_randomness_hex),
                parameter_set: Some(&size_unbound_parameter_set),
                proof_encoding: Some(&valid_proof_encoding),
                ..BallotProofBackendInputParts::default()
            }),
        );

        assert_eq!(size_unbound_parameter_verification["ok"], false);
        assert_eq!(
            size_unbound_parameter_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            size_unbound_parameter_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("byte length")
        );

        let mut size_unbound_proof_encoding = valid_proof_encoding.clone();
        size_unbound_proof_encoding
            .as_object_mut()
            .expect("proof encoding should be an object")
            .insert(
                "expectedProofSizeBytes".to_string(),
                json!(proof_size_bytes + 1),
            );
        let size_unbound_encoding_ballot_proof = create_ballot_proof(
            &statement,
            &valid_linear_statement,
            &valid_parameter_set,
            &size_unbound_proof_encoding,
        );
        let size_unbound_encoding_verification = super::verify_ballot_proof(
            &statement,
            &size_unbound_encoding_ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts {
                proof_bytes_hex: Some(proof_bytes_hex),
                linear_statement: Some(&valid_linear_statement),
                public_randomness_hex: Some(public_randomness_hex),
                parameter_set: Some(&valid_parameter_set),
                proof_encoding: Some(&size_unbound_proof_encoding),
                ..BallotProofBackendInputParts::default()
            }),
        );

        assert_eq!(size_unbound_encoding_verification["ok"], false);
        assert_eq!(
            size_unbound_encoding_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            size_unbound_encoding_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("byte length")
        );

        let mutated_linear_statement = create_linear_statement(
            &statement,
            &valid_parameter_set,
            mutated_target_case["targetVectorCoefficients"].clone(),
        );
        let mutated_ballot_proof = create_ballot_proof(
            &statement,
            &mutated_linear_statement,
            &valid_parameter_set,
            &valid_proof_encoding,
        );
        let mutated_verification = super::verify_ballot_proof(
            &statement,
            &mutated_ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts {
                proof_bytes_hex: Some(proof_bytes_hex),
                linear_statement: Some(&mutated_linear_statement),
                public_randomness_hex: Some(public_randomness_hex),
                parameter_set: Some(&valid_parameter_set),
                proof_encoding: Some(&valid_proof_encoding),
                ..BallotProofBackendInputParts::default()
            }),
        );

        assert_eq!(mutated_verification["ok"], false);
        assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");
    }

    #[test]
    fn encoded_score_field_ballot_record_rejects_without_full_relation_coverage() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
        ))
        .expect("encoded-score field vector file should parse");
        let cases = vectors["cases"]
            .as_array()
            .expect("encoded-score field vector file should contain cases");
        let valid_compact_case = cases
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-encoded-score-field-linear-proof")
            .expect("valid encoded-score field vector should exist");
        let mutated_target_compact_case = cases
            .iter()
            .find(|vector_case| {
                vector_case["caseName"] == "mutated-encoded-score-field-target-vector"
            })
            .expect("mutated encoded-score target vector should exist");
        let valid_case = expand_encoded_score_field_vector_case(&vectors, valid_compact_case);
        let mutated_target_case =
            expand_encoded_score_field_vector_case(&vectors, mutated_target_compact_case);
        let proof_bytes_hex = valid_case["proofHex"]
            .as_str()
            .expect("valid vector proofHex should be a string");
        let public_randomness_hex = valid_case["publicRandomnessHex"]
            .as_str()
            .expect("valid vector publicRandomnessHex should be a string");
        let proof_size_bytes = proof_bytes_hex.len() / 2;
        let test_digest = |label: &str| {
            super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "label": label,
                    "purpose": "encoded-score-field-ballot-proof-record-native-test"
                }),
            )
            .expect("test digest should derive")
        };
        let create_statement = || {
            let statement_payload = json!({
                "actionContextDigest": test_digest("action-context"),
                "aggregateInputEncodingProfileDigest": test_digest("aggregate-input-encoding-profile"),
                "ballotPackageDigest": test_digest("ballot-package"),
                "ballotProofProfileDigest": test_digest("ballot-proof-profile"),
                "ballotScoreEncodingProfileDigest": test_digest("ballot-score-encoding-profile"),
                "ballotShareLayoutProfileDigest": test_digest("ballot-share-layout-profile"),
                "ceremonyId": "ceremony-encoded-score-field-ballot-proof-record",
                "challengeDomainDigest": test_digest("challenge-domain"),
                "duplicateBallotPolicyDigest": test_digest("duplicate-policy"),
                "encodedAggregateLayoutDigest": test_digest("encoded-aggregate-layout"),
                "encodedShareVectorLayoutDigest": test_digest("encoded-share-vector-layout"),
                "manifestDigest": test_digest("manifest"),
                "objectType": "BallotProofStatement",
                "objectVersion": 1,
                "optionCount": 20,
                "pollSpecDigest": test_digest("poll-spec"),
                "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
                "receiverKeyProofRoot": test_digest("receiver-key-proof-root"),
                "receiverKeyRoot": test_digest("receiver-key-root"),
                "receiverPayloads": [
                    {
                        "receiverIdentity": "receiver-1",
                        "receiverPayloadCiphertextRoot": test_digest("receiver-ciphertext-1"),
                        "receiverPayloadDigest": test_digest("receiver-payload-1"),
                        "receiverRosterPosition": 1
                    }
                ],
                "receiverPublicKeys": [
                    {
                        "receiverIdentity": "receiver-1",
                        "receiverPublicKeyDigest": test_digest("receiver-public-key-1"),
                        "receiverRosterPosition": 1
                    }
                ],
                "rosterDigest": test_digest("roster"),
                "rosterExternalAcceptanceDigest": test_digest("external-acceptance"),
                "scoreDomainDigest": test_digest("score-domain"),
                "scoreMembershipProfileDigest": test_digest("score-membership-profile"),
                "shareCommitmentMessageBoundCertDigest": test_digest("share-commitment-bound-cert"),
                "shareCommitmentProfileDigest": test_digest("share-commitment-profile"),
                "shareCommitments": [
                    {
                        "receiverIdentity": "receiver-1",
                        "receiverRosterPosition": 1,
                        "shareCommitmentDigest": test_digest("share-commitment-1")
                    }
                ],
                "shareVectorWidth": 220,
                "thresholdProfileDigest": test_digest("threshold-profile"),
                "tiePolicyDigest": test_digest("tie-policy"),
                "topOptionCount": 3,
                "voterIdentityDigest": test_digest("voter-1"),
                "voterRosterPosition": 1,
                "voterSigningKeyDigest": test_digest("voter-signing-key")
            });
            let statement_digest =
                super::derive_digest("BallotProofStatementDigest", &statement_payload)
                    .expect("statement digest should derive");
            let mut statement = statement_payload;
            statement
                .as_object_mut()
                .expect("statement should be an object")
                .insert(
                    "ballotProofStatementDigest".to_string(),
                    json!(statement_digest),
                );

            statement
        };
        let create_linear_statement = |statement: &Value, vector_case: &Value| {
            let mut linear_statement = vectors["linearStatement"].clone();
            let linear_statement_object = linear_statement
                .as_object_mut()
                .expect("linear statement should be an object");
            linear_statement_object.remove("statementDigest");
            linear_statement_object.insert(
                "ballotProofStatementDigest".to_string(),
                statement["ballotProofStatementDigest"].clone(),
            );
            linear_statement_object.insert(
                "statementMatrixCoefficients".to_string(),
                vector_case["statementMatrixCoefficients"].clone(),
            );
            linear_statement_object.insert(
                "targetVectorCoefficients".to_string(),
                vector_case["targetVectorCoefficients"].clone(),
            );
            linear_statement_object.insert(
                "targetCoefficientRepresentation".to_string(),
                vector_case["targetCoefficientRepresentation"].clone(),
            );
            linear_statement_object.insert(
                "statementMatrixDigest".to_string(),
                json!(
                    super::derive_digest(
                        "ChallengeDomainDigest",
                        &json!({
                            "purpose": "ballot-proof-linear-statement-matrix-v1",
                            "statementMatrixCoefficients": vector_case["statementMatrixCoefficients"]
                        }),
                    )
                    .expect("statement matrix digest should derive")
                ),
            );
            linear_statement_object.insert(
                "targetVectorDigest".to_string(),
                json!(
                    super::derive_digest(
                        "ChallengeDomainDigest",
                        &json!({
                            "purpose": "ballot-proof-linear-target-vector-v1",
                            "targetVectorCoefficients": vector_case["targetVectorCoefficients"]
                        }),
                    )
                    .expect("target vector digest should derive")
                ),
            );
            let statement_digest = super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "payload": linear_statement,
                    "purpose": "ballot-proof-linear-proof-statement-v1"
                }),
            )
            .expect("linear statement digest should derive");
            linear_statement
                .as_object_mut()
                .expect("linear statement should still be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));

            linear_statement
        };
        let create_ballot_proof = |statement: &Value, linear_statement: &Value| {
            let proof_bytes_digest = super::derive_digest(
                "ProofBytesDigest",
                &json!({
                    "objectType": "ProofBytes",
                    "objectVersion": 1,
                    "proofBytesHex": proof_bytes_hex,
                    "proofSizeBytes": proof_size_bytes
                }),
            )
            .expect("proof bytes digest should derive");
            let proof_encoding_profile_digest =
                super::derive_ballot_proof_encoding_profile_digest(&valid_case["proofEncoding"])
                    .expect("proof encoding profile digest should derive");
            let proof_parameter_set_digest =
                super::derive_ballot_proof_parameter_set_digest(&valid_case["parameterSet"])
                    .expect("proof parameter set digest should derive");
            let public_randomness_digest =
                super::derive_ballot_proof_public_randomness_digest(public_randomness_hex)
                    .expect("public randomness digest should derive");
            let proof_root = super::derive_digest(
                "BallotProofRecordDigest",
                &json!({
                    "linearStatementDigest": linear_statement["statementDigest"],
                    "proofBytesDigest": proof_bytes_digest,
                    "proofEncodingProfileDigest": proof_encoding_profile_digest,
                    "proofParameterSetDigest": proof_parameter_set_digest,
                    "publicRandomnessDigest": public_randomness_digest,
                    "purpose": "ballot-proof-linear-proof-record-root-v1"
                }),
            )
            .expect("proof root should derive");
            let proof_payload = json!({
                "backendStatementDigest": linear_statement["backendStatementDigest"],
                "ballotProofProfileDigest": statement["ballotProofProfileDigest"],
                "ballotProofStatementDigest": statement["ballotProofStatementDigest"],
                "challengeDigest": "",
                "linearStatementDigest": linear_statement["statementDigest"],
                "objectType": "BallotProofRecord",
                "objectVersion": 1,
                "proofBackend": "LocalLinearLatticeRelation",
                "proofBytesDigest": proof_bytes_digest,
                "proofEncodingProfileDigest": proof_encoding_profile_digest,
                "proofParameterSetDigest": proof_parameter_set_digest,
                "proofRoot": proof_root,
                "proofSizeBytes": proof_size_bytes,
                "publicRandomnessDigest": public_randomness_digest,
                "relationStatementDigest": linear_statement["relationStatementDigest"],
                "statementMatrixDigest": linear_statement["statementMatrixDigest"],
                "targetVectorDigest": linear_statement["targetVectorDigest"]
            });
            let challenge_digest =
                super::derive_ballot_proof_challenge_digest(statement, &proof_payload)
                    .expect("challenge digest should derive");
            let mut proof_payload_with_challenge = proof_payload;
            proof_payload_with_challenge
                .as_object_mut()
                .expect("proof payload should be an object")
                .insert("challengeDigest".to_string(), json!(challenge_digest));
            let ballot_proof_record_digest =
                super::derive_digest("BallotProofRecordDigest", &proof_payload_with_challenge)
                    .expect("ballot proof record digest should derive");
            let mut ballot_proof = proof_payload_with_challenge;
            ballot_proof
                .as_object_mut()
                .expect("ballot proof should be an object")
                .insert(
                    "ballotProofRecordDigest".to_string(),
                    json!(ballot_proof_record_digest),
                );

            ballot_proof
        };

        let statement = create_statement();
        let valid_linear_statement = create_linear_statement(&statement, &valid_case);
        let valid_ballot_proof = create_ballot_proof(&statement, &valid_linear_statement);
        let valid_verification = super::verify_ballot_proof(
            &statement,
            &valid_ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts {
                proof_bytes_hex: Some(proof_bytes_hex),
                linear_statement: Some(&valid_linear_statement),
                public_randomness_hex: Some(public_randomness_hex),
                parameter_set: Some(&valid_case["parameterSet"]),
                proof_encoding: Some(&valid_case["proofEncoding"]),
                ..BallotProofBackendInputParts::default()
            }),
        );

        assert_eq!(
            valid_verification["ok"], false,
            "encoded-score field-only ballot proof must not verify as full coverage: {valid_verification}"
        );
        assert_eq!(
            valid_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            valid_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("full encoded-score ballot relation")
        );
        assert!(
            !valid_verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("BallotProofLinearProofVerified"))
        );

        let mut relabeled_linear_statement = valid_linear_statement.clone();
        {
            let relabeled_object = relabeled_linear_statement
                .as_object_mut()
                .expect("relabeled statement should be an object");
            relabeled_object.remove("statementDigest");
            relabeled_object.insert(
                "projectionCoverage".to_string(),
                json!(super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE),
            );
        }
        let relabeled_statement_digest = super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "payload": relabeled_linear_statement,
                "purpose": "ballot-proof-linear-proof-statement-v1"
            }),
        )
        .expect("relabeled linear statement digest should derive");
        relabeled_linear_statement
            .as_object_mut()
            .expect("relabeled statement should still be an object")
            .insert(
                "statementDigest".to_string(),
                json!(relabeled_statement_digest),
            );
        let relabeled_ballot_proof = create_ballot_proof(&statement, &relabeled_linear_statement);
        let relabeled_verification = super::verify_ballot_proof(
            &statement,
            &relabeled_ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts {
                proof_bytes_hex: Some(proof_bytes_hex),
                linear_statement: Some(&relabeled_linear_statement),
                public_randomness_hex: Some(public_randomness_hex),
                parameter_set: Some(&valid_case["parameterSet"]),
                proof_encoding: Some(&valid_case["proofEncoding"]),
                ..BallotProofBackendInputParts::default()
            }),
        );

        assert_eq!(relabeled_verification["ok"], false);
        assert_eq!(
            relabeled_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            relabeled_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("relabeled refusal message should be a string")
                .contains("dedicated full-relation parameter profile")
        );

        let mutated_linear_statement = create_linear_statement(&statement, &mutated_target_case);
        let mutated_ballot_proof = create_ballot_proof(&statement, &mutated_linear_statement);
        let mutated_verification = super::verify_ballot_proof(
            &statement,
            &mutated_ballot_proof,
            ballot_proof_backend_inputs(BallotProofBackendInputParts {
                proof_bytes_hex: Some(proof_bytes_hex),
                linear_statement: Some(&mutated_linear_statement),
                public_randomness_hex: Some(public_randomness_hex),
                parameter_set: Some(&valid_case["parameterSet"]),
                proof_encoding: Some(&valid_case["proofEncoding"]),
                ..BallotProofBackendInputParts::default()
            }),
        );

        assert_eq!(mutated_verification["ok"], false);
        assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");
    }

    fn component_proof_record_for_vector(component_id: &str, proof_bytes_hex: &str) -> Value {
        let proof_size_bytes = proof_bytes_hex.len() / 2;
        json!({
            "componentId": component_id,
            "componentProofRecordDigest": test_digest(&format!("{component_id}-component-proof-record")),
            "proofBytesDigest": super::derive_digest(
                "ProofBytesDigest",
                &json!({
                    "objectType": "ProofBytes",
                    "objectVersion": 1,
                    "proofBytesHex": proof_bytes_hex,
                    "proofSizeBytes": proof_size_bytes
                }),
            )
            .expect("proof bytes digest should derive"),
            "proofSizeBytes": proof_size_bytes
        })
    }

    fn dense_component_proof_input_for_vector(
        component_id: &str,
        vectors: &Value,
        vector_case: &Value,
    ) -> Value {
        let mut proof_statement = vectors["linearStatement"].clone();
        {
            let proof_statement_object = proof_statement
                .as_object_mut()
                .expect("proof statement should be an object");
            proof_statement_object.insert(
                "statementMatrixCoefficients".to_string(),
                vector_case["statementMatrixCoefficients"].clone(),
            );
            proof_statement_object.insert(
                "targetVectorCoefficients".to_string(),
                vector_case["targetVectorCoefficients"].clone(),
            );
            proof_statement_object.insert(
                "targetCoefficientRepresentation".to_string(),
                vector_case["targetCoefficientRepresentation"].clone(),
            );
        }

        json!({
            "componentId": component_id,
            "proofBytesHex": vector_case["proofHex"],
            "proofEncoding": vectors["proofEncoding"],
            "proofParameterSet": vectors["parameterSet"],
            "proofStatement": proof_statement,
            "proofStatementFormat": "dense-polynomial-matrix-linear-proof-v1",
            "publicRandomnessHex": vector_case["publicRandomnessHex"],
            "statementDigest": vectors["linearStatement"]["statementDigest"]
        })
    }

    fn sparse_component_proof_statement_from_dense_statement(
        component_id: &str,
        dense_statement: &Value,
    ) -> Value {
        let statement_rows = integer_property(dense_statement, "statementRows");
        let statement_columns = integer_property(dense_statement, "statementColumns");
        let ring_degree = integer_property(dense_statement, "ringDegree");
        let statement_matrix = dense_statement["statementMatrixCoefficients"]
            .as_array()
            .expect("dense statement matrix should be an array");
        let target_vector = dense_statement["targetVectorCoefficients"]
            .as_array()
            .expect("dense target vector should be an array");
        assert_eq!(
            statement_matrix.len(),
            statement_rows,
            "dense statement matrix row count should match statementRows"
        );
        assert_eq!(
            target_vector.len(),
            statement_rows,
            "dense target vector row count should match statementRows"
        );
        let mut sparse_matrix_entries = Vec::new();
        for (row_index, matrix_row) in statement_matrix.iter().enumerate().take(statement_rows) {
            let matrix_row_entries = matrix_row
                .as_array()
                .expect("matrix row should be an array");
            assert_eq!(
                matrix_row_entries.len(),
                statement_columns,
                "dense statement matrix column count should match statementColumns"
            );
            for (column_index, matrix_entry) in matrix_row_entries
                .iter()
                .enumerate()
                .take(statement_columns)
            {
                let polynomial_coefficients = matrix_entry
                    .as_array()
                    .expect("matrix polynomial should be an array");
                assert_eq!(
                    polynomial_coefficients.len(),
                    ring_degree,
                    "matrix polynomial degree should match ring degree"
                );
                assert!(
                    polynomial_coefficients
                        .iter()
                        .skip(1)
                        .all(|coefficient| coefficient.as_u64() == Some(0)),
                    "test sparse conversion only supports constant source polynomials"
                );
                if polynomial_coefficients[0].as_u64() != Some(0) {
                    sparse_matrix_entries.push(json!({
                        "rowIndex": row_index,
                        "columnIndex": column_index,
                        "constantCoefficient": polynomial_coefficients[0]
                    }));
                }
            }
        }

        let mut target_entries = Vec::new();
        for (row_index, target_entry) in target_vector.iter().enumerate().take(statement_rows) {
            let polynomial_coefficients = target_entry
                .as_array()
                .expect("target polynomial should be an array");
            assert_eq!(
                polynomial_coefficients.len(),
                ring_degree,
                "target polynomial degree should match ring degree"
            );
            assert!(
                polynomial_coefficients
                    .iter()
                    .skip(1)
                    .all(|coefficient| coefficient.as_u64() == Some(0)),
                "test sparse conversion only supports constant target polynomials"
            );
            if polynomial_coefficients[0].as_u64() != Some(0) {
                target_entries.push(json!({
                    "rowIndex": row_index,
                    "constantCoefficient": polynomial_coefficients[0]
                }));
            }
        }

        let sparse_matrix_entries_value = json!(sparse_matrix_entries);
        let target_entries_value = json!(target_entries);
        let sparse_matrix_digest =
            super::derive_sparse_statement_matrix_digest(&sparse_matrix_entries_value)
                .expect("sparse matrix digest should derive");
        let target_vector_digest = super::derive_sparse_target_vector_digest(&target_entries_value)
            .expect("sparse target vector digest should derive");
        let source_backend_column_indices = (0..statement_columns).collect::<Vec<_>>();
        let sparse_statement_payload = json!({
            "backendStatementDigest": dense_statement["backendStatementDigest"],
            "ballotProofStatementDigest": dense_statement["ballotProofStatementDigest"],
            "coefficientModulus": dense_statement["coefficientModulus"],
            "componentId": component_id,
            "objectType": "BallotProofSparseComponentLinearProofStatement",
            "objectVersion": 1,
            "parameterProfileId": dense_statement["parameterProfileId"],
            "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
            "projectionCoverage": "payload-plaintext-field-rows-only",
            "relation": dense_statement["relation"],
            "relationStatementDigest": dense_statement["relationStatementDigest"],
            "sourceBackendColumnIndices": source_backend_column_indices,
            "sourceRingDegree": dense_statement["ringDegree"],
            "sparseStatementMatrixDigest": sparse_matrix_digest,
            "sparseStatementMatrixEntries": sparse_matrix_entries_value,
            "sparseStatementTermCount": sparse_matrix_entries_value.as_array().expect("sparse matrix entries should be an array").len(),
            "statementColumns": dense_statement["statementColumns"],
            "statementRows": dense_statement["statementRows"],
            "targetCoefficientRepresentation": dense_statement["targetCoefficientRepresentation"],
            "targetVectorDigest": target_vector_digest,
            "targetVectorEntries": target_entries_value,
            "targetVectorEntryCount": target_entries_value.as_array().expect("target entries should be an array").len(),
            "witnessL2BoundSquared": dense_statement["witnessL2BoundSquared"]
        });
        let sparse_statement_digest =
            super::derive_ballot_sparse_linear_statement_digest(&sparse_statement_payload)
                .expect("sparse statement digest should derive");
        let mut sparse_statement = sparse_statement_payload;
        sparse_statement
            .as_object_mut()
            .expect("sparse statement should be an object")
            .insert(
                "statementDigest".to_string(),
                json!(sparse_statement_digest),
            );

        sparse_statement
    }

    fn sparse_component_proof_input_for_vector(
        component_id: &str,
        vectors: &Value,
        vector_case: &Value,
    ) -> Value {
        let dense_component_proof_input =
            dense_component_proof_input_for_vector(component_id, vectors, vector_case);
        let sparse_statement = sparse_component_proof_statement_from_dense_statement(
            component_id,
            &dense_component_proof_input["proofStatement"],
        );

        json!({
            "componentId": component_id,
            "proofBytesHex": vector_case["proofHex"],
            "proofEncoding": vectors["proofEncoding"],
            "proofParameterSet": vectors["parameterSet"],
            "proofStatement": sparse_statement,
            "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
            "publicRandomnessHex": vector_case["publicRandomnessHex"],
            "statementDigest": dense_component_proof_input["statementDigest"]
        })
    }

    fn sparse_statement_for_dense_compatibility_test(
        statement_rows: usize,
        statement_columns: usize,
        source_ring_degree: usize,
        coefficient_modulus: u64,
        matrix_entries_value: Value,
        target_entries_value: Value,
    ) -> Value {
        let sparse_statement_matrix_digest =
            super::derive_sparse_statement_matrix_digest(&matrix_entries_value)
                .expect("sparse matrix digest should derive");
        let target_vector_digest = super::derive_sparse_target_vector_digest(&target_entries_value)
            .expect("sparse target digest should derive");
        json!({
            "coefficientModulus": coefficient_modulus.to_string(),
            "objectType": "BallotProofSparseComponentLinearProofStatement",
            "objectVersion": 1,
            "sourceRingDegree": source_ring_degree,
            "sparseStatementMatrixDigest": sparse_statement_matrix_digest,
            "sparseStatementMatrixEntries": matrix_entries_value,
            "sparseStatementTermCount": matrix_entries_value
                .as_array()
                .expect("matrix entries should be an array")
                .len(),
            "statementColumns": statement_columns,
            "statementRows": statement_rows,
            "targetVectorDigest": target_vector_digest,
            "targetVectorEntries": target_entries_value,
            "targetVectorEntryCount": target_entries_value
                .as_array()
                .expect("target entries should be an array")
                .len()
        })
    }

    #[test]
    fn sparse_component_statement_parser_supports_polynomial_entries() {
        let sparse_statement = sparse_statement_for_dense_compatibility_test(
            2,
            2,
            4,
            17,
            json!([
                {
                    "rowIndex": 0,
                    "columnIndex": 1,
                    "polynomialCoefficients": [0, 2, 0, 16]
                },
                {
                    "rowIndex": 1,
                    "columnIndex": 0,
                    "constantCoefficient": 5
                }
            ]),
            json!([
                {
                    "rowIndex": 0,
                    "polynomialCoefficients": [1, 0, 3, 0]
                },
                {
                    "rowIndex": 1,
                    "constantCoefficient": 7
                }
            ]),
        );
        let (dense_matrix, dense_target) =
            super::dense_matrix_from_sparse_component_statement(&sparse_statement)
                .expect("polynomial sparse statement should densify");

        assert_eq!(
            dense_matrix,
            json!([[[0, 0, 0, 0], [0, 2, 0, 16]], [[5, 0, 0, 0], [0, 0, 0, 0]]])
        );
        assert_eq!(dense_target, json!([[1, 0, 3, 0], [7, 0, 0, 0]]));
    }

    #[test]
    fn sparse_component_statement_parser_rejects_noncanonical_entries() {
        let both_encodings_statement = sparse_statement_for_dense_compatibility_test(
            1,
            1,
            4,
            17,
            json!([
                {
                    "rowIndex": 0,
                    "columnIndex": 0,
                    "constantCoefficient": 1,
                    "polynomialCoefficients": [1, 0, 0, 0]
                }
            ]),
            json!([]),
        );
        let both_encodings_error =
            super::dense_matrix_from_sparse_component_statement(&both_encodings_statement)
                .expect_err("sparse entries with both encodings should be rejected");
        assert_eq!(both_encodings_error.code, "BallotPackageInvalid");
        assert!(
            both_encodings_error
                .message
                .contains("either constantCoefficient or polynomialCoefficients")
        );

        let noncanonical_statement = sparse_statement_for_dense_compatibility_test(
            1,
            1,
            4,
            17,
            json!([
                {
                    "rowIndex": 0,
                    "columnIndex": 0,
                    "polynomialCoefficients": [1, 0, 17, 0]
                }
            ]),
            json!([]),
        );
        let noncanonical_error =
            super::dense_matrix_from_sparse_component_statement(&noncanonical_statement)
                .expect_err("noncanonical sparse coefficients should be rejected");
        assert_eq!(noncanonical_error.code, "BallotPackageInvalid");
        assert!(noncanonical_error.message.contains("not canonical"));

        let zero_entry_statement = sparse_statement_for_dense_compatibility_test(
            1,
            1,
            4,
            17,
            json!([
                {
                    "rowIndex": 0,
                    "columnIndex": 0,
                    "polynomialCoefficients": [0, 0, 0, 0]
                }
            ]),
            json!([]),
        );
        let zero_entry_error =
            super::dense_matrix_from_sparse_component_statement(&zero_entry_statement)
                .expect_err("zero sparse entries should be rejected");
        assert_eq!(zero_entry_error.code, "BallotPackageInvalid");
        assert!(zero_entry_error.message.contains("zero polynomials"));
    }

    #[test]
    fn sparse_component_statement_large_shape_parses_without_dense_allocation() {
        let sparse_statement =
            sparse_statement_for_dense_compatibility_test(1024, 1024, 64, 17, json!([]), json!([]));
        let parsed_sparse_statement =
            super::sparse_matrix_from_sparse_component_statement(&sparse_statement)
                .expect("large sparse statement should parse without dense allocation");

        assert_eq!(parsed_sparse_statement.source_statement_matrix.rows(), 1024);
        assert_eq!(
            parsed_sparse_statement.source_statement_matrix.columns(),
            1024
        );

        let component_id = "share-commitment-component";
        let component_proof = component_proof_record_for_vector(component_id, "00");
        let proof_input = json!({
            "componentId": component_id,
            "proofBytesHex": "00",
            "proofEncoding": {
                "profileId": "test-proof-encoding"
            },
            "proofParameterSet": {
                "profileId": "test-proof-parameter-set"
            },
            "proofStatement": sparse_statement,
            "proofStatementFormat": "sparse-polynomial-matrix-linear-proof-v1",
            "publicRandomnessHex": "00".repeat(32),
            "statementDigest": test_digest("large-sparse-statement")
        });
        let component_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            component_id,
            &component_proof,
            &proof_input,
        );

        assert_eq!(component_verification["ok"], false);
        assert_eq!(
            component_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert_ne!(
            component_verification["unresolvedReason"],
            "OperationUnavailable"
        );
    }

    fn structured_receiver_encryption_statement_for_test(
        first_ciphertext_coefficient: u64,
    ) -> Value {
        let module_degree = 256_usize;
        let module_rank = 4_usize;
        let randomness_columns = (0..module_rank)
            .map(|vector_index| {
                (0..module_degree)
                    .map(|coefficient_index| vector_index * module_degree + coefficient_index)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let first_noise_columns = (0..module_rank)
            .map(|vector_index| {
                (0..module_degree)
                    .map(|coefficient_index| {
                        module_rank * module_degree
                            + vector_index * module_degree
                            + coefficient_index
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let second_noise_columns = (0..module_degree)
            .map(|coefficient_index| 2 * module_rank * module_degree + coefficient_index)
            .collect::<Vec<_>>();
        let zero_polynomial = vec![0_u64; module_degree];
        let mut first_ciphertext_polynomial = zero_polynomial.clone();
        first_ciphertext_polynomial[0] = first_ciphertext_coefficient;
        let first_ciphertext_vector = vec![
            first_ciphertext_polynomial,
            zero_polynomial.clone(),
            zero_polynomial.clone(),
            zero_polynomial.clone(),
        ];
        let zero_vector = vec![
            zero_polynomial.clone(),
            zero_polynomial.clone(),
            zero_polynomial.clone(),
            zero_polynomial.clone(),
        ];
        let mut statement = json!({
            "backendStatementDigest": test_digest("structured-backend-statement"),
            "coefficientModulus": "12289",
            "componentId": "receiver-encryption-component",
            "componentStatementDigest": test_digest("structured-component-statement"),
            "matrixDigest": test_digest("structured-matrix"),
            "objectType": "BallotProofStructuredReceiverEncryptionProofStatement",
            "objectVersion": 1,
            "parameterProfileId": "receiver-encryption-structured-test-v1",
            "proofStatementFormat": "structured-module-lwe-linear-proof-v1",
            "proofSystemRingDegree": 64,
            "receiverEncryptionProfileDigest": test_digest("receiver-encryption-profile"),
            "receiverRows": [
                {
                    "ciphertextChunkCount": 1,
                    "ciphertextChunks": [
                        {
                            "chunkIndex": 0,
                            "firstCiphertextVector": first_ciphertext_vector,
                            "firstNoiseColumnIndices": first_noise_columns,
                            "plaintextBitColumnIndices": [],
                            "randomnessColumnIndices": randomness_columns,
                            "secondCiphertextPolynomial": zero_polynomial,
                            "secondNoiseColumnIndices": second_noise_columns
                        }
                    ],
                    "plaintextBitLength": 0,
                    "publicKeyVector": zero_vector,
                    "publicMatrixSeedDigest": test_digest("receiver-public-matrix-seed"),
                    "receiverIdentity": "receiver-1",
                    "receiverPayloadDigest": test_digest("receiver-payload"),
                    "receiverPublicKeyDigest": test_digest("receiver-public-key"),
                    "receiverRosterPosition": 1,
                    "rowCount": 1280,
                    "rowOffsetWithinStatement": 0
                }
            ],
            "relation": "A*w + t = 0",
            "relationStatementDigest": test_digest("structured-relation-statement"),
            "sourceBackendColumnIndices": (0..2304).collect::<Vec<_>>(),
            "sourceRingDegree": 256,
            "statementColumns": 2304,
            "statementRows": 1280,
            "targetCoefficientRepresentation": "canonicalUnsignedSourceModulus",
            "targetVectorDigest": test_digest("structured-target"),
            "witnessL2BoundSquared": "8192"
        });
        let statement_digest =
            super::derive_ballot_structured_receiver_encryption_statement_digest(&statement)
                .expect("structured statement digest should derive");
        statement
            .as_object_mut()
            .expect("structured statement should be an object")
            .insert("statementDigest".to_string(), json!(statement_digest));

        statement
    }

    #[test]
    fn structured_receiver_encryption_statement_lowers_public_module_lwe_rows() {
        let zero_ciphertext_statement = structured_receiver_encryption_statement_for_test(0);
        let parsed_zero_statement =
            super::structured_receiver_encryption_statement_as_sparse(&zero_ciphertext_statement)
                .expect("structured statement should lower to sparse rows");

        assert_eq!(parsed_zero_statement.source_statement_matrix.rows(), 1280);
        assert_eq!(
            parsed_zero_statement.source_statement_matrix.columns(),
            2304
        );
        assert_eq!(parsed_zero_statement.target_vector_coefficients[0][0], 0);
        assert!(
            parsed_zero_statement
                .source_statement_matrix
                .entries()
                .len()
                > 1024
        );

        let changed_ciphertext_statement = structured_receiver_encryption_statement_for_test(1);
        let parsed_changed_statement = super::structured_receiver_encryption_statement_as_sparse(
            &changed_ciphertext_statement,
        )
        .expect("changed structured statement should lower");

        assert_eq!(
            parsed_changed_statement.target_vector_coefficients[0][0],
            12288
        );
    }

    #[test]
    fn component_linear_proof_bytes_verify_dense_and_sparse_public_statements() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
        ))
        .expect("encoded-score field vector file should parse");
        let cases = vectors["cases"]
            .as_array()
            .expect("encoded-score field vector file should contain cases");
        let valid_compact_case = cases
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-encoded-score-field-linear-proof")
            .expect("valid encoded-score field vector should exist");
        let mutated_target_compact_case = cases
            .iter()
            .find(|vector_case| {
                vector_case["caseName"] == "mutated-encoded-score-field-target-vector"
            })
            .expect("mutated encoded-score target vector should exist");
        let valid_case = expand_encoded_score_field_vector_case(&vectors, valid_compact_case);
        let mutated_target_case =
            expand_encoded_score_field_vector_case(&vectors, mutated_target_compact_case);
        let proof_bytes_hex = valid_case["proofHex"]
            .as_str()
            .expect("valid proof bytes should be a string");
        let dense_component_id = "score-and-shamir-field-component";
        let dense_component_proof =
            component_proof_record_for_vector(dense_component_id, proof_bytes_hex);
        let dense_proof_input =
            dense_component_proof_input_for_vector(dense_component_id, &vectors, &valid_case);
        let dense_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            dense_component_id,
            &dense_component_proof,
            &dense_proof_input,
        );

        assert_eq!(dense_verification["ok"], true);
        assert!(
            dense_verification["statusLabels"]
                .as_array()
                .expect("dense status labels should be an array")
                .contains(&json!("BallotProofComponentLinearProofVerified"))
        );

        let mutated_dense_proof_input = dense_component_proof_input_for_vector(
            dense_component_id,
            &vectors,
            &mutated_target_case,
        );
        let mutated_dense_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            dense_component_id,
            &dense_component_proof,
            &mutated_dense_proof_input,
        );

        assert_eq!(mutated_dense_verification["ok"], false);
        assert_eq!(
            mutated_dense_verification["unresolvedReason"],
            "InvalidFixture"
        );

        let sparse_component_id = "payload-plaintext-field-component";
        let sparse_component_proof =
            component_proof_record_for_vector(sparse_component_id, proof_bytes_hex);
        let sparse_proof_input =
            sparse_component_proof_input_for_vector(sparse_component_id, &vectors, &valid_case);
        let sparse_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            sparse_component_id,
            &sparse_component_proof,
            &sparse_proof_input,
        );

        assert_eq!(
            sparse_verification["ok"], true,
            "sparse statement expansion should verify against the same proof bytes: {sparse_verification}"
        );

        let mut sparse_input_with_stale_target_digest = sparse_proof_input.clone();
        {
            let sparse_statement = sparse_input_with_stale_target_digest["proofStatement"]
                .as_object_mut()
                .expect("sparse proof statement should be an object");
            let target_entries = sparse_statement["targetVectorEntries"]
                .as_array_mut()
                .expect("target entries should be an array");
            let first_target_entry = target_entries
                .iter_mut()
                .find(|target_entry| target_entry["constantCoefficient"].as_u64() != Some(0))
                .expect("target should have a nonzero entry");
            first_target_entry
                .as_object_mut()
                .expect("target entry should be an object")
                .insert("constantCoefficient".to_string(), json!(3));
        }
        let stale_digest_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            sparse_component_id,
            &sparse_component_proof,
            &sparse_input_with_stale_target_digest,
        );

        assert_eq!(stale_digest_verification["ok"], false);
        assert_eq!(
            stale_digest_verification["refusedObjects"][0]["code"],
            "BallotPackageInvalid"
        );
        assert!(
            stale_digest_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("stale digest refusal should be a string")
                .contains("target vector digest")
        );

        let public_zero_component_id = "receiver-key-binding-component";
        let public_zero_component_statement_digest =
            json!(test_digest("receiver-key-binding-component-statement"));
        let public_zero_component_proof =
            component_proof_record_for_vector(public_zero_component_id, "");
        let public_zero_proof_input = component_proof_input_for_test(
            public_zero_component_id,
            &public_zero_component_statement_digest,
        );
        let public_zero_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            public_zero_component_id,
            &public_zero_component_proof,
            &public_zero_proof_input,
        );

        assert_eq!(public_zero_verification["ok"], true);
        assert!(
            public_zero_verification["statusLabels"]
                .as_array()
                .expect("public-zero status labels should be an array")
                .contains(&json!(
                    "BallotProofComponentPublicZeroWitnessBindingChecked"
                ))
        );

        let mut public_zero_input_with_proof_bytes = public_zero_proof_input;
        public_zero_input_with_proof_bytes["proofBytesHex"] = json!("00");
        let public_zero_rejection = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            public_zero_component_id,
            &public_zero_component_proof,
            &public_zero_input_with_proof_bytes,
        );

        assert_eq!(public_zero_rejection["ok"], false);
        assert!(
            public_zero_rejection["refusedObjects"][0]["message"]
                .as_str()
                .expect("public-zero refusal message should be a string")
                .contains("must be empty")
        );

        let structured_component_id = "receiver-encryption-component";
        let structured_component_statement_digest =
            json!(test_digest("receiver-encryption-component-statement"));
        let structured_component_proof = component_proof_for_test(
            structured_component_id,
            &structured_component_statement_digest,
        );
        let structured_proof_input = component_proof_input_for_test(
            structured_component_id,
            &structured_component_statement_digest,
        );
        let structured_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            structured_component_id,
            &structured_component_proof,
            &structured_proof_input,
        );

        assert_eq!(structured_verification["ok"], false);
        assert_eq!(
            structured_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            structured_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("structured refusal message should be a string")
                .contains("require a public structured proof statement")
        );

        let mut malformed_structured_input = structured_proof_input;
        malformed_structured_input["proofStatement"]["structuredWitnessTermCount"] = json!("0");
        let malformed_structured_verification = super::verify_component_linear_proof_bytes(
            "verifyBallotProof",
            structured_component_id,
            &structured_component_proof,
            &malformed_structured_input,
        );

        assert_eq!(malformed_structured_verification["ok"], false);
        assert_eq!(
            malformed_structured_verification["unresolvedReason"],
            "BallotPackageInvalid"
        );
        assert!(
            malformed_structured_verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("malformed structured refusal should be a string")
                .contains("require a public structured proof statement")
        );
    }

    fn test_digest(label: &str) -> String {
        super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "label": label,
                "purpose": "ballot-component-bundle-test"
            }),
        )
        .expect("test digest should derive")
    }

    fn component_statement_for_test(component_id: &str, proof_lowering_status: &str) -> Value {
        let component_payload = json!({
            "objectType": "BallotProofComponentStatement",
            "objectVersion": 1,
            "backendStatementDigest": test_digest("backend-statement"),
            "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
            "coefficientModulus": "65537",
            "componentDigest": test_digest(&format!("{component_id}-component")),
            "componentId": component_id,
            "matrixDigest": test_digest(&format!("{component_id}-matrix")),
            "proofLoweringStatus": proof_lowering_status,
            "relationStatementDigest": test_digest("relation-statement"),
            "rowBatchMatrixDigests": [test_digest(&format!("{component_id}-row-matrix"))],
            "rowBatchNames": [format!("{component_id}-rows")],
            "rowBatchTargetVectorDigests": [test_digest(&format!("{component_id}-row-target"))],
            "rowCount": 1,
            "rowKinds": ["EncodedScoreFieldRows"],
            "targetVectorDigest": test_digest(&format!("{component_id}-target")),
            "variableColumnCount": 1,
            "variableColumnIndices": [0],
        });
        let component_statement_digest =
            super::derive_ballot_component_statement_digest(&component_payload)
                .expect("component statement digest should derive");
        let mut component_statement = component_payload;
        component_statement
            .as_object_mut()
            .expect("component statement should be an object")
            .insert(
                "componentStatementDigest".to_string(),
                json!(component_statement_digest),
            );

        component_statement
    }

    fn component_bundle_for_test(component_statements: Vec<Value>, bundle_coverage: &str) -> Value {
        let component_bundle_payload = json!({
            "objectType": "BallotProofComponentBundleStatement",
            "objectVersion": 1,
            "backendStatementDigest": test_digest("backend-statement"),
            "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
            "bundleCoverage": bundle_coverage,
            "componentStatements": component_statements,
            "relationLabel": "BallotPrivacyPvssRelation",
            "relationStatementDigest": test_digest("relation-statement"),
            "requiredComponentIds": super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        });
        let component_bundle_statement_digest =
            super::derive_ballot_component_bundle_statement_digest(&component_bundle_payload)
                .expect("component bundle statement digest should derive");
        let mut component_bundle = component_bundle_payload;
        component_bundle
            .as_object_mut()
            .expect("component bundle should be an object")
            .insert(
                "componentBundleStatementDigest".to_string(),
                json!(component_bundle_statement_digest),
            );

        component_bundle
    }

    fn proof_bytes_digest_for_test(proof_bytes_hex: &str) -> String {
        super::derive_digest(
            "ProofBytesDigest",
            &json!({
                "objectType": "ProofBytes",
                "objectVersion": 1,
                "proofBytesHex": proof_bytes_hex,
                "proofSizeBytes": proof_bytes_hex.len() / 2,
            }),
        )
        .expect("proof bytes digest should derive")
    }

    fn component_proof_input_for_test(
        component_id: &str,
        component_statement_digest: &Value,
    ) -> Value {
        let component_index = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
            .iter()
            .position(|expected_component_id| *expected_component_id == component_id)
            .expect("component id should be required");
        let public_randomness_byte = format!("{:02x}", component_index + 1);

        let proof_statement_format = if component_id == "receiver-encryption-component" {
            "structured-module-lwe-linear-proof-v1"
        } else if component_id == "receiver-key-binding-component" {
            "public-zero-witness-binding-check-v1"
        } else if component_id == "score-and-shamir-field-component" {
            "dense-polynomial-matrix-linear-proof-v1"
        } else {
            "sparse-polynomial-matrix-linear-proof-v1"
        };
        let proof_statement = component_proof_statement_for_test(
            component_id,
            component_statement_digest,
            if proof_statement_format == "structured-module-lwe-linear-proof-v1"
                || proof_statement_format == "public-zero-witness-binding-check-v1"
            {
                None
            } else {
                Some(test_digest(&format!("{component_id}-proof-statement")))
            },
            proof_statement_format,
        );
        let component_proof_statement_digest =
            super::string_field(&proof_statement, "componentProofStatementDigest")
                .map(ToString::to_string)
                .unwrap_or_else(|| test_digest(&format!("{component_id}-proof-statement")));

        json!({
            "componentId": component_id,
            "componentProofStatementDigest": component_proof_statement_digest,
            "proofBytesHex": if proof_statement_format == "public-zero-witness-binding-check-v1" {
                "".to_string()
            } else {
                test_digest(&format!("{component_id}-proof-bytes-material"))
            },
            "proofEncoding": {
                "profileId": "ballot-proof-component-encoding-v1",
                "componentId": component_id,
            },
            "proofParameterSet": {
                "profileId": "ballot-proof-component-parameter-set-v1",
                "componentId": component_id,
            },
            "proofStatement": proof_statement,
            "proofStatementFormat": proof_statement_format,
            "publicRandomnessHex": public_randomness_byte.repeat(32),
            "statementDigest": component_statement_digest,
        })
    }

    fn component_proof_statement_for_test(
        component_id: &str,
        component_statement_digest: &Value,
        component_proof_statement_digest: Option<String>,
        proof_statement_format: &str,
    ) -> Value {
        if proof_statement_format == "dense-polynomial-matrix-linear-proof-v1" {
            let statement_payload = json!({
                "objectType": "BallotProofLinearProofStatement",
                "objectVersion": 1,
                "componentId": component_id,
                "componentStatementDigest": component_statement_digest,
                "proofStatementFormat": proof_statement_format,
            });
            let statement_digest = super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "payload": statement_payload,
                    "purpose": "ballot-proof-linear-proof-statement-v1"
                }),
            )
            .expect("dense component proof statement digest should derive");
            let mut statement = statement_payload;
            statement
                .as_object_mut()
                .expect("dense component proof statement should be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));

            return statement;
        }
        if proof_statement_format == "sparse-polynomial-matrix-linear-proof-v1" {
            let statement_payload = json!({
                "objectType": "BallotProofSparseComponentLinearProofStatement",
                "objectVersion": 1,
                "componentId": component_id,
                "componentStatementDigest": component_statement_digest,
                "proofStatementFormat": proof_statement_format,
            });
            let statement_digest = super::derive_digest(
                "ChallengeDomainDigest",
                &json!({
                    "payload": statement_payload,
                    "purpose": "ballot-proof-sparse-linear-proof-statement-v1"
                }),
            )
            .expect("sparse component proof statement digest should derive");
            let mut statement = statement_payload;
            statement
                .as_object_mut()
                .expect("sparse component proof statement should be an object")
                .insert("statementDigest".to_string(), json!(statement_digest));

            return statement;
        }
        let is_structured = proof_statement_format == "structured-module-lwe-linear-proof-v1";
        let statement_payload = json!({
            "backendStatementDigest": test_digest(&format!("{component_id}-backend")),
            "coefficientModulus": if component_id == "share-commitment-component" {
                "18446744069414584321"
            } else if component_id == "score-and-shamir-field-component"
                || component_id == "payload-plaintext-field-component" {
                "65537"
            } else {
                "12289"
            },
            "objectType": "BallotProofComponentProofStatementPlan",
            "objectVersion": 1,
            "componentId": component_id,
            "componentStatementDigest": component_statement_digest,
            "denseCoefficientCount": if is_structured { json!("1024") } else { Value::Null },
            "matrixDigest": test_digest(&format!("{component_id}-matrix")),
            "proofBytesAvailability": if is_structured {
                "requires-structured-proof-statement"
            } else {
                "public-zero-witness-binding-check"
            },
            "proofLoweringStatus": "explicitRowsAvailable",
            "proofStatementFormat": proof_statement_format,
            "proofSystemRingDegree": if is_structured { json!(64) } else { Value::Null },
            "relation": "A*w + t = 0",
            "relationStatementDigest": test_digest(&format!("{component_id}-relation")),
            "rowBatchMatrixDigests": [test_digest(&format!("{component_id}-row-matrix"))],
            "rowBatchNames": [if is_structured {
                "receiver_payload_encryption_equation_rows"
            } else {
                "receiver_key_binding_rows"
            }],
            "rowBatchTargetVectorDigests": [test_digest(&format!("{component_id}-row-target"))],
            "rowBatchTermCounts": [if is_structured { "1024" } else { "0" }],
            "rowCount": 1,
            "sparseTermCount": Value::Null,
            "sourceRingDegree": if is_structured { json!(256) } else { Value::Null },
            "structuredCiphertextChunkCount": if is_structured { json!(1) } else { Value::Null },
            "structuredReceiverCount": if is_structured { json!(1) } else { Value::Null },
            "structuredWitnessTermCount": if is_structured { json!("1024") } else { Value::Null },
            "targetVectorDigest": test_digest(&format!("{component_id}-target")),
            "variableColumnCount": if is_structured { 1 } else { 0 },
            "variableColumnIndices": if is_structured { json!([0]) } else { json!([]) },
        });
        let canonical_component_proof_statement_digest = super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "payload": statement_payload,
                "purpose": "ballot-proof-component-proof-statement-plan-v1"
            }),
        )
        .expect("component proof statement plan digest should derive");
        let mut statement_plan = statement_payload;
        statement_plan
            .as_object_mut()
            .expect("component proof statement plan should be an object")
            .insert(
                "componentProofStatementDigest".to_string(),
                json!(
                    component_proof_statement_digest
                        .unwrap_or(canonical_component_proof_statement_digest)
                ),
            );

        statement_plan
    }

    fn component_proof_for_test(component_id: &str, component_statement_digest: &Value) -> Value {
        let proof_input = component_proof_input_for_test(component_id, component_statement_digest);
        let proof_bytes_hex = proof_input["proofBytesHex"]
            .as_str()
            .expect("component proof bytes should be a string");
        let proof_encoding = proof_input
            .get("proofEncoding")
            .expect("component proof encoding should exist");
        let proof_parameter_set = proof_input
            .get("proofParameterSet")
            .expect("component proof parameter set should exist");
        let public_randomness_hex = proof_input["publicRandomnessHex"]
            .as_str()
            .expect("component proof public randomness should be a string");
        let proof_bytes_digest = proof_bytes_digest_for_test(proof_bytes_hex);
        let proof_encoding_profile_digest =
            super::derive_ballot_proof_encoding_profile_digest(proof_encoding)
                .expect("component proof encoding digest should derive");
        let proof_parameter_set_digest =
            super::derive_ballot_proof_parameter_set_digest(proof_parameter_set)
                .expect("component proof parameter set digest should derive");
        let public_randomness_digest =
            super::derive_ballot_proof_public_randomness_digest(public_randomness_hex)
                .expect("component proof public randomness digest should derive");
        let proof_root = super::derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "componentId": component_id,
                "componentProofStatementDigest": proof_input["componentProofStatementDigest"],
                "componentStatementDigest": component_statement_digest,
                "proofBytesDigest": proof_bytes_digest,
                "proofEncodingProfileDigest": proof_encoding_profile_digest,
                "proofParameterSetDigest": proof_parameter_set_digest,
                "proofStatementFormat": proof_input["proofStatementFormat"],
                "publicRandomnessDigest": public_randomness_digest,
                "purpose": "ballot-proof-component-proof-root-v1",
                "statementDigest": component_statement_digest,
            }),
        )
        .expect("component proof root should derive");
        let component_proof_payload = json!({
            "objectType": "BallotProofComponentProofRecord",
            "objectVersion": 1,
            "backendStatementDigest": test_digest("backend-statement"),
            "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
            "componentId": component_id,
            "componentProofStatementDigest": proof_input["componentProofStatementDigest"],
            "componentStatementDigest": component_statement_digest,
            "proofBackend": "LocalLinearLatticeRelation",
            "proofBytesDigest": proof_bytes_digest,
            "proofEncodingProfileDigest": proof_encoding_profile_digest,
            "proofParameterSetDigest": proof_parameter_set_digest,
            "proofRoot": proof_root,
            "proofSizeBytes": proof_bytes_hex.len() / 2,
            "publicRandomnessDigest": public_randomness_digest,
            "relationStatementDigest": test_digest("relation-statement"),
        });
        let component_proof_record_digest =
            super::derive_ballot_component_proof_record_digest(&component_proof_payload)
                .expect("component proof digest should derive");
        let mut component_proof = component_proof_payload;
        component_proof
            .as_object_mut()
            .expect("component proof should be an object")
            .insert(
                "componentProofRecordDigest".to_string(),
                json!(component_proof_record_digest),
            );

        component_proof
    }

    fn component_proof_bundle_for_test(
        component_bundle_statement: &Value,
        component_proofs: Vec<Value>,
    ) -> Value {
        let component_proof_bundle_payload = json!({
            "objectType": "BallotProofComponentProofBundle",
            "objectVersion": 1,
            "backendStatementDigest": test_digest("backend-statement"),
            "ballotProofStatementDigest": test_digest("ballot-proof-statement"),
            "bundleCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
            "componentBundleStatementDigest": component_bundle_statement["componentBundleStatementDigest"],
            "componentProofs": component_proofs,
            "relationStatementDigest": test_digest("relation-statement"),
            "requiredComponentIds": super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS,
        });
        let component_proof_bundle_digest =
            super::derive_ballot_component_proof_bundle_digest(&component_proof_bundle_payload)
                .expect("component proof bundle digest should derive");
        let mut component_proof_bundle = component_proof_bundle_payload;
        component_proof_bundle
            .as_object_mut()
            .expect("component proof bundle should be an object")
            .insert(
                "componentProofBundleDigest".to_string(),
                json!(component_proof_bundle_digest),
            );

        component_proof_bundle
    }

    #[test]
    fn component_bundle_refusals_cover_incomplete_and_reordered_components() {
        let statement = json!({
            "ballotProofStatementDigest": test_digest("ballot-proof-statement")
        });
        let linear_statement = json!({
            "backendStatementDigest": test_digest("backend-statement"),
            "projectionCoverage": super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
            "relationStatementDigest": test_digest("relation-statement")
        });
        let incomplete_component_statements = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
            .iter()
            .enumerate()
            .map(|(component_index, component_id)| {
                component_statement_for_test(
                    component_id,
                    if component_index == 0 {
                        "explicitRowsAvailable"
                    } else {
                        "digestExpandedRowsPending"
                    },
                )
            })
            .collect::<Vec<_>>();
        let incomplete_bundle = component_bundle_for_test(
            incomplete_component_statements,
            super::COMPONENT_BUNDLE_INCOMPLETE_COVERAGE,
        );
        let ballot_proof = json!({
            "ballotProofRecordDigest": test_digest("ballot-proof-record"),
            "componentBundleStatementDigest": incomplete_bundle["componentBundleStatementDigest"],
        });
        let incomplete_refusals = super::collect_ballot_component_bundle_refusals(
            &statement,
            &ballot_proof,
            &linear_statement,
            Some(&incomplete_bundle),
        );

        assert!(incomplete_refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("still incomplete")
        }));
        assert!(incomplete_refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("not fully lowered")
        }));

        let mut reordered_component_statements = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
            .iter()
            .map(|component_id| component_statement_for_test(component_id, "explicitRowsAvailable"))
            .collect::<Vec<_>>();
        reordered_component_statements.swap(0, 1);
        let reordered_bundle = component_bundle_for_test(
            reordered_component_statements,
            super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        );
        let reordered_ballot_proof = json!({
            "ballotProofRecordDigest": test_digest("reordered-ballot-proof-record"),
            "componentBundleStatementDigest": reordered_bundle["componentBundleStatementDigest"],
        });
        let reordered_refusals = super::collect_ballot_component_bundle_refusals(
            &statement,
            &reordered_ballot_proof,
            &linear_statement,
            Some(&reordered_bundle),
        );

        assert!(reordered_refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("invalid canonical shape")
        }));
    }

    #[test]
    fn component_proof_bundle_refusals_cover_missing_reordered_and_wrong_statement_binding() {
        let statement = json!({
            "ballotProofStatementDigest": test_digest("ballot-proof-statement")
        });
        let component_statements = super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS
            .iter()
            .map(|component_id| component_statement_for_test(component_id, "explicitRowsAvailable"))
            .collect::<Vec<_>>();
        let component_bundle_statement = component_bundle_for_test(
            component_statements.clone(),
            super::FULL_BALLOT_PROOF_PROJECTION_COVERAGE,
        );
        let component_proofs = component_statements
            .iter()
            .zip(super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter())
            .map(|(component_statement, component_id)| {
                component_proof_for_test(
                    component_id,
                    &component_statement["componentStatementDigest"],
                )
            })
            .collect::<Vec<_>>();
        let component_proof_inputs = component_statements
            .iter()
            .zip(super::REQUIRED_BALLOT_PROOF_COMPONENT_IDS.iter())
            .map(|(component_statement, component_id)| {
                component_proof_input_for_test(
                    component_id,
                    &component_statement["componentStatementDigest"],
                )
            })
            .collect::<Vec<_>>();
        let component_proof_bundle =
            component_proof_bundle_for_test(&component_bundle_statement, component_proofs.clone());
        let component_proof_inputs = json!(component_proof_inputs);
        let ballot_proof = json!({
            "backendStatementDigest": test_digest("backend-statement"),
            "ballotProofRecordDigest": test_digest("ballot-proof-record"),
            "componentBundleStatementDigest": component_bundle_statement["componentBundleStatementDigest"],
            "componentProofBundleDigest": component_proof_bundle["componentProofBundleDigest"],
            "relationStatementDigest": test_digest("relation-statement"),
        });
        let valid_refusals = super::collect_ballot_component_proof_bundle_refusals(
            &statement,
            &ballot_proof,
            Some(&component_bundle_statement),
            Some(&component_proof_bundle),
            Some(&component_proof_inputs),
        );

        assert!(
            valid_refusals.is_empty(),
            "well-formed component proof bundle should have no structural refusals: {valid_refusals:?}"
        );

        let mut wrong_component_proof_statement_inputs = component_proof_inputs.clone();
        wrong_component_proof_statement_inputs[0]["componentProofStatementDigest"] =
            json!(test_digest("wrong-component-proof-statement"));
        let wrong_component_proof_statement_refusals =
            super::collect_ballot_component_proof_bundle_refusals(
                &statement,
                &ballot_proof,
                Some(&component_bundle_statement),
                Some(&component_proof_bundle),
                Some(&wrong_component_proof_statement_inputs),
            );
        assert!(
            wrong_component_proof_statement_refusals
                .iter()
                .any(|refusal| {
                    refusal["message"]
                        .as_str()
                        .expect("refusal message should be a string")
                        .contains("proof statement for score-and-shamir-field-component does not match the proof record")
                })
        );

        let mut wrong_supplied_proof_statement_inputs = component_proof_inputs.clone();
        wrong_supplied_proof_statement_inputs[3]["proofStatement"] =
            component_proof_statement_for_test(
                "receiver-encryption-component",
                &component_bundle_statement["componentStatements"][3]["componentStatementDigest"],
                Some(test_digest(
                    "wrong-supplied-component-proof-statement-canonical-digest",
                )),
                "structured-module-lwe-linear-proof-v1",
            );
        let wrong_supplied_proof_statement_refusals =
            super::collect_ballot_component_proof_bundle_refusals(
                &statement,
                &ballot_proof,
                Some(&component_bundle_statement),
                Some(&component_proof_bundle),
                Some(&wrong_supplied_proof_statement_inputs),
            );
        assert!(
            wrong_supplied_proof_statement_refusals
                .iter()
                .any(|refusal| {
                    refusal["message"]
                        .as_str()
                        .expect("refusal message should be a string")
                        .contains(
                            "proof statement digest for receiver-encryption-component does not match its canonical payload",
                        )
                })
        );

        let missing_bundle_refusals = super::collect_ballot_component_proof_bundle_refusals(
            &statement,
            &ballot_proof,
            Some(&component_bundle_statement),
            None,
            None,
        );
        assert!(missing_bundle_refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("was not supplied")
        }));

        let mut reordered_component_proofs = component_proofs;
        reordered_component_proofs.swap(0, 1);
        let reordered_proof_bundle = component_proof_bundle_for_test(
            &component_bundle_statement,
            reordered_component_proofs,
        );
        let reordered_ballot_proof = json!({
            "backendStatementDigest": test_digest("backend-statement"),
            "ballotProofRecordDigest": test_digest("reordered-ballot-proof-record"),
            "componentBundleStatementDigest": component_bundle_statement["componentBundleStatementDigest"],
            "componentProofBundleDigest": reordered_proof_bundle["componentProofBundleDigest"],
            "relationStatementDigest": test_digest("relation-statement"),
        });
        let reordered_refusals = super::collect_ballot_component_proof_bundle_refusals(
            &statement,
            &reordered_ballot_proof,
            Some(&component_bundle_statement),
            Some(&reordered_proof_bundle),
            Some(&component_proof_inputs),
        );
        assert!(reordered_refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("invalid canonical shape")
        }));

        let mut wrong_statement_proof_bundle = component_proof_bundle;
        wrong_statement_proof_bundle["componentProofs"][0]["componentStatementDigest"] =
            json!(test_digest("wrong-component-statement"));
        let wrong_statement_refusals = super::collect_ballot_component_proof_bundle_refusals(
            &statement,
            &ballot_proof,
            Some(&component_bundle_statement),
            Some(&wrong_statement_proof_bundle),
            Some(&component_proof_inputs),
        );
        assert!(wrong_statement_refusals.iter().any(|refusal| {
            refusal["message"]
                .as_str()
                .expect("refusal message should be a string")
                .contains("not bound to the supplied component statement")
        }));
    }
}
