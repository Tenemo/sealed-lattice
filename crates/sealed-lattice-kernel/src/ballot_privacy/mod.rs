pub mod abdlop_commitment;
pub mod encoded_relation_vectors;
pub mod lazer_demo_abdlop;
pub(crate) mod lazer_demo_many_quadratic;
pub mod lazer_demo_public_parameters;
pub(crate) mod lazer_demo_quadratic;
pub(crate) mod lazer_demo_quadratic_challenge;
pub mod lazer_demo_rng;
pub(crate) mod lazer_demo_tbox_relations;
pub mod linear_proof_norms;
pub mod linear_proof_parameters;
pub mod linear_proof_statement;
pub mod linear_proof_tbox;
pub mod linear_proof_transcript;
pub mod linear_proof_verifier;
pub mod polynomial_matrix;
pub mod polynomial_ring;
pub mod polynomial_vector;
pub mod proof_coder;
pub mod receiver_key_vectors;
pub mod sparse_polynomial_matrix;
pub mod sparse_polynomial_vector;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::{hashing::derive_protocol_digest, transcript_core::decode_hex};

pub const MODULE_MARKER: &str = "ballot-privacy";
pub const BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE: bool = false;

const UNAVAILABLE_BACKEND_MESSAGE: &str = "Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build.";
const BACKEND_NAME: &str = "LaZer-style linear lattice proof backend";
const UPSTREAM_LAZER_REFERENCE: &str = "lazer-crypto/lazer";
const ENCODED_COORDINATES_PER_OPTION: u64 = 11;

pub const REQUIRED_LAZER_PORT_COMPONENTS: &[&str] = &[
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

pub const UPSTREAM_LAZER_REFERENCE_FILES: &[&str] = &[
    "src/lin-proofs.c",
    "src/lnp.c",
    "src/lnp-tbox.c",
    "src/lnp-quad.c",
    "src/lnp-quad-many.c",
    "src/lnp-quad-eval.c",
    "src/abdlop.c",
    "src/poly.c",
    "src/polyvec.c",
    "src/polymat.c",
    "src/spolyvec.c",
    "src/spolymat.c",
    "src/coder.c",
    "src/rejection.c",
    "src/rng.c",
    "src/shake128.c",
    "scripts/lin-codegen.sage",
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
        "upstreamReference": UPSTREAM_LAZER_REFERENCE,
        "upstreamDirectDependencyUsableInBrowser": false,
        "portableRustWasmPortRequired": true,
        "requiredComponents": REQUIRED_LAZER_PORT_COMPONENTS,
        "upstreamReferenceFiles": UPSTREAM_LAZER_REFERENCE_FILES,
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

fn is_protocol_digest(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        || string_field(receiver_key_proof, "proofBackend")
            != Some("LaZerStyleLocalLatticeRelation")
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
        string_field(receiver_key_proof, "publicRandomnessDigest").is_some(),
        proof_size_bytes.is_some(),
    ]
    .iter()
    .filter(|field_present| **field_present)
    .count();
    if proof_metadata_field_count > 0 && proof_metadata_field_count != 5 {
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
        || string_field(ballot_proof, "proofBackend") != Some("LaZerStyleLocalLatticeRelation")
        || string_field(ballot_proof, "backendStatementDigest")
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
) -> Vec<Value> {
    let Some(proof_bytes_hex) = proof_bytes_hex else {
        return Vec::new();
    };
    let mut refused_objects = Vec::new();
    let proof_bytes = match decode_hex(proof_bytes_hex) {
        Ok(proof_bytes) if !proof_bytes.is_empty() => proof_bytes,
        _ => {
            refused_objects.push(structural_refusal(
                format!("{proof_label} proof bytes must be non-empty lowercase hexadecimal bytes."),
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
    let package_digest = string_field(ballot_package, "ballotPackageDigest");

    if string_field(ballot_package, "objectType") != Some("BallotPackage")
        || package_object.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || package_digest != string_field(statement, "ballotPackageDigest")
    {
        refused_objects.push(structural_refusal(
            "Claim-bearing ballot package shell digest or shape is invalid.",
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
    let expected_public_randomness_digest =
        derive_receiver_key_public_randomness_digest(public_randomness_hex);
    let expected_linear_statement_digest =
        derive_receiver_key_linear_statement_digest(linear_statement);

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
    if string_field(receiver_key_proof, "publicRandomnessDigest")
        != expected_public_randomness_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied public randomness.",
            receiver_key_proof_root,
        ));
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

fn verify_ballot_linear_proof_bytes(
    statement: &Value,
    ballot_proof: &Value,
    linear_statement: &Value,
    proof_bytes_hex: &str,
    public_randomness_hex: &str,
    parameter_set: &Value,
    proof_encoding: &Value,
) -> Value {
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

    if linear_statement_digest != expected_linear_statement_digest.as_deref() {
        refused_objects.push(structural_refusal(
            "Ballot proof linear statement digest does not match its canonical payload.",
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
    if !refused_objects.is_empty() {
        return structural_rejection("verifyBallotProof", refused_objects);
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

pub fn verify_ballot_proof(
    statement: &Value,
    ballot_proof: &Value,
    proof_bytes_hex: Option<&str>,
    linear_statement: Option<&Value>,
    public_randomness_hex: Option<&str>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
) -> Value {
    let mut refused_objects = collect_ballot_proof_refusals(statement, ballot_proof);
    refused_objects.extend(collect_proof_bytes_refusals(
        proof_bytes_hex,
        string_field(ballot_proof, "proofBytesDigest"),
        object_map(ballot_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64),
        string_field(ballot_proof, "ballotProofRecordDigest"),
        "Ballot",
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyBallotProof", refused_objects);
    }

    match (
        linear_statement,
        proof_bytes_hex,
        public_randomness_hex,
        parameter_set,
        proof_encoding,
    ) {
        (None, _, None, None, None) => {}
        (
            Some(linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(parameter_set),
            Some(proof_encoding),
        ) => {
            return verify_ballot_linear_proof_bytes(
                statement,
                ballot_proof,
                linear_statement,
                proof_bytes_hex,
                public_randomness_hex,
                parameter_set,
                proof_encoding,
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
    use serde_json::{Value, json};

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
            "proofBackend": "LaZerStyleLocalLatticeRelation",
            "proofSizeBytes": 1024
        });
        let verification =
            super::verify_ballot_proof(&statement, &ballot_proof, None, None, None, None, None);

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
    fn malformed_receiver_key_proof_rejects_before_backend_gate() {
        let verification = super::verify_receiver_key_proof(
            &json!({
                "objectType": "ReceiverKeyProof",
                "objectVersion": 1,
                "proofBackend": "LaZerStyleLocalLatticeRelation",
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
        let create_receiver_key_proof = |linear_statement: &Value| {
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
                super::derive_receiver_key_proof_encoding_profile_digest(
                    &valid_case["proofEncoding"],
                )
                .expect("proof encoding profile digest should derive");
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
                "proofBackend": "LaZerStyleLocalLatticeRelation",
                "proofBytesDigest": proof_bytes_digest,
                "proofEncodingProfileDigest": proof_encoding_profile_digest,
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
        let valid_receiver_key_proof = create_receiver_key_proof(&valid_linear_statement);
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
        let mutated_receiver_key_proof = create_receiver_key_proof(&mutated_linear_statement);
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
    }

    #[test]
    fn proof_byte_bearing_ballot_record_verifies_against_linear_backend() {
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
        let create_linear_statement = |statement: &Value, target_vector_coefficients: Value| {
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
                "parameterProfileId": "lazer-linear-demo-compatibility-v1",
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
                "proofBackend": "LaZerStyleLocalLatticeRelation",
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
        let valid_linear_statement =
            create_linear_statement(&statement, valid_case["targetVectorCoefficients"].clone());
        let valid_ballot_proof = create_ballot_proof(&statement, &valid_linear_statement);
        let valid_verification = super::verify_ballot_proof(
            &statement,
            &valid_ballot_proof,
            Some(proof_bytes_hex),
            Some(&valid_linear_statement),
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
                .contains(&json!("BallotProofLinearProofVerified"))
        );

        let mutated_linear_statement = create_linear_statement(
            &statement,
            mutated_target_case["targetVectorCoefficients"].clone(),
        );
        let mutated_ballot_proof = create_ballot_proof(&statement, &mutated_linear_statement);
        let mutated_verification = super::verify_ballot_proof(
            &statement,
            &mutated_ballot_proof,
            Some(proof_bytes_hex),
            Some(&mutated_linear_statement),
            Some(public_randomness_hex),
            Some(&valid_case["parameterSet"]),
            Some(&valid_case["proofEncoding"]),
        );

        assert_eq!(mutated_verification["ok"], false);
        assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");
    }

    #[test]
    fn encoded_score_field_ballot_record_verifies_against_linear_backend() {
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
                "proofBackend": "LaZerStyleLocalLatticeRelation",
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
            Some(proof_bytes_hex),
            Some(&valid_linear_statement),
            Some(public_randomness_hex),
            Some(&valid_case["parameterSet"]),
            Some(&valid_case["proofEncoding"]),
        );

        assert_eq!(
            valid_verification["ok"], true,
            "encoded-score field ballot proof should verify: {valid_verification}"
        );
        assert_eq!(valid_verification["unresolvedReason"], Value::Null);
        assert!(
            valid_verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("BallotProofLinearProofVerified"))
        );

        let mutated_linear_statement = create_linear_statement(&statement, &mutated_target_case);
        let mutated_ballot_proof = create_ballot_proof(&statement, &mutated_linear_statement);
        let mutated_verification = super::verify_ballot_proof(
            &statement,
            &mutated_ballot_proof,
            Some(proof_bytes_hex),
            Some(&mutated_linear_statement),
            Some(public_randomness_hex),
            Some(&valid_case["parameterSet"]),
            Some(&valid_case["proofEncoding"]),
        );

        assert_eq!(mutated_verification["ok"], false);
        assert_eq!(mutated_verification["unresolvedReason"], "InvalidFixture");
    }
}
