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
pub mod sparse_polynomial_matrix;
pub mod sparse_polynomial_vector;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::hashing::derive_protocol_digest;

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

fn collect_receiver_key_proof_refusals(receiver_key_proof: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let object_digest = string_field(receiver_key_proof, "receiverKeyProofRoot");
    let expected_digest = value_without_field(receiver_key_proof, "receiverKeyProofRoot")
        .and_then(|payload| derive_digest("ReceiverKeyProofRoot", &payload));

    if string_field(receiver_key_proof, "objectType") != Some("ReceiverKeyProof")
        || object_map(receiver_key_proof)
            .and_then(|object| object.get("objectVersion"))
            .and_then(Value::as_u64)
            != Some(1)
        || string_field(receiver_key_proof, "proofBackend")
            != Some("LaZerStyleLocalLatticeRelation")
        || string_field(receiver_key_proof, "proofRoot")
            .is_none_or(|proof_root| !is_protocol_digest(proof_root))
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof shell has an invalid canonical shape.",
            object_digest,
        ));
    }
    if expected_digest.as_deref() != object_digest {
        refused_objects.push(structural_refusal(
            "Receiver key proof root does not match its canonical payload.",
            object_digest,
        ));
    }

    refused_objects
}

fn collect_ballot_proof_refusals(statement: &Value, ballot_proof: &Value) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let statement_digest = string_field(statement, "ballotProofStatementDigest");
    let proof_record_digest = string_field(ballot_proof, "ballotProofRecordDigest");
    let expected_statement_digest = value_without_field(statement, "ballotProofStatementDigest")
        .and_then(|payload| derive_digest("BallotProofStatementDigest", &payload));
    let expected_proof_record_digest = value_without_field(ballot_proof, "ballotProofRecordDigest")
        .and_then(|payload| derive_digest("BallotProofRecordDigest", &payload));
    let expected_challenge_digest = match (
        statement_digest,
        string_field(statement, "challengeDomainDigest"),
        string_field(ballot_proof, "proofBytesDigest"),
        string_field(ballot_proof, "proofRoot"),
        string_field(ballot_proof, "relationStatementDigest"),
    ) {
        (
            Some(ballot_proof_statement_digest),
            Some(challenge_domain_digest),
            Some(proof_bytes_digest),
            Some(proof_root),
            Some(relation_statement_digest),
        ) => derive_digest(
            "ChallengeDomainDigest",
            &json!({
                "ballotProofStatementDigest": ballot_proof_statement_digest,
                "challengeDomainDigest": challenge_domain_digest,
                "proofBytesDigest": proof_bytes_digest,
                "proofRoot": proof_root,
                "relationStatementDigest": relation_statement_digest,
            }),
        ),
        _ => None,
    };

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
        || string_field(ballot_proof, "relationStatementDigest")
            .is_none_or(|digest| !is_protocol_digest(digest))
        || object_map(ballot_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .and_then(Value::as_u64)
            .is_none_or(|proof_size_bytes| proof_size_bytes == 0)
    {
        refused_objects.push(structural_refusal(
            "Ballot proof record has an invalid canonical shape.",
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

pub fn verify_receiver_key_proof(receiver_key_proof: &Value) -> Value {
    let refused_objects = collect_receiver_key_proof_refusals(receiver_key_proof);
    if !refused_objects.is_empty() {
        return structural_rejection("verifyReceiverKeyProof", refused_objects);
    }

    fail_closed("verifyReceiverKeyProof")
}

pub fn verify_ballot_proof(statement: &Value, ballot_proof: &Value) -> Value {
    let refused_objects = collect_ballot_proof_refusals(statement, ballot_proof);
    if !refused_objects.is_empty() {
        return structural_rejection("verifyBallotProof", refused_objects);
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

#[cfg(test)]
mod tests {
    use serde_json::json;

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
        let verification = super::verify_ballot_proof(&statement, &ballot_proof);

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
        let verification = super::verify_receiver_key_proof(&json!({
            "objectType": "ReceiverKeyProof",
            "objectVersion": 1,
            "proofBackend": "LaZerStyleLocalLatticeRelation",
            "receiverKeyProofRoot": "00"
        }));

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["unresolvedReason"], "BallotPackageInvalid");
        assert_eq!(
            verification["refusedObjects"][0]["code"],
            "BallotPackageInvalid"
        );
    }
}
