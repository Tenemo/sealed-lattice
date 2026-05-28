use serde_json::{Value, json};

use super::BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE;

pub(crate) const BACKEND_NAME: &str = "linear lattice proof backend";

pub(crate) fn describe_proof_backend() -> Value {
    json!({
        "backendName": BACKEND_NAME,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "portableRustWasmPortRequired": false,
        "requiredComponents": [],
        "blockedReason": Value::Null
    })
}

pub(crate) fn structural_rejection(operation: &str, refused_objects: Vec<Value>) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": [],
        "acceptedHashes": [],
        "refusedObjects": refused_objects,
        "unresolvedReason": "BallotPackageInvalid"
    })
}

pub(crate) fn structural_refusal(message: impl Into<String>, object_hash: Option<&str>) -> Value {
    let message = message.into();
    match object_hash {
        Some(object_hash) => json!({
            "code": "BallotPackageInvalid",
            "message": message,
            "objectHash": object_hash
        }),
        None => json!({
            "code": "BallotPackageInvalid",
            "message": message
        }),
    }
}
