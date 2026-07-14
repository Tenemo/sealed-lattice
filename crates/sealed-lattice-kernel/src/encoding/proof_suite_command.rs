use serde_json::{Value, json};

use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::{
    bgv::proof_suite::{generate_proof_suite_candidate, validate_proof_profile_set_bytes},
    foundation::{CanonicalDecodeLimits, FOUNDATION_PROFILE},
    transcript_core::{decode_hex, encode_hex},
};

pub(super) fn validate_proof_profile_set_command(request: &Value) -> CanonicalResult<Value> {
    let request = request.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "proof-profile validation request must be an object",
        )
    })?;
    let canonical_bytes_hex = request
        .get("canonicalBytesHex")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "canonicalBytesHex must be a string",
            )
        })?;
    let canonical_bytes = decode_hex(canonical_bytes_hex)?;
    let limits = CanonicalDecodeLimits::default();
    if canonical_bytes.len() > limits.maximum_tuple_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "proof-profile set exceeds the supported byte limit",
        ));
    }
    let round_tripped_bytes =
        validate_proof_profile_set_bytes(&canonical_bytes, &limits).map_err(|error| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("proof-profile set validation failed: {error:?}"),
            )
        })?;
    Ok(json!({
        "canonicalBytesHex": encode_hex(&round_tripped_bytes),
    }))
}

pub(super) fn generate_proof_suite_candidate_command() -> CanonicalResult<Value> {
    let candidate =
        generate_proof_suite_candidate(FOUNDATION_PROFILE.participant_count).map_err(|error| {
            let message = if error.is_semantically_incomplete() {
                "proof-suite candidate generation is unavailable because required suite semantics are incomplete"
                    .to_string()
            } else {
                format!("proof-suite candidate generation failed: {error:?}")
            };
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                message,
            )
        })?;
    let artifacts = candidate
        .artifacts
        .iter()
        .map(|artifact| {
            json!({
                "artifactKind": artifact.reference.artifact_kind.canonical_code(),
                "canonicalArtifactHex": encode_hex(&artifact.canonical_bytes),
                "byteLength": artifact.reference.byte_length,
                "artifactHash": artifact.reference.artifact_hash.to_lowercase_hex(),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "suiteId": candidate.suite_id.to_lowercase_hex(),
        "canonicalSuiteRecordHex": encode_hex(&candidate.canonical_suite_record_bytes),
        "artifacts": artifacts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::proof_suite::generate_incomplete_development_proof_suite_candidate,
        foundation::SuiteArtifactKind,
    };

    #[test]
    fn command_refuses_to_publish_a_semantically_incomplete_suite() {
        let error = generate_proof_suite_candidate_command()
            .expect_err("incomplete artifact semantics must remain fail closed");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert_eq!(
            error.message,
            "proof-suite candidate generation is unavailable because required suite semantics are incomplete"
        );
    }

    #[test]
    fn validation_command_refuses_the_unlowered_candidate_profile() {
        let candidate = generate_incomplete_development_proof_suite_candidate(
            FOUNDATION_PROFILE.participant_count,
        )
        .expect("development transcript-domain candidate");
        let proof_profile = candidate
            .artifacts
            .iter()
            .find(|artifact| artifact.reference.artifact_kind == SuiteArtifactKind::ProofProfileSet)
            .expect("proof-profile artifact");
        let request = json!({
            "command": "ValidateProofProfileSet",
            "canonicalBytesHex": encode_hex(&proof_profile.canonical_bytes),
        });
        let error = validate_proof_profile_set_command(&request)
            .expect_err("unlowered semantic plans must remain fail closed");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("IncompleteSemanticPlan"));
    }
}
