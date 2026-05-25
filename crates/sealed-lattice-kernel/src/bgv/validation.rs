use serde_json::{Value, json};

use crate::{
    bgv::serialization::{
        BgvObjectKind, canonical_bytes_hash, ciphertext_root, parse_bgv_object, plaintext_root,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    transcript_core::decode_hex,
};

pub(crate) fn bgv_profile_rejection(
    operation: &str,
    reason_code: &str,
    message: impl Into<String>,
    object_digest: Option<&str>,
) -> Value {
    let mut refused_object = json!({
        "code": "BGVProfileRejected",
        "reasonCode": reason_code,
        "message": message.into(),
    });
    if let Some(digest) = object_digest {
        refused_object["objectDigest"] = Value::String(digest.to_string());
    }

    json!({
        "ok": false,
        "operation": operation,
        "acceptedDigests": [],
        "refusedObjects": [refused_object],
        "unresolvedReason": "BGVProfileRejected",
        "statusLabels": [
            "BGVProfileRejected"
        ],
    })
}

pub(crate) fn bgv_profile_rejection_from_error(operation: &str, error: &CanonicalError) -> Value {
    bgv_profile_rejection(
        operation,
        rejection_reason_code(error),
        &error.message,
        None,
    )
}

fn rejection_reason_code(error: &CanonicalError) -> &'static str {
    match error.code {
        CanonicalErrorCode::ProfileComponentMismatch => "ProfileMismatch",
        CanonicalErrorCode::MalformedMagic
        | CanonicalErrorCode::InvalidUtf8
        | CanonicalErrorCode::InvalidEnum
        | CanonicalErrorCode::MalformedLength
        | CanonicalErrorCode::TrailingBytes
        | CanonicalErrorCode::InvalidFixture
        | CanonicalErrorCode::NonCanonicalVarUint => "InvalidCanonicalEncoding",
        CanonicalErrorCode::InvalidChunkSize
        | CanonicalErrorCode::InvalidHex
        | CanonicalErrorCode::MalformedVarUint
        | CanonicalErrorCode::MissingField
        | CanonicalErrorCode::UnsupportedCanonicalEnvelopeVersion
        | CanonicalErrorCode::UnsupportedObjectType
        | CanonicalErrorCode::UnsupportedObjectVersion
        | CanonicalErrorCode::UnknownBaseClaimProfile
        | CanonicalErrorCode::UnknownField
        | CanonicalErrorCode::UnknownMheSecurityClosure
        | CanonicalErrorCode::UnknownProofProfile
        | CanonicalErrorCode::DuplicateField
        | CanonicalErrorCode::FieldOrder
        | CanonicalErrorCode::FixtureMismatch => "InvalidParameters",
    }
}

pub(crate) fn validate_plaintext_hex(
    canonical_bytes_hex: &str,
    expected_plaintext_root: Option<&str>,
) -> CanonicalResult<Value> {
    let canonical_bytes = decode_hex(canonical_bytes_hex)?;
    let object = parse_bgv_object(&canonical_bytes)?;
    if object.object_kind != BgvObjectKind::Plaintext {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV plaintext validation received a non-plaintext object",
        ));
    }
    let root = plaintext_root(&canonical_bytes);
    if let Some(expected_root) = expected_plaintext_root
        && expected_root != root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "BGV plaintext root does not match the expected root",
        ));
    }

    Ok(json!({
        "ok": true,
        "objectKind": "plaintext",
        "componentCount": object.components.len(),
        "profileDigest": object.components[0].profile_digest,
        "basisId": object.components[0].basis_id,
        "level": object.components[0].level,
        "coefficientCount": object.components[0].coefficient_count,
        "layoutDigest": object.components[0].layout_digest,
        "plaintextRoot": root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "statusLabels": [
            "BGVProfileVerified",
            "CoefficientDomainCanonical",
            "PlaintextRootBound"
        ],
    }))
}

pub(crate) fn validate_ciphertext_hex(
    canonical_bytes_hex: &str,
    expected_ciphertext_root: Option<&str>,
) -> CanonicalResult<Value> {
    let canonical_bytes = decode_hex(canonical_bytes_hex)?;
    let object = parse_bgv_object(&canonical_bytes)?;
    if object.object_kind != BgvObjectKind::Ciphertext {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV ciphertext validation received a non-ciphertext object",
        ));
    }
    let root = ciphertext_root(&canonical_bytes);
    if let Some(expected_root) = expected_ciphertext_root
        && expected_root != root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "BGV ciphertext root does not match the expected root",
        ));
    }
    let first = &object.components[0];
    if object.components.iter().any(|component| {
        component.profile_digest != first.profile_digest
            || component.basis_id != first.basis_id
            || component.level != first.level
            || component.coefficient_count != first.coefficient_count
            || component.layout_digest != first.layout_digest
            || component.moduli != first.moduli
    }) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "BGV ciphertext components do not share one canonical profile, basis, level, and layout",
        ));
    }

    Ok(json!({
        "ok": true,
        "objectKind": "ciphertext",
        "componentCount": object.components.len(),
        "profileDigest": first.profile_digest,
        "basisId": first.basis_id,
        "level": first.level,
        "coefficientCount": first.coefficient_count,
        "layoutDigest": first.layout_digest,
        "ciphertextRoot": root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
        "statusLabels": [
            "BGVProfileVerified",
            "CoefficientDomainCanonical",
            "CiphertextRootBound"
        ],
    }))
}

pub(crate) fn reject_reference_oracle_artifact(artifact: &Value) -> Value {
    let artifact_kind = artifact
        .get("artifactKind")
        .and_then(Value::as_str)
        .unwrap_or("unknown-reference-artifact");

    json!({
        "ok": false,
        "artifactKind": artifact_kind,
        "acceptedAsProtocolEvidence": false,
        "statusLabels": [
            "ReferenceOracleRejected",
            "LattigoSerializationRejected",
            "RuntimeOracleDependencyRejected"
        ],
        "refusedObjects": [
            {
                "code": "ReferenceOracleBoundary",
                "message": "Lattigo, Docker, and oracle vectors are development-only parity material and are not sealed-lattice transcript objects."
            }
        ],
    })
}

pub(crate) fn reject_if_oracle_boundary_fields_present(request: &Value) -> CanonicalResult<()> {
    const FORBIDDEN_FIELDS: [&str; 14] = [
        "lattigoObject",
        "lattigoPublicKey",
        "lattigoRelinearizationKey",
        "lattigoRotationKey",
        "lattigoSerializationHex",
        "lattigoSetupKeyVector",
        "lattigoKeySerialization",
        "dockerOracleOutput",
        "oracleSetupSerializer",
        "oracleKeySerializer",
        "oracleVector",
        "referenceOracleVectorRoot",
        "referenceOracleProfileDigest",
        "oracleAcceptedAsEvidence",
    ];
    for field_name in FORBIDDEN_FIELDS {
        if request.get(field_name).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{field_name} is development-only oracle material and cannot be accepted by BGV object validation"
                ),
            ));
        }
    }

    Ok(())
}

pub(crate) fn reject_unexpected_bgv_request_fields(
    request: &Value,
    allowed_fields: &[&str],
    operation: &str,
) -> CanonicalResult<()> {
    reject_if_oracle_boundary_fields_present(request)?;
    let Some(request_object) = request.as_object() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{operation} request must be a JSON object"),
        ));
    };
    for field_name in request_object.keys() {
        if field_name == "command" {
            continue;
        }
        if !allowed_fields
            .iter()
            .any(|allowed_field_name| allowed_field_name == field_name)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{operation} request field {field_name} is not part of the accepted BGV request schema"
                ),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        reject_if_oracle_boundary_fields_present, reject_reference_oracle_artifact,
        reject_unexpected_bgv_request_fields, validate_plaintext_hex,
    };
    use crate::bgv::{
        encoding::encode_batch_plaintext_slots,
        serialization::{BgvObjectKind, canonical_bytes_hex, plaintext_root, serialize_bgv_object},
    };

    #[test]
    fn plaintext_validation_binds_exact_root() {
        let encoded = encode_batch_plaintext_slots(&[1, 2, 3], 0).expect("encode");
        let canonical_bytes = serialize_bgv_object(BgvObjectKind::Plaintext, &[encoded.polynomial])
            .expect("serialize");
        let canonical_bytes_hex = canonical_bytes_hex(&canonical_bytes);
        let root = plaintext_root(&canonical_bytes);

        assert!(
            validate_plaintext_hex(&canonical_bytes_hex, Some(&root)).expect("validate")["ok"]
                .as_bool()
                .expect("ok")
        );
        assert!(validate_plaintext_hex(&canonical_bytes_hex, Some("wrong")).is_err());
    }

    #[test]
    fn oracle_boundary_material_is_rejected() {
        for field_name in [
            "referenceOracleVectorRoot",
            "lattigoSetupKeyVector",
            "lattigoPublicKey",
            "lattigoRelinearizationKey",
            "lattigoRotationKey",
            "lattigoKeySerialization",
            "oracleSetupSerializer",
            "oracleKeySerializer",
        ] {
            assert!(
                reject_if_oracle_boundary_fields_present(&serde_json::json!({
                    field_name: "abc"
                }))
                .is_err(),
                "{field_name} should be rejected"
            );
        }
        assert_eq!(
            reject_reference_oracle_artifact(&serde_json::json!({
                "artifactKind": "lattigo-vector"
            }))["acceptedAsProtocolEvidence"],
            false
        );
    }

    #[test]
    fn bgv_request_field_allowlist_rejects_future_oracle_fields() {
        assert!(
            reject_unexpected_bgv_request_fields(
                &serde_json::json!({
                    "command": "ValidateBgvPlaintextObject",
                    "canonicalBytesHex": "00",
                    "futureOracleTranscript": "abc"
                }),
                &["canonicalBytesHex"],
                "validateBgvPlaintextObject"
            )
            .is_err()
        );
        assert!(
            reject_unexpected_bgv_request_fields(
                &serde_json::json!({
                    "command": "ValidateBgvPlaintextObject",
                    "canonicalBytesHex": "00"
                }),
                &["canonicalBytesHex"],
                "validateBgvPlaintextObject"
            )
            .is_ok()
        );
    }
}
