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
    object_hash: Option<&str>,
) -> Value {
    let mut refused_object = json!({
        "code": "BGVProfileRejected",
        "reasonCode": reason_code,
        "message": message.into(),
    });
    if let Some(hash) = object_hash {
        refused_object["objectHash"] = Value::String(hash.to_string());
    }

    json!({
        "ok": false,
        "operation": operation,
        "acceptedHashes": [],
        "refusedObjects": [refused_object],
        "unresolvedReason": "BGVProfileRejected",
    })
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
        "profileHash": object.components[0].profile_hash,
        "basisId": object.components[0].basis_id,
        "level": object.components[0].level,
        "coefficientCount": object.components[0].coefficient_count,
        "layoutHash": object.components[0].encrypted_ballot_aggregate_layout_hash,
        "plaintextRoot": root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
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
        component.profile_hash != first.profile_hash
            || component.basis_id != first.basis_id
            || component.level != first.level
            || component.coefficient_count != first.coefficient_count
            || component.encrypted_ballot_aggregate_layout_hash
                != first.encrypted_ballot_aggregate_layout_hash
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
        "profileHash": first.profile_hash,
        "basisId": first.basis_id,
        "level": first.level,
        "coefficientCount": first.coefficient_count,
        "layoutHash": first.encrypted_ballot_aggregate_layout_hash,
        "ciphertextRoot": root,
        "canonicalBytesHash512": canonical_bytes_hash(&canonical_bytes),
    }))
}

#[cfg(test)]
mod tests {
    use super::validate_plaintext_hex;
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
}
