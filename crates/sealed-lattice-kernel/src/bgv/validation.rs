use serde_json::{Value, json};

use crate::{
    bgv::serialization::{BgvObjectKind, ciphertext_root, parse_bgv_object, plaintext_root},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    transcript_core::decode_hex,
};

pub(crate) fn bgv_operation_rejection(
    operation: &str,
    reason_code: &str,
    message: impl Into<String>,
    object_hash: Option<&str>,
) -> Value {
    let mut refused_object = json!({
        "code": "BgvOperationRejected",
        "reasonCode": reason_code,
        "message": message.into(),
    });
    if let Some(hash) = object_hash {
        refused_object["objectHash"] = Value::String(hash.to_string());
    }

    json!({
        "isValid": false,
        "operation": operation,
        "refusedObjects": [refused_object],
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
            CanonicalErrorCode::ComponentMismatch,
            "BGV plaintext root does not match the expected root",
        ));
    }

    Ok(json!({
        "isValid": true,
        "objectKind": "plaintext",
        "componentCount": object.components.len(),
        "bgvParametersHash": object.components[0].bgv_parameters_hash,
        "basisId": object.components[0].basis_id,
        "level": object.components[0].level,
        "coefficientCount": object.components[0].coefficient_count,
        "plaintextRoot": root,
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
            CanonicalErrorCode::ComponentMismatch,
            "BGV ciphertext root does not match the expected root",
        ));
    }
    let first = &object.components[0];
    if object.components.iter().any(|component| {
        component.bgv_parameters_hash != first.bgv_parameters_hash
            || component.basis_id != first.basis_id
            || component.level != first.level
            || component.coefficient_count != first.coefficient_count
            || component.moduli != first.moduli
    }) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "BGV ciphertext components do not share one canonical parameter set, basis, and level",
        ));
    }

    Ok(json!({
        "isValid": true,
        "objectKind": "ciphertext",
        "componentCount": object.components.len(),
        "bgvParametersHash": first.bgv_parameters_hash,
        "basisId": first.basis_id,
        "level": first.level,
        "coefficientCount": first.coefficient_count,
        "ciphertextRoot": root,
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
            validate_plaintext_hex(&canonical_bytes_hex, Some(&root)).expect("validate")["isValid"]
                .as_bool()
                .expect("ok")
        );
        assert!(validate_plaintext_hex(&canonical_bytes_hex, Some("wrong")).is_err());
    }
}
