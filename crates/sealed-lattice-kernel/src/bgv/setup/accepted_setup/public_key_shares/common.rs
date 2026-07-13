use super::*;

pub(in super::super) struct PublicKeyCommonBinding {
    pub(in super::super) public_matrix_seed_hash: String,
}

pub(in super::super) fn public_key_common_binding(
    setup_package: &Value,
) -> CanonicalResult<PublicKeyCommonBinding> {
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before public-key share verification",
        )
    })?;
    let public_matrix_seed_hash = value_string(common_randomness, "publicMatrixSeedHash")?;
    Ok(PublicKeyCommonBinding {
        public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
    })
}

pub(super) fn verify_public_key_common_fields(
    value: &Value,
    common_binding: &PublicKeyCommonBinding,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    for (field_name, expected_value) in [(
        "publicMatrixSeedHash",
        common_binding.public_matrix_seed_hash.as_str(),
    )] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            let message =
                format!("{object_path}.{field_name} must match accepted common randomness");
            let path = format!("setupPackage.{object_path}.{field_name}");
            return Ok(Some(public_key_refusal(
                "publicKeyShareCommonBindingMismatch",
                message,
                path,
            )?));
        }
    }

    Ok(None)
}

pub(in super::super) fn public_key_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    )
}
