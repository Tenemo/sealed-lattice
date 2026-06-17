use super::*;

pub(super) fn expect_transport_string(
    value: &Value,
    field_name: &'static str,
    expected_value: &str,
    reason_code: &'static str,
    message: &'static str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_str) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("setupTransportCertificate.{field_name} is required"),
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
    }
}

pub(super) fn expect_transport_u64(
    value: &Value,
    field_name: &'static str,
    expected_value: u64,
    reason_code: &'static str,
    message: &'static str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_u64) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("setupTransportCertificate.{field_name} is required"),
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )),
    }
}

pub(super) fn expect_transport_string_at(
    value: &Value,
    field_name: &'static str,
    expected_value: &str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_str) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} is required"),
            format!("{object_path}.{field_name}"),
        )),
    }
}

pub(super) fn require_transport_non_empty_string_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<String, Refusal> {
    let Some(field_value) = value.get(field_name).and_then(Value::as_str) else {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    };
    if field_value.is_empty() {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(field_value.to_string())
}

pub(super) fn expect_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    expected_value: u64,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<(), Refusal> {
    match value.get(field_name).and_then(Value::as_u64) {
        Some(observed_value) if observed_value == expected_value => Ok(()),
        Some(_) => Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        )),
        None => Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} is required"),
            format!("{object_path}.{field_name}"),
        )),
    }
}

pub(super) fn require_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<u64, Refusal> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(reason_code, message, format!("{object_path}.{field_name}")))
}

pub(super) fn require_positive_transport_u64_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<u64, Refusal> {
    let field_value =
        require_transport_u64_at(value, field_name, reason_code, message, object_path)?;
    if field_value == 0 {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(field_value)
}

pub(super) fn require_transport_hash_at(
    value: &Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
    object_path: &str,
) -> Result<String, Refusal> {
    let Some(hash) = value.get(field_name).and_then(Value::as_str) else {
        return Err(Refusal::new(
            reason_code,
            message,
            format!("{object_path}.{field_name}"),
        ));
    };
    if hash.len() != 128
        || !hash
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(Refusal::new(
            reason_code,
            format!("{object_path}.{field_name} must be a protocol hash"),
            format!("{object_path}.{field_name}"),
        ));
    }

    Ok(hash.to_string())
}

pub(super) fn require_transport_hash<'a>(
    value: &'a Value,
    field_name: &'static str,
    reason_code: &'static str,
    message: &'static str,
) -> CanonicalResult<Result<&'a str, Refusal>> {
    let Some(hash) = value.get(field_name).and_then(Value::as_str) else {
        return Ok(Err(Refusal::new(
            reason_code,
            message,
            format!("setupPackage.setupTransportCertificate.{field_name}"),
        )));
    };
    validate_hash_string(hash, &format!("setupTransportCertificate.{field_name}"))?;

    Ok(Ok(hash))
}

pub(super) fn setup_transport_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
