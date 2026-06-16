use super::*;

pub(super) fn verify_setup_context(setup_context: &Value) -> CanonicalResult<()> {
    for field_name in setup_context_field_names() {
        if setup_context.get(field_name).is_none() {
            return Err(invalid_threshold_commitment_input(format!(
                "setupContext.{field_name} is required"
            )));
        }
    }
    for field_name in [
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
    ] {
        let hash = hash_string_field(setup_context, field_name)?;
        validate_hash_string(hash, &format!("setupContext.{field_name}"))?;
    }
    string_field(setup_context, "ceremonyId")?;
    string_field(setup_context, "setupEpoch")?;

    if setup_context
        .get("setupProfileHash")
        .and_then(Value::as_str)
        != Some(accepted_setup_profile_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.setupProfileHash does not match CollectiveBgvSetup-v1",
        ));
    }
    if setup_context.get("qShareHash").and_then(Value::as_str)
        != Some(accepted_q_share_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.qShareHash does not match the accepted Q_share prime list",
        ));
    }
    if setup_context
        .get("carryAwareVssShareRelationProfileHash")
        .and_then(Value::as_str)
        != Some(carry_aware_vss_share_relation_profile_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.carryAwareVssShareRelationProfileHash does not match the accepted carry-aware VSS relation profile",
        ));
    }
    if setup_context
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.commitmentProfileHash does not match the accepted setup commitment profile",
        ));
    }

    Ok(())
}

pub(super) fn compare_context_fields(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> CanonicalResult<()> {
    for field_name in setup_context_field_names() {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(invalid_threshold_commitment_input(format!(
                "{object_path}.{field_name} must match setupContext"
            )));
        }
    }

    Ok(())
}

pub(super) fn copy_context_fields(
    target: &mut Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    let target_object = target.as_object_mut().ok_or_else(|| {
        invalid_threshold_commitment_input("target context binding value must be an object")
    })?;
    for field_name in setup_context_field_names() {
        let field_value = setup_context.get(field_name).ok_or_else(|| {
            invalid_threshold_commitment_input(format!("setupContext.{field_name} is required"))
        })?;
        target_object.insert(field_name.to_string(), field_value.clone());
    }

    Ok(())
}

pub(super) fn setup_context_field_names() -> [&'static str; 8] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ]
}

pub(super) fn object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!("{field_name} must be an object"))
        })
}

pub(super) fn array_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_threshold_commitment_input(format!("{field_name} must be an array")))
}

pub(super) fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!("{field_name} must be a non-empty string"))
        })
}

pub(super) fn derivation_stream_id_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    let derivation_id = string_field(value, field_name)?;
    if derivation_id.len() > VSS_TRANSPORT_STREAM_DERIVATION_ID_MAX_BYTES
        || !derivation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid_threshold_commitment_input(format!(
            "{field_name} must be a bounded ASCII derivation identifier"
        )));
    }

    Ok(derivation_id)
}

pub(super) fn hash_string_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!(
                "{field_name} must be a protocol hash string"
            ))
        })
}

pub(super) fn u64_field(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!(
                "{field_name} must be a non-negative integer"
            ))
        })
}

pub(super) fn usize_field(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let field_value = u64_field(value, field_name)?;
    usize::try_from(field_value)
        .map_err(|_| invalid_threshold_commitment_input(format!("{field_name} does not fit usize")))
}

pub(super) fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_threshold_commitment_input(format!(
        "{field_name} must be a lowercase 512-bit hex protocol hash"
    )))
}

pub(super) fn invalid_threshold_commitment_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
