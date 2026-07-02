use super::*;

pub(super) use crate::bgv::setup_helpers::{
    array_field, object_field, string_field, u64_field, usize_field,
};

use crate::bgv::setup_helpers::is_lowercase_protocol_hash;

pub(super) fn verify_setup_context(setup_context: &Value) -> CanonicalResult<()> {
    for field_name in setup_context_field_names() {
        if setup_context.get(field_name).is_none() {
            return Err(invalid_threshold_commitment_input(format!(
                "setupContext.{field_name} is required"
            )));
        }
    }
    for field_name in ["manifestHash", "rosterHash", "setupParametersHash"] {
        let hash = hash_string_field(setup_context, field_name)?;
        validate_hash_string(hash, &format!("setupContext.{field_name}"))?;
    }
    string_field(setup_context, "ceremonyId")?;
    string_field(setup_context, "setupEpoch")?;

    // The setup parameters hash is a roster family (distinct per participant
    // count), so it must be compared against the hash derived from this setup
    // context's roster, not the first-closure n = 10 hash. It subsumes the
    // former per-component parameter hashes (Q_share, carry-aware VSS relation,
    // commitment) and the BGV parameters.
    let roster = accepted_roster_from_setup_context(setup_context);
    if setup_context
        .get("setupParametersHash")
        .and_then(Value::as_str)
        != Some(setup_parameters_hash_for_roster(&roster)?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.setupParametersHash does not match the roster-derived CollectiveBgvSetup-v1 setup parameters",
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

pub(super) fn setup_context_field_names() -> [&'static str; 5] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ]
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

pub(super) fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if is_lowercase_protocol_hash(hash) {
        return Ok(());
    }

    Err(invalid_threshold_commitment_input(format!(
        "{field_name} must be a lowercase 512-bit hex protocol hash"
    )))
}

pub(super) fn invalid_threshold_commitment_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
