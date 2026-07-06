use super::*;

pub(super) fn array_value<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })
}

// The accepted VSS coefficient commitment root that later phases (private VSS
// envelopes, share acceptances, transport) bind against: the coefficient
// commitment set root.
pub(in super::super) fn accepted_vss_coefficient_commitment_root(
    setup_package: &Value,
) -> Option<&str> {
    setup_package
        .get("vssPublicCoefficientCommitmentSet")
        .and_then(|commitment_set| commitment_set.get("coefficientCommitmentRoot"))
        .and_then(Value::as_str)
}

pub(super) fn value_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })
}

pub(super) fn value_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-negative integer"),
            )
        })
}

// Ceremony-identifying setup-context fields a bound object must carry
// identically so a bound artifact cannot be transplanted across ceremonies,
// rosters, parameter sets, or epochs. Used by the VSS public-material
// binding checks.
const SETUP_CONTEXT_BINDING_FIELDS: [&str; 5] = [
    "ceremonyId",
    "manifestHash",
    "rosterHash",
    "setupParametersHash",
    "setupEpoch",
];

pub(super) fn setup_context_binding_value<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    match field_name {
        "ceremonyId" | "setupEpoch" => value_string(value, field_name),
        _ => hash_at_path(value, &[field_name]),
    }
}

pub(super) fn compare_required_u64_binding(
    actual: u64,
    expected: u64,
    description: &str,
) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{description} does not match its setup-context binding"),
        ));
    }

    Ok(())
}

pub(super) fn compare_setup_context_binding(
    setup_context: &Value,
    bound_value: &Value,
    bound_object_description: &str,
) -> CanonicalResult<()> {
    for field_name in SETUP_CONTEXT_BINDING_FIELDS {
        let actual = setup_context_binding_value(bound_value, field_name)?;
        let expected = setup_context_binding_value(setup_context, field_name)?;
        compare_required_string(
            actual,
            expected,
            &format!("{bound_object_description} {field_name}"),
        )?;
    }

    Ok(())
}

pub(super) fn compare_setup_context_participant_count(
    setup_context: &Value,
    bound_value: &Value,
    bound_object_description: &str,
) -> CanonicalResult<()> {
    compare_required_u64_binding(
        value_u64(bound_value, "participantCount")?,
        value_u64(setup_context, "participantCount")?,
        &format!("{bound_object_description} participantCount"),
    )
}

pub(super) fn compare_setup_context_threshold_degree(
    setup_context: &Value,
    bound_value: &Value,
    bound_object_description: &str,
) -> CanonicalResult<()> {
    compare_required_u64_binding(
        value_u64(bound_value, "thresholdDegree")?,
        value_u64(setup_context, "qDec")?,
        &format!("{bound_object_description} thresholdDegree"),
    )
}

pub(super) fn validate_lowercase_hex(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{field_name} must be lowercase canonical hex"),
    ))
}

pub(super) fn validate_lowercase_hex_length(
    value: &str,
    expected_byte_length: usize,
    field_name: &str,
) -> CanonicalResult<()> {
    validate_lowercase_hex(value, field_name)?;
    if value.len() == expected_byte_length * 2 {
        return Ok(());
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{field_name} must be {expected_byte_length} bytes"),
    ))
}
