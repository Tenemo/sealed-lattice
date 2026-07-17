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
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{field_name} must be an array"),
            )
        })
}

pub(in super::super) fn accepted_vss_coefficient_commitment_root(
    setup_package: &Value,
) -> CanonicalResult<String> {
    let commitment_set = setup_package
        .get("vssPublicCoefficientCommitmentSet")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "VSS public coefficient commitment set is required",
            )
        })?;
    let expected_trustees = setup_intent::expected_trustees_from_setup_intent(
        &setup_intent::setup_intent_trustee_registrations_from_package(setup_package)?,
    );
    let trustee_identities = (0..expected_trustees.len())
        .map(|roster_position| {
            expected_trustees
                .get(&(roster_position as u64))
                .cloned()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup-intent trustee positions must be contiguous",
                    )
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    crate::bgv::setup::vss_commitment::vss_public_coefficient_commitment_set_root(
        commitment_set,
        &trustee_identities,
    )
}

pub(super) fn value_string<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
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
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{field_name} must be a non-negative integer"),
            )
        })
}

pub(in super::super) fn setup_context_hash(setup_context: &Value) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "CollectiveBgvSetupContext",
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupParametersHash": value_string(setup_context, "setupParametersHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "participantCount": value_u64(setup_context, "participantCount")?,
    }))
}

pub(super) fn compare_setup_context_binding(
    setup_context: &Value,
    bound_value: &Value,
    bound_object_description: &str,
) -> CanonicalResult<()> {
    compare_required_string(
        value_string(bound_value, "setupContextHash")?,
        &setup_context_hash(setup_context)?,
        &format!("{bound_object_description} setupContextHash"),
    )
}

#[cfg(test)]
pub(super) fn compare_complete_q_share_limb_count(
    bound_value: &Value,
    bound_object_description: &str,
) -> CanonicalResult<()> {
    compare_required_u64(
        value_u64(bound_value, "qShareRnsLimbCount")?,
        DATA_PRIMES.len() as u64,
        &format!("{bound_object_description} qShareRnsLimbCount"),
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
        CanonicalErrorCode::InvalidProtocolObject,
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
        CanonicalErrorCode::InvalidProtocolObject,
        format!("{field_name} must be {expected_byte_length} bytes"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_q_share_limb_count_requires_every_data_prime() {
        compare_complete_q_share_limb_count(
            &json!({ "qShareRnsLimbCount": DATA_PRIMES.len() }),
            "test statement",
        )
        .expect("the complete Q_share basis must pass");

        let error = compare_complete_q_share_limb_count(
            &json!({ "qShareRnsLimbCount": DATA_PRIMES.len() - 1 }),
            "test statement",
        )
        .expect_err("a strict Q_share prefix must not pass accepted setup");
        assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
        assert!(error.message.contains("qShareRnsLimbCount"));
    }
}
