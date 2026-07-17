use super::*;

const MAX_SETUP_CONTEXT_TOKEN_BYTES: usize = 128;

// Restricting these tokens keeps them safe as hash and signature-context inputs: no delimiters, no control bytes, and a bounded preimage length.
fn validate_setup_context_token(field_name: &str, value: &str) -> Option<Refusal> {
    if value.is_empty() {
        return Some(Refusal::new(
            crate::foundation::RefusalReason::MissingPrerequisite,
            format!("setupContext.{field_name} must be a non-empty setup context token"),
        ));
    }
    if value.len() > MAX_SETUP_CONTEXT_TOKEN_BYTES {
        return Some(Refusal::new(
            crate::foundation::RefusalReason::MalformedEncoding,
            format!(
                "setupContext.{field_name} must be at most {MAX_SETUP_CONTEXT_TOKEN_BYTES} bytes"
            ),
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
    }) {
        return Some(Refusal::new(
            crate::foundation::RefusalReason::MalformedEncoding,
            format!(
                "setupContext.{field_name} contains a character outside the setup context token alphabet"
            ),
        ));
    }

    None
}

pub(super) fn verify_context(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Refusals>> {
    let Some(setup_context) = setup_package.get("setupContext") else {
        return Ok(Some(setup_refusals(
            vec!["setupContext".to_string()],
            Vec::new(),
        )));
    };
    if !setup_context.is_object() {
        return Ok(Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::MalformedEncoding,
                "setupContext must be a JSON object",
            )],
        )));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if setup_context.get(field_name).is_none() {
            return Ok(Some(setup_refusals(
                vec![format!("setupContext.{field_name}")],
                Vec::new(),
            )));
        }
    }
    for field_name in ["manifestHash", "rosterHash", "setupParametersHash"] {
        let Some(field_value) = setup_context.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(setup_refusals(
                Vec::new(),
                vec![Refusal::new(
                    crate::foundation::RefusalReason::MalformedEncoding,
                    format!("setupContext.{field_name} must be a protocol hash"),
                )],
            )));
        };
        validate_hash_string(field_value, &format!("setupContext.{field_name}"))?;
    }
    for field_name in ["ceremonyId", "setupEpoch"] {
        let Some(field_value) = setup_context.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(setup_refusals(
                Vec::new(),
                vec![Refusal::new(
                    crate::foundation::RefusalReason::MalformedEncoding,
                    format!("setupContext.{field_name} must be a setup context token"),
                )],
            )));
        };
        if let Some(refusal) = validate_setup_context_token(field_name, field_value) {
            return Ok(Some(setup_refusals(Vec::new(), vec![refusal])));
        }
    }

    let Some(participant_count) = setup_context
        .get("participantCount")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(setup_refusals(
            vec!["setupContext.participantCount".to_string()],
            Vec::new(),
        )));
    };
    if !participant_count_is_configurable(participant_count) {
        return Ok(Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::OutsideSupportedProfile,
                "setupContext.participantCount must be an integer from 3 through 20",
            )],
        )));
    }
    let roster = roster_parameters_from_participant_count(participant_count);
    // The setup parameters hash is a roster family (distinct per participant
    // count), so it is compared against the hash derived from this setup
    // context's roster. It binds the evaluator key schedule and the canonical
    // BGV parameters, including the exact ordered data-prime basis.
    let expected_setup_parameters_hash = setup_parameters_hash_for_roster(&roster)?;
    if setup_context
        .get("setupParametersHash")
        .and_then(Value::as_str)
        != Some(expected_setup_parameters_hash.as_str())
    {
        return Ok(Some(setup_refusals(
            Vec::new(),
            vec![Refusal::new(
                crate::foundation::RefusalReason::WrongHashOrRoot,
                "setupContext.setupParametersHash does not match the roster-derived collective BGV setup parameters",
            )],
        )));
    }

    compare_expected_hash(
        request,
        setup_context,
        "expectedManifestHash",
        "manifestHash",
    )?;
    compare_expected_hash(request, setup_context, "expectedRosterHash", "rosterHash")?;

    Ok(None)
}

fn compare_expected_hash(
    request: &Value,
    setup_context: &Value,
    expected_field_name: &str,
    context_field_name: &str,
) -> CanonicalResult<()> {
    let Some(expected_hash) = request.get(expected_field_name).and_then(Value::as_str) else {
        return Ok(());
    };
    validate_hash_string(expected_hash, expected_field_name)?;
    let actual_hash = setup_context
        .get(context_field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("setupContext.{context_field_name} must be a protocol hash"),
            )
        })?;
    if expected_hash != actual_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("setupContext.{context_field_name} does not match {expected_field_name}"),
        ));
    }

    Ok(())
}
