use super::*;

const MAX_SETUP_CONTEXT_TOKEN_BYTES: usize = 128;

// Restricting these tokens keeps them safe as hash and signature-context inputs: no delimiters, no control bytes, and a bounded preimage length.
fn validate_setup_context_token(field_name: &str, value: &str) -> Option<Refusal> {
    if value.is_empty() {
        return Some(Refusal::new(
            "setupContextTokenMissing",
            format!("setupContext.{field_name} must be a non-empty setup context token"),
            format!("setupPackage.setupContext.{field_name}"),
        ));
    }
    if value.len() > MAX_SETUP_CONTEXT_TOKEN_BYTES {
        return Some(Refusal::new(
            "setupContextTokenMalformed",
            format!(
                "setupContext.{field_name} must be at most {MAX_SETUP_CONTEXT_TOKEN_BYTES} bytes"
            ),
            format!("setupPackage.setupContext.{field_name}"),
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
    }) {
        return Some(Refusal::new(
            "setupContextTokenMalformed",
            format!(
                "setupContext.{field_name} contains a character outside the setup context token alphabet"
            ),
            format!("setupPackage.setupContext.{field_name}"),
        ));
    }

    None
}

pub(super) fn verify_context(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(setup_context) = setup_package.get("setupContext") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupIntent"),
            vec!["setupContext".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !setup_context.is_object() {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "setupContextNotObject",
                "setupContext must be a JSON object",
                "setupPackage.setupContext".to_string(),
            )],
            Vec::new(),
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if setup_context.get(field_name).is_none() {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("setupIntent"),
                vec![format!("setupContext.{field_name}")],
                Vec::new(),
                Vec::new(),
            )?));
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
        let Some(field_value) = setup_context.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some("setupIntent"),
                Vec::new(),
                vec![Refusal::new(
                    "setupContextHashMalformed",
                    format!("setupContext.{field_name} must be a protocol hash"),
                    format!("setupPackage.setupContext.{field_name}"),
                )],
                Vec::new(),
            )?));
        };
        validate_hash_string(field_value, &format!("setupContext.{field_name}"))?;
    }
    for field_name in ["ceremonyId", "setupEpoch"] {
        let Some(field_value) = setup_context.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some("setupIntent"),
                Vec::new(),
                vec![Refusal::new(
                    "setupContextTokenMalformed",
                    format!("setupContext.{field_name} must be a setup context token"),
                    format!("setupPackage.setupContext.{field_name}"),
                )],
                Vec::new(),
            )?));
        };
        if let Some(refusal) = validate_setup_context_token(field_name, field_value) {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some("setupIntent"),
                Vec::new(),
                vec![refusal],
                Vec::new(),
            )?));
        }
    }

    let expected_setup_profile_hash = setup_profile_hash()?;
    if setup_context
        .get("setupProfileHash")
        .and_then(Value::as_str)
        != Some(expected_setup_profile_hash.as_str())
    {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "setupProfileHashMismatch",
                "setupContext.setupProfileHash does not match CollectiveBgvSetup-v1",
                "setupPackage.setupContext.setupProfileHash".to_string(),
            )],
            Vec::new(),
        )?));
    }

    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("qSetupComplete", FIRST_PROFILE_SETUP_COMPLETION_QUORUM),
        ("qBallotRelease", FIRST_PROFILE_BALLOT_RELEASE_QUORUM),
        ("qFinal", FIRST_PROFILE_FINALITY_QUORUM),
        ("qDec", FIRST_PROFILE_DECRYPTION_THRESHOLD),
    ] {
        match setup_context.get(field_name).and_then(Value::as_u64) {
            Some(actual_value) if actual_value == expected_value => {}
            Some(_) => {
                return Ok(Some(verification_response(
                    VerifierStatus::OutsideProfile,
                    Some("setupIntent"),
                    Vec::new(),
                    vec![Refusal::new(
                        "firstProfileParameterMismatch",
                        format!(
                            "setupContext.{field_name} does not match the first accepted profile"
                        ),
                        format!("setupPackage.setupContext.{field_name}"),
                    )],
                    Vec::new(),
                )?));
            }
            None => {
                return Ok(Some(verification_response(
                    VerifierStatus::Pending,
                    Some("setupIntent"),
                    vec![format!("setupContext.{field_name}")],
                    Vec::new(),
                    Vec::new(),
                )?));
            }
        }
    }
    if setup_context.get("qShareHash").and_then(Value::as_str) != Some(q_share_hash()?.as_str()) {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "qShareHashMismatch",
                "setupContext.qShareHash does not match the accepted Q_share prime list",
                "setupPackage.setupContext.qShareHash".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if setup_context
        .get("carryAwareVssShareRelationProfileHash")
        .and_then(Value::as_str)
        != Some(carry_aware_vss_share_relation_profile_hash()?.as_str())
    {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "carryAwareVssRelationProfileHashMismatch",
                "setupContext.carryAwareVssShareRelationProfileHash does not match the accepted carry-aware VSS relation profile",
                "setupPackage.setupContext.carryAwareVssShareRelationProfileHash".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if setup_context
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "commitmentProfileHashMismatch",
                "setupContext.commitmentProfileHash does not match the accepted setup commitment profile",
                "setupPackage.setupContext.commitmentProfileHash".to_string(),
            )],
            Vec::new(),
        )?));
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

pub(super) fn verify_q_share(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(q_share) = setup_package.get("qShare") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupIntent"),
            vec!["qShare".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if q_share != &q_share_value() {
        return Ok(Some(verification_response(
            VerifierStatus::OutsideProfile,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "qShareMismatch",
                "qShare must be the exact ordered accepted RNS prime list",
                "setupPackage.qShare".to_string(),
            )],
            Vec::new(),
        )?));
    }

    Ok(None)
}

pub(super) fn q_share_hash() -> CanonicalResult<String> {
    derive_protocol_hash("QSharePrimeListHash", &q_share_value())
}

pub(super) fn q_share_value() -> Value {
    json!({
        "objectType": "QSharePrimeList",
        "objectVersion": 1,
        "sharingDomain": "per-rns-prime",
        "primeOrder": "profile-order",
        // This readiness flag is hashed into qShareHash on purpose, so the closed-target claim boundary is committed by every object that binds the Q_share list.
        "targetDecryptionReadiness": "refused-until-q-target-certificate-closes",
        "primes": DATA_PRIMES,
    })
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
                CanonicalErrorCode::InvalidFixture,
                format!("setupContext.{context_field_name} must be a protocol hash"),
            )
        })?;
    if expected_hash != actual_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("setupContext.{context_field_name} does not match {expected_field_name}"),
        ));
    }

    Ok(())
}
