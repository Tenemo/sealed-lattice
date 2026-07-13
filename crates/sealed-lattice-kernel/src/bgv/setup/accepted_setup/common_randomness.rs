use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn verify_common_randomness(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Value>> {
    let Some(common_randomness) = setup_package.get("commonRandomness") else {
        return Ok(Some(verification_response(
            vec!["commonRandomness".to_string()],
            Vec::new(),
        )?));
    };
    if !common_randomness.is_object() {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessNotObject",
            "commonRandomness must be a JSON object",
            "setupPackage.commonRandomness",
        )?));
    }
    if common_randomness.get("objectType").and_then(Value::as_str) != Some("SetupCommonRandomness")
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessObjectTypeMismatch",
            "commonRandomness.objectType must be SetupCommonRandomness",
            "setupPackage.commonRandomness.objectType",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before common randomness verification",
        )
    })?;
    let roster = super::accepted_roster_from_package(setup_package)?;

    let Some(commit_records) = common_randomness
        .get("commitRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            vec!["commonRandomness.commitRecords".to_string()],
            Vec::new(),
        )?));
    };
    let Some(reveal_records) = common_randomness
        .get("revealRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            vec!["commonRandomness.revealRecords".to_string()],
            Vec::new(),
        )?));
    };
    if commit_records.len() != roster.participant_count as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessCommitCountMismatch",
            "commonRandomness.commitRecords must contain one commit per participant",
            "setupPackage.commonRandomness.commitRecords",
        )?));
    }
    if reveal_records.len() != roster.participant_count as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRevealCountMismatch",
            "commonRandomness.revealRecords must contain one reveal per participant",
            "setupPackage.commonRandomness.revealRecords",
        )?));
    }

    let mut commit_reveal_hashes_by_position = BTreeMap::<u64, String>::new();
    for commit_record in commit_records {
        let (roster_position, reveal_hash) = verify_common_randomness_commit_record(
            commit_record,
            setup_context,
            trustee_registrations,
        )?;
        if commit_reveal_hashes_by_position
            .insert(roster_position, reveal_hash)
            .is_some()
        {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessCommitDuplicate",
                "commonRandomness.commitRecords contains duplicate roster positions",
                "setupPackage.commonRandomness.commitRecords",
            )?));
        }
    }

    let mut ordered_reveal_hashes = BTreeMap::<u64, String>::new();
    for reveal_record in reveal_records {
        let (roster_position, reveal_hash) = verify_common_randomness_reveal_record(
            reveal_record,
            setup_context,
            trustee_registrations,
        )?;
        let Some(committed_reveal_hash) = commit_reveal_hashes_by_position.get(&roster_position)
        else {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealWithoutCommit",
                "commonRandomness.revealRecords contains a reveal without a matching commit",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        };
        if committed_reveal_hash != &reveal_hash {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealHashMismatch",
                "common-randomness reveal hash does not match the participant commit",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        }
        if ordered_reveal_hashes
            .insert(roster_position, reveal_hash)
            .is_some()
        {
            return Ok(Some(common_randomness_refusal(
                "commonRandomnessRevealDuplicate",
                "commonRandomness.revealRecords contains duplicate roster positions",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        }
    }
    if ordered_reveal_hashes.len() != roster.participant_count as usize {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessRevealCoverageMismatch",
            "commonRandomness.revealRecords must cover the full foundation roster",
            "setupPackage.commonRandomness.revealRecords",
        )?));
    }

    // Commitments bind each reveal before opening. Folding the roster-ordered
    // reveal hashes derives the canonical public-matrix seed.
    let ordered_reveal_hash_values = ordered_reveal_hashes
        .values()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let expected_public_matrix_seed_hash = derive_canonical_object_hash(&json!({
        "objectType": "SetupPublicMatrixSeed",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "orderedRevealHashes": ordered_reveal_hash_values,
    }))?;
    if common_randomness
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(expected_public_matrix_seed_hash.as_str())
    {
        return Ok(Some(common_randomness_refusal(
            "commonRandomnessPublicMatrixSeedMismatch",
            "commonRandomness.publicMatrixSeedHash does not match the ordered reveal set",
            "setupPackage.commonRandomness.publicMatrixSeedHash",
        )?));
    }
    Ok(None)
}

fn verify_common_randomness_commit_record(
    commit_record: &Value,
    setup_context: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<(u64, String)> {
    verify_common_randomness_participant_record_shape(
        commit_record,
        setup_context,
        "CommonRandomnessCommit",
        "commonRandomness.commitRecords",
        trustee_registrations,
    )?;
    let Some(reveal_hash) = commit_record.get("revealHash").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessCommit.revealHash is required",
        ));
    };
    validate_hash_string(reveal_hash, "CommonRandomnessCommit.revealHash")?;
    let commit_payload = common_randomness_commit_payload_value(commit_record)?;
    let commit_hash = derive_canonical_object_hash(&commit_payload)?;
    verify_common_randomness_signature(
        commit_record,
        setup_context,
        &CommonRandomnessSignatureExpectation {
            object_type: "CommonRandomnessCommit",
            object_root: &commit_hash,
            trustee_registrations,
        },
    )?;

    Ok((
        commit_record["rosterPosition"]
            .as_u64()
            .expect("roster position was checked"),
        reveal_hash.to_string(),
    ))
}

fn verify_common_randomness_reveal_record(
    reveal_record: &Value,
    setup_context: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<(u64, String)> {
    verify_common_randomness_participant_record_shape(
        reveal_record,
        setup_context,
        "CommonRandomnessReveal",
        "commonRandomness.revealRecords",
        trustee_registrations,
    )?;
    let Some(reveal_hex) = reveal_record.get("revealHex").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "CommonRandomnessReveal.revealHex is required",
        ));
    };
    validate_common_randomness_reveal_hex(reveal_hex)?;
    let reveal_payload = common_randomness_reveal_payload_value(reveal_record)?;
    let reveal_hash = derive_canonical_object_hash(&reveal_payload)?;
    verify_common_randomness_signature(
        reveal_record,
        setup_context,
        &CommonRandomnessSignatureExpectation {
            object_type: "CommonRandomnessReveal",
            object_root: &reveal_hash,
            trustee_registrations,
        },
    )?;

    Ok((
        reveal_record["rosterPosition"]
            .as_u64()
            .expect("roster position was checked"),
        reveal_hash,
    ))
}

fn verify_common_randomness_participant_record_shape(
    record: &Value,
    setup_context: &Value,
    object_type: &str,
    object_path: &str,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<()> {
    let roster = super::accepted_roster_from_setup_context(setup_context)?;
    if !record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} entries must be objects"),
        ));
    }
    if record.get("objectType").and_then(Value::as_str) != Some(object_type) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} entries must use {object_type}"),
        ));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if record.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_type}.{field_name} does not match setupContext"),
            ));
        }
    }
    let Some(trustee_identity) = record.get("trusteeIdentity").and_then(Value::as_str) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.trusteeIdentity is required"),
        ));
    };
    if trustee_identity.is_empty() || trustee_identity.nfc().collect::<String>() != trustee_identity
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.trusteeIdentity must be non-empty NFC text"),
        ));
    }
    let Some(roster_position) = record.get("rosterPosition").and_then(Value::as_u64) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.rosterPosition is required"),
        ));
    };
    if roster_position >= roster.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.rosterPosition is outside the first accepted roster"),
        ));
    }
    let Some(registration) = trustee_registrations.get(&roster_position) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.rosterPosition is missing from setupIntent registrations"),
        ));
    };
    if registration.trustee_identity != trustee_identity {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_type}.trusteeIdentity must match setupIntent registration"),
        ));
    }
    for field_name in ["recoveryEpoch", "deviceEpoch"] {
        if record.get(field_name).and_then(Value::as_u64).is_none() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_type}.{field_name} is required"),
            ));
        }
    }
    Ok(())
}

fn common_randomness_commit_payload_value(record: &Value) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "CommonRandomnessCommit",
        "ceremonyId": value_string(record, "ceremonyId")?,
        "manifestHash": value_string(record, "manifestHash")?,
        "rosterHash": value_string(record, "rosterHash")?,
        "setupParametersHash": value_string(record, "setupParametersHash")?,
        "setupEpoch": value_string(record, "setupEpoch")?,
        "trusteeIdentity": value_string(record, "trusteeIdentity")?,
        "rosterPosition": value_u64(record, "rosterPosition")?,
        "recoveryEpoch": value_u64(record, "recoveryEpoch")?,
        "deviceEpoch": value_u64(record, "deviceEpoch")?,
        "revealHash": value_string(record, "revealHash")?,
    }))
}

fn common_randomness_reveal_payload_value(record: &Value) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "CommonRandomnessReveal",
        "ceremonyId": value_string(record, "ceremonyId")?,
        "manifestHash": value_string(record, "manifestHash")?,
        "rosterHash": value_string(record, "rosterHash")?,
        "setupParametersHash": value_string(record, "setupParametersHash")?,
        "setupEpoch": value_string(record, "setupEpoch")?,
        "trusteeIdentity": value_string(record, "trusteeIdentity")?,
        "rosterPosition": value_u64(record, "rosterPosition")?,
        "recoveryEpoch": value_u64(record, "recoveryEpoch")?,
        "deviceEpoch": value_u64(record, "deviceEpoch")?,
        "revealHex": value_string(record, "revealHex")?,
    }))
}

struct CommonRandomnessSignatureExpectation<'a> {
    object_type: &'static str,
    object_root: &'a str,
    trustee_registrations: &'a setup_intent::SetupIntentTrusteeRegistrationMap,
}

fn verify_common_randomness_signature(
    record: &Value,
    setup_context: &Value,
    expectation: &CommonRandomnessSignatureExpectation<'_>,
) -> CanonicalResult<()> {
    let roster_position = value_u64(record, "rosterPosition")?;
    let trustee_identity = value_string(record, "trusteeIdentity")?;
    let registration = expectation
        .trustee_registrations
        .get(&roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{}.rosterPosition is missing from setupIntent registrations",
                    expectation.object_type,
                ),
            )
        })?;
    let context_hash = derive_canonical_object_hash(&json!({
        "objectType": format!("{}SignatureContext", expectation.object_type),
        "ceremonyId": value_string(record, "ceremonyId")?,
        "manifestHash": value_string(record, "manifestHash")?,
        "rosterHash": value_string(record, "rosterHash")?,
        "setupParametersHash": value_string(record, "setupParametersHash")?,
        "setupEpoch": value_string(record, "setupEpoch")?,
        "trusteeIdentity": trustee_identity,
        "rosterPosition": roster_position,
        "objectRoot": expectation.object_root,
    }))?;
    let signature_envelope = record.get("signatureEnvelope").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{}.signatureEnvelope is required", expectation.object_type),
        )
    })?;
    let manifest_hash = setup_context_string(setup_context, "manifestHash")?;
    let ceremony_id = setup_context_string(setup_context, "ceremonyId")?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: expectation.object_type,
            signer_role: "Trustee",
            signer_identity: trustee_identity,
            ceremony_id,
            public_key_hash: &registration.signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(expectation.object_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: &context_hash,
            recovery_epoch: value_u64(record, "recoveryEpoch")?,
            device_epoch: value_u64(record, "deviceEpoch")?,
        },
    )?;
    match verification {
        Ok(()) => Ok(()),
        Err(failure) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            failure.message,
        )),
    }
}

fn validate_common_randomness_reveal_hex(reveal_hex: &str) -> CanonicalResult<()> {
    if reveal_hex.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "common-randomness revealHex must contain 64 lowercase hex characters",
        ));
    }
    if !reveal_hex
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "common-randomness revealHex must be lowercase hexadecimal",
        ));
    }

    Ok(())
}

fn common_randomness_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    )
}
