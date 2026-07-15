use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn verify_common_randomness(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(common_randomness) = setup_package.get("commonRandomness") else {
        return Ok(Some(setup_refusals(
            vec!["commonRandomness".to_string()],
            Vec::new(),
        )));
    };
    if !common_randomness.is_object() {
        return Ok(Some(common_randomness_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "commonRandomnessNotObject",
            "commonRandomness must be a JSON object",
            "setupPackage.commonRandomness",
        )?));
    }
    if common_randomness.get("objectType").and_then(Value::as_str) != Some("SetupCommonRandomness")
    {
        return Ok(Some(common_randomness_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
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
        return Ok(Some(setup_refusals(
            vec!["commonRandomness.commitRecords".to_string()],
            Vec::new(),
        )));
    };
    let Some(reveal_records) = common_randomness
        .get("revealRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(setup_refusals(
            vec!["commonRandomness.revealRecords".to_string()],
            Vec::new(),
        )));
    };
    if commit_records.len() != roster.participant_count as usize {
        return Ok(Some(common_randomness_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "commonRandomnessCommitCountMismatch",
            "commonRandomness.commitRecords must contain one commit per participant",
            "setupPackage.commonRandomness.commitRecords",
        )?));
    }
    if reveal_records.len() != roster.participant_count as usize {
        return Ok(Some(common_randomness_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
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
                crate::foundation::RefusalReason::Equivocation,
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
                crate::foundation::RefusalReason::MissingPrerequisite,
                "commonRandomnessRevealWithoutCommit",
                "commonRandomness.revealRecords contains a reveal without a matching commit",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        };
        if committed_reveal_hash != &reveal_hash {
            return Ok(Some(common_randomness_refusal(
                crate::foundation::RefusalReason::WrongHashOrRoot,
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
                crate::foundation::RefusalReason::Equivocation,
                "commonRandomnessRevealDuplicate",
                "commonRandomness.revealRecords contains duplicate roster positions",
                "setupPackage.commonRandomness.revealRecords",
            )?));
        }
    }
    if ordered_reveal_hashes.len() != roster.participant_count as usize {
        return Ok(Some(common_randomness_refusal(
            crate::foundation::RefusalReason::WrongHashOrRoot,
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
        "setupContextHash": setup_context_hash(setup_context)?,
        "orderedRevealHashes": ordered_reveal_hash_values,
    }))?;
    if common_randomness
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(expected_public_matrix_seed_hash.as_str())
    {
        return Ok(Some(common_randomness_refusal(
            crate::foundation::RefusalReason::WrongHashOrRoot,
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
    let participant = verify_common_randomness_participant_record_shape(
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
    let commit_payload =
        common_randomness_commit_payload_value(setup_context, &participant, reveal_hash)?;
    let commit_hash = derive_canonical_object_hash(&commit_payload)?;
    verify_common_randomness_signature(
        commit_record,
        &participant,
        &CommonRandomnessSignatureExpectation {
            object_type: "CommonRandomnessCommit",
            object_root: &commit_hash,
            trustee_registrations,
        },
    )?;

    Ok((participant.roster_position, reveal_hash.to_string()))
}

fn verify_common_randomness_reveal_record(
    reveal_record: &Value,
    setup_context: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<(u64, String)> {
    let participant = verify_common_randomness_participant_record_shape(
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
    let reveal_payload =
        common_randomness_reveal_payload_value(setup_context, &participant, reveal_hex)?;
    let reveal_hash = derive_canonical_object_hash(&reveal_payload)?;
    verify_common_randomness_signature(
        reveal_record,
        &participant,
        &CommonRandomnessSignatureExpectation {
            object_type: "CommonRandomnessReveal",
            object_root: &reveal_hash,
            trustee_registrations,
        },
    )?;

    Ok((participant.roster_position, reveal_hash))
}

struct CommonRandomnessParticipantBinding {
    roster_position: u64,
    trustee_identity: String,
    recovery_epoch: u64,
    device_epoch: u64,
}

fn verify_common_randomness_participant_record_shape(
    record: &Value,
    setup_context: &Value,
    object_type: &str,
    object_path: &str,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<CommonRandomnessParticipantBinding> {
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
    Ok(CommonRandomnessParticipantBinding {
        roster_position,
        trustee_identity: registration.trustee_identity.clone(),
        recovery_epoch: registration.recovery_epoch,
        device_epoch: registration.device_epoch,
    })
}

fn common_randomness_commit_payload_value(
    setup_context: &Value,
    participant: &CommonRandomnessParticipantBinding,
    reveal_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "CommonRandomnessCommit",
        "setupContextHash": setup_context_hash(setup_context)?,
        "trusteeIdentity": participant.trustee_identity.as_str(),
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "revealHash": reveal_hash,
    }))
}

fn common_randomness_reveal_payload_value(
    setup_context: &Value,
    participant: &CommonRandomnessParticipantBinding,
    reveal_hex: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "CommonRandomnessReveal",
        "setupContextHash": setup_context_hash(setup_context)?,
        "trusteeIdentity": participant.trustee_identity.as_str(),
        "rosterPosition": participant.roster_position,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "revealHex": reveal_hex,
    }))
}

struct CommonRandomnessSignatureExpectation<'a> {
    object_type: &'static str,
    object_root: &'a str,
    trustee_registrations: &'a setup_intent::SetupIntentTrusteeRegistrationMap,
}

fn verify_common_randomness_signature(
    record: &Value,
    participant: &CommonRandomnessParticipantBinding,
    expectation: &CommonRandomnessSignatureExpectation<'_>,
) -> CanonicalResult<()> {
    let registration = expectation
        .trustee_registrations
        .get(&participant.roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{}.rosterPosition is missing from setupIntent registrations",
                    expectation.object_type,
                ),
            )
        })?;
    let signature_envelope = record.get("signatureEnvelope").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{}.signatureEnvelope is required", expectation.object_type),
        )
    })?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: expectation.object_type,
            public_key_hash: &registration.signing_public_key_hash,
            object_root: expectation.object_root,
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
    refusal_reason: crate::foundation::RefusalReason,
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Refusals> {
    Ok(setup_refusals(
        Vec::new(),
        vec![Refusal::new(
            refusal_reason,
            reason_code,
            message,
            object_path,
        )],
    ))
}
