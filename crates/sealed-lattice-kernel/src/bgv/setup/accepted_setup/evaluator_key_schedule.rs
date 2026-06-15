use super::*;

pub(super) fn verify_evaluator_key_schedule(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(schedule) = setup_package.get("evaluatorKeySchedule") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("relinearizationRoundOne"),
            vec!["evaluatorKeySchedule".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !schedule.is_object() {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleNotObject",
            "evaluatorKeySchedule must be a root-bound object, not an array or scalar",
            "setupPackage.evaluatorKeySchedule",
        )?));
    }
    if schedule.get("objectType").and_then(Value::as_str)
        != Some(EVALUATOR_KEY_SCHEDULE_OBJECT_TYPE)
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleTypeMismatch",
            "evaluatorKeySchedule.objectType must be EvaluatorKeySchedule",
            "setupPackage.evaluatorKeySchedule.objectType",
        )?));
    }
    if schedule.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleVersionMismatch",
            "evaluatorKeySchedule.objectVersion must be 1",
            "setupPackage.evaluatorKeySchedule.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before evaluator-key schedule verification",
        )
    })?;
    if let Err(error) = verify_context_fields_match(schedule, setup_context, "evaluatorKeySchedule")
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleContextMismatch",
            error.message,
            "setupPackage.evaluatorKeySchedule",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        (
            "genericKeySwitchPolicy",
            "refused-unless-explicitly-required",
        ),
        (
            "genericKeySwitchProofStatus",
            "not-required-for-first-profile",
        ),
        (
            "scheduleBindingStatus",
            "relinearization-and-galois-proof-verifiers-bound-by-accepted-setup-proof-accounting",
        ),
    ] {
        if schedule.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeyScheduleProfileMismatch",
                format!("evaluatorKeySchedule.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if schedule.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeyScheduleCountMismatch",
                format!("evaluatorKeySchedule.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }

    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before evaluator-key schedule verification",
        )
    })?;
    let public_derivations = common_randomness.get("publicDerivations").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations was required before evaluator-key schedule verification",
        )
    })?;
    let crp_roots = public_derivations.get("crpRoots").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations.crpRoots was required before evaluator-key schedule verification",
        )
    })?;
    for (field_name, expected_value) in [
        (
            "publicMatrixSeedHash",
            value_string(common_randomness, "publicMatrixSeedHash")?,
        ),
        (
            "relinearizationCrpRoot",
            value_string(crp_roots, "relinearizationCrpRoot")?,
        ),
        (
            "galoisKeyCrpRoot",
            value_string(crp_roots, "galoisKeyCrpRoot")?,
        ),
    ] {
        if schedule.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeySchedulePublicBindingMismatch",
                format!("evaluatorKeySchedule.{field_name} must match accepted common randomness"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }

    for (field_name, expected_value, message) in [
        (
            "sameSecretConsistencyRoot",
            same_secret_consistency_root_from_package(setup_package)?,
            "same-secret statement root",
        ),
        (
            "publicKeyShareSetRoot",
            setup_package
                .get("publicKeyShares")
                .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "publicKeyShareSetRoot was required before evaluator-key schedule verification",
                    )
                })?
                .to_string(),
            "public-key share set root",
        ),
        (
            "publicKeyShareProofSetRoot",
            setup_package
                .get("publicKeyShareProofs")
                .and_then(|proof_set| proof_set.get("publicKeyShareProofSetRoot"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "publicKeyShareProofSetRoot was required before evaluator-key schedule verification",
                    )
                })?
                .to_string(),
            "public-key share proof set root",
        ),
    ] {
        if schedule.get(field_name).and_then(Value::as_str) != Some(expected_value.as_str()) {
            return Ok(Some(evaluator_key_schedule_refusal(
                "evaluatorKeyScheduleSetupRootMismatch",
                format!("evaluatorKeySchedule.{field_name} must match accepted {message}"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }

    let expected_relinearization_level_schedule = expected_relinearization_level_schedule();
    if schedule.get("relinearizationLevelSchedule")
        != Some(&expected_relinearization_level_schedule)
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleRelinearizationMismatch",
            "evaluatorKeySchedule.relinearizationLevelSchedule must match the frozen first-profile relinearization levels",
            "setupPackage.evaluatorKeySchedule.relinearizationLevelSchedule",
        )?));
    }
    let expected_required_galois_key_schedule = expected_required_galois_key_schedule()?;
    if schedule.get("requiredGaloisKeySchedule") != Some(&expected_required_galois_key_schedule) {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleGaloisMismatch",
            "evaluatorKeySchedule.requiredGaloisKeySchedule must match the frozen first-profile Galois key schedule",
            "setupPackage.evaluatorKeySchedule.requiredGaloisKeySchedule",
        )?));
    }
    let expected_required_galois_set_hash =
        expected_required_galois_set_hash(&expected_required_galois_key_schedule)?;
    if schedule
        .get("requiredGaloisSetHash")
        .and_then(Value::as_str)
        != Some(expected_required_galois_set_hash.as_str())
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            "requiredGaloisSetHashMismatch",
            "evaluatorKeySchedule.requiredGaloisSetHash does not match the frozen first-profile Galois set",
            "setupPackage.evaluatorKeySchedule.requiredGaloisSetHash",
        )?));
    }

    let Some(evaluator_key_schedule_root) = schedule
        .get("evaluatorKeyScheduleRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("relinearizationRoundOne"),
            vec!["evaluatorKeySchedule.evaluatorKeyScheduleRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        evaluator_key_schedule_root,
        "evaluatorKeySchedule.evaluatorKeyScheduleRoot",
    )?;
    let mut root_input = schedule.clone();
    root_input
        .as_object_mut()
        .expect("evaluator key schedule object was checked")
        .remove("evaluatorKeyScheduleRoot");
    let expected_root = derive_protocol_hash("EvaluatorKeyScheduleRoot", &root_input)?;
    if evaluator_key_schedule_root != expected_root {
        return Ok(Some(evaluator_key_schedule_refusal(
            "evaluatorKeyScheduleRootMismatch",
            "evaluatorKeyScheduleRoot does not match the canonical evaluator-key schedule",
            "setupPackage.evaluatorKeySchedule.evaluatorKeyScheduleRoot",
        )?));
    }

    Ok(None)
}

pub(super) fn verify_context_fields_match(
    value: &Value,
    setup_context: &Value,
    value_name: &str,
) -> CanonicalResult<()> {
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
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{value_name}.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

fn evaluator_key_schedule_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("relinearizationRoundOne"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn verify_pending_evaluation_key_material_boundary(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    if let Some(response) = verify_relinearization_key_share_rounds(setup_package, request)? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_galois_key_share_batches(setup_package, request)? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_trustee_evaluation_key_proofs(setup_package, request)? {
        return Ok(Some(response));
    }

    if let Some(response) = verify_public_evaluation_key_set(setup_package, request, false)? {
        return Ok(Some(response));
    }

    Ok(None)
}

pub(super) fn verify_generic_key_switch_policy(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let evaluator_key_schedule = setup_package
        .get("evaluatorKeySchedule")
        .and_then(Value::as_object);
    let generic_key_switch_policy = evaluator_key_schedule
        .and_then(|schedule| schedule.get("genericKeySwitchPolicy"))
        .and_then(Value::as_str)
        .unwrap_or("refused-unless-explicitly-required");
    if setup_package.get("genericKeySwitchKeys").is_some()
        && generic_key_switch_policy != "explicitly-required-by-frozen-schedule"
    {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
            Some("setupPackageVerification"),
            Vec::new(),
            vec![Refusal::new(
                "genericKeySwitchOutsideProfile",
                "generic key-switch material is refused unless the frozen evaluator schedule explicitly requires it",
                "setupPackage.genericKeySwitchKeys".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if generic_key_switch_policy == "explicitly-required-by-frozen-schedule"
        && setup_package.get("genericKeySwitchProofs").is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageVerification"),
            vec!["genericKeySwitchProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }

    Ok(None)
}
