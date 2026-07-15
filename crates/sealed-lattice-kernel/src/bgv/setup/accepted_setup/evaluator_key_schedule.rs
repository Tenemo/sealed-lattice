use super::*;

use super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;
pub(super) fn verify_evaluator_key_schedule(
    setup_package: &Value,
) -> CanonicalResult<Option<Refusals>> {
    let Some(schedule) = setup_package.get("evaluatorKeySchedule") else {
        return Ok(Some(setup_refusals(
            vec!["evaluatorKeySchedule".to_string()],
            Vec::new(),
        )));
    };
    if !schedule.is_object() {
        return Ok(Some(evaluator_key_schedule_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "evaluatorKeyScheduleNotObject",
            "evaluatorKeySchedule must be a root-bound object, not an array or scalar",
            "setupPackage.evaluatorKeySchedule",
        )?));
    }
    if schedule.get("objectType").and_then(Value::as_str)
        != Some(EVALUATOR_KEY_SCHEDULE_OBJECT_TYPE)
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "evaluatorKeyScheduleTypeMismatch",
            "evaluatorKeySchedule.objectType must be EvaluatorKeySchedule",
            "setupPackage.evaluatorKeySchedule.objectType",
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
            crate::foundation::RefusalReason::WrongContext,
            "evaluatorKeyScheduleContextMismatch",
            error.message,
            "setupPackage.evaluatorKeySchedule",
        )?));
    }
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before evaluator-key schedule verification",
        )
    })?;
    let public_matrix_seed_hash = value_string(common_randomness, "publicMatrixSeedHash")?;
    for (field_name, expected_value) in [("publicMatrixSeedHash", public_matrix_seed_hash)] {
        if schedule.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluator_key_schedule_refusal(
                crate::foundation::RefusalReason::WrongHashOrRoot,
                "evaluatorKeySchedulePublicBindingMismatch",
                format!("evaluatorKeySchedule.{field_name} must match accepted common randomness"),
                format!("setupPackage.evaluatorKeySchedule.{field_name}"),
            )?));
        }
    }

    let public_key_share_set_root = derive_public_key_share_set_root(setup_package)?;
    if schedule
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
        != Some(public_key_share_set_root.as_str())
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "evaluatorKeyScheduleSetupRootMismatch",
            "evaluatorKeySchedule.publicKeyShareSetRoot must match the accepted public-key share set root",
            "setupPackage.evaluatorKeySchedule.publicKeyShareSetRoot",
        )?));
    }

    let expected_relinearization_level_schedule = expected_relinearization_level_schedule();
    if schedule.get("relinearizationLevelSchedule")
        != Some(&expected_relinearization_level_schedule)
    {
        return Ok(Some(evaluator_key_schedule_refusal(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "evaluatorKeyScheduleRelinearizationMismatch",
            "evaluatorKeySchedule.relinearizationLevelSchedule must match the frozen foundation-roster relinearization levels",
            "setupPackage.evaluatorKeySchedule.relinearizationLevelSchedule",
        )?));
    }
    let expected_required_galois_key_schedule = expected_required_galois_key_schedule()?;
    if schedule.get("requiredGaloisKeySchedule") != Some(&expected_required_galois_key_schedule) {
        return Ok(Some(evaluator_key_schedule_refusal(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "evaluatorKeyScheduleGaloisMismatch",
            "evaluatorKeySchedule.requiredGaloisKeySchedule must match the frozen foundation-roster Galois key schedule",
            "setupPackage.evaluatorKeySchedule.requiredGaloisKeySchedule",
        )?));
    }
    Ok(None)
}

pub(super) fn verify_context_fields_match(
    value: &Value,
    setup_context: &Value,
    value_name: &str,
) -> CanonicalResult<()> {
    if value_string(value, "setupContextHash")? != setup_context_hash(setup_context)? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{value_name}.setupContextHash must match setupContext"),
        ));
    }

    Ok(())
}

fn evaluator_key_schedule_refusal(
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

pub(super) fn verify_pending_evaluation_key_material_boundary(
    setup_package: &Value,
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let complete_share_record_containers = setup_package
        .get("relinearizationKeyShareRounds")
        .and_then(Value::as_object)
        .is_some_and(|rounds| !rounds.is_empty())
        && setup_package
            .get("galoisKeyShareBatches")
            .and_then(Value::as_array)
            .is_some_and(|batches| !batches.is_empty());
    if !complete_share_record_containers
        && let Some(response) = verify_trustee_evaluation_key_proofs(
            setup_package,
            verified_same_secret_bridge,
            proof_binding_session,
        )?
    {
        return Ok(Some(response));
    }
    if let Some(response) =
        verify_relinearization_key_share_rounds(setup_package, trustee_registrations)?
    {
        return Ok(Some(response));
    }
    if let Some(response) = verify_galois_key_share_batches(setup_package, trustee_registrations)? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_trustee_evaluation_key_proofs(
        setup_package,
        verified_same_secret_bridge,
        proof_binding_session,
    )? {
        return Ok(Some(response));
    }

    Ok(None)
}
