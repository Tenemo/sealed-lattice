use super::expected_roots::*;
use super::material_transport::*;
use super::*;

pub(in super::super) fn verify_required_public_evaluation_key_set(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    verify_public_evaluation_key_set(setup_package, request, true)
}

pub(in super::super) fn verify_public_evaluation_key_set(
    setup_package: &Value,
    request: &Value,
    require_material: bool,
) -> CanonicalResult<Option<Value>> {
    let Some(evaluation_keys) = setup_package.get("evaluationKeys") else {
        if !require_material {
            return Ok(None);
        }
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["evaluationKeys".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !evaluation_keys.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysNotObject",
            "evaluationKeys must be a root-bound PublicEvaluationKeySet object",
            "setupPackage.evaluationKeys",
        )?));
    }
    if evaluation_keys
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
    {
        if !require_material {
            return Ok(None);
        }
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["evaluationKeys".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
    if evaluation_keys.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_SET_OBJECT_TYPE)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysTypeMismatch",
            "evaluationKeys.objectType must be PublicEvaluationKeySet",
            "setupPackage.evaluationKeys.objectType",
        )?));
    }
    if evaluation_keys.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysVersionMismatch",
            "evaluationKeys.objectVersion must be 1",
            "setupPackage.evaluationKeys.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before evaluation-key assembly verification",
        )
    })?;
    let roster = super::super::accepted_roster_from_package(setup_package);
    if let Err(error) =
        verify_context_fields_match(evaluation_keys, setup_context, "evaluationKeys")
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysContextMismatch",
            error.message,
            "setupPackage.evaluationKeys",
        )?));
    }
    for (field_name, expected_value) in
        [("materialEncoding", PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING)]
    {
        if evaluation_keys.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysProfileMismatch",
                format!("evaluationKeys.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", roster.participant_count),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysCountMismatch",
                format!("evaluationKeys.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let relinearization_key_share_rounds_root = setup_package
        .get("relinearizationKeyShareRounds")
        .and_then(|rounds| rounds.get("relinearizationKeyShareRoundsRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRoundsRoot was required before evaluation-key assembly",
            )
        })?;
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            binding.same_secret_proof_family_binding_root.as_str(),
        ),
        (
            "publicKeyShareSuccinctProofSetRoot",
            binding.public_key_share_succinct_proof_set_root.as_str(),
        ),
        (
            "relinearizationKeyShareRoundsRoot",
            relinearization_key_share_rounds_root,
        ),
        (
            "requiredGaloisSetHash",
            binding.required_galois_set_hash.as_str(),
        ),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysBindingMismatch",
                format!("evaluationKeys.{field_name} must match the verified setup binding"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    if evaluation_keys.get("relinearizationLevelSchedule")
        != Some(&expected_relinearization_level_schedule())
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysRelinearizationScheduleMismatch",
            "evaluationKeys.relinearizationLevelSchedule must match the frozen evaluator schedule",
            "setupPackage.evaluationKeys.relinearizationLevelSchedule",
        )?));
    }
    if evaluation_keys.get("requiredGaloisKeySchedule")
        != Some(&expected_required_galois_key_schedule()?)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysGaloisScheduleMismatch",
            "evaluationKeys.requiredGaloisKeySchedule must match the frozen evaluator schedule",
            "setupPackage.evaluationKeys.requiredGaloisKeySchedule",
        )?));
    }
    if evaluation_keys.get("genericKeySwitchKeyRoots") != Some(&Value::Array(Vec::new())) {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysGenericKeySwitchOutsideProfile",
            "evaluationKeys.genericKeySwitchKeyRoots must be empty for the first profile",
            "setupPackage.evaluationKeys.genericKeySwitchKeyRoots",
        )?));
    }

    let expected_relinearization_key_roots =
        expected_relinearization_key_roots_for_evaluation_keys(setup_package, &binding)?;
    let supplied_relinearization_key_roots =
        array_value(evaluation_keys, "relinearizationKeyRoots")?;
    if supplied_relinearization_key_roots.len() != expected_relinearization_key_roots.len() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyRelinearizationKeyCountMismatch",
            "evaluationKeys.relinearizationKeyRoots must contain one key root per scheduled relinearization level",
            "setupPackage.evaluationKeys.relinearizationKeyRoots",
        )?));
    }
    if supplied_relinearization_key_roots != &expected_relinearization_key_roots {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyRelinearizationKeyRootMismatch",
            "evaluationKeys.relinearizationKeyRoots must be derived from verified relinearization proof aggregates",
            "setupPackage.evaluationKeys.relinearizationKeyRoots",
        )?));
    }

    let expected_galois_batch_roots =
        expected_galois_batch_roots_for_evaluation_keys(setup_package)?;
    let supplied_galois_batch_roots = array_value(evaluation_keys, "galoisKeyShareBatchRoots")?;
    if supplied_galois_batch_roots.len() != expected_galois_batch_roots.len() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisBatchCountMismatch",
            "evaluationKeys.galoisKeyShareBatchRoots must contain one batch root per trustee",
            "setupPackage.evaluationKeys.galoisKeyShareBatchRoots",
        )?));
    }
    if supplied_galois_batch_roots != &expected_galois_batch_roots {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisBatchRootMismatch",
            "evaluationKeys.galoisKeyShareBatchRoots must match verified Galois proof batches",
            "setupPackage.evaluationKeys.galoisKeyShareBatchRoots",
        )?));
    }

    let expected_galois_key_roots =
        expected_galois_key_roots_for_evaluation_keys(setup_package, &binding)?;
    let supplied_galois_key_roots = array_value(evaluation_keys, "galoisKeyRoots")?;
    if supplied_galois_key_roots.len() != expected_galois_key_roots.len() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisKeyCountMismatch",
            "evaluationKeys.galoisKeyRoots must contain one key root per required Galois key",
            "setupPackage.evaluationKeys.galoisKeyRoots",
        )?));
    }
    if supplied_galois_key_roots != &expected_galois_key_roots {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyGaloisKeyRootMismatch",
            "evaluationKeys.galoisKeyRoots must be derived from verified Galois proof batches",
            "setupPackage.evaluationKeys.galoisKeyRoots",
        )?));
    }

    let supplied_evaluation_key_set_hash = value_string(evaluation_keys, "evaluationKeySetHash")?;
    let mut root_input = evaluation_keys.clone();
    root_input
        .as_object_mut()
        .expect("evaluationKeys object was checked")
        .remove("evaluationKeySetHash");
    let expected_evaluation_key_set_hash =
        derive_protocol_hash("EvaluationKeySetHash", &root_input)?;
    if supplied_evaluation_key_set_hash != expected_evaluation_key_set_hash {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeySetHashMismatch",
            "evaluationKeySetHash does not match the canonical public evaluation-key set",
            "setupPackage.evaluationKeys.evaluationKeySetHash",
        )?));
    }
    if public_evaluation_key_set_has_material_reference(evaluation_keys) {
        if let Some(response) = verify_public_evaluation_key_material_transport(
            setup_package,
            evaluation_keys,
            request,
        )? {
            return Ok(Some(response));
        }
    } else if request
        .get("transportedPublicEvaluationKeyMaterial")
        .is_some()
    {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialUndeclared",
            "transported public evaluation-key material must be declared by evaluationKeys",
            "transportedPublicEvaluationKeyMaterial",
        )?));
    }

    Ok(None)
}

fn public_evaluation_key_set_has_material_reference(evaluation_keys: &Value) -> bool {
    [
        "publicEvaluationKeyMaterialEncoding",
        "publicEvaluationKeyMaterialRoot",
        "publicEvaluationKeyMaterialChunkSizeBytes",
        "publicEvaluationKeyMaterialChunkCount",
        "publicEvaluationKeyMaterialTotalByteLength",
        "publicEvaluationKeyMaterialFullObjectHash",
        "publicEvaluationKeyMaterialChunkRoot",
        "publicEvaluationKeyMaterialChunkHashes",
    ]
    .into_iter()
    .any(|field_name| evaluation_keys.get(field_name).is_some())
}
