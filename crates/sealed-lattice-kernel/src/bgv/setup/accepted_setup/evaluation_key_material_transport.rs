use super::*;

pub(super) fn verify_required_public_evaluation_key_set(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    verify_public_evaluation_key_set(setup_package, request, true)
}

pub(super) fn verify_public_evaluation_key_set(
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
    if let Some(unexpected_field) = unexpected_public_evaluation_key_set_field(evaluation_keys) {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysUnexpectedField",
            format!("evaluationKeys contains unexpected field {unexpected_field}"),
            format!("setupPackage.evaluationKeys.{unexpected_field}"),
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
    if let Err(error) =
        verify_context_fields_match(evaluation_keys, setup_context, "evaluationKeys")
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeysContextMismatch",
            error.message,
            "setupPackage.evaluationKeys",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("assemblyStatus", PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS),
        ("materialEncoding", PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING),
        ("materialSource", PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysProfileMismatch",
                format!("evaluationKeys.{field_name} must be {expected_value}"),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
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
    for (field_name, expected_value) in [
        ("rawKeyBytesEmbedded", false),
        ("verifierGeneratedKeyMaterial", false),
    ] {
        if evaluation_keys.get(field_name).and_then(Value::as_bool) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeysMaterialBoundaryMismatch",
                format!("evaluationKeys.{field_name} must be false"),
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
    if let Some(response) = verify_public_evaluation_key_set_hash_preflight(setup_package)? {
        return Ok(Some(response));
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
    let expected_evaluation_key_set_hash = derive_protocol_hash_omitting_object_field(
        "EvaluationKeySetHash",
        evaluation_keys,
        "evaluationKeySetHash",
    )?;
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

pub(super) fn verify_public_evaluation_key_set_hash_preflight(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(evaluation_keys) = setup_package.get("evaluationKeys") else {
        return Ok(None);
    };
    if !evaluation_keys.is_object()
        || evaluation_keys
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        || evaluation_keys.get("evaluationKeySetHash").is_none()
    {
        return Ok(None);
    }

    let supplied_evaluation_key_set_hash = value_string(evaluation_keys, "evaluationKeySetHash")?;
    let expected_evaluation_key_set_hash = derive_protocol_hash_omitting_object_field(
        "EvaluationKeySetHash",
        evaluation_keys,
        "evaluationKeySetHash",
    )?;
    if supplied_evaluation_key_set_hash != expected_evaluation_key_set_hash {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeySetHashMismatch",
            "evaluationKeySetHash does not match the canonical public evaluation-key set",
            "setupPackage.evaluationKeys.evaluationKeySetHash",
        )?));
    }

    Ok(None)
}

#[derive(Debug, Clone)]
pub(in crate::bgv::setup) struct PublicEvaluationKeyMaterialTransportHashes {
    pub(in crate::bgv::setup) full_object_hash: String,
    pub(in crate::bgv::setup) chunk_hashes: Vec<String>,
    pub(in crate::bgv::setup) chunk_root: String,
    pub(in crate::bgv::setup) total_byte_length: u64,
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

pub(super) fn transported_evaluation_key_share_component_material_from_request(
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    if request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .is_some()
    {
        return Ok(None);
    }
    let Some(public_evaluation_key_material) =
        request.get("transportedPublicEvaluationKeyMaterial")
    else {
        return Ok(None);
    };
    let Some(component_materials) = public_evaluation_key_material.get("componentMaterials") else {
        return Ok(None);
    };
    if !component_materials.is_array() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public evaluation-key material componentMaterials must be an array",
        ));
    }

    Ok(Some(json!({
        "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "componentMaterials": component_materials,
    })))
}

fn verify_public_evaluation_key_material_transport(
    setup_package: &Value,
    evaluation_keys: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    for field_name in [
        "publicEvaluationKeyMaterialEncoding",
        "publicEvaluationKeyMaterialRoot",
        "publicEvaluationKeyMaterialChunkSizeBytes",
        "publicEvaluationKeyMaterialChunkCount",
        "publicEvaluationKeyMaterialTotalByteLength",
        "publicEvaluationKeyMaterialFullObjectHash",
        "publicEvaluationKeyMaterialChunkRoot",
        "publicEvaluationKeyMaterialChunkHashes",
    ] {
        if evaluation_keys.get(field_name).is_none() {
            return Ok(Some(evaluation_key_material_refusal(
                "publicEvaluationKeyMaterialReferenceIncomplete",
                format!(
                    "evaluationKeys.{field_name} is required when public evaluation-key material is declared"
                ),
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    if evaluation_keys
        .get("publicEvaluationKeyMaterialEncoding")
        .and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialEncodingMismatch",
            format!(
                "evaluationKeys.publicEvaluationKeyMaterialEncoding must be {PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING}"
            ),
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialEncoding",
        )?));
    }
    let Some(transported_material_set) = request.get("transportedPublicEvaluationKeyMaterial")
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["transportedPublicEvaluationKeyMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if transported_material_set
        .get("objectType")
        .and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
        || transported_material_set
            .get("objectVersion")
            .and_then(Value::as_u64)
            != Some(1)
        || transported_material_set
            .get("setupProfileId")
            .and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || transported_material_set
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
        || transported_material_set
            .get("materialEncoding")
            .and_then(Value::as_str)
            != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialTransportHeaderMismatch",
            "transportedPublicEvaluationKeyMaterial must be a public evaluation-key material transport set",
            "transportedPublicEvaluationKeyMaterial",
        )?));
    }
    if let Err(error) = verify_public_evaluation_key_material_component_roots(
        setup_package,
        transported_material_set,
        request,
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "transportedPublicEvaluationKeyMaterial.componentMaterials",
        )?));
    }
    let expected_material_root = value_string(evaluation_keys, "publicEvaluationKeyMaterialRoot")?;
    validate_hash_string(
        expected_material_root,
        "evaluationKeys.publicEvaluationKeyMaterialRoot",
    )?;
    let material_entries = array_value(transported_material_set, "publicEvaluationKeyMaterials")?;
    let mut matching_material = None;
    for material_entry in material_entries {
        if value_string(material_entry, "publicEvaluationKeyMaterialRoot")?
            != expected_material_root
        {
            continue;
        }
        if matching_material.is_some() {
            return Ok(Some(evaluation_key_material_refusal(
                "publicEvaluationKeyMaterialDuplicateRoot",
                "transported public evaluation-key material contains duplicate material roots",
                "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
            )?));
        }
        matching_material = Some(material_entry);
    }
    let Some(material_entry) = matching_material else {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialMissingRoot",
            "transported public evaluation-key material is missing the declared publicEvaluationKeyMaterialRoot",
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    };
    if let Err(error) =
        verify_public_evaluation_key_material_entry_header(evaluation_keys, material_entry)
    {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    }
    let chunks = match public_evaluation_key_material_chunks(material_entry) {
        Ok(chunks) => chunks,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials.chunks",
            )?));
        }
    };
    let transport_hashes = match public_evaluation_key_material_transport_hashes(&chunks) {
        Ok(transport_hashes) => transport_hashes,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials.chunks",
            )?));
        }
    };
    if let Err(error) = verify_public_evaluation_key_material_hash_fields(
        material_entry,
        &transport_hashes,
        "transported public evaluation-key material",
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    }
    if let Err(error) = verify_public_evaluation_key_material_hash_fields(
        evaluation_keys,
        &transport_hashes,
        "public evaluation-key material reference",
    ) {
        return Ok(Some(evaluation_key_material_verification_failure(
            error,
            "setupPackage.evaluationKeys",
        )?));
    }
    let expected_manifest =
        public_evaluation_key_material_manifest(setup_package, evaluation_keys)?;
    let canonical_material_root = public_evaluation_key_material_reference_root(
        evaluation_keys,
        &expected_manifest,
        &transport_hashes,
    )?;
    if expected_material_root != canonical_material_root {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialRootMismatch",
            "publicEvaluationKeyMaterialRoot does not match the canonical material reference",
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialRoot",
        )?));
    }
    let decoded_manifest =
        match decode_public_evaluation_key_material_manifest(&chunks, &transport_hashes) {
            Ok(decoded_manifest) => decoded_manifest,
            Err(error) => {
                return Ok(Some(evaluation_key_material_verification_failure(
                    error,
                    "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
                )?));
            }
        };
    if decoded_manifest != expected_manifest {
        return Ok(Some(evaluation_key_material_refusal(
            "publicEvaluationKeyMaterialManifestMismatch",
            "transported public evaluation-key material manifest does not match the verified setup package",
            "transportedPublicEvaluationKeyMaterial.publicEvaluationKeyMaterials",
        )?));
    }
    if accepted_setup_evaluation_key_records_use_profile_ring(setup_package)? {
        if let Err(error) =
            accepted_setup_public_relinearization_keys_from_transport(setup_package, request)
        {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.componentMaterials",
            )?));
        }
        if let Err(error) = accepted_setup_public_galois_keys_from_transport(setup_package, request)
        {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.componentMaterials",
            )?));
        }
    }

    Ok(None)
}

fn evaluation_key_material_verification_failure(
    error: CanonicalError,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    evaluation_key_material_refusal(
        "evaluationKeyMaterialVerificationFailed",
        error.message,
        object_path,
    )
}

fn verify_public_evaluation_key_material_component_roots(
    setup_package: &Value,
    transported_material_set: &Value,
    request: &Value,
) -> CanonicalResult<()> {
    let expected_roots = expected_public_evaluation_key_component_material_roots(setup_package)?;
    let supplied_component_materials = match transported_material_set.get("componentMaterials") {
        Some(component_materials) => Some(component_materials.as_array().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public evaluation-key material componentMaterials must be an array",
            )
        })?),
        None => None,
    };
    let request_component_material_roots =
        transported_evaluation_key_share_component_material_roots_from_request(request)?;
    if expected_roots.is_empty() {
        if supplied_component_materials.is_some_and(|materials| !materials.is_empty()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public evaluation-key material must not include undeclared component material",
            ));
        }
        if request_component_material_roots.is_some_and(|roots| !roots.is_empty()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key component material must not be supplied when public evaluation-key records do not use binary component material",
            ));
        }
        return Ok(());
    }
    if let Some(component_materials) = supplied_component_materials
        && !component_materials.is_empty()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public evaluation-key material must not duplicate evaluation-key component material chunks; use transportedEvaluationKeyShareComponentMaterial",
        ));
    }
    let Some(supplied_roots) = request_component_material_roots else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "request must include transportedEvaluationKeyShareComponentMaterial for binary public evaluation-key proof records",
        ));
    };
    if supplied_roots != expected_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "request-side transported evaluation-key component roots do not match proof records",
        ));
    }

    Ok(())
}

fn transported_evaluation_key_share_component_material_roots_from_request(
    request: &Value,
) -> CanonicalResult<Option<BTreeSet<String>>> {
    let Some(material_set) = request.get("transportedEvaluationKeyShareComponentMaterial") else {
        return Ok(None);
    };
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
        || material_set.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || material_set.get("setupProfileId").and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || material_set
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareComponentMaterial must be an evaluation-key component material transport set",
        ));
    }
    let component_materials = array_value(material_set, "componentMaterials")?;
    evaluation_key_component_material_roots_from_values(
        component_materials,
        "transportedEvaluationKeyShareComponentMaterial.componentMaterials",
    )
    .map(Some)
}

fn evaluation_key_component_material_roots_from_values(
    component_materials: &[Value],
    object_path: &str,
) -> CanonicalResult<BTreeSet<String>> {
    let mut supplied_roots = BTreeSet::new();
    for component_material in component_materials {
        let material_root = value_string(component_material, "keySwitchComponentMaterialRoot")?;
        validate_hash_string(
            material_root,
            &format!("{object_path}.keySwitchComponentMaterialRoot"),
        )?;
        if !supplied_roots.insert(material_root.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path} contains duplicate component material roots"),
            ));
        }
    }

    Ok(supplied_roots)
}

fn expected_public_evaluation_key_component_material_roots(
    setup_package: &Value,
) -> CanonicalResult<BTreeSet<String>> {
    let mut expected_roots = BTreeSet::new();
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public evaluation-key material verification",
            )
        })?;
    for record_field_name in ["roundOneRecords", "roundTwoRecords"] {
        for record in array_value(rounds, record_field_name)? {
            collect_binary_key_switch_component_material_root(record, &mut expected_roots)?;
        }
    }
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public evaluation-key material verification",
            )
        })?;
    for batch in batches {
        for material_record in array_value(batch, "galoisKeyShareMaterialRecords")? {
            collect_binary_key_switch_component_material_root(
                material_record,
                &mut expected_roots,
            )?;
        }
    }

    Ok(expected_roots)
}

fn collect_binary_key_switch_component_material_root(
    record: &Value,
    expected_roots: &mut BTreeSet<String>,
) -> CanonicalResult<()> {
    if record
        .get("keySwitchMaterialEncoding")
        .and_then(Value::as_str)
        == Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
    {
        expected_roots.insert(value_string(record, "keySwitchComponentMaterialRoot")?.to_string());
    }

    Ok(())
}

fn verify_public_evaluation_key_material_entry_header(
    evaluation_keys: &Value,
    material_entry: &Value,
) -> CanonicalResult<()> {
    if material_entry.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_MATERIAL_TRANSPORT_OBJECT_TYPE)
        || material_entry.get("objectVersion").and_then(Value::as_u64) != Some(1)
        || material_entry.get("setupProfileId").and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || material_entry
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
        || material_entry
            .get("materialEncoding")
            .and_then(Value::as_str)
            != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public evaluation-key material entry header is invalid",
        ));
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
        "evaluationKeySetHash",
        "publicEvaluationKeyMaterialRoot",
    ] {
        if material_entry.get(field_name) != evaluation_keys.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "transported public evaluation-key material {field_name} must match evaluationKeys"
                ),
            ));
        }
    }

    Ok(())
}

fn public_evaluation_key_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public evaluation-key material chunkSizeBytes must match the setup transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public evaluation-key material chunkCount does not fit usize",
        )
    })?;
    let chunk_values = array_value(value, "chunks")?;
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public evaluation-key material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if value_u64(chunk_value, "chunkIndex")?
            != u64::try_from(expected_chunk_index).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public evaluation-key material chunk index does not fit u64",
                )
            })?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public evaluation-key material chunks must be in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

pub(in crate::bgv::setup) fn public_evaluation_key_material_transport_hashes(
    chunks: &[Vec<u8>],
) -> CanonicalResult<PublicEvaluationKeyMaterialTransportHashes> {
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public evaluation-key material transport requires at least one chunk",
        ));
    }
    let chunk_size = usize::try_from(SETUP_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |byte_count, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public evaluation-key material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public evaluation-key material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public evaluation-key material contains a short non-final chunk",
                    ));
                }
                byte_count
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public evaluation-key material chunk length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public evaluation-key material byte length overflowed",
                        )
                    })
            })?;
    let full_object_hash =
        public_evaluation_key_material_full_object_hash(total_byte_length, chunks);
    let chunk_hashes = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            public_evaluation_key_material_chunk_hash(&full_object_hash, chunk_index, chunk)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let chunk_root = derive_protocol_hash(
        "PublicEvaluationKeyMaterialChunkRoot",
        &json!({
            "objectType": "PublicEvaluationKeyMaterialChunkManifest",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": chunk_hashes.len(),
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )?;

    Ok(PublicEvaluationKeyMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

// Prefixing the total length (and folding chunk_index per chunk) makes the chunk concatenation injective, so a re-chunked or reordered stream cannot collide to the same full-object hash.
fn public_evaluation_key_material_full_object_hash(
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> String {
    let total_length_bytes = total_byte_length.to_le_bytes();
    let mut parts = Vec::with_capacity(chunks.len() + 1);
    parts.push(total_length_bytes.as_slice());
    for chunk in chunks {
        parts.push(chunk.as_slice());
    }

    hash512_hex(
        "sealed-lattice/setup/public-evaluation-key-material/full-object-v1",
        &parts,
    )
}

fn public_evaluation_key_material_chunk_hash(
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let chunk_index_bytes = u64::try_from(chunk_index)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public evaluation-key material chunk index does not fit u64",
            )
        })?
        .to_le_bytes();

    Ok(hash512_hex(
        "sealed-lattice/setup/public-evaluation-key-material/chunk-v1",
        &[full_object_hash.as_bytes(), &chunk_index_bytes, chunk],
    ))
}

fn verify_public_evaluation_key_material_hash_fields(
    value: &Value,
    transport_hashes: &PublicEvaluationKeyMaterialTransportHashes,
    value_name: &str,
) -> CanonicalResult<()> {
    let chunk_size = value_u64(value, "chunkSizeBytes")
        .or_else(|_| value_u64(value, "publicEvaluationKeyMaterialChunkSizeBytes"))?;
    let chunk_count = value_u64(value, "chunkCount")
        .or_else(|_| value_u64(value, "publicEvaluationKeyMaterialChunkCount"))?;
    let total_byte_length = value_u64(value, "totalByteLength")
        .or_else(|_| value_u64(value, "publicEvaluationKeyMaterialTotalByteLength"))?;
    let full_object_hash = value_string(value, "fullObjectHash")
        .or_else(|_| value_string(value, "publicEvaluationKeyMaterialFullObjectHash"))?;
    let chunk_root = value_string(value, "chunkRoot")
        .or_else(|_| value_string(value, "publicEvaluationKeyMaterialChunkRoot"))?;
    if chunk_size != SETUP_TRANSPORT_CHUNK_SIZE_BYTES
        || chunk_count
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public evaluation-key material chunk count does not fit u64",
                )
            })?
        || total_byte_length != transport_hashes.total_byte_length
        || full_object_hash != transport_hashes.full_object_hash
        || chunk_root != transport_hashes.chunk_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{value_name} hash metadata does not match supplied chunks"),
        ));
    }
    let chunk_hash_values = value
        .get("chunkHashes")
        .or_else(|| value.get("publicEvaluationKeyMaterialChunkHashes"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{value_name} must list every public evaluation-key material chunk hash"),
            )
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{value_name} chunk hash count must match supplied chunks"),
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{value_name} chunk hashes must match supplied chunks"),
            ));
        }
    }

    Ok(())
}

pub(in crate::bgv::setup) fn public_evaluation_key_material_reference_root(
    evaluation_keys: &Value,
    expected_manifest: &Value,
    transport_hashes: &PublicEvaluationKeyMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "PublicEvaluationKeyMaterialRoot",
        &json!({
            "objectType": "PublicEvaluationKeyMaterialReference",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
            "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
            "ceremonyId": value_string(evaluation_keys, "ceremonyId")?,
            "manifestHash": value_string(evaluation_keys, "manifestHash")?,
            "rosterHash": value_string(evaluation_keys, "rosterHash")?,
            "setupProfileHash": value_string(evaluation_keys, "setupProfileHash")?,
            "qShareHash": value_string(evaluation_keys, "qShareHash")?,
            "carryAwareVssShareRelationProfileHash": value_string(
                evaluation_keys,
                "carryAwareVssShareRelationProfileHash",
            )?,
            "commitmentProfileHash": value_string(evaluation_keys, "commitmentProfileHash")?,
            "setupEpoch": value_string(evaluation_keys, "setupEpoch")?,
            "evaluatorKeyScheduleRoot": value_string(
                evaluation_keys,
                "evaluatorKeyScheduleRoot",
            )?,
            "sameSecretProofFamilyBindingRoot": value_string(
                evaluation_keys,
                "sameSecretProofFamilyBindingRoot",
            )?,
            "publicKeyShareSuccinctProofSetRoot": value_string(
                evaluation_keys,
                "publicKeyShareSuccinctProofSetRoot",
            )?,
            "relinearizationKeyShareRoundsRoot": value_string(
                evaluation_keys,
                "relinearizationKeyShareRoundsRoot",
            )?,
            "requiredGaloisSetHash": value_string(evaluation_keys, "requiredGaloisSetHash")?,
            "expectedMaterialManifest": expected_manifest,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        }),
    )
}

pub(in crate::bgv::setup) fn public_evaluation_key_material_manifest(
    setup_package: &Value,
    evaluation_keys: &Value,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "PublicEvaluationKeyMaterialManifest",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
        "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
        "materialTransportEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
        "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
        "ceremonyId": value_string(evaluation_keys, "ceremonyId")?,
        "manifestHash": value_string(evaluation_keys, "manifestHash")?,
        "rosterHash": value_string(evaluation_keys, "rosterHash")?,
        "setupProfileHash": value_string(evaluation_keys, "setupProfileHash")?,
        "qShareHash": value_string(evaluation_keys, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(
            evaluation_keys,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": value_string(evaluation_keys, "commitmentProfileHash")?,
        "setupEpoch": value_string(evaluation_keys, "setupEpoch")?,
        "participantCount": value_u64(evaluation_keys, "participantCount")?,
        "rnsLimbCount": value_u64(evaluation_keys, "rnsLimbCount")?,
        "evaluatorKeyScheduleRoot": value_string(evaluation_keys, "evaluatorKeyScheduleRoot")?,
        "sameSecretProofFamilyBindingRoot": value_string(
            evaluation_keys,
            "sameSecretProofFamilyBindingRoot",
        )?,
        "publicKeyShareSuccinctProofSetRoot": value_string(
            evaluation_keys,
            "publicKeyShareSuccinctProofSetRoot",
        )?,
        "relinearizationKeyShareRoundsRoot": value_string(
            evaluation_keys,
            "relinearizationKeyShareRoundsRoot",
        )?,
        "relinearizationLevelSchedule": evaluation_keys["relinearizationLevelSchedule"],
        "relinearizationKeyRoots": evaluation_keys["relinearizationKeyRoots"],
        "relinearizationShareMaterialRoots": relinearization_share_material_manifest(setup_package)?,
        "requiredGaloisSetHash": value_string(evaluation_keys, "requiredGaloisSetHash")?,
        "requiredGaloisKeySchedule": evaluation_keys["requiredGaloisKeySchedule"],
        "galoisKeyShareBatchRoots": evaluation_keys["galoisKeyShareBatchRoots"],
        "galoisKeyRoots": evaluation_keys["galoisKeyRoots"],
        "galoisShareMaterialRoots": galois_share_material_manifest(setup_package)?,
        "genericKeySwitchKeyRoots": evaluation_keys["genericKeySwitchKeyRoots"],
        "rawKeyBytesEmbedded": false,
        "verifierGeneratedKeyMaterial": false,
    }))
}

fn relinearization_share_material_manifest(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public evaluation-key material binding",
            )
        })?;
    let mut entries = Vec::new();
    for (round_label, record_field_name, share_root_field_name, record_root_field_name) in [
        (
            "round-one",
            "roundOneRecords",
            "roundOneShareRoot",
            "roundOneRecordRoot",
        ),
        (
            "round-two",
            "roundTwoRecords",
            "roundTwoShareRoot",
            "roundTwoRecordRoot",
        ),
    ] {
        for record in array_value(rounds, record_field_name)? {
            entries.push((
                value_u64(record, "level")?,
                value_u64(record, "trusteeRosterPosition")?,
                if round_label == "round-one" {
                    0_u8
                } else {
                    1_u8
                },
                json!({
                    "round": round_label,
                    "trusteeIdentity": value_string(record, "trusteeIdentity")?,
                    "trusteeRosterPosition": value_u64(record, "trusteeRosterPosition")?,
                    "level": value_u64(record, "level")?,
                    "keySwitchMaterialEncoding": value_string(record, "keySwitchMaterialEncoding")?,
                    "keySwitchDomain": value_string(record, "keySwitchDomain")?,
                    "keySwitchSeedHex": value_string(record, "keySwitchSeedHex")?,
                    "keySwitchComponentVectorRoot": value_string(
                        record,
                        "keySwitchComponentVectorRoot",
                    )?,
                    "keySwitchComponentMaterialRoot": record
                        .get("keySwitchComponentMaterialRoot")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "shareRoot": value_string(record, share_root_field_name)?,
                    "recordRoot": value_string(record, record_root_field_name)?,
                }),
            ));
        }
    }
    entries.sort_by_key(|(level, trustee_roster_position, round_order, _)| {
        (*level, *round_order, *trustee_roster_position)
    });

    Ok(entries.into_iter().map(|(_, _, _, entry)| entry).collect())
}

fn galois_share_material_manifest(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public evaluation-key material binding",
            )
        })?;
    let mut entries = Vec::new();
    for batch in batches {
        for proof_record in array_value(batch, "galoisKeyShareMaterialRecords")? {
            entries.push((
                value_u64(proof_record, "rotation")?,
                value_u64(proof_record, "level")?,
                value_u64(proof_record, "trusteeRosterPosition")?,
                json!({
                    "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
                    "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
                    "rotation": value_u64(proof_record, "rotation")?,
                    "level": value_u64(proof_record, "level")?,
                    "keySwitchMaterialEncoding": value_string(
                        proof_record,
                        "keySwitchMaterialEncoding",
                    )?,
                    "keySwitchDomain": value_string(proof_record, "keySwitchDomain")?,
                    "keySwitchSeedHex": value_string(proof_record, "keySwitchSeedHex")?,
                    "keySwitchComponentVectorRoot": value_string(
                        proof_record,
                        "keySwitchComponentVectorRoot",
                    )?,
                    "keySwitchComponentMaterialRoot": proof_record
                        .get("keySwitchComponentMaterialRoot")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "galoisKeyShareRoot": value_string(proof_record, "galoisKeyShareRoot")?,
                }),
            ));
        }
    }
    entries.sort_by_key(|(rotation, level, trustee_roster_position, _)| {
        (*rotation, *level, *trustee_roster_position)
    });

    Ok(entries.into_iter().map(|(_, _, _, entry)| entry).collect())
}

fn decode_public_evaluation_key_material_manifest(
    chunks: &[Vec<u8>],
    transport_hashes: &PublicEvaluationKeyMaterialTransportHashes,
) -> CanonicalResult<Value> {
    let total_byte_length = usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public evaluation-key material byte length does not fit usize",
        )
    })?;
    let mut material_bytes = Vec::with_capacity(total_byte_length);
    for chunk in chunks {
        material_bytes.extend_from_slice(chunk);
    }
    if material_bytes.len() < PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()
        || &material_bytes[..PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()]
            != PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material has the wrong format marker",
        ));
    }
    let manifest_bytes = &material_bytes[PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()..];
    let manifest: Value = serde_json::from_slice(manifest_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material manifest is not valid JSON",
        )
    })?;
    if canonical_json(&manifest)?.as_bytes() != manifest_bytes {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material manifest must use canonical JSON bytes",
        ));
    }

    Ok(manifest)
}

#[cfg(test)]
pub(in crate::bgv::setup) fn encode_public_evaluation_key_material_manifest(
    manifest: &Value,
) -> CanonicalResult<Vec<u8>> {
    let mut material_bytes = Vec::new();
    material_bytes.extend_from_slice(PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC);
    material_bytes.extend_from_slice(canonical_json(manifest)?.as_bytes());

    Ok(material_bytes)
}

fn expected_relinearization_key_roots_for_evaluation_keys(
    setup_package: &Value,
    binding: &EvaluationKeyProofCommonBinding,
) -> CanonicalResult<Vec<Value>> {
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before evaluation-key assembly",
            )
        })?;
    let relinearization_key_share_rounds_root =
        value_string(rounds, "relinearizationKeyShareRoundsRoot")?;
    let round_one_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneAggregateRoot",
    )?;
    let round_two_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoAggregateRoot",
    )?;

    scheduled_relinearization_levels()?
        .into_iter()
        .map(|level| {
            let round_one_aggregate_root =
                round_one_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-one aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let round_two_aggregate_root =
                round_two_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-two aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let decomposition_digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "relinearization level overflowed while deriving evaluation-key assembly",
                )
            })?;
            let key_root = derive_protocol_hash(
                "RelinearizationKeyRoot",
                &json!({
                    "objectType": "RelinearizationKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                    "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                    "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
                    "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
                    "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
                    "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                    "sameSecretProofFamilyBindingRoot": binding
                        .same_secret_proof_family_binding_root
                        .as_str(),
                    "publicKeyShareSuccinctProofSetRoot": binding
                        .public_key_share_succinct_proof_set_root
                        .as_str(),
                    "relinearizationKeyShareRoundsRoot": relinearization_key_share_rounds_root,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "roundOneAggregateRoot": round_one_aggregate_root,
                    "roundTwoAggregateRoot": round_two_aggregate_root,
                }),
            )?;

            Ok(json!({
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
                "relinearizationKeyRoot": key_root,
            }))
        })
        .collect()
}

fn expected_galois_batch_roots_for_evaluation_keys(
    setup_package: &Value,
) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before evaluation-key assembly",
            )
        })?;
    let mut batch_roots = BTreeMap::<u64, Value>::new();
    for batch in batches {
        let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
        let trustee_identity = value_string(batch, "trusteeIdentity")?;
        let galois_key_share_batch_root = value_string(batch, "galoisKeyShareBatchRoot")?;
        if batch_roots
            .insert(
                trustee_roster_position,
                json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "galoisKeyShareBatchRoot": galois_key_share_batch_root,
                }),
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batches must not repeat a trustee roster position",
            ));
        }
    }

    Ok(batch_roots.into_values().collect())
}

fn expected_galois_key_roots_for_evaluation_keys(
    setup_package: &Value,
    binding: &EvaluationKeyProofCommonBinding,
) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before evaluation-key assembly",
            )
        })?;
    let expected_schedule = expected_required_galois_key_schedule()?;
    let expected_schedule = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "required Galois key schedule must be an array",
        )
    })?;
    let mut ordered_batches = batches
        .iter()
        .map(|batch| Ok((value_u64(batch, "trusteeRosterPosition")?, batch)))
        .collect::<CanonicalResult<Vec<_>>>()?;
    ordered_batches.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);

    expected_schedule
        .iter()
        .map(|schedule_entry| {
            let rotation = value_u64(schedule_entry, "rotation")?;
            let level = value_u64(schedule_entry, "level")?;
            let decomposition_digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "Galois key level overflowed while deriving evaluation-key assembly",
                )
            })?;
            let mut contributing_share_roots = Vec::new();
            for (_, batch) in &ordered_batches {
                let trustee_identity = value_string(batch, "trusteeIdentity")?;
                let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
                let material_record =
                    galois_key_share_material_for_schedule(batch, rotation, level)?;
                contributing_share_roots.push(json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "galoisKeyShareRoot": value_string(material_record, "galoisKeyShareRoot")?,
                }));
            }
            let galois_key_root = derive_protocol_hash(
                "RotationKeyRoot",
                &json!({
                    "objectType": "GaloisKeyAggregate",
                    "objectVersion": 1,
                    "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                    "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                    "assemblyStatus": PUBLIC_EVALUATION_KEY_ASSEMBLY_STATUS,
                    "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
                    "materialSource": PUBLIC_EVALUATION_KEY_MATERIAL_SOURCE,
                    "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                    "sameSecretProofFamilyBindingRoot": binding
                        .same_secret_proof_family_binding_root
                        .as_str(),
                    "publicKeyShareSuccinctProofSetRoot": binding
                        .public_key_share_succinct_proof_set_root
                        .as_str(),
                    "galoisKeyCrpRoot": binding.galois_key_crp_root.as_str(),
                    "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
                    "rotation": rotation,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "contributingShareRoots": contributing_share_roots,
                }),
            )?;

            Ok(json!({
                "rotation": rotation,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "galoisKeyRoot": galois_key_root,
                "contributingShareRoots": contributing_share_roots,
            }))
        })
        .collect()
}

fn accepted_setup_evaluation_key_records_use_profile_ring(
    setup_package: &Value,
) -> CanonicalResult<bool> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(false);
    };
    for field_name in ["roundOneRecords", "roundTwoRecords"] {
        for record in array_value(rounds, field_name)? {
            if value_u64(record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Ok(false);
            }
        }
    }
    let Some(galois_batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    else {
        return Ok(false);
    };
    for batch in galois_batches {
        for material_record in array_value(batch, "galoisKeyShareMaterialRecords")? {
            if value_u64(material_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

pub(in crate::bgv::setup) fn accepted_setup_public_relinearization_keys_from_transport(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<BTreeMap<usize, KeySwitchKey>> {
    accepted_setup_verifier_phase("loading accepted public relinearization key material");
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let mut component_material_cache = EvaluationKeyShareComponentMaterialCache::default();
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public relinearization key material loading",
            )
        })?;
    let round_two_records = array_value(rounds, "roundTwoRecords")?;
    let mut records_by_level_and_trustee = BTreeMap::new();
    for record in round_two_records {
        if value_string(record, "objectType")? != RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public relinearization key material must use round-two records",
            ));
        }
        let level = value_u64(record, "level")?;
        let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
        if records_by_level_and_trustee
            .insert((level, trustee_roster_position), record)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public relinearization key material must not repeat a trustee record for a level",
            ));
        }
    }

    let expected_levels = scheduled_relinearization_levels()?;
    let expected_record_count = expected_levels
        .len()
        .checked_mul(FIRST_PROFILE_PARTICIPANT_COUNT as usize)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "accepted public relinearization key material record count overflowed",
            )
        })?;
    if records_by_level_and_trustee.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted public relinearization key material requires one round-two record per scheduled level and trustee",
        ));
    }

    let mut relinearization_keys = BTreeMap::new();
    for level in expected_levels {
        let level_usize = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "relinearization key level does not fit usize",
            )
        })?;
        let key_switch_seed_hex =
            expected_relinearization_key_switch_seed(&binding, "round-two", level)?;
        let mut aggregate_component_b = None;
        for trustee_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT {
            let proof_record = records_by_level_and_trustee
                .get(&(level, trustee_roster_position))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "accepted public relinearization key material is missing a trustee record for a scheduled level",
                    )
                })?;
            verify_relinearization_key_switch_sample_binding(
                proof_record,
                &binding,
                "round-two",
                level,
            )?;
            if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public relinearization key runtime material requires profile-ring component vectors",
                ));
            }
            let component_b = component_b_vectors_from_record_with_cache(
                EvaluationKeyShareProofFamily::Relinearization,
                proof_record,
                transported_key_switch_component_material,
                &mut component_material_cache,
            )?;
            add_accepted_key_switch_component_b(
                &mut aggregate_component_b,
                component_b,
                level_usize,
            )?;
        }
        let aggregate_component_b = aggregate_component_b.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public relinearization key aggregation requires at least one component share",
            )
        })?;
        let key_switch_key = key_switch_key_from_public_component_b(
            level_usize,
            "relinearization",
            &key_switch_seed_hex,
            aggregate_component_b,
        )?;
        relinearization_keys.insert(level_usize, key_switch_key);
        accepted_setup_verifier_phase(&format!(
            "loaded accepted public relinearization key level {level}"
        ));
    }
    accepted_setup_verifier_phase("loaded accepted public relinearization key material");

    Ok(relinearization_keys)
}

pub(in crate::bgv::setup) fn accepted_setup_public_galois_keys_from_transport(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<BTreeMap<(usize, usize), KeySwitchKey>> {
    accepted_setup_verifier_phase("loading accepted public Galois key material");
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let mut component_material_cache = EvaluationKeyShareComponentMaterialCache::default();
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public Galois key material loading",
            )
        })?;
    let mut sorted_batches = batches
        .iter()
        .map(|batch| Ok((value_u64(batch, "trusteeRosterPosition")?, batch)))
        .collect::<CanonicalResult<Vec<_>>>()?;
    sorted_batches.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);
    if sorted_batches.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted public Galois key material requires one proof batch per trustee",
        ));
    }
    let mut seen_trustee_roster_positions = BTreeSet::new();
    for (trustee_roster_position, _) in &sorted_batches {
        if !seen_trustee_roster_positions.insert(*trustee_roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public Galois key material must not repeat a trustee batch",
            ));
        }
    }
    let expected_schedule = expected_required_galois_key_schedule()?;
    let expected_schedule = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "required Galois key schedule must be an array",
        )
    })?;
    let mut rotation_keys = BTreeMap::new();
    for schedule_entry in expected_schedule {
        let rotation = value_u64(schedule_entry, "rotation")?;
        let level = value_u64(schedule_entry, "level")?;
        let level_usize = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois key level does not fit usize",
            )
        })?;
        let rotation_usize = usize::try_from(rotation).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois key rotation does not fit usize",
            )
        })?;
        let key_switch_domain = format!("galois-{rotation}");
        let key_switch_seed_hex = expected_galois_key_switch_seed(&binding, rotation, level)?;
        let mut aggregate_component_b = None;
        for (_, batch) in &sorted_batches {
            let proof_record = galois_key_share_material_for_schedule(batch, rotation, level)?;
            verify_galois_key_switch_sample_binding(proof_record, &binding, rotation, level)?;
            if value_u64(proof_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public Galois key runtime material requires profile-ring component vectors",
                ));
            }
            let component_b = component_b_vectors_from_record_with_cache(
                EvaluationKeyShareProofFamily::Galois,
                proof_record,
                transported_key_switch_component_material,
                &mut component_material_cache,
            )?;
            add_accepted_key_switch_component_b(
                &mut aggregate_component_b,
                component_b,
                level_usize,
            )?;
        }
        let aggregate_component_b = aggregate_component_b.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public Galois key aggregation requires at least one component share",
            )
        })?;
        let key_switch_key = key_switch_key_from_public_component_b(
            level_usize,
            &key_switch_domain,
            &key_switch_seed_hex,
            aggregate_component_b,
        )?;
        rotation_keys.insert((rotation_usize, level_usize), key_switch_key);
        accepted_setup_verifier_phase(&format!(
            "loaded accepted public Galois key rotation {rotation} level {level}"
        ));
    }
    accepted_setup_verifier_phase("loaded accepted public Galois key material");

    Ok(rotation_keys)
}

fn add_accepted_key_switch_component_b(
    aggregate_component_b: &mut Option<Vec<Vec<Vec<u64>>>>,
    component_b: Vec<Vec<Vec<u64>>>,
    level: usize,
) -> CanonicalResult<()> {
    let primes = DATA_PRIMES.get(..=level).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component aggregation level is outside Q_share",
        )
    })?;
    if component_b.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component aggregation digit count does not match its level",
        ));
    }
    match aggregate_component_b {
        None => {
            validate_key_switch_component_shape(&component_b, primes)?;
            *aggregate_component_b = Some(component_b);
        }
        Some(aggregate) => {
            validate_key_switch_component_shape(aggregate, primes)?;
            validate_key_switch_component_shape(&component_b, primes)?;
            for (digit_index, (aggregate_by_limb, component_by_limb)) in
                aggregate.iter_mut().zip(component_b.iter()).enumerate()
            {
                if aggregate_by_limb.len() != primes.len()
                    || component_by_limb.len() != primes.len()
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "key-switch component aggregation limb count does not match its level",
                    ));
                }
                for (rns_limb_index, (aggregate_coefficients, component_coefficients)) in
                    aggregate_by_limb
                        .iter_mut()
                        .zip(component_by_limb.iter())
                        .enumerate()
                {
                    if aggregate_coefficients.len() != POLYNOMIAL_DEGREE
                        || component_coefficients.len() != POLYNOMIAL_DEGREE
                    {
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "key-switch component aggregation requires profile-ring coefficient vectors",
                        ));
                    }
                    let modulus = primes[rns_limb_index];
                    for (coefficient, addend) in aggregate_coefficients
                        .iter_mut()
                        .zip(component_coefficients.iter())
                    {
                        *coefficient = add_mod(*coefficient, *addend, modulus)?;
                    }
                }
                if digit_index >= primes.len() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "key-switch component aggregation digit index is outside its level",
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_key_switch_component_shape(
    component_b: &[Vec<Vec<u64>>],
    primes: &[u64],
) -> CanonicalResult<()> {
    if component_b.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component digit count does not match its level",
        ));
    }
    for component_by_limb in component_b {
        if component_by_limb.len() != primes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "key-switch component limb count does not match its level",
            ));
        }
        for (rns_limb_index, coefficients) in component_by_limb.iter().enumerate() {
            if coefficients.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "key-switch component coefficient count must match the profile ring degree",
                ));
            }
            if coefficients
                .iter()
                .any(|coefficient| *coefficient >= primes[rns_limb_index])
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "key-switch component contains non-canonical Q_share residues",
                ));
            }
        }
    }

    Ok(())
}

fn unexpected_public_evaluation_key_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "assemblyStatus",
            "materialEncoding",
            "materialSource",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "evaluatorKeyScheduleRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareSuccinctProofSetRoot",
            "relinearizationKeyShareRoundsRoot",
            "relinearizationLevelSchedule",
            "relinearizationKeyRoots",
            "requiredGaloisSetHash",
            "requiredGaloisKeySchedule",
            "galoisKeyShareBatchRoots",
            "galoisKeyRoots",
            "genericKeySwitchKeyRoots",
            "rawKeyBytesEmbedded",
            "verifierGeneratedKeyMaterial",
            "publicEvaluationKeyMaterialEncoding",
            "publicEvaluationKeyMaterialRoot",
            "publicEvaluationKeyMaterialChunkSizeBytes",
            "publicEvaluationKeyMaterialChunkCount",
            "publicEvaluationKeyMaterialTotalByteLength",
            "publicEvaluationKeyMaterialFullObjectHash",
            "publicEvaluationKeyMaterialChunkRoot",
            "publicEvaluationKeyMaterialChunkHashes",
            "evaluationKeySetHash",
        ],
    )
}

pub(super) fn evaluation_key_material_refusal(
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
