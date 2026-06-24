use super::expected_roots::*;
use super::manifest::*;
use super::public_key_reconstruction::*;
use super::*;

pub(in super::super) fn transported_evaluation_key_share_component_material_from_request(
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

pub(super) fn verify_public_evaluation_key_material_transport(
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
            "materialEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
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
