use super::helpers::*;
use super::verification::*;
use super::*;

pub(super) fn setup_proof_material_transport_stream_sessions()
-> &'static Mutex<BTreeMap<String, SetupProofMaterialTransportStreamSession>> {
    SETUP_PROOF_MATERIAL_TRANSPORT_STREAM_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn verified_setup_proof_materials()
-> &'static Mutex<BTreeMap<String, VerifiedSetupProofMaterial>> {
    VERIFIED_SETUP_PROOF_MATERIALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn read_setup_proof_material_transport_stream_header(
    value: &Value,
    object_path: &str,
) -> CanonicalResult<SetupProofMaterialTransportStreamHeader> {
    if value.get("chunks").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material stream header must not contain embedded chunks",
        ));
    }
    let proof_family = string_field_at(value, "proofFamily", object_path)?.to_string();
    validate_supported_setup_proof_transport_family(&proof_family, object_path)?;
    let proof_material_root = string_field_at(value, "proofMaterialRoot", object_path)?.to_string();
    validate_hash_string(
        &proof_material_root,
        &format!("{object_path}.proofMaterialRoot"),
    )?;
    let metadata = setup_proof_material_metadata_from_value(value, object_path)?;

    Ok(SetupProofMaterialTransportStreamHeader {
        proof_family,
        proof_material_root,
        metadata,
    })
}

pub(super) fn setup_proof_material_metadata_from_value(
    value: &Value,
    object_path: &str,
) -> CanonicalResult<SetupProofMaterialMetadata> {
    let uses_prefixed_fields = [
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| value.get(*field_name).is_some());
    let uses_direct_fields = [
        "chunkCount",
        "totalByteLength",
        "fullObjectHash",
        "chunkRoot",
        "chunkHashes",
    ]
    .iter()
    .any(|field_name| value.get(*field_name).is_some());
    if uses_prefixed_fields && uses_direct_fields {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path} must not mix direct and proof-prefixed chunk metadata"),
        ));
    }
    let (
        chunk_count_field,
        total_byte_length_field,
        full_object_hash_field,
        chunk_root_field,
        chunk_hashes_field,
    ) = if uses_prefixed_fields {
        (
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
        )
    } else {
        (
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkRoot",
            "chunkHashes",
        )
    };
    let chunk_size_bytes = SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES;
    let chunk_count = usize::try_from(u64_field_at(value, chunk_count_field, object_path)?)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{object_path}.{chunk_count_field} does not fit usize"),
            )
        })?;
    if chunk_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_path}.{chunk_count_field} must be positive"),
        ));
    }
    let total_byte_length = u64_field_at(value, total_byte_length_field, object_path)?;
    if total_byte_length == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_path}.{total_byte_length_field} must be positive"),
        ));
    }
    let full_object_hash = string_field_at(value, full_object_hash_field, object_path)?.to_string();
    validate_hash_string(
        &full_object_hash,
        &format!("{object_path}.{full_object_hash_field}"),
    )?;
    let chunk_root = string_field_at(value, chunk_root_field, object_path)?.to_string();
    validate_hash_string(&chunk_root, &format!("{object_path}.{chunk_root_field}"))?;
    let chunk_hashes =
        setup_proof_material_hash_array(value, chunk_hashes_field, object_path, chunk_count)?;
    let expected_chunk_root = setup_proof_material_chunk_manifest_root(
        string_field_at(value, "proofFamily", object_path)?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;
    if expected_chunk_root != chunk_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{object_path}.{chunk_root_field} does not match the canonical proof chunk manifest"
            ),
        ));
    }

    Ok(SetupProofMaterialMetadata {
        chunk_size_bytes,
        chunk_count,
        total_byte_length,
        full_object_hash,
        chunk_root,
        chunk_hashes,
    })
}

pub(super) fn setup_proof_material_hash_array(
    value: &Value,
    field_name: &str,
    object_path: &str,
    expected_chunk_count: usize,
) -> CanonicalResult<Vec<String>> {
    let chunk_hash_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name} must list every proof material chunk hash"),
            )
        })?;
    if chunk_hash_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path}.{field_name} length must match the chunk count"),
        ));
    }
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name}[{chunk_index}] must be a hash string"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("{object_path}.{field_name}[{chunk_index}]"),
        )?;
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

pub(super) fn absorb_setup_proof_material_transport_stream_chunk(
    session: &mut SetupProofMaterialTransportStreamSession,
    chunk_index: usize,
    chunk: Vec<u8>,
) -> CanonicalResult<Value> {
    if chunk_index != session.next_chunk_index {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material chunks must be absorbed in ascending chunk-index order",
        ));
    }
    if chunk_index >= session.header.metadata.chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material stream received more chunks than declared",
        ));
    }
    validate_setup_proof_material_transport_stream_chunk(
        chunk_index,
        &chunk,
        &session.header.metadata,
        session.observed_total_byte_length,
    )?;
    session.observed_total_byte_length = session
        .observed_total_byte_length
        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk length does not fit u64",
            )
        })?)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material byte length overflowed",
            )
        })?;
    session.chunks.push(chunk);
    session.next_chunk_index += 1;

    Ok(json!({
        "operation": "absorbSetupProofMaterialTransportStreamChunk",
        "absorbedChunkIndex": chunk_index,
        "nextChunkIndex": session.next_chunk_index,
        "observedTotalByteLength": session.observed_total_byte_length,
    }))
}

pub(super) fn validate_setup_proof_material_transport_stream_chunk(
    chunk_index: usize,
    chunk: &[u8],
    metadata: &SetupProofMaterialMetadata,
    observed_total_byte_length: u64,
) -> CanonicalResult<()> {
    if chunk.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunks must be non-empty",
        ));
    }
    let chunk_size = usize::try_from(metadata.chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size does not fit usize",
        )
    })?;
    if chunk.len() > chunk_size {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk exceeds the accepted chunk size",
        ));
    }
    let is_final_chunk = chunk_index + 1 == metadata.chunk_count;
    if !is_final_chunk && chunk.len() != chunk_size {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material contains a short non-final chunk",
        ));
    }
    let new_total = observed_total_byte_length
        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk length does not fit u64",
            )
        })?)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material byte length overflowed",
            )
        })?;
    if new_total > metadata.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material stream chunk bytes exceed declared totalByteLength",
        ));
    }
    if is_final_chunk && new_total != metadata.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "final setup proof material chunk must finish at declared totalByteLength",
        ));
    }

    Ok(())
}

pub(super) fn finish_setup_proof_material_transport_stream(
    verification_id: &str,
    session: SetupProofMaterialTransportStreamSession,
) -> CanonicalResult<Value> {
    if session.next_chunk_index != session.header.metadata.chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material stream is missing declared chunks",
        ));
    }
    if session.observed_total_byte_length != session.header.metadata.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material stream totalByteLength does not match absorbed chunk bytes",
        ));
    }
    let transport_hashes = setup_proof_material_transport_hashes(
        &session.header.proof_family,
        &session.chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    let observed_metadata = SetupProofMaterialMetadata {
        chunk_size_bytes: SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        chunk_count: transport_hashes.chunk_hashes.len(),
        total_byte_length: transport_hashes.total_byte_length,
        full_object_hash: transport_hashes.full_object_hash.clone(),
        chunk_root: transport_hashes.chunk_root.clone(),
        chunk_hashes: transport_hashes.chunk_hashes.clone(),
    };
    compare_setup_proof_material_metadata(
        &observed_metadata,
        &session.header.metadata,
        "transportedSetupProofMaterial",
    )?;
    let verified_material_reference = verified_setup_proof_material_reference_value(
        verification_id,
        &session.header.proof_family,
        &session.header.proof_material_root,
        &transport_hashes,
    );
    verified_setup_proof_materials()
        .lock()
        .map_err(|_| setup_proof_error("verified setup proof material store is unavailable"))?
        .insert(
            verification_id.to_string(),
            VerifiedSetupProofMaterial {
                reference: verified_material_reference.clone(),
                chunks: Arc::new(session.chunks),
            },
        );

    Ok(json!({
        "operation": "finishSetupProofMaterialTransportStream",
        "verificationId": verification_id,
        "proofFamily": session.header.proof_family,
        "proofMaterialRoot": session.header.proof_material_root,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "transport": {
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        },
        "verifiedSetupProofMaterial": verified_material_reference,
    }))
}

pub(super) fn verified_setup_proof_material_reference_value(
    verification_id: &str,
    proof_family: &str,
    proof_material_root: &str,
    hashes: &SetupProofMaterialTransportHashes,
) -> Value {
    json!({
        "objectType": VERIFIED_SETUP_PROOF_MATERIAL_OBJECT_TYPE,
        "verificationId": verification_id,
        "proofFamily": proof_family,
        "proofMaterialRoot": proof_material_root,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofChunkCount": hashes.chunk_hashes.len(),
        "proofTotalByteLength": hashes.total_byte_length,
        "proofFullObjectHash": hashes.full_object_hash,
        "proofChunkRoot": hashes.chunk_root,
        "proofChunkHashes": hashes.chunk_hashes,
    })
}

pub(super) fn verify_verified_setup_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    if !value.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verifiedSetupProofMaterials must be an object",
        ));
    }
    if value.get("objectType").and_then(Value::as_str)
        != Some(VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "verifiedSetupProofMaterials.objectType must be {VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE}"
            ),
        ));
    }

    Ok(())
}

pub(super) fn verify_verified_setup_proof_material_header(
    value: &Value,
    object_path: &str,
) -> CanonicalResult<()> {
    if !value.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path} must be an object"),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", VERIFIED_SETUP_PROOF_MATERIAL_OBJECT_TYPE),
        ("proofBytesEncoding", SETUP_PROOF_MATERIAL_ENCODING),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name} must be {expected_value}"),
            ));
        }
    }
    setup_proof_material_verification_id_field(value)?;
    validate_supported_setup_proof_transport_family(
        string_field_at(value, "proofFamily", object_path)?,
        object_path,
    )?;
    validate_hash_string(
        string_field_at(value, "proofMaterialRoot", object_path)?,
        &format!("{object_path}.proofMaterialRoot"),
    )?;

    Ok(())
}

pub(super) fn compare_setup_proof_material_metadata(
    observed: &SetupProofMaterialMetadata,
    expected: &SetupProofMaterialMetadata,
    object_path: &str,
) -> CanonicalResult<()> {
    if observed.chunk_size_bytes != expected.chunk_size_bytes
        || observed.chunk_count != expected.chunk_count
        || observed.total_byte_length != expected.total_byte_length
        || observed.full_object_hash != expected.full_object_hash
        || observed.chunk_root != expected.chunk_root
        || observed.chunk_hashes != expected.chunk_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{object_path} metadata does not match the stream-verified setup proof material"
            ),
        ));
    }

    Ok(())
}

pub(super) fn validate_supported_setup_proof_transport_family(
    proof_family: &str,
    object_path: &str,
) -> CanonicalResult<()> {
    if !SETUP_PROOF_TRANSPORT_FAMILIES.contains(&proof_family) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path}.proofFamily is not in the setup proof transport parameters"),
        ));
    }

    Ok(())
}

pub(super) fn setup_proof_material_verification_id_field(value: &Value) -> CanonicalResult<&str> {
    let verification_id = string_field_at(value, "verificationId", "verificationId")?;
    if verification_id.is_empty()
        || verification_id.len() > SETUP_PROOF_MATERIAL_STREAM_ID_MAX_BYTES
        || !verification_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_:.".contains(character))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material verificationId must be a short ASCII identifier",
        ));
    }

    Ok(verification_id)
}
