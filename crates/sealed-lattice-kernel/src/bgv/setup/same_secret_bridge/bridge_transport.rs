use super::statement_record::*;
use super::*;

// Resolved same-secret bridge proof bytes plus the canonical proof
// record whose root binds them. The embedded form carries the proof bytes as
// base64 inside the record; the transported form streams the bytes through the
// shared setup proof-material transport and binds the transport reference into
// the record root instead of the base64 bytes.
pub(super) struct ResolvedSameSecretBridgeProofBytes {
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

pub(super) fn resolve_same_secret_bridge_proof_bytes(
    proof_record: &Value,
    request: &Value,
    bridge_statement_root: &str,
) -> CanonicalResult<ResolvedSameSecretBridgeProofBytes> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    let proof_record_root = hash_at_path(proof_record, &["proofRecordRoot"])?.to_string();
    if proof_record.get("proofBytesBase64").is_some() {
        if proof_record.get("proofBytesEncoding").is_some()
            || same_secret_bridge_proof_has_transport_reference(proof_record)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge proof record must not mix embedded proofBytesBase64 with transported proof material",
            ));
        }
        let proof_bytes_base64 = string_at_path(proof_record, &["proofBytesBase64"])?;
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_bytes_base64,
            "same-secret bridge proofBytesBase64",
        )?;
        let expected_proof_bytes_hash =
            hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        compare_required_string(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "same-secret bridge proof record proofBytesHash",
        )?;
        let proof_record_without_root = json!({
            "objectType": "VssSameSecretBridgeProofRecord",
            "objectVersion": 1,
            "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "sameSecretBridgeStatementRoot": bridge_statement_root,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesBase64": proof_bytes_base64,
        });
        let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
        if expected_proof_record_root != proof_record_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge proof record root does not match its bound proof bytes",
            ));
        }

        return Ok(ResolvedSameSecretBridgeProofBytes {
            proof_bytes,
            proof_record_without_root,
            proof_record_root,
        });
    }

    compare_required_string(
        string_at_path(proof_record, &["proofBytesEncoding"])?,
        SETUP_PROOF_MATERIAL_ENCODING,
        "same-secret bridge proof record proofBytesEncoding",
    )?;
    let proof_material_root = hash_at_path(proof_record, &["proofMaterialRoot"])?;
    let transported_binding =
        transported_same_secret_bridge_proof_material_binding(request, proof_material_root)?;
    verify_same_secret_bridge_proof_transport_reference(
        proof_record,
        &transported_binding.transport_hashes,
    )?;
    compare_required_string(
        proof_bytes_hash,
        &transported_binding.proof_bytes_hash,
        "same-secret bridge proof record proofBytesHash",
    )?;
    let proof_record_without_root = json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementRoot": bridge_statement_root,
        "proofBytesHash": proof_bytes_hash,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_material_root,
        "proofChunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "proofChunkCount": transported_binding.transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transported_binding.transport_hashes.total_byte_length,
        "proofFullObjectHash": transported_binding.transport_hashes.full_object_hash,
        "proofChunkRoot": transported_binding.transport_hashes.chunk_root,
        "proofChunkHashes": transported_binding.transport_hashes.chunk_hashes,
    });
    let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    if expected_proof_record_root != proof_record_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret bridge proof record root does not match its transported proof material",
        ));
    }

    Ok(ResolvedSameSecretBridgeProofBytes {
        proof_bytes: transported_binding.proof_bytes,
        proof_record_without_root,
        proof_record_root,
    })
}

pub(super) struct SameSecretBridgeProofTransportBinding {
    pub(super) transport_hashes: SetupProofMaterialTransportHashes,
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_bytes_hash: String,
}

pub(super) fn transported_same_secret_bridge_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SameSecretBridgeProofTransportBinding> {
    let material_set = value_at_path(request, &["transportedSameSecretBridgeProofMaterial"])
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretBridgeProofMaterial is required by transported same-secret bridge proof records",
            )
        })?;
    verify_transported_same_secret_bridge_proof_material_set_header(material_set)?;
    let proof_materials = array_at_path(material_set, &["proofMaterials"])?;
    let mut matching_binding = None;
    for (proof_material_index, proof_material) in proof_materials.iter().enumerate() {
        verify_transported_same_secret_bridge_proof_material_header(proof_material)?;
        let proof_material_root = hash_at_path(proof_material, &["proofMaterialRoot"])?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretBridgeProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            Arc::new(transported_same_secret_bridge_proof_chunks(
                proof_material,
                proof_material_index,
            )?)
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                SAME_SECRET_BRIDGE_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedSameSecretBridgeProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            chunks.as_ref(),
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_same_secret_bridge_proof_material_hashes(
            proof_material,
            &transport_hashes,
        )?;
        let proof_bytes = chunks.iter().flatten().copied().collect::<Vec<u8>>();
        let proof_bytes_hash =
            hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        matching_binding = Some(SameSecretBridgeProofTransportBinding {
            transport_hashes,
            proof_bytes,
            proof_bytes_hash,
        });
    }

    matching_binding.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transportedSameSecretBridgeProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

pub(super) fn verify_transported_same_secret_bridge_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_BRIDGE_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transportedSameSecretBridgeProofMaterial.{field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transportedSameSecretBridgeProofMaterial.objectVersion",
    )
}

pub(super) fn verify_transported_same_secret_bridge_proof_material_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_BRIDGE_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transported same-secret bridge proof material {field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transported same-secret bridge proof material objectVersion",
    )?;
    hash_at_path(value, &["proofMaterialRoot"])?;

    Ok(())
}

pub(super) fn transported_same_secret_bridge_proof_chunks(
    value: &Value,
    proof_material_index: usize,
) -> CanonicalResult<Vec<Vec<u8>>> {
    compare_required_u64(
        unsigned_at_path(value, &["chunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "transported same-secret bridge proof material chunkSizeBytes",
    )?;
    let chunk_count = read_positive_usize_at_path(
        value,
        &["chunkCount"],
        "transported same-secret bridge proof material chunkCount",
    )?;
    let chunk_values = array_at_path(value, &["chunks"])?;
    if chunk_values.len() != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret bridge proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        compare_required_u64(
            unsigned_at_path(chunk_value, &["chunkIndex"])?,
            expected_chunk_index as u64,
            &format!(
                "transportedSameSecretBridgeProofMaterial.proofMaterials.{proof_material_index}.chunks.{expected_chunk_index}.chunkIndex"
            ),
        )?;
        chunks.push(crate::transcript_core::decode_standard_base64(
            string_at_path(chunk_value, &["bytesBase64"])?,
            "transported same-secret bridge proof material bytesBase64",
        )?);
    }

    Ok(chunks)
}

pub(super) fn verify_transported_same_secret_bridge_proof_material_hashes(
    value: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(value, &["totalByteLength"])?,
        transport_hashes.total_byte_length,
        "transported same-secret bridge proof material totalByteLength",
    )?;
    compare_required_string(
        hash_at_path(value, &["fullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "transported same-secret bridge proof material fullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(value, &["chunkRoot"])?,
        &transport_hashes.chunk_root,
        "transported same-secret bridge proof material chunkRoot",
    )?;
    let chunk_hash_values = array_at_path(value, &["chunkHashes"])?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret bridge proof material chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        compare_required_string(
            hash_at_path(chunk_hash_value, &[])?,
            expected_chunk_hash,
            &format!("transported same-secret bridge proof material chunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

pub(super) fn verify_same_secret_bridge_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "same-secret bridge proof record proofChunkSizeBytes",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkCount"])?,
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret bridge proof chunk count does not fit u64",
            )
        })?,
        "same-secret bridge proof record proofChunkCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofTotalByteLength"])?,
        transport_hashes.total_byte_length,
        "same-secret bridge proof record proofTotalByteLength",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofFullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "same-secret bridge proof record proofFullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofChunkRoot"])?,
        &transport_hashes.chunk_root,
        "same-secret bridge proof record proofChunkRoot",
    )?;
    let proof_chunk_hashes = array_at_path(proof_record, &["proofChunkHashes"])?;
    if proof_chunk_hashes.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge proof record proofChunkHashes length must match transported chunks",
        ));
    }
    for (chunk_index, (proof_chunk_hash, expected_chunk_hash)) in proof_chunk_hashes
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        compare_required_string(
            hash_at_path(proof_chunk_hash, &[])?,
            expected_chunk_hash,
            &format!("same-secret bridge proof record proofChunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

pub(super) fn same_secret_bridge_proof_has_transport_reference(proof_record: &Value) -> bool {
    [
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some())
}
