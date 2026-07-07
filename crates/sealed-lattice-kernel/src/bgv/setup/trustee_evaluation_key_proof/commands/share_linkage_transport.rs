use super::decoding::*;
use super::share_linkage_verification::*;
use super::*;

// Resolved share-linkage proof bytes plus the canonical proof record
// whose root binds them. The embedded form carries the proof bytes as base64
// inside the record; the transported form streams the bytes through the shared
// setup proof-material transport and binds the transport reference into the
// record root instead of the base64 bytes.
pub(super) struct ResolvedVssShareLinkageProofBytes {
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

pub(super) fn resolve_vss_share_linkage_proof_bytes(
    proof_record: &Value,
    request: &Value,
    coverage: &[Value],
    vss_share_linkage: &Value,
) -> CanonicalResult<ResolvedVssShareLinkageProofBytes> {
    let proof_bytes_hash = read_string(proof_record, "proofBytesHash")?;
    let proof_record_root = read_string(proof_record, "proofRecordRoot")?.to_string();
    if proof_record.get("proofBytesBase64").is_some() {
        if proof_record.get("proofBytesEncoding").is_some()
            || vss_share_linkage_proof_has_transport_reference(proof_record)
        {
            return Err(invalid_succinct_setup_proof(
                "share-linkage proof record must not mix embedded proofBytesBase64 with transported proof material",
            ));
        }
        let proof_bytes_base64 = read_string(proof_record, "proofBytesBase64")?;
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_bytes_base64,
            "share-linkage proofBytesBase64",
        )?;
        let expected_proof_bytes_hash =
            hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        compare_string_value(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "share-linkage proof record proofBytesHash",
        )?;
        let proof_record_without_root = json!({
            "objectType": "VssShareLinkageProofRecord",
            "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
            "linkageItems": coverage,
            "vssShareLinkage": vss_share_linkage,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesBase64": proof_bytes_base64,
        });
        let expected_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
        compare_string_value(
            &proof_record_root,
            &expected_record_root,
            "share-linkage proof record proofRecordRoot",
        )?;

        return Ok(ResolvedVssShareLinkageProofBytes {
            proof_bytes,
            proof_record_without_root,
            proof_record_root,
        });
    }

    compare_string_value(
        read_string(proof_record, "proofBytesEncoding")?,
        SETUP_PROOF_MATERIAL_ENCODING,
        "share-linkage proof record proofBytesEncoding",
    )?;
    let proof_material_root = read_string(proof_record, "proofMaterialRoot")?;
    let transported_binding =
        transported_vss_share_linkage_proof_material_binding(request, proof_material_root)?;
    verify_vss_share_linkage_proof_transport_reference(
        proof_record,
        &transported_binding.transport_hashes,
    )?;
    compare_string_value(
        proof_bytes_hash,
        &transported_binding.proof_bytes_hash,
        "share-linkage proof record proofBytesHash",
    )?;
    let proof_record_without_root = json!({
        "objectType": "VssShareLinkageProofRecord",
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "linkageItems": coverage,
        "vssShareLinkage": vss_share_linkage,
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
    let expected_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    compare_string_value(
        &proof_record_root,
        &expected_record_root,
        "share-linkage proof record proofRecordRoot",
    )?;

    Ok(ResolvedVssShareLinkageProofBytes {
        proof_bytes: transported_binding.proof_bytes,
        proof_record_without_root,
        proof_record_root,
    })
}

pub(super) struct VssShareLinkageProofTransportBinding {
    pub(super) transport_hashes: SetupProofMaterialTransportHashes,
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_bytes_hash: String,
}

pub(super) fn transported_vss_share_linkage_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<VssShareLinkageProofTransportBinding> {
    let material_set = request
        .get("transportedVssShareLinkageProofMaterial")
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "transportedVssShareLinkageProofMaterial is required by transported share-linkage proof records",
            )
        })?;
    verify_transported_vss_share_linkage_proof_material_set_header(material_set)?;
    let proof_materials = material_set
        .get("proofMaterials")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "transportedVssShareLinkageProofMaterial.proofMaterials must be an array",
            )
        })?;
    let mut matching_binding = None;
    for (proof_material_index, proof_material) in proof_materials.iter().enumerate() {
        verify_transported_vss_share_linkage_proof_material_header(proof_material)?;
        let proof_material_root = read_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(invalid_succinct_setup_proof(
                "transportedVssShareLinkageProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            Arc::new(transported_vss_share_linkage_proof_chunks(
                proof_material,
                proof_material_index,
            )?)
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedVssShareLinkageProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            chunks.as_ref(),
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_vss_share_linkage_proof_material_hashes(
            proof_material,
            &transport_hashes,
        )?;
        let proof_bytes = chunks.iter().flatten().copied().collect::<Vec<u8>>();
        let proof_bytes_hash =
            hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        matching_binding = Some(VssShareLinkageProofTransportBinding {
            transport_hashes,
            proof_bytes,
            proof_bytes_hash,
        });
    }

    matching_binding.ok_or_else(|| {
        invalid_succinct_setup_proof(
            "transportedVssShareLinkageProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

pub(super) fn verify_transported_vss_share_linkage_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE),
        ("proofFamily", VSS_SHARE_LINKAGE_PROOF_FAMILY),
    ] {
        compare_string_value(
            read_string(value, field_name)?,
            expected_value,
            &format!("transportedVssShareLinkageProofMaterial.{field_name}"),
        )?;
    }
    Ok(())
}

pub(super) fn verify_transported_vss_share_linkage_proof_material_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", VSS_SHARE_LINKAGE_PROOF_FAMILY),
    ] {
        compare_string_value(
            read_string(value, field_name)?,
            expected_value,
            &format!("transported share-linkage proof material {field_name}"),
        )?;
    }
    read_string(value, "proofMaterialRoot")?;

    Ok(())
}

pub(super) fn transported_vss_share_linkage_proof_chunks(
    value: &Value,
    proof_material_index: usize,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let chunk_count = usize::try_from(read_u64(value, "chunkCount")?).map_err(|_| {
        invalid_succinct_setup_proof(
            "transported share-linkage proof material chunkCount does not fit usize",
        )
    })?;
    if chunk_count == 0 {
        return Err(invalid_succinct_setup_proof(
            "transported share-linkage proof material chunkCount must be positive",
        ));
    }
    let chunk_values = value
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "transported share-linkage proof material chunks must be an array",
            )
        })?;
    if chunk_values.len() != chunk_count {
        return Err(invalid_succinct_setup_proof(
            "transported share-linkage proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        compare_u64_value(
            read_u64(chunk_value, "chunkIndex")?,
            expected_chunk_index as u64,
            &format!(
                "transportedVssShareLinkageProofMaterial.proofMaterials.{proof_material_index}.chunks.{expected_chunk_index}.chunkIndex"
            ),
        )?;
        chunks.push(crate::transcript_core::decode_standard_base64(
            read_string(chunk_value, "bytesBase64")?,
            "transported share-linkage proof material bytesBase64",
        )?);
    }

    Ok(chunks)
}

pub(super) fn verify_transported_vss_share_linkage_proof_material_hashes(
    value: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_u64_value(
        read_u64(value, "totalByteLength")?,
        transport_hashes.total_byte_length,
        "transported share-linkage proof material totalByteLength",
    )?;
    compare_string_value(
        read_string(value, "fullObjectHash")?,
        &transport_hashes.full_object_hash,
        "transported share-linkage proof material fullObjectHash",
    )?;
    compare_string_value(
        read_string(value, "chunkRoot")?,
        &transport_hashes.chunk_root,
        "transported share-linkage proof material chunkRoot",
    )?;
    let chunk_hash_values = value
        .get("chunkHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "transported share-linkage proof material chunkHashes must be an array",
            )
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(invalid_succinct_setup_proof(
            "transported share-linkage proof material chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(invalid_succinct_setup_proof(format!(
                "transported share-linkage proof material chunkHashes.{chunk_index} must be a string"
            )));
        };
        compare_string_value(
            chunk_hash,
            expected_chunk_hash,
            &format!("transported share-linkage proof material chunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

pub(super) fn verify_vss_share_linkage_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_u64_value(
        read_u64(proof_record, "proofChunkCount")?,
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            invalid_succinct_setup_proof("share-linkage proof chunk count does not fit u64")
        })?,
        "share-linkage proof record proofChunkCount",
    )?;
    compare_u64_value(
        read_u64(proof_record, "proofTotalByteLength")?,
        transport_hashes.total_byte_length,
        "share-linkage proof record proofTotalByteLength",
    )?;
    compare_string_value(
        read_string(proof_record, "proofFullObjectHash")?,
        &transport_hashes.full_object_hash,
        "share-linkage proof record proofFullObjectHash",
    )?;
    compare_string_value(
        read_string(proof_record, "proofChunkRoot")?,
        &transport_hashes.chunk_root,
        "share-linkage proof record proofChunkRoot",
    )?;
    let proof_chunk_hashes = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "share-linkage proof record proofChunkHashes must be an array",
            )
        })?;
    if proof_chunk_hashes.len() != transport_hashes.chunk_hashes.len() {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof record proofChunkHashes length must match transported chunks",
        ));
    }
    for (chunk_index, (proof_chunk_hash, expected_chunk_hash)) in proof_chunk_hashes
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(proof_chunk_hash) = proof_chunk_hash.as_str() else {
            return Err(invalid_succinct_setup_proof(format!(
                "share-linkage proof record proofChunkHashes.{chunk_index} must be a string"
            )));
        };
        compare_string_value(
            proof_chunk_hash,
            expected_chunk_hash,
            &format!("share-linkage proof record proofChunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

pub(super) fn vss_share_linkage_proof_has_transport_reference(proof_record: &Value) -> bool {
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
