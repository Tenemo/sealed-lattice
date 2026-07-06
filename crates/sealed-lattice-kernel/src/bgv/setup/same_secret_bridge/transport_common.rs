use super::*;

// A same-secret proof-material transport family: the two same-secret proof
// records (the data-basis anchor and the target-basis bridge) carry their
// transported proof material through the identical inline-base64 transport,
// differing only in these object-type and message strings and in how the
// resolved chunks are finally bound into the proof-bytes hash (which each
// caller does itself). The verification logic below is shared byte-for-byte.
pub(super) struct TransportFamily {
    pub(super) proof_family: &'static str,
    pub(super) transport_field: &'static str,
    pub(super) set_object_type: &'static str,
    pub(super) material_object_type: &'static str,
    pub(super) family_prose: &'static str,
}

// Resolve the transported proof material for `expected_proof_material_root`:
// verify the material-set and per-material headers, decode the inline base64
// chunks (or stream them through the shared setup transport), recompute the
// transport hashes and verify the material carries them. Returns the recomputed
// hashes plus the decoded chunks; the caller derives the family-specific proof
// bytes and proof-bytes hash from the chunks.
pub(super) fn resolve_transported_proof_material(
    request: &Value,
    expected_proof_material_root: &str,
    family: &TransportFamily,
) -> CanonicalResult<(SetupProofMaterialTransportHashes, Arc<Vec<Vec<u8>>>)> {
    let material_set = value_at_path(request, &[family.transport_field]).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "{} is required by transported {} proof records",
                family.transport_field, family.family_prose
            ),
        )
    })?;
    verify_transported_material_set_header(material_set, family)?;
    let proof_materials = array_at_path(material_set, &["proofMaterials"])?;
    let mut matching_binding = None;
    for (proof_material_index, proof_material) in proof_materials.iter().enumerate() {
        verify_transported_material_header(proof_material, family)?;
        let proof_material_root = hash_at_path(proof_material, &["proofMaterialRoot"])?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!(
                    "{} contains duplicate proofMaterialRoot entries",
                    family.transport_field
                ),
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            Arc::new(transported_material_chunks(
                proof_material,
                proof_material_index,
                family,
            )?)
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                family.proof_family,
                expected_proof_material_root,
                proof_material,
                &format!("{}.proofMaterials", family.transport_field),
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            family.proof_family,
            chunks.as_ref(),
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_material_hashes(proof_material, &transport_hashes, family)?;
        matching_binding = Some((transport_hashes, chunks));
    }

    matching_binding.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "{} is missing the requested proofMaterialRoot",
                family.transport_field
            ),
        )
    })
}

fn verify_transported_material_set_header(
    value: &Value,
    family: &TransportFamily,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", family.set_object_type),
        ("proofFamily", family.proof_family),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("{}.{field_name}", family.transport_field),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        &format!("{}.objectVersion", family.transport_field),
    )
}

fn verify_transported_material_header(
    value: &Value,
    family: &TransportFamily,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", family.material_object_type),
        ("proofFamily", family.proof_family),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!(
                "transported {} proof material {field_name}",
                family.family_prose
            ),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        &format!(
            "transported {} proof material objectVersion",
            family.family_prose
        ),
    )?;
    hash_at_path(value, &["proofMaterialRoot"])?;

    Ok(())
}

fn transported_material_chunks(
    value: &Value,
    proof_material_index: usize,
    family: &TransportFamily,
) -> CanonicalResult<Vec<Vec<u8>>> {
    compare_required_u64(
        unsigned_at_path(value, &["chunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        &format!(
            "transported {} proof material chunkSizeBytes",
            family.family_prose
        ),
    )?;
    let chunk_count = read_positive_usize_at_path(
        value,
        &["chunkCount"],
        &format!(
            "transported {} proof material chunkCount",
            family.family_prose
        ),
    )?;
    let chunk_values = array_at_path(value, &["chunks"])?;
    if chunk_values.len() != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!(
                "transported {} proof material chunks length must match chunkCount",
                family.family_prose
            ),
        ));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        compare_required_u64(
            unsigned_at_path(chunk_value, &["chunkIndex"])?,
            expected_chunk_index as u64,
            &format!(
                "{}.proofMaterials.{proof_material_index}.chunks.{expected_chunk_index}.chunkIndex",
                family.transport_field
            ),
        )?;
        chunks.push(crate::transcript_core::decode_standard_base64(
            string_at_path(chunk_value, &["bytesBase64"])?,
            &format!(
                "transported {} proof material bytesBase64",
                family.family_prose
            ),
        )?);
    }

    Ok(chunks)
}

fn verify_transported_material_hashes(
    value: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
    family: &TransportFamily,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(value, &["totalByteLength"])?,
        transport_hashes.total_byte_length,
        &format!(
            "transported {} proof material totalByteLength",
            family.family_prose
        ),
    )?;
    compare_required_string(
        hash_at_path(value, &["fullObjectHash"])?,
        &transport_hashes.full_object_hash,
        &format!(
            "transported {} proof material fullObjectHash",
            family.family_prose
        ),
    )?;
    compare_required_string(
        hash_at_path(value, &["chunkRoot"])?,
        &transport_hashes.chunk_root,
        &format!(
            "transported {} proof material chunkRoot",
            family.family_prose
        ),
    )?;
    let chunk_hash_values = array_at_path(value, &["chunkHashes"])?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!(
                "transported {} proof material chunkHashes length must match supplied chunks",
                family.family_prose
            ),
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
            &format!(
                "transported {} proof material chunkHashes.{chunk_index}",
                family.family_prose
            ),
        )?;
    }

    Ok(())
}

pub(super) fn verify_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
    family: &TransportFamily,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        &format!("{} proof record proofChunkSizeBytes", family.family_prose),
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkCount"])?,
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{} proof chunk count does not fit u64", family.family_prose),
            )
        })?,
        &format!("{} proof record proofChunkCount", family.family_prose),
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofTotalByteLength"])?,
        transport_hashes.total_byte_length,
        &format!("{} proof record proofTotalByteLength", family.family_prose),
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofFullObjectHash"])?,
        &transport_hashes.full_object_hash,
        &format!("{} proof record proofFullObjectHash", family.family_prose),
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofChunkRoot"])?,
        &transport_hashes.chunk_root,
        &format!("{} proof record proofChunkRoot", family.family_prose),
    )?;
    let proof_chunk_hashes = array_at_path(proof_record, &["proofChunkHashes"])?;
    if proof_chunk_hashes.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!(
                "{} proof record proofChunkHashes length must match transported chunks",
                family.family_prose
            ),
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
            &format!(
                "{} proof record proofChunkHashes.{chunk_index}",
                family.family_prose
            ),
        )?;
    }

    Ok(())
}

pub(super) fn proof_has_transport_reference(proof_record: &Value) -> bool {
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
