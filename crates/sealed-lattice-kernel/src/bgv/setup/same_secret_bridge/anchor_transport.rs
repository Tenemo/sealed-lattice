use super::*;
use super::statement_record::*;

pub(super) struct SameSecretProofTransportBinding {
    pub(super) transport_hashes: SetupProofMaterialTransportHashes,
    pub(super) proof_bytes_hash: String,
}

pub(super) fn transported_same_secret_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SameSecretProofTransportBinding> {
    let material_set = value_at_path(request, &["transportedSameSecretProofMaterial"]).map_err(
        |_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretProofMaterial is required by transported same-secret proof records",
            )
        },
    )?;
    verify_transported_same_secret_proof_material_set_header(material_set)?;
    let proof_materials = array_at_path(material_set, &["proofMaterials"])?;
    let mut matching_binding = None;
    for (proof_material_index, proof_material) in proof_materials.iter().enumerate() {
        verify_transported_same_secret_proof_material_header(proof_material)?;
        let proof_material_root = hash_at_path(proof_material, &["proofMaterialRoot"])?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            Arc::new(transported_same_secret_proof_chunks(
                proof_material,
                proof_material_index,
            )?)
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                SAME_SECRET_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedSameSecretProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_PROOF_FAMILY,
            chunks.as_ref(),
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_same_secret_proof_material_hashes(proof_material, &transport_hashes)?;
        let chunk_slices = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
        matching_binding = Some(SameSecretProofTransportBinding {
            transport_hashes,
            proof_bytes_hash: hash512_hex(
                SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN,
                &chunk_slices,
            ),
        });
    }

    matching_binding.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transportedSameSecretProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

pub(super) fn verify_transported_same_secret_proof_material_set_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transportedSameSecretProofMaterial.{field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transportedSameSecretProofMaterial.objectVersion",
    )
}

pub(super) fn verify_transported_same_secret_proof_material_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transported same-secret proof material {field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transported same-secret proof material objectVersion",
    )?;
    hash_at_path(value, &["proofMaterialRoot"])?;

    Ok(())
}

pub(super) fn transported_same_secret_proof_chunks(
    value: &Value,
    proof_material_index: usize,
) -> CanonicalResult<Vec<Vec<u8>>> {
    compare_required_u64(
        unsigned_at_path(value, &["chunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "transported same-secret proof material chunkSizeBytes",
    )?;
    let chunk_count = read_positive_usize_at_path(
        value,
        &["chunkCount"],
        "transported same-secret proof material chunkCount",
    )?;
    let chunk_values = array_at_path(value, &["chunks"])?;
    if chunk_values.len() != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        compare_required_u64(
            unsigned_at_path(chunk_value, &["chunkIndex"])?,
            expected_chunk_index as u64,
            &format!(
                "transportedSameSecretProofMaterial.proofMaterials.{proof_material_index}.chunks.{expected_chunk_index}.chunkIndex"
            ),
        )?;
        chunks.push(crate::transcript_core::decode_standard_base64(
            string_at_path(chunk_value, &["bytesBase64"])?,
            "transported same-secret proof material bytesBase64",
        )?);
    }

    Ok(chunks)
}

pub(super) fn verify_transported_same_secret_proof_material_hashes(
    value: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(value, &["totalByteLength"])?,
        transport_hashes.total_byte_length,
        "transported same-secret proof material totalByteLength",
    )?;
    compare_required_string(
        hash_at_path(value, &["fullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "transported same-secret proof material fullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(value, &["chunkRoot"])?,
        &transport_hashes.chunk_root,
        "transported same-secret proof material chunkRoot",
    )?;
    let chunk_hash_values = array_at_path(value, &["chunkHashes"])?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret proof material chunkHashes length must match supplied chunks",
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
            &format!("transported same-secret proof material chunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

pub(super) fn verify_same_secret_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "same-secret proof record proofChunkSizeBytes",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkCount"])?,
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret proof chunk count does not fit u64",
            )
        })?,
        "same-secret proof record proofChunkCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofTotalByteLength"])?,
        transport_hashes.total_byte_length,
        "same-secret proof record proofTotalByteLength",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofFullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "same-secret proof record proofFullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofChunkRoot"])?,
        &transport_hashes.chunk_root,
        "same-secret proof record proofChunkRoot",
    )?;
    let proof_chunk_hashes = array_at_path(proof_record, &["proofChunkHashes"])?;
    if proof_chunk_hashes.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof record proofChunkHashes length must match transported chunks",
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
            &format!("same-secret proof record proofChunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

pub(super) fn same_secret_anchor_proof_material_root(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SameSecretLinkageAnchorProofMaterialReference",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "trusteeIdentity": string_at_path(proof_record, &["trusteeIdentity"])?,
        "trusteeRosterPosition": unsigned_at_path(proof_record, &["trusteeRosterPosition"])?,
        "statementHash": hash_at_path(proof_record, &["statementHash"])?,
        "proofSizeBytes": unsigned_at_path(proof_record, &["proofSizeBytes"])?,
        "proofBytesHash": hash_at_path(proof_record, &["proofBytesHash"])?,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
}

pub(super) fn same_secret_proof_has_transport_reference(proof_record: &Value) -> bool {
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

