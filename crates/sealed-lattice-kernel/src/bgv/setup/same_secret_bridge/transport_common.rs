use super::*;

// Parameters for the same-secret bridge proof-material transport. Proof bytes
// can be carried inline or through the setup transport, while the resolved
// bytes remain bound to the bridge proof record and its canonical hashes.
pub(super) struct TransportFamily {
    pub(super) proof_family: &'static str,
    pub(super) transport_field: &'static str,
    pub(super) set_object_type: &'static str,
    pub(super) material_object_type: &'static str,
    pub(super) family_prose: &'static str,
}

// Resolve the transported proof material for `expected_proof_material_root`:
// verify the material-set and per-material headers, decode the inline base64
// chunks (or read the stream-verified handle from the shared setup transport)
// into one contiguous buffer, recompute the transport hashes and verify the
// material carries them. Returns the recomputed hashes plus the contiguous proof
// bytes; the caller derives the family-specific proof-bytes hash from them.
pub(super) fn resolve_transported_proof_material(
    request: &Value,
    expected_proof_material_root: &str,
    family: &TransportFamily,
) -> CanonicalResult<(SetupProofMaterialTransportHashes, Arc<Vec<u8>>)> {
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
    for proof_material in proof_materials.iter() {
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
        let proof_bytes = if proof_material.get("chunks").is_some() {
            Arc::new(transported_material_bytes(proof_material, family)?)
        } else {
            verified_setup_proof_material_bytes_from_request(
                request,
                family.proof_family,
                expected_proof_material_root,
                proof_material,
                &format!("{}.proofMaterials", family.transport_field),
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            family.proof_family,
            &proof_bytes,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_material_hashes(proof_material, &transport_hashes, family)?;
        matching_binding = Some((transport_hashes, proof_bytes));
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
    Ok(())
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
    hash_at_path(value, &["proofMaterialRoot"])?;

    Ok(())
}

fn transported_material_bytes(value: &Value, family: &TransportFamily) -> CanonicalResult<Vec<u8>> {
    let chunk_values = array_at_path(value, &["chunks"])?;
    let mut proof_bytes = Vec::new();
    for chunk_value in chunk_values.iter() {
        proof_bytes.extend_from_slice(&crate::transcript_core::decode_standard_base64(
            string_at_path(chunk_value, &["bytesBase64"])?,
            &format!(
                "transported {} proof material bytesBase64",
                family.family_prose
            ),
        )?);
    }

    Ok(proof_bytes)
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
    // The transport-reference checks are family-independent: one shared verifier
    // recomputes chunk size, count, total length, full-object hash, chunk root,
    // and per-chunk hashes against the recomputed transport manifest. The family
    // only supplies the message prose.
    crate::bgv::setup::setup_proof::verify_setup_proof_record_transport_reference(
        proof_record,
        transport_hashes,
        family.family_prose,
        family.family_prose,
        family.family_prose,
    )
}

pub(super) fn proof_has_transport_reference(proof_record: &Value) -> bool {
    [
        "proofMaterialRoot",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some())
}
