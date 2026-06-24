use super::*;

use crate::bgv::setup::trustee_evaluation_key_proof::PUBLIC_KEY_SHARE_PROOF_FAMILY;

pub(super) fn public_key_share_succinct_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = [
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some());

    // Embedded and transported proof bytes are mutually exclusive so a record cannot present one byte string for verification and bind a different one through the transport manifest.
    if has_embedded_proof_bytes && has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proof requires proofBytesHex or transported proof material",
        ));
    }

    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    if proof_bytes_encoding != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(
        proof_material_root,
        "publicKeyShareSuccinctProof.proofMaterialRoot",
    )?;
    let chunks = transported_public_key_share_proof_material_chunks(request, proof_material_root)?;
    let transport_hashes = setup_proof_material_transport_hashes(
        "public-key-share",
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_public_key_share_succinct_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        public_key_share_succinct_proof_material_root(proof_record, &transport_hashes)?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

// Canonical transported proof material reference for one public-key share
// succinct proof. The succinct proof has no LNP relation commitment or tbox
// prefix, so the reference binds only the statement hash and proof byte
// identity, mirroring the same-secret anchor proof material reference.
pub(in crate::bgv::setup) fn public_key_share_succinct_proof_material_root(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "PublicKeyShareProofMaterialRoot",
        &json!({
            "objectType": "PublicKeyShareSuccinctProofMaterialReference",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "public-key-share",
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "statementHash": value_string(proof_record, "statementHash")?,
            "proofSizeBytes": value_u64(proof_record, "proofSizeBytes")?,
            "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        }),
    )
}

fn verify_public_key_share_succinct_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share proofChunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count =
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key proof material chunk count does not fit u64",
            )
        })?;
    if value_u64(proof_record, "proofChunkCount")? != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkCount must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofTotalByteLength must match transported proof chunks",
        ));
    }
    // proofSizeBytes is bound both here and inside the material root, so it must equal the chunk-manifest total or the two commitments could diverge.
    if value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofSizeBytes must match transported proof byte length",
        ));
    }
    if value_string(proof_record, "proofFullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofFullObjectHash must match transported proof chunks",
        ));
    }
    if value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkRoot must match the canonical proof chunk manifest",
        ));
    }
    let Some(chunk_hash_values) = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkHashes must list every transported proof chunk",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share succinct proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "public-key share succinct proofChunkHashes[{chunk_index}] must be a hash string"
                ),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("publicKeyShareSuccinctProof.proofChunkHashes[{chunk_index}]"),
        )?;
        if chunk_hash != expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share succinct proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_public_key_share_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedPublicKeyShareProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedPublicKeyShareProofMaterial was required by transported public-key share succinct proof records",
            )
        })?;
    verify_transported_public_key_share_proof_material_set_header(material_set)?;
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial.proofMaterials must list transported proof material objects",
        ));
    };
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        verify_transported_public_key_share_proof_material_header(proof_material)?;
        let proof_material_root = value_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedPublicKeyShareProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            transported_public_key_share_proof_chunks(proof_material)?
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                PUBLIC_KEY_SHARE_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedPublicKeyShareProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            PUBLIC_KEY_SHARE_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_public_key_share_proof_material_hashes(
            proof_material,
            &transport_hashes,
        )?;
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_public_key_share_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        (
            "objectType",
            PUBLIC_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE,
        ),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transportedPublicKeyShareProofMaterial.{field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareProofMaterial.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_transported_public_key_share_proof_material_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", PUBLIC_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported public-key share succinct proof material {field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material objectVersion must be 1",
        ));
    }
    validate_hash_string(
        value_string(value, "proofMaterialRoot")?,
        "transportedPublicKeyShareProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_public_key_share_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material chunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share succinct proof material chunkCount does not fit usize",
        )
    })?;
    let Some(chunk_values) = value.get("chunks").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material chunks are required",
        ));
    };
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        let observed_chunk_index = value_u64(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index as u64 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share succinct proof chunks must be supplied in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

fn verify_transported_public_key_share_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(value, "totalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof totalByteLength must match supplied chunks",
        ));
    }
    if value_string(value, "fullObjectHash")? != transport_hashes.full_object_hash.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof fullObjectHash must match supplied chunks",
        ));
    }
    if value_string(value, "chunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof chunkRoot must match supplied chunks",
        ));
    }
    let Some(chunk_hash_values) = value.get("chunkHashes").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof chunkHashes are required",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share succinct proof chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share succinct proof chunkHashes must match supplied chunks",
            ));
        }
    }

    Ok(())
}
