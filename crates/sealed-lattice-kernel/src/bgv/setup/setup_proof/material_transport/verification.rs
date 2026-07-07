use super::helpers::*;
use super::*;

pub(crate) fn setup_proof_material_transport_hashes(
    proof_family: &str,
    chunks: &[Vec<u8>],
    chunk_size_bytes: u64,
) -> CanonicalResult<SetupProofMaterialTransportHashes> {
    if !SETUP_PROOF_TRANSPORT_FAMILIES.contains(&proof_family) {
        return Err(setup_proof_error(
            "setup proof material proof family is not in the fixed setup-proof parameters",
        ));
    }
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size must be positive",
        ));
    }
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material transport requires at least one chunk",
        ));
    }
    let chunk_size_usize = usize::try_from(chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |accumulator, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material contains a short non-final chunk",
                    ));
                }
                let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material chunk length does not fit u64",
                    )
                })?;
                accumulator.checked_add(chunk_length).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "setup proof material byte length overflowed",
                    )
                })
            })?;

    let full_object_hash =
        setup_proof_material_full_object_hash(proof_family, total_byte_length, chunks)?;
    let mut chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        chunk_hashes.push(setup_proof_material_chunk_hash(
            proof_family,
            &full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_root = setup_proof_material_chunk_manifest_root(
        proof_family,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(SetupProofMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

pub(in crate::bgv::setup) fn setup_proof_record_has_transport_reference(value: &Value) -> bool {
    SETUP_PROOF_RECORD_TRANSPORT_REFERENCE_FIELDS
        .iter()
        .any(|field_name| value.get(*field_name).is_some())
}

pub(in crate::bgv::setup) fn verify_setup_proof_record_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
    _chunk_size_message_label: &str,
    reference_message_label: &str,
    chunk_hash_field_path_prefix: &str,
) -> CanonicalResult<()> {
    let expected_chunk_count =
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{reference_message_label} proof material chunk count does not fit u64"),
            )
        })?;
    if setup_proof_transport_u64_field(proof_record, "proofChunkCount")? != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{reference_message_label} proofChunkCount must match transported proof chunks"
            ),
        ));
    }
    if setup_proof_transport_u64_field(proof_record, "proofTotalByteLength")?
        != transport_hashes.total_byte_length
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{reference_message_label} proofTotalByteLength must match transported proof chunks"
            ),
        ));
    }
    if setup_proof_transport_string_field(proof_record, "proofFullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{reference_message_label} proofFullObjectHash must match transported proof chunks"
            ),
        ));
    }
    if setup_proof_transport_string_field(proof_record, "proofChunkRoot")?
        != transport_hashes.chunk_root.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{reference_message_label} proofChunkRoot must match the canonical proof chunk manifest"
            ),
        ));
    }
    let chunk_hash_values = setup_proof_transport_array_field(proof_record, "proofChunkHashes")
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{reference_message_label} proofChunkHashes must list every transported proof chunk"
                ),
            )
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{reference_message_label} proofChunkHashes length must match transported proof chunks"
            ),
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
                    "{reference_message_label} proofChunkHashes[{chunk_index}] must be a hash string"
                ),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("{chunk_hash_field_path_prefix}.proofChunkHashes[{chunk_index}]"),
        )?;
        if chunk_hash != expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{reference_message_label} proofChunkHashes must match transported proof chunks"
                ),
            ));
        }
    }

    Ok(())
}

pub(in crate::bgv::setup) fn transported_setup_proof_material_chunks(
    value: &Value,
    material_message_label: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let chunk_values = setup_proof_transport_array_field(value, "chunks").map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{material_message_label} chunks are required"),
        )
    })?;
    let mut chunks = Vec::with_capacity(chunk_values.len());
    for chunk_value in chunk_values.iter() {
        chunks.push(decode_hex(setup_proof_transport_string_field(
            chunk_value,
            "bytesHex",
        )?)?);
    }

    Ok(chunks)
}

pub(in crate::bgv::setup) fn verify_transported_setup_proof_material_hashes(
    value: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
    hash_message_label: &str,
) -> CanonicalResult<()> {
    if setup_proof_transport_u64_field(value, "totalByteLength")?
        != transport_hashes.total_byte_length
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{hash_message_label} totalByteLength must match supplied chunks"),
        ));
    }
    if setup_proof_transport_string_field(value, "fullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{hash_message_label} fullObjectHash must match supplied chunks"),
        ));
    }
    if setup_proof_transport_string_field(value, "chunkRoot")?
        != transport_hashes.chunk_root.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{hash_message_label} chunkRoot must match supplied chunks"),
        ));
    }
    let chunk_hash_values =
        setup_proof_transport_array_field(value, "chunkHashes").map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{hash_message_label} chunkHashes are required"),
            )
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{hash_message_label} chunkHashes length must match supplied chunks"),
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{hash_message_label} chunkHashes must match supplied chunks"),
            ));
        }
    }

    Ok(())
}
