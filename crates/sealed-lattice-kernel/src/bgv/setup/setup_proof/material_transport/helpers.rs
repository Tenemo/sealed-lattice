use super::*;

pub(super) fn object_field_at<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field_value| field_value.is_object())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name} must be an object"),
            )
        })
}

pub(super) fn string_field_at<'a>(
    value: &'a Value,
    field_name: &str,
    object_path: &str,
) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name} must be a string"),
            )
        })
}

pub(super) fn u64_field_at(
    value: &Value,
    field_name: &str,
    object_path: &str,
) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name} must be an integer"),
            )
        })
}

pub(super) fn usize_field_at(
    value: &Value,
    field_name: &str,
    object_path: &str,
) -> CanonicalResult<usize> {
    usize::try_from(u64_field_at(value, field_name, object_path)?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_path}.{field_name} does not fit usize"),
        )
    })
}

pub(super) fn setup_proof_transport_string_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a string"),
            )
        })
}

pub(super) fn setup_proof_transport_u64_field(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-negative integer"),
            )
        })
}

pub(super) fn setup_proof_transport_array_field<'a>(
    value: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be an array"),
            )
        })
}

// Chunks are streamed unframed; the bound total length plus the enforced
// uniform chunk size make this concatenation unambiguous, so no per-chunk length
// prefix is needed.
pub(super) fn setup_proof_material_full_object_hash(
    proof_family: &str,
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> CanonicalResult<String> {
    let mut hasher = Shake256::default();
    hasher.update(HASH512_PREIMAGE_PREFIX);
    append_bytes_to_hasher(
        &mut hasher,
        b"sealed-lattice/setup/proof-material/full-object-v1",
    )?;
    append_bytes_to_hasher(&mut hasher, proof_family.as_bytes())?;
    let mut length = Vec::new();
    append_varuint(&mut length, total_byte_length);
    hasher.update(&length);
    for chunk in chunks {
        hasher.update(chunk);
    }
    let mut output = [0_u8; 64];
    hasher.finalize_xof().read(&mut output);

    Ok(to_hex(&output))
}

pub(super) fn setup_proof_material_chunk_hash(
    proof_family: &str,
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    validate_hash_string(full_object_hash, "setupProofMaterial.fullObjectHash")?;
    let mut chunk_index_bytes = Vec::new();
    append_varuint(
        &mut chunk_index_bytes,
        u64::try_from(chunk_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk index does not fit u64",
            )
        })?,
    );

    Ok(hash512_hex(
        "sealed-lattice/setup/proof-material/chunk-v1",
        &[
            proof_family.as_bytes(),
            full_object_hash.as_bytes(),
            &chunk_index_bytes,
            chunk,
        ],
    ))
}

pub(super) fn setup_proof_material_chunk_manifest_root(
    proof_family: &str,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE,
        "proofFamily": proof_family,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": full_object_hash,
    }))
}

pub(super) fn append_bytes_to_hasher(hasher: &mut Shake256, value: &[u8]) -> CanonicalResult<()> {
    let mut encoded = Vec::new();
    append_bytes(&mut encoded, value);
    hasher.update(&encoded);

    Ok(())
}
