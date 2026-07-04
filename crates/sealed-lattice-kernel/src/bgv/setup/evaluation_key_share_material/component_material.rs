use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::setup) fn evaluation_key_share_component_vector_hash(
    coefficients: &[u64],
) -> String {
    coefficient_vector_hash512(
        coefficients,
        EVALUATION_KEY_SHARE_COMPONENT_VECTOR_HASH_DOMAIN,
    )
}

pub(in crate::bgv::setup) fn evaluation_key_share_component_vector_root(
    proof_family: EvaluationKeyShareProofFamily,
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    level: usize,
    ring_degree: usize,
    component_vector_entries: &[Value],
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluationKeyShareComponentVectorSet",
        "objectVersion": 1,
        "proofFamily": proof_family.proof_family(),
        "keySwitchDomain": key_switch_domain,
        "keySwitchSeedHex": key_switch_seed_hex,
        "level": level,
        "ringDegree": ring_degree,
        // The gadget decomposition base is the RNS base itself: for a key at
        // this level there is exactly one digit per active prime, so the
        // component matrix is square with digitCount = rnsLimbCount = level + 1.
        "digitCount": level + 1,
        "rnsLimbCount": level + 1,
        "componentVectors": component_vector_entries,
    }))
}

pub(in crate::bgv::setup) fn evaluation_key_share_component_material_transport_hashes(
    proof_family: EvaluationKeyShareProofFamily,
    chunks: &[Vec<u8>],
    chunk_size_bytes: u64,
) -> CanonicalResult<EvaluationKeyShareComponentMaterialTransportHashes> {
    if chunk_size_bytes == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material chunk size must be positive",
        ));
    }
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material transport requires at least one chunk",
        ));
    }
    let chunk_size_usize = usize::try_from(chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material chunk size does not fit usize",
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
                        "evaluation-key component material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size_usize {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material contains a short non-final chunk",
                    ));
                }
                let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material chunk length does not fit u64",
                    )
                })?;
                byte_count.checked_add(chunk_length).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key component material byte length overflowed",
                    )
                })
            })?;

    let full_object_hash = evaluation_key_share_component_material_full_object_hash(
        proof_family,
        total_byte_length,
        chunks,
    )?;
    let mut chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        chunk_hashes.push(evaluation_key_share_component_material_chunk_hash(
            proof_family,
            &full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_count = u64::try_from(chunks.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key component material chunk count does not fit u64",
        )
    })?;
    let chunk_root = derive_canonical_object_hash(&json!({
        "objectType": "EvaluationKeyShareComponentMaterialChunkManifest",
        "objectVersion": 1,
        "proofFamily": proof_family.proof_family(),
        "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": full_object_hash,
    }))?;

    Ok(EvaluationKeyShareComponentMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

fn verified_evaluation_key_share_component_material_chunks()
-> &'static Mutex<BTreeMap<String, VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry>> {
    VERIFIED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_CHUNKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn stored_verified_evaluation_key_share_component_material_chunks(
    material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let stored_chunks = verified_evaluation_key_share_component_material_chunks()
        .lock()
        .map_err(|_| {
            invalid_evaluation_key_share_material(
                "verified evaluation-key component material store is unavailable",
            )
        })?;
    let store_entry = stored_chunks.get(material_root).cloned().ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material requires chunks or a live verified material handle",
        )
    })?;
    drop(stored_chunks);

    read_verified_evaluation_key_share_component_material_chunks(&store_entry)
}

fn read_verified_evaluation_key_share_component_material_chunks(
    store_entry: &VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material chunk size does not fit usize",
        )
    })?;
    let mut remaining_byte_length = store_entry.total_byte_length;
    let mut file = File::open(&store_entry.path).map_err(|error| {
        invalid_evaluation_key_share_material(format!(
            "verified evaluation-key component material store entry could not be opened: {error}",
        ))
    })?;
    let mut chunks = Vec::new();
    while remaining_byte_length > 0 {
        let next_chunk_length =
            usize::try_from(remaining_byte_length.min(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES))
                .map_err(|_| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key component material chunk length does not fit usize",
                    )
                })?;
        let mut chunk = vec![0_u8; next_chunk_length.min(chunk_size)];
        file.read_exact(&mut chunk).map_err(|error| {
            invalid_evaluation_key_share_material(format!(
                "verified evaluation-key component material store entry could not be read: {error}",
            ))
        })?;
        remaining_byte_length -= u64::try_from(chunk.len()).map_err(|_| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material chunk length does not fit u64",
            )
        })?;
        chunks.push(chunk);
    }

    Ok(chunks)
}

pub(in crate::bgv::setup) fn evaluation_key_share_component_material_reference_root(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    transport_hashes: &EvaluationKeyShareComponentMaterialTransportHashes,
) -> CanonicalResult<String> {
    let level = value_u64(proof_record, "level")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key digit count overflowed")
    })?;
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluationKeyShareComponentMaterialReference",
        "objectVersion": 1,
        "proofFamily": proof_family.proof_family(),
        "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
        "trusteeIdentity": string_field(proof_record, "trusteeIdentity")?,
        "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
        "keySwitchDomain": string_field(proof_record, "keySwitchDomain")?,
        "keySwitchSeedHex": string_field(proof_record, "keySwitchSeedHex")?,
        "level": level,
        "ringDegree": value_u64(proof_record, "ringDegree")?,
        "digitCount": digit_count,
        "rnsLimbCount": digit_count,
        "keySwitchComponentVectorRoot": string_field(
            proof_record,
            "keySwitchComponentVectorRoot",
        )?,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
}

// Each chunk is a length-framed hash part here (unlike the streamed setup-proof
// full-object hash), so the two transport digests are not interchangeable.
fn evaluation_key_share_component_material_full_object_hash(
    proof_family: EvaluationKeyShareProofFamily,
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> CanonicalResult<String> {
    let mut total_length_bytes = Vec::new();
    append_varuint(&mut total_length_bytes, total_byte_length);
    let mut parts = Vec::with_capacity(chunks.len() + 2);
    parts.push(proof_family.proof_family().as_bytes());
    parts.push(total_length_bytes.as_slice());
    for chunk in chunks {
        parts.push(chunk.as_slice());
    }

    Ok(hash512_hex(
        "sealed-lattice/setup/evaluation-key-share/component-material/full-object-v1",
        &parts,
    ))
}

fn evaluation_key_share_component_material_chunk_hash(
    proof_family: EvaluationKeyShareProofFamily,
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let mut chunk_index_bytes = Vec::new();
    append_varuint(
        &mut chunk_index_bytes,
        u64::try_from(chunk_index).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "evaluation-key component material chunk index does not fit u64",
            )
        })?,
    );

    Ok(hash512_hex(
        "sealed-lattice/setup/evaluation-key-share/component-material/chunk-v1",
        &[
            proof_family.proof_family().as_bytes(),
            full_object_hash.as_bytes(),
            &chunk_index_bytes,
            chunk,
        ],
    ))
}

pub(in crate::bgv::setup) fn component_b_vectors_from_record(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    transported_key_switch_component_material: Option<&Value>,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    match string_field(record, "keySwitchMaterialEncoding")? {
        "embedded-full-key-switch-component-vectors" => {
            if record.get("keySwitchComponentMaterialRoot").is_some()
                || record.get("keySwitchComponentChunkSizeBytes").is_some()
                || record.get("keySwitchComponentChunkCount").is_some()
                || record.get("keySwitchComponentTotalByteLength").is_some()
                || record.get("keySwitchComponentFullObjectHash").is_some()
                || record.get("keySwitchComponentChunkRoot").is_some()
                || record.get("keySwitchComponentChunkHashes").is_some()
            {
                return Err(invalid_evaluation_key_share_material(
                    "embedded evaluation-key component material must not include transported component references",
                ));
            }
            component_b_vectors_from_embedded_record(proof_family, record)
        }
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING => {
            if record.get("keySwitchComponentVectors").is_some() {
                return Err(invalid_evaluation_key_share_material(
                    "binary evaluation-key component material must not embed keySwitchComponentVectors",
                ));
            }
            let transported_material_set =
                transported_key_switch_component_material.ok_or_else(|| {
                    invalid_evaluation_key_share_material(
                        "transported evaluation-key component material is required by binary keySwitchMaterialEncoding",
                    )
                })?;
            component_b_vectors_from_transported_material(
                proof_family,
                record,
                transported_material_set,
            )
        }
        _ => Err(invalid_evaluation_key_share_material(
            "evaluation-key keySwitchMaterialEncoding is not accepted",
        )),
    }
}

fn component_b_vectors_from_embedded_record(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let level = value_usize(record, "level")?;
    let ring_degree = value_usize(record, "ringDegree")?;
    let key_switch_domain = string_field(record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(record, "keySwitchSeedHex")?;
    validate_hex_string(key_switch_seed_hex, "keySwitchSeedHex")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key level digit count overflowed")
    })?;
    let limb_count = digit_count;
    let entries = array_field(record, "keySwitchComponentVectors")?;
    if entries.len()
        != digit_count.checked_mul(limb_count).ok_or_else(|| {
            invalid_evaluation_key_share_material(
                "evaluation-key component vector count overflowed",
            )
        })?
    {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component vectors must contain one vector for every digit and active limb",
        ));
    }
    let mut component_b_by_digit = vec![vec![Vec::<u64>::new(); limb_count]; digit_count];
    for entry in entries {
        let digit_index = value_usize(entry, "digitIndex")?;
        let rns_limb_index = value_usize(entry, "rnsLimbIndex")?;
        if digit_index >= digit_count || rns_limb_index >= limb_count {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component vector index is outside the proof level",
            ));
        }
        if entry.get("rnsPrime").and_then(Value::as_u64) != Some(DATA_PRIMES[rns_limb_index])
            || entry.get("component").and_then(Value::as_str) != Some("b")
            || entry.get("coefficientByteLength").and_then(Value::as_u64)
                != Some(
                    u64::try_from(ring_degree.checked_mul(8).ok_or_else(|| {
                        invalid_evaluation_key_share_material(
                            "evaluation-key coefficient byte length overflowed",
                        )
                    })?)
                    .map_err(|_| {
                        invalid_evaluation_key_share_material(
                            "evaluation-key coefficient byte length does not fit u64",
                        )
                    })?,
                )
        {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component vector metadata does not match the proof level",
            ));
        }
        if !component_b_by_digit[digit_index][rns_limb_index].is_empty() {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component vectors contain a duplicate digit and limb",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            string_field(entry, "coefficientsLeHex")?,
            ring_degree,
            "evaluation-key component vector width",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component vector contains non-canonical Q_share residues",
            ));
        }
        let expected_coefficient_vector_hash =
            evaluation_key_share_component_vector_hash(&coefficients);
        if entry
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
            != Some(expected_coefficient_vector_hash.as_str())
        {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component vector hash does not match coefficientsLeHex",
            ));
        }
        component_b_by_digit[digit_index][rns_limb_index] = coefficients;
    }
    let expected_root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        entries,
    )?;
    if record
        .get("keySwitchComponentVectorRoot")
        .and_then(Value::as_str)
        != Some(expected_root.as_str())
    {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component vector root does not match embedded public material",
        ));
    }

    Ok(component_b_by_digit)
}

fn component_b_vectors_from_transported_material(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    material_set: &Value,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_SET_OBJECT_TYPE)
        || material_set.get("objectVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material set header is invalid",
        ));
    }
    let expected_material_root = string_field(record, "keySwitchComponentMaterialRoot")?;
    let component_materials = array_field(material_set, "componentMaterials")?;
    let mut matching_component_material = None;
    for component_material in component_materials {
        if string_field(component_material, "keySwitchComponentMaterialRoot")?
            != expected_material_root
        {
            continue;
        }
        if matching_component_material.is_some() {
            return Err(invalid_evaluation_key_share_material(
                "transported evaluation-key component material contains duplicate keySwitchComponentMaterialRoot entries",
            ));
        }
        matching_component_material = Some(component_material);
    }
    let component_material = matching_component_material.ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material is missing the requested keySwitchComponentMaterialRoot",
        )
    })?;
    verify_evaluation_key_share_component_material_header(
        proof_family,
        record,
        component_material,
    )?;
    let chunks = evaluation_key_share_component_material_chunks(component_material)?;
    let transport_hashes = evaluation_key_share_component_material_transport_hashes(
        proof_family,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_evaluation_key_share_component_material_hash_fields(
        component_material,
        &transport_hashes,
        "transported evaluation-key component material",
    )?;
    verify_evaluation_key_share_component_material_hash_fields(
        record,
        &transport_hashes,
        "evaluation-key component material reference",
    )?;
    let canonical_material_root = evaluation_key_share_component_material_reference_root(
        proof_family,
        record,
        &transport_hashes,
    )?;
    if expected_material_root != canonical_material_root {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material root must match the canonical transported material reference",
        ));
    }
    let total_byte_length = usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key transported component material length does not fit usize",
        )
    })?;
    let mut material_bytes = Vec::with_capacity(total_byte_length);
    for chunk in chunks {
        material_bytes.extend_from_slice(&chunk);
    }

    decode_evaluation_key_share_component_vectors(proof_family, record, &material_bytes)
}

fn verify_evaluation_key_share_component_material_header(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    component_material: &Value,
) -> CanonicalResult<()> {
    if component_material.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE)
        || component_material
            .get("objectVersion")
            .and_then(Value::as_u64)
            != Some(1)
        || component_material
            .get("proofFamily")
            .and_then(Value::as_str)
            != Some(proof_family.proof_family())
        || component_material
            .get("keySwitchMaterialEncoding")
            .and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
    {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material header is invalid",
        ));
    }
    for field_name in [
        "trusteeIdentity",
        "trusteeRosterPosition",
        "keySwitchDomain",
        "keySwitchSeedHex",
        "level",
        "ringDegree",
        "keySwitchComponentVectorRoot",
    ] {
        if component_material.get(field_name) != record.get(field_name) {
            return Err(invalid_evaluation_key_share_material(format!(
                "transported evaluation-key component material {field_name} must match the proof record"
            )));
        }
    }
    let level = value_u64(record, "level")?;
    let digit_count = level.checked_add(1).ok_or_else(|| {
        invalid_evaluation_key_share_material("evaluation-key digit count overflowed")
    })?;
    if component_material.get("digitCount").and_then(Value::as_u64) != Some(digit_count)
        || component_material
            .get("rnsLimbCount")
            .and_then(Value::as_u64)
            != Some(digit_count)
    {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material digit and limb counts must match the proof level",
        ));
    }

    Ok(())
}

fn evaluation_key_share_component_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material chunkSizeBytes must match the setup transport parameters",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material chunkCount does not fit usize",
        )
    })?;
    let Some(chunk_values) = value.get("chunks") else {
        let material_root = string_field(value, "keySwitchComponentMaterialRoot")?;
        let chunks = stored_verified_evaluation_key_share_component_material_chunks(material_root)?;
        if chunks.len() != expected_chunk_count {
            return Err(invalid_evaluation_key_share_material(
                "verified evaluation-key component material chunks length must match chunkCount",
            ));
        }

        return Ok(chunks);
    };
    let chunk_values = chunk_values.as_array().ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material chunks must be an array",
        )
    })?;
    if chunk_values.len() != expected_chunk_count {
        return Err(invalid_evaluation_key_share_material(
            "transported evaluation-key component material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        let observed_chunk_index = value_usize(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index {
            return Err(invalid_evaluation_key_share_material(
                "transported evaluation-key component material chunks must be in ascending chunk-index order",
            ));
        }
        let bytes_hex = string_field(chunk_value, "bytesHex")?;
        chunks.push(crate::transcript_core::decode_hex(bytes_hex)?);
    }

    Ok(chunks)
}

fn verify_evaluation_key_share_component_material_hash_fields(
    value: &Value,
    transport_hashes: &EvaluationKeyShareComponentMaterialTransportHashes,
    value_name: &str,
) -> CanonicalResult<()> {
    if value_u64(value, "chunkSizeBytes")
        .or_else(|_| value_u64(value, "keySwitchComponentChunkSizeBytes"))?
        != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
        || value_u64(value, "chunkCount")
            .or_else(|_| value_u64(value, "keySwitchComponentChunkCount"))?
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "evaluation-key component material chunk count does not fit u64",
                )
            })?
        || value_u64(value, "totalByteLength")
            .or_else(|_| value_u64(value, "keySwitchComponentTotalByteLength"))?
            != transport_hashes.total_byte_length
        || string_field(value, "fullObjectHash")
            .or_else(|_| string_field(value, "keySwitchComponentFullObjectHash"))?
            != transport_hashes.full_object_hash
        || string_field(value, "chunkRoot")
            .or_else(|_| string_field(value, "keySwitchComponentChunkRoot"))?
            != transport_hashes.chunk_root
    {
        return Err(invalid_evaluation_key_share_material(format!(
            "{value_name} hash metadata does not match supplied chunks"
        )));
    }
    let chunk_hash_values = value
        .get("chunkHashes")
        .or_else(|| value.get("keySwitchComponentChunkHashes"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_evaluation_key_share_material(format!(
                "{value_name} must list every component material chunk hash"
            ))
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(invalid_evaluation_key_share_material(format!(
            "{value_name} chunk hash count must match supplied chunks"
        )));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(invalid_evaluation_key_share_material(format!(
                "{value_name} chunk hashes must match supplied chunks"
            )));
        }
    }

    Ok(())
}

// Canonical decode: fixed record order, in-range residues, and zero trailing
// bytes make the binary encoding injective and non-malleable against the bound
// component-vector root.
fn decode_evaluation_key_share_component_vectors(
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    material_bytes: &[u8],
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(material_bytes, &mut cursor)?;
    if &magic != EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_MAGIC {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material has the wrong format marker",
        ));
    }
    let level = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material level does not fit usize",
        )
    })?;
    let ring_degree = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material ringDegree does not fit usize",
        )
    })?;
    let digit_count = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material digit count does not fit usize",
        )
    })?;
    let limb_count = usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
        invalid_evaluation_key_share_material(
            "evaluation-key component material limb count does not fit usize",
        )
    })?;
    if level != value_usize(record, "level")?
        || ring_degree != value_usize(record, "ringDegree")?
        || ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE
        || digit_count
            != level.checked_add(1).ok_or_else(|| {
                invalid_evaluation_key_share_material("evaluation-key digit count overflowed")
            })?
        || limb_count != digit_count
        || limb_count == 0
        || limb_count > DATA_PRIMES.len()
    {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material shape does not match the proof record",
        ));
    }
    let key_switch_domain = string_field(record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(record, "keySwitchSeedHex")?;
    validate_hex_string(key_switch_seed_hex, "keySwitchSeedHex")?;
    let mut component_b_by_digit = vec![vec![Vec::<u64>::new(); limb_count]; digit_count];
    let mut entries = Vec::with_capacity(digit_count * limb_count);
    for expected_digit_index in 0..digit_count {
        for expected_rns_limb_index in 0..limb_count {
            let digit_index =
                usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key component material digit index does not fit usize",
                    )
                })?;
            let rns_limb_index =
                usize::try_from(read_u64(material_bytes, &mut cursor)?).map_err(|_| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key component material RNS limb index does not fit usize",
                    )
                })?;
            let rns_prime = read_u64(material_bytes, &mut cursor)?;
            let coefficient_count = usize::try_from(read_u64(material_bytes, &mut cursor)?)
                .map_err(|_| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key component material coefficient count does not fit usize",
                    )
                })?;
            if digit_index != expected_digit_index
                || rns_limb_index != expected_rns_limb_index
                || rns_limb_index >= DATA_PRIMES.len()
                || rns_prime != DATA_PRIMES[rns_limb_index]
                || coefficient_count != ring_degree
            {
                return Err(invalid_evaluation_key_share_material(
                    "evaluation-key component material record order or metadata is invalid",
                ));
            }
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                let coefficient = read_u64(material_bytes, &mut cursor)?;
                if coefficient >= DATA_PRIMES[rns_limb_index] {
                    return Err(invalid_evaluation_key_share_material(
                        "evaluation-key component material contains non-canonical Q_share residues",
                    ));
                }
                coefficients.push(coefficient);
            }
            entries.push(json!({
                "digitIndex": digit_index,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "component": "b",
                "coefficientByteLength": ring_degree.checked_mul(8).ok_or_else(|| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key coefficient byte length overflowed",
                    )
                })?,
                "coefficientVectorHash512": evaluation_key_share_component_vector_hash(&coefficients),
                "coefficientsLeHex": coefficient_vector_le_hex(&coefficients),
            }));
            component_b_by_digit[digit_index][rns_limb_index] = coefficients;
        }
    }
    if cursor != material_bytes.len() {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component material has trailing bytes",
        ));
    }
    let expected_root = evaluation_key_share_component_vector_root(
        proof_family,
        key_switch_domain,
        key_switch_seed_hex,
        level,
        ring_degree,
        &entries,
    )?;
    if string_field(record, "keySwitchComponentVectorRoot")? != expected_root {
        return Err(invalid_evaluation_key_share_material(
            "evaluation-key component vector root does not match transported public material",
        ));
    }

    Ok(component_b_by_digit)
}

static VERIFIED_EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_CHUNKS: OnceLock<
    Mutex<BTreeMap<String, VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry>>,
> = OnceLock::new();

#[derive(Debug, Clone)]
struct VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
    path: PathBuf,
    total_byte_length: u64,
}
