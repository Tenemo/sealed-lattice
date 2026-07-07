use super::*;

#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufWriter, Write};

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
        "proofFamily": proof_family.proof_family(),
        "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
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
    match &store_entry.backing {
        #[cfg(any(target_arch = "wasm32", test))]
        VerifiedComponentMaterialBacking::Memory(chunks) => {
            let mut staged_total = 0_u64;
            for chunk in chunks {
                staged_total = staged_total
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        invalid_evaluation_key_share_material(
                            "in-memory component material chunk length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_material(
                            "in-memory component material byte length overflowed",
                        )
                    })?;
            }
            if staged_total != store_entry.total_byte_length {
                return Err(invalid_evaluation_key_share_material(
                    "in-memory component material total byte length does not match the verified handle",
                ));
            }
            Ok(chunks.clone())
        }
        #[cfg(not(target_arch = "wasm32"))]
        VerifiedComponentMaterialBacking::TempFile(path) => {
            let chunk_size =
                usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
                    invalid_evaluation_key_share_material(
                        "evaluation-key component material chunk size does not fit usize",
                    )
                })?;
            let mut remaining_byte_length = store_entry.total_byte_length;
            let mut file = std::fs::File::open(path).map_err(|error| {
                invalid_evaluation_key_share_material(format!(
                    "verified evaluation-key component material store entry could not be opened: {error}",
                ))
            })?;
            let mut chunks = Vec::new();
            while remaining_byte_length > 0 {
                let next_chunk_length = usize::try_from(
                    remaining_byte_length.min(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES),
                )
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
    }
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
    let Some(chunk_values) = value.get("chunks") else {
        let material_root = string_field(value, "keySwitchComponentMaterialRoot")?;
        return stored_verified_evaluation_key_share_component_material_chunks(material_root);
    };
    let chunk_values = chunk_values.as_array().ok_or_else(|| {
        invalid_evaluation_key_share_material(
            "transported evaluation-key component material chunks must be an array",
        )
    })?;
    let mut chunks = Vec::with_capacity(chunk_values.len());
    for chunk_value in chunk_values.iter() {
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
    if value_u64(value, "chunkCount")
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
    backing: VerifiedComponentMaterialBacking,
    total_byte_length: u64,
}

// Where verified component material lives after a stream finishes. Native runs
// stage to a temp file so only one component (about 72.25 MiB) is resident at a
// time and CI memory stays bounded; the browser wasm runtime has no filesystem,
// so it holds the verified chunks in memory. The in-memory backing is also
// compiled under `test` so the native stream tests exercise it without a browser.
#[derive(Debug, Clone)]
enum VerifiedComponentMaterialBacking {
    #[cfg(not(target_arch = "wasm32"))]
    TempFile(PathBuf),
    #[cfg(any(target_arch = "wasm32", test))]
    Memory(Vec<Vec<u8>>),
}

// Streamed transport for evaluation-key component material. begin records the
// declared chunk manifest and opens a staging sink, absorb structurally
// validates each chunk (order, size, and running total) and stages it, and
// finish reads the staged chunks back, recomputes the component-material
// transport hashes, verifies them against the declared manifest, and registers
// the verified handle. One component is about 72.25 MiB and the whole per-roster
// class is tens of GB, so native stages to a temp file and keeps only one
// component resident; the browser wasm runtime has no filesystem and stages in
// memory. The accepted-setup verifier then reads the handle transiently through
// the shared read path. The material size, not the staging backend, is the open
// supported-phone runtime constraint (see SEC-008 and SEC-012).
pub(crate) use component_material_stream::{
    absorb_evaluation_key_share_component_material_transport_stream_chunk_request,
    begin_evaluation_key_share_component_material_transport_stream_request,
    finish_evaluation_key_share_component_material_transport_stream_request,
};

mod component_material_stream {
    use super::*;

    const COMPONENT_MATERIAL_STREAM_ID_MAX_BYTES: usize = 128;
    #[cfg(not(target_arch = "wasm32"))]
    const COMPONENT_MATERIAL_STREAM_TEMP_FILE_DOMAIN: &str =
        "sealed-lattice/setup/evaluation-key-share/component-material/stream-temp-v1";

    static COMPONENT_MATERIAL_TRANSPORT_STREAM_SESSIONS: OnceLock<
        Mutex<BTreeMap<String, ComponentMaterialTransportStreamSession>>,
    > = OnceLock::new();

    struct ComponentMaterialStreamHeader {
        proof_family: EvaluationKeyShareProofFamily,
        material_root: String,
        chunk_count: usize,
        total_byte_length: u64,
        full_object_hash: String,
        chunk_root: String,
        chunk_hashes: Vec<String>,
    }

    struct ComponentMaterialTransportStreamSession {
        header: ComponentMaterialStreamHeader,
        next_chunk_index: usize,
        observed_total_byte_length: u64,
        sink: ComponentMaterialStreamSink,
    }

    // Where an in-flight stream stages its chunks before finish verifies them.
    // Native stages to a temp file; the browser wasm runtime stages in memory.
    // Compiled under `test` so the native stream tests exercise the in-memory
    // path without a browser.
    enum ComponentMaterialStreamSink {
        #[cfg(not(target_arch = "wasm32"))]
        TempFile {
            path: PathBuf,
            writer: BufWriter<File>,
        },
        #[cfg(any(target_arch = "wasm32", test))]
        Memory { chunks: Vec<Vec<u8>> },
    }

    // Open a staging sink for a new stream. Native opens a temp file; the wasm
    // runtime stages in memory.
    fn open_component_material_stream_sink(
        verification_id: &str,
    ) -> CanonicalResult<ComponentMaterialStreamSink> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = component_material_stream_temp_path(verification_id)?;
            let file = File::create(&path).map_err(|error| {
                invalid_evaluation_key_share_material(format!(
                    "evaluation-key component material stream temp file could not be created: {error}"
                ))
            })?;
            Ok(ComponentMaterialStreamSink::TempFile {
                path,
                writer: BufWriter::new(file),
            })
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = verification_id;
            Ok(ComponentMaterialStreamSink::Memory { chunks: Vec::new() })
        }
    }

    // Append one validated chunk to the staging sink.
    fn stage_component_material_stream_chunk(
        sink: &mut ComponentMaterialStreamSink,
        chunk: &[u8],
    ) -> CanonicalResult<()> {
        match sink {
            #[cfg(not(target_arch = "wasm32"))]
            ComponentMaterialStreamSink::TempFile { writer, .. } => {
                writer.write_all(chunk).map_err(|error| {
                    invalid_evaluation_key_share_material(format!(
                        "evaluation-key component material chunk could not be written: {error}"
                    ))
                })
            }
            #[cfg(any(target_arch = "wasm32", test))]
            ComponentMaterialStreamSink::Memory { chunks } => {
                chunks.push(chunk.to_vec());
                Ok(())
            }
        }
    }

    // Read the fully staged material back as chunks so finish can recompute and
    // verify the transport hashes. Native flushes and reads the temp file; the
    // wasm runtime already holds the chunks.
    fn staged_component_material_stream_chunks(
        sink: &mut ComponentMaterialStreamSink,
        total_byte_length: u64,
    ) -> CanonicalResult<Vec<Vec<u8>>> {
        match sink {
            #[cfg(not(target_arch = "wasm32"))]
            ComponentMaterialStreamSink::TempFile { path, writer } => {
                writer.flush().map_err(|error| {
                    invalid_evaluation_key_share_material(format!(
                        "evaluation-key component material stream file could not be flushed: {error}"
                    ))
                })?;
                let store_entry = VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
                    backing: VerifiedComponentMaterialBacking::TempFile(path.clone()),
                    total_byte_length,
                };
                read_verified_evaluation_key_share_component_material_chunks(&store_entry)
            }
            #[cfg(any(target_arch = "wasm32", test))]
            ComponentMaterialStreamSink::Memory { chunks } => {
                let store_entry = VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
                    backing: VerifiedComponentMaterialBacking::Memory(chunks.clone()),
                    total_byte_length,
                };
                read_verified_evaluation_key_share_component_material_chunks(&store_entry)
            }
        }
    }

    // Consume the staging sink into the verified store backing that persists for
    // downstream reads: native keeps the temp file, the wasm runtime keeps the
    // in-memory chunks.
    fn component_material_stream_sink_into_backing(
        sink: ComponentMaterialStreamSink,
    ) -> VerifiedComponentMaterialBacking {
        match sink {
            #[cfg(not(target_arch = "wasm32"))]
            ComponentMaterialStreamSink::TempFile { path, .. } => {
                VerifiedComponentMaterialBacking::TempFile(path)
            }
            #[cfg(any(target_arch = "wasm32", test))]
            ComponentMaterialStreamSink::Memory { chunks } => {
                VerifiedComponentMaterialBacking::Memory(chunks)
            }
        }
    }

    // Discard a staging sink whose stream failed, removing any temp file.
    fn discard_component_material_stream_sink(sink: &ComponentMaterialStreamSink) {
        match sink {
            #[cfg(not(target_arch = "wasm32"))]
            ComponentMaterialStreamSink::TempFile { path, .. } => {
                let _ = std::fs::remove_file(path);
            }
            #[cfg(any(target_arch = "wasm32", test))]
            ComponentMaterialStreamSink::Memory { .. } => {}
        }
    }

    fn component_material_transport_stream_sessions()
    -> &'static Mutex<BTreeMap<String, ComponentMaterialTransportStreamSession>> {
        COMPONENT_MATERIAL_TRANSPORT_STREAM_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    fn component_material_stream_verification_id(value: &Value) -> CanonicalResult<String> {
        let verification_id = string_field(value, "verificationId")?;
        if verification_id.is_empty()
            || verification_id.len() > COMPONENT_MATERIAL_STREAM_ID_MAX_BYTES
            || !verification_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_:.".contains(character))
        {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material verificationId must be a short ASCII identifier",
            ));
        }

        Ok(verification_id.to_string())
    }

    fn evaluation_key_share_proof_family_from_str(
        value: &str,
    ) -> CanonicalResult<EvaluationKeyShareProofFamily> {
        match value {
            "relinearization-key-share" => Ok(EvaluationKeyShareProofFamily::Relinearization),
            "galois-key-share" => Ok(EvaluationKeyShareProofFamily::Galois),
            _ => Err(invalid_evaluation_key_share_material(
                "evaluation-key component material proofFamily is not accepted",
            )),
        }
    }

    // A stable, cross-platform temp filename for a stream: the verificationId can
    // contain characters that are not valid on every filesystem, so the file is
    // named by a domain-separated hash of it.
    #[cfg(not(target_arch = "wasm32"))]
    fn component_material_stream_temp_path(verification_id: &str) -> CanonicalResult<PathBuf> {
        let mut directory = std::env::temp_dir();
        directory.push("sealed-lattice-evaluation-key-component-material");
        std::fs::create_dir_all(&directory).map_err(|error| {
        invalid_evaluation_key_share_material(format!(
            "evaluation-key component material stream temp directory could not be created: {error}"
        ))
    })?;
        let file_name = hash512_hex(
            COMPONENT_MATERIAL_STREAM_TEMP_FILE_DOMAIN,
            &[verification_id.as_bytes()],
        );
        directory.push(format!("{file_name}.bin"));

        Ok(directory)
    }

    fn read_component_material_stream_header(
        reference: &Value,
    ) -> CanonicalResult<ComponentMaterialStreamHeader> {
        if reference.get("chunks").is_some() {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream header must not contain embedded chunks",
            ));
        }
        if reference.get("objectType").and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE)
            || reference
                .get("keySwitchMaterialEncoding")
                .and_then(Value::as_str)
                != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
        {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream header is invalid",
            ));
        }
        let proof_family =
            evaluation_key_share_proof_family_from_str(string_field(reference, "proofFamily")?)?;
        let material_root = string_field(reference, "keySwitchComponentMaterialRoot")?.to_string();
        validate_hex_string(&material_root, "keySwitchComponentMaterialRoot")?;
        let chunk_count = value_usize(reference, "chunkCount")?;
        if chunk_count == 0 {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream chunkCount must be positive",
            ));
        }
        let total_byte_length = value_u64(reference, "totalByteLength")?;
        if total_byte_length == 0 {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream totalByteLength must be positive",
            ));
        }
        let full_object_hash = string_field(reference, "fullObjectHash")?.to_string();
        validate_hex_string(&full_object_hash, "fullObjectHash")?;
        let chunk_root = string_field(reference, "chunkRoot")?.to_string();
        validate_hex_string(&chunk_root, "chunkRoot")?;
        let chunk_hash_values = array_field(reference, "chunkHashes")?;
        if chunk_hash_values.len() != chunk_count {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream chunkHashes length must match chunkCount",
            ));
        }
        let mut chunk_hashes = Vec::with_capacity(chunk_count);
        for chunk_hash_value in chunk_hash_values {
            let chunk_hash = chunk_hash_value.as_str().ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material stream chunkHashes must be hash strings",
                )
            })?;
            validate_hex_string(chunk_hash, "chunkHashes")?;
            chunk_hashes.push(chunk_hash.to_string());
        }

        Ok(ComponentMaterialStreamHeader {
            proof_family,
            material_root,
            chunk_count,
            total_byte_length,
            full_object_hash,
            chunk_root,
            chunk_hashes,
        })
    }

    pub(crate) fn begin_evaluation_key_share_component_material_transport_stream_request(
        request: &Value,
    ) -> CanonicalResult<Value> {
        let verification_id = component_material_stream_verification_id(request)?;
        let reference = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .ok_or_else(|| {
            invalid_evaluation_key_share_material(
                "transportedEvaluationKeyShareComponentMaterial is required to begin the component material stream",
            )
        })?;
        let header = read_component_material_stream_header(reference)?;
        let sink = open_component_material_stream_sink(&verification_id)?;

        let sessions = component_material_transport_stream_sessions();
        let mut sessions = sessions.lock().map_err(|_| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material stream session store is unavailable",
            )
        })?;
        if sessions.contains_key(&verification_id) {
            discard_component_material_stream_sink(&sink);
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material verificationId is already active",
            ));
        }
        let chunk_count = header.chunk_count;
        let total_byte_length = header.total_byte_length;
        let material_root = header.material_root.clone();
        let proof_family = header.proof_family.proof_family();
        sessions.insert(
            verification_id.clone(),
            ComponentMaterialTransportStreamSession {
                header,
                next_chunk_index: 0,
                observed_total_byte_length: 0,
                sink,
            },
        );

        Ok(json!({
            "operation": "beginEvaluationKeyShareComponentMaterialTransportStream",
            "verificationId": verification_id,
            "proofFamily": proof_family,
            "keySwitchComponentMaterialRoot": material_root,
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "transport": {
                "chunkCount": chunk_count,
                "totalByteLength": total_byte_length,
            },
        }))
    }

    pub(crate) fn absorb_evaluation_key_share_component_material_transport_stream_chunk_request(
        request: &Value,
    ) -> CanonicalResult<Value> {
        let verification_id = component_material_stream_verification_id(request)?;
        let chunk_index = value_usize(request, "chunkIndex")?;
        let chunk = crate::transcript_core::decode_hex(string_field(request, "bytesHex")?)?;

        let sessions = component_material_transport_stream_sessions();
        let mut sessions = sessions.lock().map_err(|_| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material stream session store is unavailable",
            )
        })?;
        let absorb_result = {
            let session = sessions.get_mut(&verification_id).ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material verificationId is not active",
                )
            })?;
            absorb_component_material_stream_chunk(session, chunk_index, &chunk)
        };
        match absorb_result {
            Ok(response) => Ok(response),
            Err(error) => {
                if let Some(session) = sessions.remove(&verification_id) {
                    discard_component_material_stream_sink(&session.sink);
                }
                Err(error)
            }
        }
    }

    fn absorb_component_material_stream_chunk(
        session: &mut ComponentMaterialTransportStreamSession,
        chunk_index: usize,
        chunk: &[u8],
    ) -> CanonicalResult<Value> {
        if chunk_index != session.next_chunk_index {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material chunks must be absorbed in ascending chunk-index order",
            ));
        }
        if chunk_index >= session.header.chunk_count {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream received more chunks than declared",
            ));
        }
        if chunk.is_empty() {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material chunks must be non-empty",
            ));
        }
        let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material chunk size does not fit usize",
            )
        })?;
        if chunk.len() > chunk_size {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material chunk exceeds the accepted chunk size",
            ));
        }
        let is_final_chunk = chunk_index + 1 == session.header.chunk_count;
        if !is_final_chunk && chunk.len() != chunk_size {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material contains a short non-final chunk",
            ));
        }
        let new_total = session
            .observed_total_byte_length
            .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material chunk length does not fit u64",
                )
            })?)
            .ok_or_else(|| {
                invalid_evaluation_key_share_material(
                    "evaluation-key component material byte length overflowed",
                )
            })?;
        if new_total > session.header.total_byte_length {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream chunk bytes exceed declared totalByteLength",
            ));
        }
        if is_final_chunk && new_total != session.header.total_byte_length {
            return Err(invalid_evaluation_key_share_material(
                "final evaluation-key component material chunk must finish at declared totalByteLength",
            ));
        }
        stage_component_material_stream_chunk(&mut session.sink, chunk)?;
        session.observed_total_byte_length = new_total;
        session.next_chunk_index += 1;

        Ok(json!({
            "operation": "absorbEvaluationKeyShareComponentMaterialTransportStreamChunk",
            "absorbedChunkIndex": chunk_index,
            "nextChunkIndex": session.next_chunk_index,
            "observedTotalByteLength": session.observed_total_byte_length,
        }))
    }

    pub(crate) fn finish_evaluation_key_share_component_material_transport_stream_request(
        request: &Value,
    ) -> CanonicalResult<Value> {
        let verification_id = component_material_stream_verification_id(request)?;
        let sessions = component_material_transport_stream_sessions();
        let mut sessions = sessions.lock().map_err(|_| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material stream session store is unavailable",
            )
        })?;
        let session = sessions.remove(&verification_id).ok_or_else(|| {
            invalid_evaluation_key_share_material(
                "evaluation-key component material verificationId is not active",
            )
        })?;
        drop(sessions);

        finish_component_material_stream(&verification_id, session)
    }

    fn finish_component_material_stream(
        verification_id: &str,
        mut session: ComponentMaterialTransportStreamSession,
    ) -> CanonicalResult<Value> {
        let finish_result = finish_component_material_stream_inner(&mut session);
        if finish_result.is_err() {
            discard_component_material_stream_sink(&session.sink);
        }
        let transport_hashes = finish_result?;

        let backing = component_material_stream_sink_into_backing(session.sink);
        verified_evaluation_key_share_component_material_chunks()
            .lock()
            .map_err(|_| {
                invalid_evaluation_key_share_material(
                    "verified evaluation-key component material store is unavailable",
                )
            })?
            .insert(
                session.header.material_root.clone(),
                VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
                    backing,
                    total_byte_length: session.header.total_byte_length,
                },
            );

        Ok(json!({
            "operation": "finishEvaluationKeyShareComponentMaterialTransportStream",
            "verificationId": verification_id,
            "proofFamily": session.header.proof_family.proof_family(),
            "keySwitchComponentMaterialRoot": session.header.material_root,
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "verifiedEvaluationKeyShareComponentMaterial": {
                "objectType": "VerifiedEvaluationKeyShareComponentMaterial",
                "verificationId": verification_id,
                "proofFamily": session.header.proof_family.proof_family(),
                "keySwitchComponentMaterialRoot": session.header.material_root,
                "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
                "chunkCount": transport_hashes.chunk_hashes.len(),
                "totalByteLength": transport_hashes.total_byte_length,
                "fullObjectHash": transport_hashes.full_object_hash,
                "chunkRoot": transport_hashes.chunk_root,
                "chunkHashes": transport_hashes.chunk_hashes,
            },
        }))
    }

    fn finish_component_material_stream_inner(
        session: &mut ComponentMaterialTransportStreamSession,
    ) -> CanonicalResult<EvaluationKeyShareComponentMaterialTransportHashes> {
        if session.next_chunk_index != session.header.chunk_count {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream is missing declared chunks",
            ));
        }
        if session.observed_total_byte_length != session.header.total_byte_length {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream totalByteLength does not match absorbed chunk bytes",
            ));
        }
        let total_byte_length = session.header.total_byte_length;
        let proof_family = session.header.proof_family;
        let chunks = staged_component_material_stream_chunks(&mut session.sink, total_byte_length)?;
        let transport_hashes = evaluation_key_share_component_material_transport_hashes(
            proof_family,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        if transport_hashes.chunk_hashes.len() != session.header.chunk_count
            || transport_hashes.total_byte_length != session.header.total_byte_length
            || transport_hashes.full_object_hash != session.header.full_object_hash
            || transport_hashes.chunk_root != session.header.chunk_root
            || transport_hashes.chunk_hashes != session.header.chunk_hashes
        {
            return Err(invalid_evaluation_key_share_material(
                "evaluation-key component material stream does not match the declared chunk manifest",
            ));
        }

        Ok(transport_hashes)
    }

    // The in-memory sink is the wasm runtime's staging path. These tests exercise
    // it on native (no filesystem, no browser) so the shared verification logic is
    // covered on both backends.
    #[cfg(test)]
    mod memory_sink_tests {
        use super::*;

        fn arbitrary_bytes(byte_length: usize) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(byte_length);
            let mut state = 0x0f0f_f0f0_1234_5678_u64;
            for _ in 0..byte_length {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                bytes.push((state >> 33) as u8);
            }
            bytes
        }

        fn memory_session(
            chunks: &[Vec<u8>],
            material_root: &str,
        ) -> ComponentMaterialTransportStreamSession {
            let hashes = evaluation_key_share_component_material_transport_hashes(
                EvaluationKeyShareProofFamily::Relinearization,
                chunks,
                SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            )
            .expect("transport hashes over the reference chunks");
            let header = ComponentMaterialStreamHeader {
                proof_family: EvaluationKeyShareProofFamily::Relinearization,
                material_root: material_root.to_string(),
                chunk_count: chunks.len(),
                total_byte_length: hashes.total_byte_length,
                full_object_hash: hashes.full_object_hash,
                chunk_root: hashes.chunk_root,
                chunk_hashes: hashes.chunk_hashes,
            };
            ComponentMaterialTransportStreamSession {
                header,
                next_chunk_index: 0,
                observed_total_byte_length: 0,
                sink: ComponentMaterialStreamSink::Memory { chunks: Vec::new() },
            }
        }

        #[test]
        fn in_memory_sink_verifies_and_reads_back_without_a_filesystem() {
            let chunk_size =
                usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).expect("chunk size");
            let chunks: Vec<Vec<u8>> = arbitrary_bytes(chunk_size + 4096)
                .chunks(chunk_size)
                .map(<[u8]>::to_vec)
                .collect();
            let reference_hashes = evaluation_key_share_component_material_transport_hashes(
                EvaluationKeyShareProofFamily::Relinearization,
                &chunks,
                SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            )
            .expect("reference transport hashes");
            let mut session = memory_session(&chunks, &"ab".repeat(64));
            for (chunk_index, chunk) in chunks.iter().enumerate() {
                absorb_component_material_stream_chunk(&mut session, chunk_index, chunk)
                    .expect("absorb a chunk into the in-memory sink");
            }
            let transport_hashes = finish_component_material_stream_inner(&mut session)
                .expect("finish verifies the in-memory staged material against the manifest");
            assert_eq!(transport_hashes.chunk_hashes, reference_hashes.chunk_hashes);

            let backing = component_material_stream_sink_into_backing(session.sink);
            let store_entry = VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry {
                backing,
                total_byte_length: transport_hashes.total_byte_length,
            };
            let read_back =
                read_verified_evaluation_key_share_component_material_chunks(&store_entry)
                    .expect("the in-memory backing reads back its staged chunks");
            assert_eq!(
                read_back, chunks,
                "in-memory backing returns exactly the staged chunks"
            );
        }

        #[test]
        fn in_memory_sink_rejects_out_of_order_chunks() {
            let chunk_size =
                usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).expect("chunk size");
            let chunks: Vec<Vec<u8>> = arbitrary_bytes(chunk_size + 32)
                .chunks(chunk_size)
                .map(<[u8]>::to_vec)
                .collect();
            assert!(
                chunks.len() >= 2,
                "need at least two chunks for the ordering test"
            );
            let mut session = memory_session(&chunks, &"cd".repeat(64));
            absorb_component_material_stream_chunk(&mut session, 1, &chunks[1])
                .expect_err("a chunk absorbed out of ascending order must be refused");
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod stream_tests {
    use super::*;

    fn arbitrary_material_bytes(byte_length: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(byte_length);
        let mut state = 0x1234_5678_9abc_def0_u64;
        for _ in 0..byte_length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            bytes.push((state >> 33) as u8);
        }
        bytes
    }

    fn chunk_bytes(bytes: &[u8]) -> Vec<Vec<u8>> {
        let chunk_size =
            usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).expect("chunk size");
        bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
    }

    fn stream_reference(chunks: &[Vec<u8>], material_root: &str) -> Value {
        let hashes = evaluation_key_share_component_material_transport_hashes(
            EvaluationKeyShareProofFamily::Relinearization,
            chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("component material transport hashes");
        json!({
            "objectType": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_TRANSPORT_OBJECT_TYPE,
            "proofFamily": "relinearization-key-share",
            "keySwitchMaterialEncoding": EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING,
            "keySwitchComponentMaterialRoot": material_root,
            "chunkCount": chunks.len(),
            "totalByteLength": chunks.iter().map(Vec::len).sum::<usize>(),
            "fullObjectHash": hashes.full_object_hash,
            "chunkRoot": hashes.chunk_root,
            "chunkHashes": hashes.chunk_hashes,
        })
    }

    fn begin(verification_id: &str, reference: &Value) -> CanonicalResult<Value> {
        begin_evaluation_key_share_component_material_transport_stream_request(&json!({
            "verificationId": verification_id,
            "transportedEvaluationKeyShareComponentMaterial": reference,
        }))
    }

    fn absorb(verification_id: &str, chunk_index: usize, chunk: &[u8]) -> CanonicalResult<Value> {
        absorb_evaluation_key_share_component_material_transport_stream_chunk_request(&json!({
            "verificationId": verification_id,
            "chunkIndex": chunk_index,
            "bytesHex": crate::hashing::to_hex(chunk),
        }))
    }

    fn finish(verification_id: &str) -> CanonicalResult<Value> {
        finish_evaluation_key_share_component_material_transport_stream_request(&json!({
            "verificationId": verification_id,
        }))
    }

    #[test]
    fn streams_multi_chunk_material_to_a_verified_file_backed_handle() {
        // One full 1 MiB chunk plus a short final chunk exercises the chunk
        // boundary and the short-final-chunk path.
        let byte_length =
            usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).expect("chunk size") + 4096;
        let bytes = arbitrary_material_bytes(byte_length);
        let chunks = chunk_bytes(&bytes);
        assert_eq!(chunks.len(), 2);
        let material_root = "1".repeat(128);
        let reference = stream_reference(&chunks, &material_root);
        let verification_id = "component-material-stream-happy";

        begin(verification_id, &reference).expect("begin");
        for (chunk_index, chunk) in chunks.iter().enumerate() {
            absorb(verification_id, chunk_index, chunk).expect("absorb");
        }
        finish(verification_id).expect("finish");

        let read_back =
            stored_verified_evaluation_key_share_component_material_chunks(&material_root)
                .expect("verified store holds the streamed material");
        assert_eq!(
            read_back.concat(),
            bytes,
            "the streamed, file-backed material must read back byte-identically"
        );
    }

    #[test]
    fn absorb_rejects_out_of_order_chunks_and_drops_the_session() {
        let bytes = arbitrary_material_bytes(8192);
        let chunks = chunk_bytes(&bytes);
        assert_eq!(chunks.len(), 1);
        let material_root = "2".repeat(128);
        let reference = stream_reference(&chunks, &material_root);
        let verification_id = "component-material-stream-order";

        begin(verification_id, &reference).expect("begin");
        // The only chunk is index 0; absorbing index 1 first is out of order.
        assert!(
            absorb(verification_id, 1, &chunks[0]).is_err(),
            "an out-of-order chunk must be rejected"
        );
        // The failed absorb drops the session, so the stream cannot be finished.
        assert!(
            finish(verification_id).is_err(),
            "a dropped session must not finish"
        );
    }

    #[test]
    fn finish_rejects_bytes_that_do_not_match_the_declared_manifest() {
        let bytes = arbitrary_material_bytes(8192);
        let chunks = chunk_bytes(&bytes);
        let material_root = "3".repeat(128);
        let reference = stream_reference(&chunks, &material_root);
        let verification_id = "component-material-stream-tamper";

        begin(verification_id, &reference).expect("begin");
        // Same length so the structural checks pass, different content so the
        // recomputed manifest cannot match the declared one.
        let mut tampered = chunks[0].clone();
        tampered[0] ^= 0xff;
        absorb(verification_id, 0, &tampered).expect("absorb accepts well-formed chunk bytes");
        assert!(
            finish(verification_id).is_err(),
            "finish must reject material that does not match the declared manifest"
        );
        assert!(
            stored_verified_evaluation_key_share_component_material_chunks(&material_root).is_err(),
            "a rejected stream must not register a verified handle"
        );
    }
}
