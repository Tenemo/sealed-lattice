use super::*;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

use crate::transcript_core::decode_hex;

const VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE: &str = "VerifiedSetupProofMaterialSet";
const VERIFIED_SETUP_PROOF_MATERIAL_OBJECT_TYPE: &str = "VerifiedSetupProofMaterial";
const SETUP_PROOF_MATERIAL_STREAM_ID_MAX_BYTES: usize = 128;

static SETUP_PROOF_MATERIAL_TRANSPORT_STREAM_SESSIONS: OnceLock<
    Mutex<BTreeMap<String, SetupProofMaterialTransportStreamSession>>,
> = OnceLock::new();
static VERIFIED_SETUP_PROOF_MATERIALS: OnceLock<
    Mutex<BTreeMap<String, VerifiedSetupProofMaterial>>,
> = OnceLock::new();

#[derive(Debug, Clone)]
pub(crate) struct SetupProofMaterialTransportHashes {
    pub(crate) full_object_hash: String,
    pub(crate) chunk_hashes: Vec<String>,
    pub(crate) chunk_root: String,
    pub(crate) total_byte_length: u64,
}

#[derive(Debug, Clone)]
struct SetupProofMaterialMetadata {
    chunk_size_bytes: u64,
    chunk_count: usize,
    total_byte_length: u64,
    full_object_hash: String,
    chunk_root: String,
    chunk_hashes: Vec<String>,
}

#[derive(Debug, Clone)]
struct SetupProofMaterialTransportStreamHeader {
    proof_family: String,
    proof_material_root: String,
    metadata: SetupProofMaterialMetadata,
}

#[derive(Debug)]
struct SetupProofMaterialTransportStreamSession {
    header: SetupProofMaterialTransportStreamHeader,
    next_chunk_index: usize,
    observed_total_byte_length: u64,
    chunks: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct VerifiedSetupProofMaterial {
    reference: Value,
    chunks: Arc<Vec<Vec<u8>>>,
}

pub(in crate::bgv::setup) fn setup_proof_record_binding_value(
    setup_parameters_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofRecordBinding",
        "objectVersion": 1,
        "setupParametersHash": setup_parameters_hash,
        "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
        "proofSerialization": SETUP_PROOF_SERIALIZATION,
        "proofByteDecoder": SETUP_PROOF_BYTE_DECODER,
    }))
}

pub(crate) fn begin_setup_proof_material_transport_stream_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let verification_id = setup_proof_material_verification_id_field(request)?.to_string();
    let transported_material = object_field_at(
        request,
        "transportedSetupProofMaterial",
        "transportedSetupProofMaterial",
    )?;
    let header = read_setup_proof_material_transport_stream_header(
        transported_material,
        "transportedSetupProofMaterial",
    )?;

    let sessions = setup_proof_material_transport_stream_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        setup_proof_error("setup proof material transport session store is unavailable")
    })?;
    if sessions.contains_key(&verification_id) {
        return Err(setup_proof_error(
            "setup proof material verificationId is already active",
        ));
    }
    if verified_setup_proof_materials()
        .lock()
        .map_err(|_| setup_proof_error("verified setup proof material store is unavailable"))?
        .contains_key(&verification_id)
    {
        return Err(setup_proof_error(
            "setup proof material verificationId already has verified material",
        ));
    }
    sessions.insert(
        verification_id.clone(),
        SetupProofMaterialTransportStreamSession {
            chunks: Vec::with_capacity(header.metadata.chunk_count),
            header: header.clone(),
            next_chunk_index: 0,
            observed_total_byte_length: 0,
        },
    );

    Ok(json!({
        "isValid": true,
        "operation": "beginSetupProofMaterialTransportStream",
        "verificationId": verification_id,
        "proofFamily": header.proof_family,
        "proofMaterialRoot": header.proof_material_root,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "transport": {
            "chunkSizeBytes": header.metadata.chunk_size_bytes,
            "chunkCount": header.metadata.chunk_count,
            "totalByteLength": header.metadata.total_byte_length,
        },
    }))
}

pub(crate) fn absorb_setup_proof_material_transport_stream_chunk_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let verification_id = setup_proof_material_verification_id_field(request)?.to_string();
    let chunk_index = usize_field_at(request, "chunkIndex", "chunkIndex")?;
    let bytes_hex = string_field_at(request, "bytesHex", "bytesHex")?;
    let chunk = decode_hex(bytes_hex)?;

    let sessions = setup_proof_material_transport_stream_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        setup_proof_error("setup proof material transport session store is unavailable")
    })?;
    let absorb_result = {
        let session = sessions.get_mut(&verification_id).ok_or_else(|| {
            setup_proof_error("setup proof material verificationId is not active")
        })?;
        absorb_setup_proof_material_transport_stream_chunk(session, chunk_index, chunk)
    };
    match absorb_result {
        Ok(response) => Ok(response),
        Err(error) => {
            sessions.remove(&verification_id);
            Err(error)
        }
    }
}

pub(crate) fn finish_setup_proof_material_transport_stream_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let verification_id = setup_proof_material_verification_id_field(request)?.to_string();
    let sessions = setup_proof_material_transport_stream_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        setup_proof_error("setup proof material transport session store is unavailable")
    })?;
    let session = sessions
        .remove(&verification_id)
        .ok_or_else(|| setup_proof_error("setup proof material verificationId is not active"))?;
    drop(sessions);

    finish_setup_proof_material_transport_stream(&verification_id, session)
}

pub(in crate::bgv::setup) fn verified_setup_proof_material_chunks_from_request(
    request: &Value,
    proof_family: &str,
    expected_proof_material_root: &str,
    transported_proof_material: &Value,
    transported_material_path: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    validate_supported_setup_proof_transport_family(proof_family, "proofFamily")?;
    validate_hash_string(
        expected_proof_material_root,
        &format!("{transported_material_path}.proofMaterialRoot"),
    )?;
    let expected_metadata = setup_proof_material_metadata_from_value(
        transported_proof_material,
        transported_material_path,
    )?;
    let verified_material_set = request.get("verifiedSetupProofMaterials").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verifiedSetupProofMaterials was required by chunkless transported setup proof material",
        )
    })?;
    verify_verified_setup_proof_material_set_header(verified_material_set)?;
    let proof_materials = verified_material_set
        .get("proofMaterials")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "verifiedSetupProofMaterials.proofMaterials must list verified setup proof material handles",
            )
        })?;
    let verified_materials = verified_setup_proof_materials();
    let verified_materials = verified_materials
        .lock()
        .map_err(|_| setup_proof_error("verified setup proof material store is unavailable"))?;
    let mut matching_chunks = None;
    for (material_index, proof_material) in proof_materials.iter().enumerate() {
        let proof_material_path =
            format!("verifiedSetupProofMaterials.proofMaterials[{material_index}]");
        verify_verified_setup_proof_material_header(proof_material, &proof_material_path)?;
        if string_field_at(proof_material, "proofFamily", &proof_material_path)? != proof_family
            || string_field_at(proof_material, "proofMaterialRoot", &proof_material_path)?
                != expected_proof_material_root
        {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "verifiedSetupProofMaterials contains duplicate proof material handles for one proofMaterialRoot",
            ));
        }
        let handle_metadata =
            setup_proof_material_metadata_from_value(proof_material, &proof_material_path)?;
        compare_setup_proof_material_metadata(
            &handle_metadata,
            &expected_metadata,
            &proof_material_path,
        )?;
        let verification_id =
            setup_proof_material_verification_id_field(proof_material)?.to_string();
        let stored_material = verified_materials.get(&verification_id).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "verified setup proof material handle does not match a live stream-verified material",
            )
        })?;
        if stored_material.reference != *proof_material {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "verified setup proof material handle does not match the stream-verified metadata",
            ));
        }
        matching_chunks = Some(stored_material.chunks.as_ref().clone());
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verifiedSetupProofMaterials is missing the requested proofMaterialRoot",
        )
    })
}

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
        chunk_size_bytes,
        u64::try_from(chunks.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk count does not fit u64",
            )
        })?,
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

fn setup_proof_material_transport_stream_sessions()
-> &'static Mutex<BTreeMap<String, SetupProofMaterialTransportStreamSession>> {
    SETUP_PROOF_MATERIAL_TRANSPORT_STREAM_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn verified_setup_proof_materials() -> &'static Mutex<BTreeMap<String, VerifiedSetupProofMaterial>>
{
    VERIFIED_SETUP_PROOF_MATERIALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn read_setup_proof_material_transport_stream_header(
    value: &Value,
    object_path: &str,
) -> CanonicalResult<SetupProofMaterialTransportStreamHeader> {
    if value.get("chunks").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material stream header must not contain embedded chunks",
        ));
    }
    let proof_family = string_field_at(value, "proofFamily", object_path)?.to_string();
    validate_supported_setup_proof_transport_family(&proof_family, object_path)?;
    let proof_material_root = string_field_at(value, "proofMaterialRoot", object_path)?.to_string();
    validate_hash_string(
        &proof_material_root,
        &format!("{object_path}.proofMaterialRoot"),
    )?;
    let metadata = setup_proof_material_metadata_from_value(value, object_path)?;

    Ok(SetupProofMaterialTransportStreamHeader {
        proof_family,
        proof_material_root,
        metadata,
    })
}

fn setup_proof_material_metadata_from_value(
    value: &Value,
    object_path: &str,
) -> CanonicalResult<SetupProofMaterialMetadata> {
    let uses_prefixed_fields = [
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| value.get(*field_name).is_some());
    let uses_direct_fields = [
        "chunkSizeBytes",
        "chunkCount",
        "totalByteLength",
        "fullObjectHash",
        "chunkRoot",
        "chunkHashes",
    ]
    .iter()
    .any(|field_name| value.get(*field_name).is_some());
    if uses_prefixed_fields && uses_direct_fields {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path} must not mix direct and proof-prefixed chunk metadata"),
        ));
    }
    let (
        chunk_size_field,
        chunk_count_field,
        total_byte_length_field,
        full_object_hash_field,
        chunk_root_field,
        chunk_hashes_field,
    ) = if uses_prefixed_fields {
        (
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
        )
    } else {
        (
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkRoot",
            "chunkHashes",
        )
    };
    let chunk_size_bytes = u64_field_at(value, chunk_size_field, object_path)?;
    if chunk_size_bytes != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{object_path}.{chunk_size_field} must match the setup proof transport chunk size"
            ),
        ));
    }
    let chunk_count = usize::try_from(u64_field_at(value, chunk_count_field, object_path)?)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{object_path}.{chunk_count_field} does not fit usize"),
            )
        })?;
    if chunk_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_path}.{chunk_count_field} must be positive"),
        ));
    }
    let total_byte_length = u64_field_at(value, total_byte_length_field, object_path)?;
    if total_byte_length == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_path}.{total_byte_length_field} must be positive"),
        ));
    }
    let full_object_hash = string_field_at(value, full_object_hash_field, object_path)?.to_string();
    validate_hash_string(
        &full_object_hash,
        &format!("{object_path}.{full_object_hash_field}"),
    )?;
    let chunk_root = string_field_at(value, chunk_root_field, object_path)?.to_string();
    validate_hash_string(&chunk_root, &format!("{object_path}.{chunk_root_field}"))?;
    let chunk_hashes =
        setup_proof_material_hash_array(value, chunk_hashes_field, object_path, chunk_count)?;
    let expected_chunk_root = setup_proof_material_chunk_manifest_root(
        string_field_at(value, "proofFamily", object_path)?,
        chunk_size_bytes,
        u64::try_from(chunk_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk count does not fit u64",
            )
        })?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;
    if expected_chunk_root != chunk_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{object_path}.{chunk_root_field} does not match the canonical proof chunk manifest"
            ),
        ));
    }

    Ok(SetupProofMaterialMetadata {
        chunk_size_bytes,
        chunk_count,
        total_byte_length,
        full_object_hash,
        chunk_root,
        chunk_hashes,
    })
}

fn setup_proof_material_hash_array(
    value: &Value,
    field_name: &str,
    object_path: &str,
    expected_chunk_count: usize,
) -> CanonicalResult<Vec<String>> {
    let chunk_hash_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name} must list every proof material chunk hash"),
            )
        })?;
    if chunk_hash_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path}.{field_name} length must match the chunk count"),
        ));
    }
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name}[{chunk_index}] must be a hash string"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("{object_path}.{field_name}[{chunk_index}]"),
        )?;
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

fn absorb_setup_proof_material_transport_stream_chunk(
    session: &mut SetupProofMaterialTransportStreamSession,
    chunk_index: usize,
    chunk: Vec<u8>,
) -> CanonicalResult<Value> {
    if chunk_index != session.next_chunk_index {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material chunks must be absorbed in ascending chunk-index order",
        ));
    }
    if chunk_index >= session.header.metadata.chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material stream received more chunks than declared",
        ));
    }
    validate_setup_proof_material_transport_stream_chunk(
        chunk_index,
        &chunk,
        &session.header.metadata,
        session.observed_total_byte_length,
    )?;
    session.observed_total_byte_length = session
        .observed_total_byte_length
        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk length does not fit u64",
            )
        })?)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material byte length overflowed",
            )
        })?;
    session.chunks.push(chunk);
    session.next_chunk_index += 1;

    Ok(json!({
        "isValid": true,
        "operation": "absorbSetupProofMaterialTransportStreamChunk",
        "absorbedChunkIndex": chunk_index,
        "nextChunkIndex": session.next_chunk_index,
        "observedTotalByteLength": session.observed_total_byte_length,
    }))
}

fn validate_setup_proof_material_transport_stream_chunk(
    chunk_index: usize,
    chunk: &[u8],
    metadata: &SetupProofMaterialMetadata,
    observed_total_byte_length: u64,
) -> CanonicalResult<()> {
    if chunk.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunks must be non-empty",
        ));
    }
    let chunk_size = usize::try_from(metadata.chunk_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk size does not fit usize",
        )
    })?;
    if chunk.len() > chunk_size {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material chunk exceeds the accepted chunk size",
        ));
    }
    let is_final_chunk = chunk_index + 1 == metadata.chunk_count;
    if !is_final_chunk && chunk.len() != chunk_size {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material contains a short non-final chunk",
        ));
    }
    let new_total = observed_total_byte_length
        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material chunk length does not fit u64",
            )
        })?)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "setup proof material byte length overflowed",
            )
        })?;
    if new_total > metadata.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material stream chunk bytes exceed declared totalByteLength",
        ));
    }
    if is_final_chunk && new_total != metadata.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "final setup proof material chunk must finish at declared totalByteLength",
        ));
    }

    Ok(())
}

fn finish_setup_proof_material_transport_stream(
    verification_id: &str,
    session: SetupProofMaterialTransportStreamSession,
) -> CanonicalResult<Value> {
    if session.next_chunk_index != session.header.metadata.chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material stream is missing declared chunks",
        ));
    }
    if session.observed_total_byte_length != session.header.metadata.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup proof material stream totalByteLength does not match absorbed chunk bytes",
        ));
    }
    let transport_hashes = setup_proof_material_transport_hashes(
        &session.header.proof_family,
        &session.chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    let observed_metadata = SetupProofMaterialMetadata {
        chunk_size_bytes: SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        chunk_count: transport_hashes.chunk_hashes.len(),
        total_byte_length: transport_hashes.total_byte_length,
        full_object_hash: transport_hashes.full_object_hash.clone(),
        chunk_root: transport_hashes.chunk_root.clone(),
        chunk_hashes: transport_hashes.chunk_hashes.clone(),
    };
    compare_setup_proof_material_metadata(
        &observed_metadata,
        &session.header.metadata,
        "transportedSetupProofMaterial",
    )?;
    let verified_material_reference = verified_setup_proof_material_reference_value(
        verification_id,
        &session.header.proof_family,
        &session.header.proof_material_root,
        &transport_hashes,
    );
    verified_setup_proof_materials()
        .lock()
        .map_err(|_| setup_proof_error("verified setup proof material store is unavailable"))?
        .insert(
            verification_id.to_string(),
            VerifiedSetupProofMaterial {
                reference: verified_material_reference.clone(),
                chunks: Arc::new(session.chunks),
            },
        );

    Ok(json!({
        "isValid": true,
        "operation": "finishSetupProofMaterialTransportStream",
        "verificationId": verification_id,
        "proofFamily": session.header.proof_family,
        "proofMaterialRoot": session.header.proof_material_root,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "transport": {
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        },
        "verifiedSetupProofMaterial": verified_material_reference,
    }))
}

fn verified_setup_proof_material_reference_value(
    verification_id: &str,
    proof_family: &str,
    proof_material_root: &str,
    hashes: &SetupProofMaterialTransportHashes,
) -> Value {
    json!({
        "objectType": VERIFIED_SETUP_PROOF_MATERIAL_OBJECT_TYPE,
        "objectVersion": 1,
        "verificationId": verification_id,
        "proofFamily": proof_family,
        "proofMaterialRoot": proof_material_root,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofChunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "proofChunkCount": hashes.chunk_hashes.len(),
        "proofTotalByteLength": hashes.total_byte_length,
        "proofFullObjectHash": hashes.full_object_hash,
        "proofChunkRoot": hashes.chunk_root,
        "proofChunkHashes": hashes.chunk_hashes,
    })
}

fn verify_verified_setup_proof_material_set_header(value: &Value) -> CanonicalResult<()> {
    if !value.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verifiedSetupProofMaterials must be an object",
        ));
    }
    if value.get("objectType").and_then(Value::as_str)
        != Some(VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "verifiedSetupProofMaterials.objectType must be {VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE}"
            ),
        ));
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verifiedSetupProofMaterials.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_verified_setup_proof_material_header(
    value: &Value,
    object_path: &str,
) -> CanonicalResult<()> {
    if !value.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path} must be an object"),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", VERIFIED_SETUP_PROOF_MATERIAL_OBJECT_TYPE),
        ("proofBytesEncoding", SETUP_PROOF_MATERIAL_ENCODING),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("{object_path}.{field_name} must be {expected_value}"),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path}.objectVersion must be 1"),
        ));
    }
    setup_proof_material_verification_id_field(value)?;
    validate_supported_setup_proof_transport_family(
        string_field_at(value, "proofFamily", object_path)?,
        object_path,
    )?;
    validate_hash_string(
        string_field_at(value, "proofMaterialRoot", object_path)?,
        &format!("{object_path}.proofMaterialRoot"),
    )?;

    Ok(())
}

fn compare_setup_proof_material_metadata(
    observed: &SetupProofMaterialMetadata,
    expected: &SetupProofMaterialMetadata,
    object_path: &str,
) -> CanonicalResult<()> {
    if observed.chunk_size_bytes != expected.chunk_size_bytes
        || observed.chunk_count != expected.chunk_count
        || observed.total_byte_length != expected.total_byte_length
        || observed.full_object_hash != expected.full_object_hash
        || observed.chunk_root != expected.chunk_root
        || observed.chunk_hashes != expected.chunk_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!(
                "{object_path} metadata does not match the stream-verified setup proof material"
            ),
        ));
    }

    Ok(())
}

fn validate_supported_setup_proof_transport_family(
    proof_family: &str,
    object_path: &str,
) -> CanonicalResult<()> {
    if !SETUP_PROOF_TRANSPORT_FAMILIES.contains(&proof_family) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("{object_path}.proofFamily is not in the setup proof transport parameters"),
        ));
    }

    Ok(())
}

fn setup_proof_material_verification_id_field(value: &Value) -> CanonicalResult<&str> {
    let verification_id = string_field_at(value, "verificationId", "verificationId")?;
    if verification_id.is_empty()
        || verification_id.len() > SETUP_PROOF_MATERIAL_STREAM_ID_MAX_BYTES
        || !verification_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_:.".contains(character))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup proof material verificationId must be a short ASCII identifier",
        ));
    }

    Ok(verification_id)
}

fn object_field_at<'a>(
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

fn string_field_at<'a>(
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

fn u64_field_at(value: &Value, field_name: &str, object_path: &str) -> CanonicalResult<u64> {
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

fn usize_field_at(value: &Value, field_name: &str, object_path: &str) -> CanonicalResult<usize> {
    usize::try_from(u64_field_at(value, field_name, object_path)?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_path}.{field_name} does not fit usize"),
        )
    })
}

// Chunks are streamed unframed; the bound total length plus the enforced
// uniform chunk size make this concatenation unambiguous, so no per-chunk length
// prefix is needed.
fn setup_proof_material_full_object_hash(
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

fn setup_proof_material_chunk_hash(
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

fn setup_proof_material_chunk_manifest_root(
    proof_family: &str,
    chunk_size_bytes: u64,
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE,
        "objectVersion": 1,
        "proofFamily": proof_family,
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": full_object_hash,
    }))
}

fn append_bytes_to_hasher(hasher: &mut Shake256, value: &[u8]) -> CanonicalResult<()> {
    let mut encoded = Vec::new();
    append_bytes(&mut encoded, value);
    hasher.update(&encoded);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_proof_material_stream_handle_recovers_chunkless_material() {
        let proof_family = "same-secret-linkage-anchor";
        let proof_chunks = vec![b"bounded setup proof material".to_vec()];
        let transport_hashes = setup_proof_material_transport_hashes(
            proof_family,
            &proof_chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("setup proof material transport hashes");
        let proof_material_root = valid_hash_for_test('7');
        let transported_proof_material = json!({
            "objectType": "SetupTransportedSameSecretProofMaterial",
            "objectVersion": 1,
            "proofFamily": proof_family,
            "proofMaterialRoot": proof_material_root,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        });
        let verification_id = "same-secret-handle-test";

        begin_setup_proof_material_transport_stream_request(&json!({
            "verificationId": verification_id,
            "transportedSetupProofMaterial": transported_proof_material.clone(),
        }))
        .expect("begin setup proof material stream");
        absorb_setup_proof_material_transport_stream_chunk_request(&json!({
            "verificationId": verification_id,
            "chunkIndex": 0,
            "bytesHex": to_hex(&proof_chunks[0]),
        }))
        .expect("absorb setup proof material chunk");
        let finished = finish_setup_proof_material_transport_stream_request(&json!({
            "verificationId": verification_id,
        }))
        .expect("finish setup proof material stream");
        let verified_setup_proof_material = finished["verifiedSetupProofMaterial"].clone();
        let request = json!({
            "verifiedSetupProofMaterials": {
                "objectType": VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE,
                "objectVersion": 1,
                "proofMaterials": [
                    verified_setup_proof_material
                ],
            },
        });

        let recovered_chunks = verified_setup_proof_material_chunks_from_request(
            &request,
            proof_family,
            &proof_material_root,
            &transported_proof_material,
            "transportedSameSecretProofMaterial.proofMaterials[0]",
        )
        .expect("verified setup proof material chunks");

        assert_eq!(recovered_chunks, proof_chunks);
    }

    #[test]
    fn setup_proof_material_stream_handle_rejects_metadata_rebinding() {
        let proof_family = "public-key-share";
        let proof_chunks = vec![b"public-key proof bytes".to_vec()];
        let transport_hashes = setup_proof_material_transport_hashes(
            proof_family,
            &proof_chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("setup proof material transport hashes");
        let proof_material_root = valid_hash_for_test('8');
        let mut transported_proof_material = json!({
            "objectType": "SetupTransportedPublicKeyShareProofMaterial",
            "objectVersion": 1,
            "proofFamily": proof_family,
            "proofMaterialRoot": proof_material_root,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        });
        let verification_id = "public-key-handle-rebinding-test";

        begin_setup_proof_material_transport_stream_request(&json!({
            "verificationId": verification_id,
            "transportedSetupProofMaterial": transported_proof_material.clone(),
        }))
        .expect("begin setup proof material stream");
        absorb_setup_proof_material_transport_stream_chunk_request(&json!({
            "verificationId": verification_id,
            "chunkIndex": 0,
            "bytesHex": to_hex(&proof_chunks[0]),
        }))
        .expect("absorb setup proof material chunk");
        let finished = finish_setup_proof_material_transport_stream_request(&json!({
            "verificationId": verification_id,
        }))
        .expect("finish setup proof material stream");
        let request = json!({
            "verifiedSetupProofMaterials": {
                "objectType": VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE,
                "objectVersion": 1,
                "proofMaterials": [
                    finished["verifiedSetupProofMaterial"].clone()
                ],
            },
        });
        transported_proof_material["fullObjectHash"] = json!(valid_hash_for_test('9'));

        let error = verified_setup_proof_material_chunks_from_request(
            &request,
            proof_family,
            &proof_material_root,
            &transported_proof_material,
            "transportedPublicKeyShareProofMaterial.proofMaterials[0]",
        )
        .expect_err("rebinding must fail");

        assert!(
            error
                .message
                .contains("does not match the canonical proof chunk manifest")
                || error
                    .message
                    .contains("metadata does not match the stream-verified setup proof material"),
            "unexpected error: {}",
            error.message
        );
    }

    fn valid_hash_for_test(character: char) -> String {
        character.to_string().repeat(128)
    }
}
