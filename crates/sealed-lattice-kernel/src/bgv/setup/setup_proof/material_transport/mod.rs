use super::*;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

use crate::transcript_core::decode_hex;

const VERIFIED_SETUP_PROOF_MATERIAL_SET_OBJECT_TYPE: &str = "VerifiedSetupProofMaterialSet";
const VERIFIED_SETUP_PROOF_MATERIAL_OBJECT_TYPE: &str = "VerifiedSetupProofMaterial";
const SETUP_PROOF_MATERIAL_STREAM_ID_MAX_BYTES: usize = 128;
const SETUP_PROOF_RECORD_TRANSPORT_REFERENCE_FIELDS: &[&str] = &[
    "proofBytesEncoding",
    "proofMaterialRoot",
    "proofChunkCount",
    "proofTotalByteLength",
    "proofFullObjectHash",
    "proofChunkRoot",
    "proofChunkHashes",
];

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
    chunks: SetupProofMaterialChunks,
}

pub(in crate::bgv::setup) type SetupProofMaterialChunks = Arc<Vec<Vec<u8>>>;

pub(in crate::bgv::setup) fn setup_proof_record_binding_value(
    setup_parameters_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProofRecordBinding",
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
        "operation": "beginSetupProofMaterialTransportStream",
        "verificationId": verification_id,
        "proofFamily": header.proof_family,
        "proofMaterialRoot": header.proof_material_root,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "transport": {
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
) -> CanonicalResult<SetupProofMaterialChunks> {
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
        matching_chunks = Some(Arc::clone(&stored_material.chunks));
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verifiedSetupProofMaterials is missing the requested proofMaterialRoot",
        )
    })
}

mod helpers;
mod stream_session;
mod verification;

use helpers::*;
use stream_session::*;

pub(crate) use verification::setup_proof_material_transport_hashes;
pub(in crate::bgv::setup) use verification::{
    setup_proof_record_has_transport_reference, transported_setup_proof_material_chunks,
    verify_setup_proof_record_transport_reference, verify_transported_setup_proof_material_hashes,
};

#[cfg(test)]
mod tests;
