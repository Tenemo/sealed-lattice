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
    // The absorbed proof bytes accumulate into one contiguous buffer. The bound
    // total length plus the enforced uniform chunk size make the concatenation
    // unambiguous, so the canonical chunk windows are recovered on demand with
    // `chunks(chunk_size)` and never stored per-chunk.
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct VerifiedSetupProofMaterial {
    reference: Value,
    proof_bytes: SetupProofMaterialBytes,
}

pub(in crate::bgv::setup) type SetupProofMaterialBytes = Arc<Vec<u8>>;

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
            // Grow the buffer only as bytes are actually absorbed, so a hostile
            // `begin` declaring a gigantic totalByteLength cannot reserve it up
            // front.
            bytes: Vec::new(),
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

pub(in crate::bgv::setup) fn verified_setup_proof_material_bytes_from_request(
    request: &Value,
    proof_family: &str,
    expected_proof_material_root: &str,
    transported_proof_material: &Value,
    transported_material_path: &str,
) -> CanonicalResult<SetupProofMaterialBytes> {
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
    let mut matching_bytes = None;
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
        if matching_bytes.is_some() {
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
        matching_bytes = Some(Arc::clone(&stored_material.proof_bytes));
    }

    matching_bytes.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verifiedSetupProofMaterials is missing the requested proofMaterialRoot",
        )
    })
}

// Collect the verificationId of every verified setup proof material handle a
// request references. Best-effort: a malformed entry contributes no id, because
// verification already rejects malformed handles and this guard is a lifecycle
// mechanism, not a validator.
fn request_verified_setup_proof_material_verification_ids(request: &Value) -> Vec<String> {
    request
        .get("verifiedSetupProofMaterials")
        .and_then(|material_set| material_set.get("proofMaterials"))
        .and_then(Value::as_array)
        .map(|proof_materials| {
            proof_materials
                .iter()
                .filter_map(|proof_material| {
                    proof_material
                        .get("verificationId")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

// Drop the verified setup proof material entries a completed verification
// consumed, so the process-global store does not retain them. The verifier reads
// each entry a few times (share-linkage, the same-secret bridge, public-key
// shares, and the evaluation-key proof checks), so eviction happens
// once, after verify returns, rather than on first read. Absent ids are skipped,
// so eviction is idempotent. Without it the store would grow with every verified
// package on the wasm runtime, whose linear memory never returns to the OS.
fn evict_verified_setup_proof_materials(verification_ids: &[String]) {
    let Ok(mut verified_materials) = verified_setup_proof_materials().lock() else {
        return;
    };
    for verification_id in verification_ids {
        verified_materials.remove(verification_id);
    }
}

// RAII guard that evicts a verification's stream-verified setup proof material
// from the process-global store when verify returns by any path (acceptance,
// refusal, pending-with-missing-objects, or error), scoped to the request's own
// verificationIds. Mirrors `VerifiedComponentMaterialEvictionGuard`.
pub(in crate::bgv::setup) struct VerifiedSetupProofMaterialEvictionGuard {
    verification_ids: Vec<String>,
}

impl VerifiedSetupProofMaterialEvictionGuard {
    pub(in crate::bgv::setup) fn for_request(request: &Value) -> Self {
        Self {
            verification_ids: request_verified_setup_proof_material_verification_ids(request),
        }
    }
}

impl Drop for VerifiedSetupProofMaterialEvictionGuard {
    fn drop(&mut self) {
        evict_verified_setup_proof_materials(&self.verification_ids);
    }
}

mod helpers;
mod stream_session;
mod verification;

use helpers::*;
use stream_session::*;

pub(crate) use verification::setup_proof_material_transport_hashes;
pub(in crate::bgv::setup) use verification::{
    setup_proof_record_has_transport_reference, transported_setup_proof_material_bytes,
    verify_setup_proof_record_transport_reference, verify_transported_setup_proof_material_hashes,
};

#[cfg(test)]
mod tests;
