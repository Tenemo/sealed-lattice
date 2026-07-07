use super::transport_common::*;
use super::*;

// Resolved same-secret bridge proof bytes plus the canonical proof
// record whose root binds them. The embedded form carries the proof bytes as
// base64 inside the record; the transported form streams the bytes through the
// shared setup proof-material transport and binds the transport reference into
// the record root instead of the base64 bytes.
pub(super) struct ResolvedSameSecretBridgeProofBytes {
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

pub(super) fn resolve_same_secret_bridge_proof_bytes(
    proof_record: &Value,
    request: &Value,
    bridge_statement_root: &str,
) -> CanonicalResult<ResolvedSameSecretBridgeProofBytes> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    let proof_record_root = hash_at_path(proof_record, &["proofRecordRoot"])?.to_string();
    if proof_record.get("proofBytesBase64").is_some() {
        if proof_record.get("proofBytesEncoding").is_some()
            || same_secret_bridge_proof_has_transport_reference(proof_record)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge proof record must not mix embedded proofBytesBase64 with transported proof material",
            ));
        }
        let proof_bytes_base64 = string_at_path(proof_record, &["proofBytesBase64"])?;
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_bytes_base64,
            "same-secret bridge proofBytesBase64",
        )?;
        let expected_proof_bytes_hash =
            hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        compare_required_string(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "same-secret bridge proof record proofBytesHash",
        )?;
        let proof_record_without_root = json!({
            "objectType": "VssSameSecretBridgeProofRecord",
            "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "sameSecretBridgeStatementRoot": bridge_statement_root,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesBase64": proof_bytes_base64,
        });
        let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
        if expected_proof_record_root != proof_record_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge proof record root does not match its bound proof bytes",
            ));
        }

        return Ok(ResolvedSameSecretBridgeProofBytes {
            proof_bytes,
            proof_record_without_root,
            proof_record_root,
        });
    }

    compare_required_string(
        string_at_path(proof_record, &["proofBytesEncoding"])?,
        SETUP_PROOF_MATERIAL_ENCODING,
        "same-secret bridge proof record proofBytesEncoding",
    )?;
    let proof_material_root = hash_at_path(proof_record, &["proofMaterialRoot"])?;
    let transported_binding =
        transported_same_secret_bridge_proof_material_binding(request, proof_material_root)?;
    verify_same_secret_bridge_proof_transport_reference(
        proof_record,
        &transported_binding.transport_hashes,
    )?;
    compare_required_string(
        proof_bytes_hash,
        &transported_binding.proof_bytes_hash,
        "same-secret bridge proof record proofBytesHash",
    )?;
    let proof_record_without_root = json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementRoot": bridge_statement_root,
        "proofBytesHash": proof_bytes_hash,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_material_root,
        "proofChunkCount": transported_binding.transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transported_binding.transport_hashes.total_byte_length,
        "proofFullObjectHash": transported_binding.transport_hashes.full_object_hash,
        "proofChunkRoot": transported_binding.transport_hashes.chunk_root,
        "proofChunkHashes": transported_binding.transport_hashes.chunk_hashes,
    });
    let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    if expected_proof_record_root != proof_record_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret bridge proof record root does not match its transported proof material",
        ));
    }

    Ok(ResolvedSameSecretBridgeProofBytes {
        proof_bytes: transported_binding.proof_bytes,
        proof_record_without_root,
        proof_record_root,
    })
}

pub(super) struct SameSecretBridgeProofTransportBinding {
    pub(super) transport_hashes: SetupProofMaterialTransportHashes,
    pub(super) proof_bytes: Vec<u8>,
    pub(super) proof_bytes_hash: String,
}

const SAME_SECRET_BRIDGE_TRANSPORT_FAMILY: TransportFamily = TransportFamily {
    proof_family: SAME_SECRET_BRIDGE_PROOF_FAMILY,
    transport_field: "transportedSameSecretBridgeProofMaterial",
    set_object_type: SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE,
    material_object_type: SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE,
    family_prose: "same-secret bridge",
};

pub(super) fn transported_same_secret_bridge_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SameSecretBridgeProofTransportBinding> {
    let (transport_hashes, chunks) = resolve_transported_proof_material(
        request,
        expected_proof_material_root,
        &SAME_SECRET_BRIDGE_TRANSPORT_FAMILY,
    )?;
    let proof_bytes = chunks.iter().flatten().copied().collect::<Vec<u8>>();
    let proof_bytes_hash = hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
    Ok(SameSecretBridgeProofTransportBinding {
        transport_hashes,
        proof_bytes,
        proof_bytes_hash,
    })
}

pub(super) fn verify_same_secret_bridge_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    verify_proof_transport_reference(
        proof_record,
        transport_hashes,
        &SAME_SECRET_BRIDGE_TRANSPORT_FAMILY,
    )
}

pub(super) fn same_secret_bridge_proof_has_transport_reference(proof_record: &Value) -> bool {
    proof_has_transport_reference(proof_record)
}
