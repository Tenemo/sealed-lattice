use super::*;

// Resolved same-secret bridge proof bytes plus the canonical proof record whose
// root binds the canonical stream reference.
pub(super) struct ResolvedSameSecretBridgeProofBytes {
    pub(super) proof_bytes: SetupProofMaterialBytes,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

pub(super) fn resolve_same_secret_bridge_proof_bytes(
    proof_record: &Value,
    request: &Value,
    bridge_statement_root: &str,
) -> CanonicalResult<ResolvedSameSecretBridgeProofBytes> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    let proof_record_root =
        hash_at_path(proof_record, &["sameSecretBridgeProofRecordRoot"])?.to_string();
    compare_required_string(
        string_at_path(proof_record, &["proofBytesEncoding"])?,
        SETUP_PROOF_MATERIAL_ENCODING,
        "same-secret bridge proof record proofBytesEncoding",
    )?;
    let proof_material_root = hash_at_path(proof_record, &["proofMaterialRoot"])?;
    let transported_binding =
        transported_same_secret_bridge_proof_material_binding(request, proof_material_root)?;
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
    pub(super) proof_bytes: SetupProofMaterialBytes,
    pub(super) proof_bytes_hash: String,
}

const SAME_SECRET_BRIDGE_TRANSPORT_FAMILY: SetupProofMaterialTransportFamily =
    SetupProofMaterialTransportFamily {
        proof_family: SAME_SECRET_BRIDGE_PROOF_FAMILY,
        transport_field: "transportedSameSecretBridgeProofMaterial",
        set_object_type: SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE,
        material_object_type: SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE,
        family_description: "same-secret bridge",
    };

pub(super) fn transported_same_secret_bridge_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SameSecretBridgeProofTransportBinding> {
    let proof_bytes = resolve_transported_setup_proof_material(
        request,
        expected_proof_material_root,
        &SAME_SECRET_BRIDGE_TRANSPORT_FAMILY,
    )?;
    let proof_bytes_hash = proof_bytes.hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_required_string(
        expected_proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "same-secret bridge proof material root",
    )?;
    Ok(SameSecretBridgeProofTransportBinding {
        proof_bytes,
        proof_bytes_hash,
    })
}
