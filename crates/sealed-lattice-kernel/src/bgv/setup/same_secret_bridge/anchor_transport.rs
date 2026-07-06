use super::transport_common::*;
use super::*;

const ANCHOR_FAMILY: TransportFamily = TransportFamily {
    proof_family: SAME_SECRET_PROOF_FAMILY,
    transport_field: "transportedSameSecretProofMaterial",
    set_object_type: SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE,
    material_object_type: SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE,
    family_prose: "same-secret",
};

pub(super) struct SameSecretProofTransportBinding {
    pub(super) transport_hashes: SetupProofMaterialTransportHashes,
    pub(super) proof_bytes_hash: String,
}

pub(super) fn transported_same_secret_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SameSecretProofTransportBinding> {
    let (transport_hashes, chunks) =
        resolve_transported_proof_material(request, expected_proof_material_root, &ANCHOR_FAMILY)?;
    let chunk_slices = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(SameSecretProofTransportBinding {
        transport_hashes,
        proof_bytes_hash: hash512_hex(SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN, &chunk_slices),
    })
}

pub(super) fn verify_same_secret_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    verify_proof_transport_reference(proof_record, transport_hashes, &ANCHOR_FAMILY)
}

pub(super) fn same_secret_anchor_proof_material_root(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SameSecretLinkageAnchorProofMaterialReference",
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "trusteeIdentity": string_at_path(proof_record, &["trusteeIdentity"])?,
        "trusteeRosterPosition": unsigned_at_path(proof_record, &["trusteeRosterPosition"])?,
        "statementHash": hash_at_path(proof_record, &["statementHash"])?,
        "proofSizeBytes": unsigned_at_path(proof_record, &["proofSizeBytes"])?,
        "proofBytesHash": hash_at_path(proof_record, &["proofBytesHash"])?,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
}

pub(super) fn same_secret_proof_has_transport_reference(proof_record: &Value) -> bool {
    proof_has_transport_reference(proof_record)
}
