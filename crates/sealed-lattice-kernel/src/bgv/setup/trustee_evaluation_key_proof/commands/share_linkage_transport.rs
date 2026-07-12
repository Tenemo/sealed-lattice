use super::decoding::*;
use super::share_linkage_verification::*;
use super::*;
use crate::bgv::setup_helpers::compare_required_string;

// Resolved share-linkage proof bytes plus the canonical proof record whose root
// binds the canonical stream reference.
pub(super) struct ResolvedVssShareLinkageProofBytes {
    pub(super) proof_bytes: SetupProofMaterialBytes,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

pub(super) fn resolve_vss_share_linkage_proof_bytes(
    proof_record: &Value,
    request: &Value,
    coverage: &[Value],
    vss_share_linkage: &Value,
) -> CanonicalResult<ResolvedVssShareLinkageProofBytes> {
    let proof_bytes_hash = read_string(proof_record, "proofBytesHash")?;
    let proof_record_root = read_string(proof_record, "proofRecordRoot")?.to_string();
    compare_string_value(
        read_string(proof_record, "proofBytesEncoding")?,
        SETUP_PROOF_MATERIAL_ENCODING,
        "share-linkage proof record proofBytesEncoding",
    )?;
    let proof_material_root = read_string(proof_record, "proofMaterialRoot")?;
    let transported_binding =
        transported_vss_share_linkage_proof_material_binding(request, proof_material_root)?;
    compare_string_value(
        proof_bytes_hash,
        &transported_binding.proof_bytes_hash,
        "share-linkage proof record proofBytesHash",
    )?;
    let proof_record_without_root = json!({
        "objectType": "VssShareLinkageProofRecord",
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "linkageItems": coverage,
        "vssShareLinkage": vss_share_linkage,
        "proofBytesHash": proof_bytes_hash,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_material_root,
    });
    let expected_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    compare_string_value(
        &proof_record_root,
        &expected_record_root,
        "share-linkage proof record proofRecordRoot",
    )?;

    Ok(ResolvedVssShareLinkageProofBytes {
        proof_bytes: transported_binding.proof_bytes,
        proof_record_without_root,
        proof_record_root,
    })
}

pub(super) struct VssShareLinkageProofTransportBinding {
    pub(super) proof_bytes: SetupProofMaterialBytes,
    pub(super) proof_bytes_hash: String,
}

const VSS_SHARE_LINKAGE_TRANSPORT_FAMILY: SetupProofMaterialTransportFamily =
    SetupProofMaterialTransportFamily {
        proof_family: VSS_SHARE_LINKAGE_PROOF_FAMILY,
        transport_field: "transportedVssShareLinkageProofMaterial",
        set_object_type: VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE,
        material_object_type: VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE,
        family_description: "share-linkage",
    };

pub(super) fn transported_vss_share_linkage_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<VssShareLinkageProofTransportBinding> {
    let proof_bytes = resolve_transported_setup_proof_material(
        request,
        expected_proof_material_root,
        &VSS_SHARE_LINKAGE_TRANSPORT_FAMILY,
    )?;
    let proof_bytes_hash = proof_bytes.hash512_hex(VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_required_string(
        expected_proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "share-linkage proof material root",
    )?;
    Ok(VssShareLinkageProofTransportBinding {
        proof_bytes,
        proof_bytes_hash,
    })
}

pub(in crate::bgv::setup) fn verified_vss_share_linkage_proof_material_bytes(
    request: &Value,
    proof_material_root: &str,
    expected_proof_bytes_hash: &str,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let binding =
        transported_vss_share_linkage_proof_material_binding(request, proof_material_root)?;
    compare_string_value(
        &binding.proof_bytes_hash,
        expected_proof_bytes_hash,
        "VSS share-linkage proof bytes hash",
    )?;

    Ok(binding.proof_bytes)
}
