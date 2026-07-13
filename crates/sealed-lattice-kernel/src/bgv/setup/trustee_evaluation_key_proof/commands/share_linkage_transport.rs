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

pub(super) struct ValidatedVssShareLinkageProofReference {
    pub(super) proof_bytes_hash: String,
    pub(super) proof_material_root: String,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

pub(super) fn validate_vss_share_linkage_proof_reference(
    proof_record: &Value,
    vss_share_linkage: &Value,
) -> CanonicalResult<ValidatedVssShareLinkageProofReference> {
    let proof_bytes_hash = read_string(proof_record, "proofBytesHash")?.to_string();
    let proof_record_root = read_string(proof_record, "proofRecordRoot")?.to_string();
    let proof_material_root = read_string(proof_record, "proofMaterialRoot")?.to_string();
    compare_string_value(
        &proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "share-linkage proof material root",
    )?;
    let proof_record_without_root = json!({
        "objectType": "VssShareLinkageProofRecord",
        "vssShareLinkage": vss_share_linkage,
        "proofBytesHash": &proof_bytes_hash,
        "proofMaterialRoot": &proof_material_root,
    });
    let expected_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    compare_string_value(
        &proof_record_root,
        &expected_record_root,
        "share-linkage proof record proofRecordRoot",
    )?;

    Ok(ValidatedVssShareLinkageProofReference {
        proof_bytes_hash,
        proof_material_root,
        proof_record_without_root,
        proof_record_root,
    })
}

pub(super) fn resolve_vss_share_linkage_proof_bytes(
    reference: ValidatedVssShareLinkageProofReference,
    request: &Value,
) -> CanonicalResult<ResolvedVssShareLinkageProofBytes> {
    let transported_binding = transported_vss_share_linkage_proof_material_binding(
        request,
        &reference.proof_material_root,
    )?;
    compare_string_value(
        &reference.proof_bytes_hash,
        &transported_binding.proof_bytes_hash,
        "share-linkage proof record proofBytesHash",
    )?;

    Ok(ResolvedVssShareLinkageProofBytes {
        proof_bytes: transported_binding.proof_bytes,
        proof_record_without_root: reference.proof_record_without_root,
        proof_record_root: reference.proof_record_root,
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
