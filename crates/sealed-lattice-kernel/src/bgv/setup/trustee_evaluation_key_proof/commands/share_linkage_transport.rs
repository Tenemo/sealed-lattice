use super::decoding::*;
use super::share_linkage_verification::*;
use super::*;

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
    if proof_record.get("proofBytesBase64").is_some() {
        return Err(invalid_succinct_setup_proof(
            "share-linkage proof requires canonical streamed proof material",
        ));
    }

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

pub(super) fn transported_vss_share_linkage_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<VssShareLinkageProofTransportBinding> {
    let material_set = request
        .get("transportedVssShareLinkageProofMaterial")
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "transportedVssShareLinkageProofMaterial is required by transported share-linkage proof records",
            )
        })?;
    verify_transported_vss_share_linkage_proof_material_set_header(material_set)?;
    let proof_materials = material_set
        .get("proofMaterials")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "transportedVssShareLinkageProofMaterial.proofMaterials must be an array",
            )
        })?;
    let mut matching_binding = None;
    for proof_material in proof_materials {
        verify_transported_vss_share_linkage_proof_material_header(proof_material)?;
        let proof_material_root = read_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(invalid_succinct_setup_proof(
                "transportedVssShareLinkageProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        if proof_material.get("chunks").is_some() {
            return Err(invalid_succinct_setup_proof(
                "share-linkage proof material must arrive through the canonical binary stream",
            ));
        }
        let proof_bytes = verified_setup_proof_material_bytes_from_request(
            request,
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            expected_proof_material_root,
            proof_material,
            "transportedVssShareLinkageProofMaterial.proofMaterials",
        )?;
        let proof_bytes_hash = hash512_hex(
            VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes[..]],
        );
        compare_string_value(
            expected_proof_material_root,
            &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
                VSS_SHARE_LINKAGE_PROOF_FAMILY,
                &proof_bytes_hash,
            )?,
            "share-linkage proof material root",
        )?;
        matching_binding = Some(VssShareLinkageProofTransportBinding {
            proof_bytes,
            proof_bytes_hash,
        });
    }

    matching_binding.ok_or_else(|| {
        invalid_succinct_setup_proof(
            "transportedVssShareLinkageProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

pub(super) fn verify_transported_vss_share_linkage_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE),
        ("proofFamily", VSS_SHARE_LINKAGE_PROOF_FAMILY),
    ] {
        compare_string_value(
            read_string(value, field_name)?,
            expected_value,
            &format!("transportedVssShareLinkageProofMaterial.{field_name}"),
        )?;
    }
    Ok(())
}

pub(super) fn verify_transported_vss_share_linkage_proof_material_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", VSS_SHARE_LINKAGE_PROOF_FAMILY),
    ] {
        compare_string_value(
            read_string(value, field_name)?,
            expected_value,
            &format!("transported share-linkage proof material {field_name}"),
        )?;
    }
    read_string(value, "proofMaterialRoot")?;

    Ok(())
}
