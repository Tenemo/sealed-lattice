use super::*;

// Parameters for the same-secret bridge proof-material transport. Proof bytes
// can be carried inline or through the setup transport, while the resolved
// bytes remain bound to the bridge proof record and its canonical hashes.
pub(super) struct TransportFamily {
    pub(super) proof_family: &'static str,
    pub(super) transport_field: &'static str,
    pub(super) set_object_type: &'static str,
    pub(super) material_object_type: &'static str,
    pub(super) family_prose: &'static str,
}

// Resolve material already authenticated by the canonical binary stream. The
// JSON object is a semantic reference only and must never carry proof bytes.
pub(super) fn resolve_transported_proof_material(
    request: &Value,
    expected_proof_material_root: &str,
    family: &TransportFamily,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let material_set = value_at_path(request, &[family.transport_field]).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "{} is required by transported {} proof records",
                family.transport_field, family.family_prose
            ),
        )
    })?;
    verify_transported_material_set_header(material_set, family)?;
    let proof_materials = array_at_path(material_set, &["proofMaterials"])?;
    let mut matching_binding = None;
    for proof_material in proof_materials.iter() {
        verify_transported_material_header(proof_material, family)?;
        let proof_material_root = hash_at_path(proof_material, &["proofMaterialRoot"])?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!(
                    "{} contains duplicate proofMaterialRoot entries",
                    family.transport_field
                ),
            ));
        }
        let proof_bytes = verified_setup_proof_material_bytes_from_request(
            request,
            family.proof_family,
            expected_proof_material_root,
            proof_material,
            &format!("{}.proofMaterials", family.transport_field),
        )?;
        matching_binding = Some(proof_bytes);
    }

    matching_binding.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "{} is missing the requested proofMaterialRoot",
                family.transport_field
            ),
        )
    })
}

fn verify_transported_material_set_header(
    value: &Value,
    family: &TransportFamily,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", family.set_object_type),
        ("proofFamily", family.proof_family),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("{}.{field_name}", family.transport_field),
        )?;
    }
    Ok(())
}

fn verify_transported_material_header(
    value: &Value,
    family: &TransportFamily,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", family.material_object_type),
        ("proofFamily", family.proof_family),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!(
                "transported {} proof material {field_name}",
                family.family_prose
            ),
        )?;
    }
    hash_at_path(value, &["proofMaterialRoot"])?;

    Ok(())
}
