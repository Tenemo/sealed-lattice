use super::*;

// Resolved same-secret bridge proof bytes plus the canonical proof record whose
// root binds the canonical stream reference.
pub(super) struct ResolvedSameSecretBridgeProofBytes {
    pub(super) proof_bytes: SetupProofMaterialBytes,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

#[derive(Debug)]
pub(super) struct ValidatedSameSecretBridgeProofReference {
    pub(super) proof_bytes_hash: String,
    pub(super) proof_material_root: String,
    pub(super) proof_record_without_root: Value,
    pub(super) proof_record_root: String,
}

pub(super) fn validate_same_secret_bridge_proof_reference(
    proof_record: &Value,
    bridge_statement_root: &str,
) -> CanonicalResult<ValidatedSameSecretBridgeProofReference> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?.to_string();
    let proof_record_root =
        hash_at_path(proof_record, &["sameSecretBridgeProofRecordRoot"])?.to_string();
    compare_required_string(
        string_at_path(proof_record, &["proofBytesEncoding"])?,
        SETUP_PROOF_MATERIAL_ENCODING,
        "same-secret bridge proof record proofBytesEncoding",
    )?;
    let proof_material_root = hash_at_path(proof_record, &["proofMaterialRoot"])?.to_string();
    compare_required_string(
        &proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "same-secret bridge proof material root",
    )?;
    let proof_record_without_root = json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementRoot": bridge_statement_root,
        "proofBytesHash": &proof_bytes_hash,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": &proof_material_root,
    });
    let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    if expected_proof_record_root != proof_record_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret bridge proof record root does not match its transported proof material",
        ));
    }

    Ok(ValidatedSameSecretBridgeProofReference {
        proof_bytes_hash,
        proof_material_root,
        proof_record_without_root,
        proof_record_root,
    })
}

pub(super) fn resolve_same_secret_bridge_proof_bytes(
    reference: ValidatedSameSecretBridgeProofReference,
    request: &Value,
) -> CanonicalResult<ResolvedSameSecretBridgeProofBytes> {
    let transported_binding = transported_same_secret_bridge_proof_material_binding(
        request,
        &reference.proof_material_root,
    )?;
    compare_required_string(
        &reference.proof_bytes_hash,
        &transported_binding.proof_bytes_hash,
        "same-secret bridge proof record proofBytesHash",
    )?;

    Ok(ResolvedSameSecretBridgeProofBytes {
        proof_bytes: transported_binding.proof_bytes,
        proof_record_without_root: reference.proof_record_without_root,
        proof_record_root: reference.proof_record_root,
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

pub(super) fn validate_transported_same_secret_bridge_proof_material_reference(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<()> {
    let material_set = value_at_path(request, &[SAME_SECRET_BRIDGE_TRANSPORT_FAMILY.transport_field])
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretBridgeProofMaterial is required by transported same-secret bridge proof records",
            )
        })?;
    for (field_name, expected_value) in [
        (
            "objectType",
            SAME_SECRET_BRIDGE_TRANSPORT_FAMILY.set_object_type,
        ),
        ("proofFamily", SAME_SECRET_BRIDGE_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(material_set, &[field_name])?,
            expected_value,
            &format!("transportedSameSecretBridgeProofMaterial.{field_name}"),
        )?;
    }

    let mut matching_material_count = 0_usize;
    for proof_material in array_at_path(material_set, &["proofMaterials"])? {
        for (field_name, expected_value) in [
            (
                "objectType",
                SAME_SECRET_BRIDGE_TRANSPORT_FAMILY.material_object_type,
            ),
            ("proofFamily", SAME_SECRET_BRIDGE_PROOF_FAMILY),
        ] {
            compare_required_string(
                string_at_path(proof_material, &[field_name])?,
                expected_value,
                &format!("transported same-secret bridge proof material {field_name}"),
            )?;
        }
        if hash_at_path(proof_material, &["proofMaterialRoot"])? == expected_proof_material_root {
            matching_material_count += 1;
        }
    }
    match matching_material_count {
        1 => Ok(()),
        0 => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transportedSameSecretBridgeProofMaterial is missing the requested proofMaterialRoot",
        )),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transportedSameSecretBridgeProofMaterial contains duplicate proofMaterialRoot entries",
        )),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn transported_material(proof_material_root: &str) -> Value {
        json!({
            "objectType": SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE,
            "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "proofMaterialRoot": proof_material_root,
        })
    }

    fn transport_request(proof_materials: Vec<Value>) -> Value {
        json!({
            "transportedSameSecretBridgeProofMaterial": {
                "objectType": SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE,
                "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
                "proofMaterials": proof_materials,
            },
        })
    }

    #[test]
    fn transported_bridge_reference_requires_one_exact_material_root() {
        let requested_root = "1".repeat(128);
        let other_root = "2".repeat(128);
        validate_transported_same_secret_bridge_proof_material_reference(
            &transport_request(vec![
                transported_material(&other_root),
                transported_material(&requested_root),
            ]),
            &requested_root,
        )
        .expect("one exact transported bridge proof reference is accepted");

        let missing_error = validate_transported_same_secret_bridge_proof_material_reference(
            &transport_request(vec![transported_material(&other_root)]),
            &requested_root,
        )
        .expect_err("a missing bridge proof reference must be rejected");
        assert_eq!(missing_error.code, CanonicalErrorCode::ComponentMismatch);
        assert!(missing_error.message.contains("missing"));

        let duplicate_error = validate_transported_same_secret_bridge_proof_material_reference(
            &transport_request(vec![
                transported_material(&requested_root),
                transported_material(&requested_root),
            ]),
            &requested_root,
        )
        .expect_err("duplicate bridge proof references must be rejected");
        assert_eq!(duplicate_error.code, CanonicalErrorCode::ComponentMismatch);
        assert!(duplicate_error.message.contains("duplicate"));
    }

    #[test]
    fn bridge_proof_record_binds_hash_encoding_material_root_and_statement() {
        let proof_bytes_hash = "3".repeat(128);
        let proof_material_root =
            crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
                SAME_SECRET_BRIDGE_PROOF_FAMILY,
                &proof_bytes_hash,
            )
            .expect("same-secret bridge proof material root");
        let bridge_statement_root = "4".repeat(128);
        let mut proof_record = json!({
            "objectType": "VssSameSecretBridgeProofRecord",
            "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "sameSecretBridgeStatementRoot": &bridge_statement_root,
            "proofBytesHash": &proof_bytes_hash,
            "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
            "proofMaterialRoot": &proof_material_root,
        });
        proof_record["sameSecretBridgeProofRecordRoot"] = json!(
            derive_canonical_object_hash(&proof_record)
                .expect("same-secret bridge proof record root")
        );
        let validated =
            validate_same_secret_bridge_proof_reference(&proof_record, &bridge_statement_root)
                .expect("fully bound same-secret bridge proof reference is accepted");
        assert_eq!(validated.proof_bytes_hash, proof_bytes_hash);
        assert_eq!(validated.proof_material_root, proof_material_root);

        let wrong_statement_root = "5".repeat(128);
        let wrong_statement_error =
            validate_same_secret_bridge_proof_reference(&proof_record, &wrong_statement_root)
                .expect_err("a proof record rebound to another statement must be rejected");
        assert_eq!(
            wrong_statement_error.code,
            CanonicalErrorCode::ComponentMismatch
        );

        let mut wrong_material_record = proof_record;
        wrong_material_record["proofMaterialRoot"] = json!("6".repeat(128));
        let wrong_material_error = validate_same_secret_bridge_proof_reference(
            &wrong_material_record,
            &bridge_statement_root,
        )
        .expect_err("a proof record with a non-derived material root must be rejected");
        assert_eq!(
            wrong_material_error.code,
            CanonicalErrorCode::ComponentMismatch
        );
    }
}
