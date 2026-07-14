use super::*;

use crate::bgv::setup::setup_proof::take_verified_setup_proof_material_bytes;

#[derive(Debug)]
pub(super) struct ValidatedSameSecretBridgeProofReference {
    pub(super) proof_bytes_hash: String,
    pub(super) proof_material_root: String,
}

pub(super) fn validate_same_secret_bridge_proof_reference(
    proof_record: &Value,
    bridge_statement_root: &str,
) -> CanonicalResult<ValidatedSameSecretBridgeProofReference> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?.to_string();
    let proof_record_root =
        hash_at_path(proof_record, &["sameSecretBridgeProofRecordRoot"])?.to_string();
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
        "sameSecretBridgeStatementRoot": bridge_statement_root,
        "proofBytesHash": &proof_bytes_hash,
        "proofMaterialRoot": &proof_material_root,
    });
    let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    if expected_proof_record_root != proof_record_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret bridge proof record root does not match its canonical fields",
        ));
    }

    Ok(ValidatedSameSecretBridgeProofReference {
        proof_bytes_hash,
        proof_material_root,
    })
}

pub(super) fn resolve_same_secret_bridge_proof_bytes(
    reference: ValidatedSameSecretBridgeProofReference,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let proof_bytes = take_verified_setup_proof_material_bytes(
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        &reference.proof_material_root,
        "sameSecretBridgeProofRecord.proofMaterialRoot",
        proof_binding_session,
    )?;
    let proof_bytes_hash = proof_bytes.hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN)?;
    compare_required_string(
        &reference.proof_bytes_hash,
        &proof_bytes_hash,
        "same-secret bridge proof record proofBytesHash",
    )?;
    compare_required_string(
        &reference.proof_material_root,
        &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &proof_bytes_hash,
        )?,
        "same-secret bridge proof material root",
    )?;

    Ok(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_proof_record_binds_hash_material_root_and_statement() {
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
            "sameSecretBridgeStatementRoot": &bridge_statement_root,
            "proofBytesHash": &proof_bytes_hash,
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
