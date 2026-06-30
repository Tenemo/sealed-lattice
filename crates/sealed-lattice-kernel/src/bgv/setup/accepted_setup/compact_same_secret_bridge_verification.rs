use super::*;

const COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD: &str = "compactSameSecretBridgeStatementSet";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD: &str =
    "compactSameSecretBridgeProofMaterialSet";

pub(super) fn verify_optional_compact_same_secret_bridge_statement_set(
    setup_package: &Value,
    _request: &Value,
) -> CanonicalResult<Option<Value>> {
    let compact_bridge_material_fields = [
        COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD,
        COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD,
    ];
    let present_compact_bridge_field_count = compact_bridge_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();
    if present_compact_bridge_field_count == 0 {
        return Ok(None);
    }

    let required_bridge_material_fields = [
        COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD,
        COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD,
        "sameSecretConsistency",
        "sameSecretProofs",
    ];
    let present_field_count = required_bridge_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();

    if present_field_count != required_bridge_material_fields.len() {
        let missing_fields = required_bridge_material_fields
            .into_iter()
            .filter(|field_name| setup_package.get(*field_name).is_none())
            .map(|field_name| format!("setupPackage.{field_name}"))
            .collect::<Vec<_>>()
            .join(", ");

        return Ok(Some(compact_same_secret_bridge_refusal(
            "compactSameSecretBridgeEvidenceIncomplete",
            format!(
                "compact same-secret bridge material requires the statement set, proof material set, same-secret statements, and same-secret proofs; missing {missing_fields}"
            ),
            "setupPackage",
        )?));
    }

    if let Err(error) = verify_compact_same_secret_bridge_prebinding(setup_package) {
        return Ok(Some(compact_same_secret_bridge_refusal(
            "compactSameSecretBridgeMalformed",
            format!(
                "compact same-secret bridge material is malformed: {}",
                error.message
            ),
            "setupPackage",
        )?));
    }

    Ok(None)
}

fn verify_compact_same_secret_bridge_prebinding(setup_package: &Value) -> CanonicalResult<()> {
    let statement_set = setup_package
        .get(COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD)
        .ok_or_else(|| {
            compact_same_secret_bridge_error("compact same-secret bridge statement set")
        })?;
    let proof_material_set = setup_package
        .get(COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD)
        .ok_or_else(|| {
            compact_same_secret_bridge_error("compact same-secret bridge proof material set")
        })?;
    let same_secret_consistency = setup_package
        .get("sameSecretConsistency")
        .ok_or_else(|| compact_same_secret_bridge_error("same-secret consistency"))?;
    let same_secret_proofs = setup_package
        .get("sameSecretProofs")
        .ok_or_else(|| compact_same_secret_bridge_error("same-secret proofs"))?;

    let statement_verification =
        crate::bgv::setup::verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
            "statementSet": statement_set,
            "sameSecretConsistency": same_secret_consistency,
            "sameSecretProofs": same_secret_proofs,
        }))?;
    verify_compact_same_secret_bridge_setup_binding(
        setup_package,
        statement_set,
        &statement_verification,
        same_secret_consistency,
        same_secret_proofs,
    )?;

    crate::bgv::setup::verify_compact_vss_same_secret_bridge_proof_material_set_request(&json!({
        "statementSet": statement_set,
        "sameSecretConsistency": same_secret_consistency,
        "sameSecretProofs": same_secret_proofs,
        "proofMaterialSet": proof_material_set,
    }))?;
    Ok(())
}

fn verify_compact_same_secret_bridge_setup_binding(
    setup_package: &Value,
    statement_set: &Value,
    statement_verification: &Value,
    same_secret_consistency: &Value,
    same_secret_proofs: &Value,
) -> CanonicalResult<()> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        compact_same_secret_bridge_error("compact same-secret bridge requires setup context")
    })?;
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        compact_same_secret_bridge_error("compact same-secret bridge requires common randomness")
    })?;
    let coefficient_commitment_set = setup_package
        .get("compactVssCoefficientCommitmentSet")
        .ok_or_else(|| {
            compact_same_secret_bridge_error(
                "compact same-secret bridge requires compact coefficient commitment set",
            )
        })?;

    compare_setup_context_binding(
        setup_context,
        statement_set,
        "compact same-secret bridge statement set",
    )?;
    compare_setup_context_participant_count(
        setup_context,
        statement_verification,
        "compact same-secret bridge statement set",
    )?;
    compare_setup_context_threshold_degree(
        setup_context,
        statement_verification,
        "compact same-secret bridge statement set",
    )?;
    compare_required_string(
        hash_at_path(statement_verification, &["publicMatrixSeedHash"])?,
        hash_at_path(common_randomness, &["publicMatrixSeedHash"])?,
        "compact same-secret bridge statement set publicMatrixSeedHash",
    )?;
    compare_required_string(
        hash_at_path(
            statement_verification,
            &["compactCoefficientCommitmentRoot"],
        )?,
        hash_at_path(coefficient_commitment_set, &["coefficientCommitmentRoot"])?,
        "compact same-secret bridge statement set compactCoefficientCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(statement_verification, &["sameSecretConsistencyRoot"])?,
        hash_at_path(same_secret_consistency, &["sameSecretConsistencyRoot"])?,
        "compact same-secret bridge statement set sameSecretConsistencyRoot",
    )?;
    compare_required_string(
        hash_at_path(statement_verification, &["sameSecretProofSetRoot"])?,
        hash_at_path(same_secret_proofs, &["sameSecretProofSetRoot"])?,
        "compact same-secret bridge statement set sameSecretProofSetRoot",
    )?;

    Ok(())
}

fn compact_same_secret_bridge_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn compact_same_secret_bridge_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("proofVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_compact_same_secret_bridge_is_absent_by_default() -> CanonicalResult<()> {
        let response =
            verify_optional_compact_same_secret_bridge_statement_set(&json!({}), &json!({}))?;

        assert!(response.is_none());
        Ok(())
    }

    #[test]
    fn ordinary_same_secret_fields_do_not_enable_compact_bridge() -> CanonicalResult<()> {
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "sameSecretConsistency": {},
                "sameSecretProofs": {},
            }),
            &json!({}),
        )?;

        assert!(response.is_none());
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_proof_material_without_statement_set()
    -> CanonicalResult<()> {
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeProofMaterialSet": {},
            }),
            &json!({}),
        )?
        .expect("compact bridge proof material without statement set must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeEvidenceIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_statement_set_without_proof_material()
    -> CanonicalResult<()> {
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": {},
            }),
            &json!({}),
        )?
        .expect("compact bridge statement set must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeEvidenceIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_rejects_malformed_complete_field_group()
    -> CanonicalResult<()> {
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": {},
                "compactSameSecretBridgeProofMaterialSet": {},
                "sameSecretConsistency": {},
                "sameSecretProofs": {},
            }),
            &json!({}),
        )
        .expect("complete compact bridge refusal")
        .expect("complete compact bridge evidence must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeMalformed")
        );
        Ok(())
    }
}
