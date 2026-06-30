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

    Ok(Some(compact_same_secret_bridge_refusal(
        "compactSameSecretBridgeNotBinding",
        "compact same-secret bridge material depends on compact VSS public material whose commitment profile lacks certificate-grade binding evidence; keep the standalone bridge proof verifier as development evidence only",
        "setupPackage",
    )?))
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
    fn optional_compact_same_secret_bridge_refuses_complete_field_group_until_binding_review()
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
            json!("compactSameSecretBridgeNotBinding")
        );
        Ok(())
    }
}
