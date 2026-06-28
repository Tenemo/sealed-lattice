use super::*;

const COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD: &str = "compactSameSecretBridgeStatementSet";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD: &str =
    "compactSameSecretBridgeProofMaterialSet";

pub(super) fn verify_optional_compact_same_secret_bridge_statement_set(
    setup_package: &Value,
    _request: &Value,
) -> CanonicalResult<Option<Value>> {
    let statement_set_is_present = setup_package
        .get(COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD)
        .is_some();
    let proof_material_set_is_present = setup_package
        .get(COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD)
        .is_some();

    match (statement_set_is_present, proof_material_set_is_present) {
        (false, false) => Ok(None),
        (false, true) => Ok(Some(compact_same_secret_bridge_refusal(
            "compactSameSecretBridgeEvidenceIncomplete",
            "compact same-secret bridge proof material requires the matching bridge statement set",
            format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD}"),
        )?)),
        (true, _) => Ok(Some(compact_same_secret_bridge_refusal(
            "compactSameSecretBridgeNotBinding",
            "compact same-secret bridge material is not accepted by this verifier because it uses the current sparse linear compact commitment, which is not certificate-grade binding evidence",
            format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD}"),
        )?)),
    }
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
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeProofMaterialSet")
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
            json!("compactSameSecretBridgeNotBinding")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeStatementSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_complete_field_group() -> CanonicalResult<()> {
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": {},
                "compactSameSecretBridgeProofMaterialSet": {},
                "sameSecretConsistency": {},
                "sameSecretProofs": {},
            }),
            &json!({}),
        )?
        .expect("complete compact bridge evidence must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeNotBinding")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeStatementSet")
        );
        Ok(())
    }
}
