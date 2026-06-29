use super::*;

const COMPACT_VSS_COEFFICIENT_COMMITMENT_SET_FIELD: &str = "compactVssCoefficientCommitmentSet";
const COMPACT_VSS_RECIPIENT_SHARE_COMMITMENT_SET_FIELD: &str =
    "compactVssRecipientShareCommitmentSet";
const COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "compactVssAggregateThresholdCommitmentSet";
const COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "compactVssShareLinkageStatement";

pub(super) fn verify_optional_compact_vss_public_material(
    setup_package: &Value,
    _request: &Value,
) -> CanonicalResult<Option<Value>> {
    let compact_public_material_fields = [
        COMPACT_VSS_COEFFICIENT_COMMITMENT_SET_FIELD,
        COMPACT_VSS_RECIPIENT_SHARE_COMMITMENT_SET_FIELD,
        COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD,
        COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD,
    ];
    let present_field_count = compact_public_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();
    if present_field_count == 0 {
        return Ok(None);
    }

    if present_field_count != compact_public_material_fields.len() {
        let missing_fields = compact_public_material_fields
            .into_iter()
            .filter(|field_name| setup_package.get(*field_name).is_none())
            .map(|field_name| format!("setupPackage.{field_name}"))
            .collect::<Vec<_>>()
            .join(", ");

        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssPublicMaterialIncomplete",
            format!(
                "compact VSS public material requires all compact commitment sets and the share-linkage statement; missing {missing_fields}"
            ),
            "setupPackage",
        )?));
    }

    Ok(Some(compact_vss_public_material_refusal(
        "compactVssPublicMaterialNotBinding",
        "compact VSS public material is not accepted by this verifier because the current sparse linear commitment is not binding for full-width coefficient vectors",
        "setupPackage.compactVssCoefficientCommitmentSet",
    )?))
}

fn compact_vss_public_material_refusal(
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
    fn optional_compact_vss_public_material_is_absent_by_default() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(&json!({}), &json!({}))?;

        assert!(response.is_none());
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_requires_complete_field_group() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(
            &json!({
                "compactVssCoefficientCommitmentSet": {},
            }),
            &json!({}),
        )?
        .expect("partial compact VSS public material must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssPublicMaterialIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_refuses_complete_field_group() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(
            &json!({
                "compactVssCoefficientCommitmentSet": {},
                "compactVssRecipientShareCommitmentSet": {},
                "compactVssAggregateThresholdCommitmentSet": {},
                "compactVssShareLinkageStatement": {},
            }),
            &json!({}),
        )?
        .expect("complete compact VSS public material must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssPublicMaterialNotBinding")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactVssCoefficientCommitmentSet")
        );
        Ok(())
    }
}
