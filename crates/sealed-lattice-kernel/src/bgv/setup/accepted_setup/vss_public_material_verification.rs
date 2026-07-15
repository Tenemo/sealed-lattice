use super::*;

const VSS_PUBLIC_COEFFICIENT_COMMITMENT_SET_FIELD: &str = "vssPublicCoefficientCommitmentSet";
const VSS_PUBLIC_RECIPIENT_SHARE_COMMITMENT_SET_FIELD: &str =
    "vssPublicRecipientShareCommitmentSet";
const VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "vssPublicAggregateThresholdCommitmentSet";
const VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "vssShareLinkageStatement";
const VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD: &str = "vssShareLinkageProofMaterialSet";

#[derive(Debug, Clone)]
pub(super) enum VssPublicMaterialVerification {
    Verified { ring_degree: usize },
    Refused(Refusals),
}

pub(super) fn verify_vss_public_material(
    setup_package: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<VssPublicMaterialVerification> {
    let public_material_fields = [
        VSS_PUBLIC_COEFFICIENT_COMMITMENT_SET_FIELD,
        VSS_PUBLIC_RECIPIENT_SHARE_COMMITMENT_SET_FIELD,
        VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD,
        VSS_SHARE_LINKAGE_STATEMENT_FIELD,
        VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD,
    ];
    let missing_fields = public_material_fields
        .into_iter()
        .filter(|field_name| setup_package.get(*field_name).is_none())
        .map(|field_name| format!("setupPackage.{field_name}"))
        .collect::<Vec<_>>();
    if !missing_fields.is_empty() {
        return Ok(VssPublicMaterialVerification::Refused(
            vss_public_material_refusal(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "vssPublicMaterialIncomplete",
                format!(
                    "VSS public material is required; missing {}",
                    missing_fields.join(", ")
                ),
                "setupPackage",
            )?,
        ));
    }

    match verify_vss_public_material_binding(
        setup_package,
        expected_trustees,
        proof_binding_session,
    ) {
        Ok(ring_degree) => Ok(VssPublicMaterialVerification::Verified { ring_degree }),
        Err(error) => Ok(VssPublicMaterialVerification::Refused(
            vss_public_material_refusal(
                crate::foundation::RefusalReason::MalformedEncoding,
                "vssPublicMaterialMalformed",
                format!("VSS public material is malformed: {}", error.message),
                "setupPackage",
            )?,
        )),
    }
}

fn verify_vss_public_material_binding(
    setup_package: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<usize> {
    let coefficient_set = setup_package
        .get(VSS_PUBLIC_COEFFICIENT_COMMITMENT_SET_FIELD)
        .ok_or_else(|| public_material_error("coefficient commitment set"))?;
    let recipient_share_set = setup_package
        .get(VSS_PUBLIC_RECIPIENT_SHARE_COMMITMENT_SET_FIELD)
        .ok_or_else(|| public_material_error("recipient-share commitment set"))?;
    let aggregate_threshold_set = setup_package
        .get(VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD)
        .ok_or_else(|| public_material_error("aggregate threshold set"))?;
    let statement = setup_package
        .get(VSS_SHARE_LINKAGE_STATEMENT_FIELD)
        .ok_or_else(|| public_material_error("share-linkage statement"))?;
    let proof_material_set = setup_package
        .get(VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD)
        .ok_or_else(|| public_material_error("share-linkage proof material set"))?;

    let trustee_identities = (0..expected_trustees.len())
        .map(|roster_position| {
            expected_trustees
                .get(&(roster_position as u64))
                .cloned()
                .ok_or_else(|| {
                    public_material_error("accepted setup roster positions must be contiguous")
                })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let proof_material_request = serde_json::Map::from_iter([
        ("statement".to_string(), statement.clone()),
        (
            "coefficientCommitmentSet".to_string(),
            coefficient_set.clone(),
        ),
        (
            "recipientShareCommitmentSet".to_string(),
            recipient_share_set.clone(),
        ),
        (
            "aggregateThresholdCommitmentSet".to_string(),
            aggregate_threshold_set.clone(),
        ),
        ("proofMaterialSet".to_string(), proof_material_set.clone()),
    ]);
    let statement_verification =
        crate::bgv::setup::vss_commitment::verify_vss_share_linkage_bindings_request(
            &Value::Object(proof_material_request),
            &trustee_identities,
        )?;
    let setup_context = setup_package
        .get("setupContext")
        .ok_or_else(|| public_material_error("VSS public material requires setup context"))?;
    compare_setup_context_binding(setup_context, statement, "VSS share-linkage statement")?;
    let common_randomness = setup_package
        .get("commonRandomness")
        .ok_or_else(|| public_material_error("VSS public material requires common randomness"))?;
    let accepted_public_matrix_seed_hash =
        hash_at_path(common_randomness, &["publicMatrixSeedHash"])?;
    compare_required_string(
        &statement_verification.public_matrix_seed_hash,
        accepted_public_matrix_seed_hash,
        "VSS share-linkage statement publicMatrixSeedHash",
    )?;
    let _ring_degree = statement_verification.ring_degree;
    let _ = proof_binding_session;
    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "accepted setup requires the VSS share-linkage and aggregate relations to be verified by the common proof suite",
    ))
}

fn public_material_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn vss_public_material_refusal(
    refusal_reason: crate::foundation::RefusalReason,
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Refusals> {
    Ok(setup_refusals(
        Vec::new(),
        vec![Refusal::new(
            refusal_reason,
            reason_code,
            message,
            object_path,
        )],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_vss_public_material_rejects_malformed_records() -> CanonicalResult<()> {
        let VssPublicMaterialVerification::Refused(response) = verify_vss_public_material(
            &json!({
                "vssPublicCoefficientCommitmentSet": {},
                "vssPublicRecipientShareCommitmentSet": {},
                "vssPublicAggregateThresholdCommitmentSet": {},
                "vssShareLinkageStatement": {},
                "vssShareLinkageProofMaterialSet": {},
            }),
            &BTreeMap::new(),
            None,
        )
        .expect("complete VSS public material refusal") else {
            panic!("complete VSS public material must refuse");
        };

        assert_eq!(
            response.first().map(|refusal| refusal.reason_code),
            Some("vssPublicMaterialMalformed")
        );
        Ok(())
    }
}
