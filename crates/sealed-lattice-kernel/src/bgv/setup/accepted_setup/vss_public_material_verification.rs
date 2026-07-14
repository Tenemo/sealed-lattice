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
                "vssPublicMaterialIncomplete",
                format!(
                    "VSS public material is required; missing {}",
                    missing_fields.join(", ")
                ),
                "setupPackage",
            )?,
        ));
    }

    match verify_vss_public_material_binding(setup_package, proof_binding_session) {
        Ok(ring_degree) => Ok(VssPublicMaterialVerification::Verified { ring_degree }),
        Err(error) => Ok(VssPublicMaterialVerification::Refused(
            vss_public_material_refusal(
                "vssPublicMaterialMalformed",
                format!("VSS public material is malformed: {}", error.message),
                "setupPackage",
            )?,
        )),
    }
}

fn verify_vss_public_material_binding(
    setup_package: &Value,
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
        crate::bgv::setup::trustee_evaluation_key_proof::verify_vss_share_linkage_statement_and_proof_material_set_from_request(
            &Value::Object(proof_material_request),
            proof_binding_session,
        )?;
    let setup_context = setup_package
        .get("setupContext")
        .ok_or_else(|| public_material_error("VSS public material requires setup context"))?;
    compare_setup_context_binding(setup_context, statement, "VSS share-linkage statement")?;
    compare_setup_context_participant_count(
        setup_context,
        &statement_verification,
        "VSS share-linkage statement",
    )?;
    compare_setup_context_threshold_degree(
        setup_context,
        &statement_verification,
        "VSS share-linkage statement",
    )?;
    let ring_degree = usize::try_from(unsigned_at_path(&statement_verification, &["ringDegree"])?)
        .map_err(|_| public_material_error("VSS share-linkage ring degree does not fit usize"))?;

    let common_randomness = setup_package
        .get("commonRandomness")
        .ok_or_else(|| public_material_error("VSS public material requires common randomness"))?;
    let accepted_public_matrix_seed_hash =
        hash_at_path(common_randomness, &["publicMatrixSeedHash"])?;
    compare_required_string(
        hash_at_path(&statement_verification, &["publicMatrixSeedHash"])?,
        accepted_public_matrix_seed_hash,
        "VSS share-linkage statement publicMatrixSeedHash",
    )?;
    compare_complete_q_share_limb_count(&statement_verification, "VSS share-linkage statement")?;

    // The proven threshold-share aggregate binding: every aggregate record's
    // committed T_{j,l} is shown to be the modular sum of the committed source
    // recipient shares by a unit-point share-linkage proof.
    crate::bgv::setup::verify_vss_public_aggregate_threshold_proofs(
        proof_binding_session,
        coefficient_set,
        recipient_share_set,
        aggregate_threshold_set,
        &crate::bgv::setup::VssAggregateThresholdProofContext {
            public_matrix_seed_hash: accepted_public_matrix_seed_hash,
            setup_context_hash: setup_context_hash(setup_context)?,
            ring_degree,
            participant_count: unsigned_at_path(&statement_verification, &["participantCount"])?
                .try_into()
                .map_err(|_| {
                    public_material_error("aggregate participant count does not fit usize")
                })?,
            rns_limb_count: unsigned_at_path(&statement_verification, &["qShareRnsLimbCount"])?
                .try_into()
                .map_err(|_| {
                    public_material_error("aggregate RNS limb count does not fit usize")
                })?,
        },
    )?;

    Ok(ring_degree)
}

fn public_material_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn vss_public_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Refusals> {
    Ok(setup_refusals(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
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
