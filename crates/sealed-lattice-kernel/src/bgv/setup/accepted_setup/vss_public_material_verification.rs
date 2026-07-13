use super::*;

const VSS_PUBLIC_COEFFICIENT_COMMITMENT_SET_FIELD: &str = "vssPublicCoefficientCommitmentSet";
const VSS_PUBLIC_RECIPIENT_SHARE_COMMITMENT_SET_FIELD: &str =
    "vssPublicRecipientShareCommitmentSet";
const VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "vssPublicAggregateThresholdCommitmentSet";
const VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "vssShareLinkageStatement";
const VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD: &str = "vssShareLinkageProofMaterialSet";

#[derive(Debug, Clone)]
pub(super) struct VerifiedVssPublicMaterial {
    pub(super) public_matrix_seed_hash: String,
    pub(super) aggregate_threshold_commitment_root: String,
    pub(super) statement_root: String,
    pub(super) proof_material_set_root: String,
    pub(super) participant_count: u64,
    pub(super) q_share_rns_limb_count: u64,
    pub(super) threshold_degree: u64,
    pub(super) ring_degree: u64,
}

#[derive(Debug, Clone)]
pub(super) enum VssPublicMaterialVerification {
    Absent,
    Verified(VerifiedVssPublicMaterial),
    Refused(Value),
}

pub(super) fn verify_optional_vss_public_material(
    setup_package: &Value,
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<VssPublicMaterialVerification> {
    let public_material_fields = [
        VSS_PUBLIC_COEFFICIENT_COMMITMENT_SET_FIELD,
        VSS_PUBLIC_RECIPIENT_SHARE_COMMITMENT_SET_FIELD,
        VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD,
        VSS_SHARE_LINKAGE_STATEMENT_FIELD,
        VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD,
    ];
    let present_field_count = public_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();
    if present_field_count == 0 {
        return Ok(VssPublicMaterialVerification::Absent);
    }

    if present_field_count != public_material_fields.len() {
        let missing_fields = public_material_fields
            .into_iter()
            .filter(|field_name| setup_package.get(*field_name).is_none())
            .map(|field_name| format!("setupPackage.{field_name}"))
            .collect::<Vec<_>>()
            .join(", ");

        return Ok(VssPublicMaterialVerification::Refused(
            vss_public_material_refusal(
                "vssPublicMaterialIncomplete",
                format!(
                    "VSS public material requires all commitment sets, the share-linkage statement, and its proof material set; missing {missing_fields}"
                ),
                "setupPackage",
            )?,
        ));
    }

    match verify_vss_public_material_binding(setup_package, request, proof_binding_session) {
        Ok(verified_material) => Ok(VssPublicMaterialVerification::Verified(verified_material)),
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
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<VerifiedVssPublicMaterial> {
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

    let mut proof_material_request = serde_json::Map::from_iter([
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
    for field_name in [
        "transportedVssShareLinkageProofMaterial",
        "verifiedSetupProofMaterials",
    ] {
        if let Some(value) = request.get(field_name) {
            proof_material_request.insert(field_name.to_string(), value.clone());
        }
    }
    let (statement_verification, proof_material_verification) =
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
    compare_required_string(
        hash_at_path(&proof_material_verification, &["proofMaterialSetRoot"])?,
        hash_at_path(proof_material_set, &["proofMaterialSetRoot"])?,
        "VSS share-linkage proof material set root",
    )?;

    // The proven threshold-share aggregate binding: every aggregate record's
    // committed T_{j,l} is shown to be the modular sum of the committed source
    // recipient shares by a unit-point share-linkage proof.
    crate::bgv::setup::verify_vss_public_aggregate_threshold_proofs(
        proof_binding_session,
        request,
        coefficient_set,
        recipient_share_set,
        aggregate_threshold_set,
        &crate::bgv::setup::VssAggregateThresholdProofContext {
            public_matrix_seed_hash: accepted_public_matrix_seed_hash,
            ceremony_id: string_at_path(setup_context, &["ceremonyId"])?,
            manifest_hash: hash_at_path(setup_context, &["manifestHash"])?,
            roster_hash: hash_at_path(setup_context, &["rosterHash"])?,
            setup_epoch: string_at_path(setup_context, &["setupEpoch"])?,
            ring_degree: unsigned_at_path(&statement_verification, &["ringDegree"])?
                .try_into()
                .map_err(|_| public_material_error("aggregate ring degree does not fit usize"))?,
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

    Ok(VerifiedVssPublicMaterial {
        public_matrix_seed_hash: accepted_public_matrix_seed_hash.to_string(),
        aggregate_threshold_commitment_root: hash_at_path(
            &statement_verification,
            &["aggregateThresholdCommitmentRoot"],
        )?
        .to_string(),
        statement_root: hash_at_path(&statement_verification, &["statementRoot"])?.to_string(),
        proof_material_set_root: hash_at_path(
            &proof_material_verification,
            &["proofMaterialSetRoot"],
        )?
        .to_string(),
        participant_count: unsigned_at_path(&statement_verification, &["participantCount"])?,
        q_share_rns_limb_count: unsigned_at_path(&statement_verification, &["qShareRnsLimbCount"])?,
        threshold_degree: unsigned_at_path(&statement_verification, &["thresholdDegree"])?,
        ring_degree: unsigned_at_path(&statement_verification, &["ringDegree"])?,
    })
}

fn public_material_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn vss_public_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
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
    fn optional_vss_public_material_requires_complete_field_group() -> CanonicalResult<()> {
        let VssPublicMaterialVerification::Refused(response) = verify_optional_vss_public_material(
            &json!({
                "vssPublicCoefficientCommitmentSet": {},
            }),
            &json!({}),
            None,
        )?
        else {
            panic!("partial VSS public material must refuse");
        };

        assert_eq!(response["isValid"], json!(false));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("vssPublicMaterialIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_vss_public_material_requires_proof_material() -> CanonicalResult<()> {
        let VssPublicMaterialVerification::Refused(response) = verify_optional_vss_public_material(
            &json!({
                "vssPublicCoefficientCommitmentSet": {},
                "vssPublicRecipientShareCommitmentSet": {},
                "vssPublicAggregateThresholdCommitmentSet": {},
                "vssShareLinkageStatement": {},
            }),
            &json!({}),
            None,
        )?
        else {
            panic!("complete VSS public material must refuse");
        };

        assert_eq!(response["isValid"], json!(false));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("vssPublicMaterialIncomplete")
        );
        assert!(
            response["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message")
                .contains("vssShareLinkageProofMaterialSet")
        );
        Ok(())
    }

    #[test]
    fn optional_vss_public_material_rejects_malformed_complete_field_group() -> CanonicalResult<()>
    {
        let VssPublicMaterialVerification::Refused(response) = verify_optional_vss_public_material(
            &json!({
                "vssPublicCoefficientCommitmentSet": {},
                "vssPublicRecipientShareCommitmentSet": {},
                "vssPublicAggregateThresholdCommitmentSet": {},
                "vssShareLinkageStatement": {},
                "vssShareLinkageProofMaterialSet": {},
            }),
            &json!({}),
            None,
        )
        .expect("complete VSS public material refusal") else {
            panic!("complete VSS public material must refuse");
        };

        assert_eq!(response["isValid"], json!(false));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("vssPublicMaterialMalformed")
        );
        Ok(())
    }
}
