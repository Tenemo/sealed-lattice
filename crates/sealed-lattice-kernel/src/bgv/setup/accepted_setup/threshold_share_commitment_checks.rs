use super::vss_public_material_verification::VerifiedVssPublicMaterial;
use super::*;

pub(super) const THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE: &str =
    "ThresholdShareCommitmentBinding";

pub(super) fn verify_threshold_share_commitments(
    setup_package: &Value,
    verified_vss_public_material: Option<&VerifiedVssPublicMaterial>,
) -> CanonicalResult<Option<Value>> {
    let Some(threshold_share_commitments) = setup_package.get("thresholdShareCommitments") else {
        return Ok(Some(verification_response(
            Some("thresholdShareCommitments"),
            vec!["thresholdShareCommitments".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !threshold_share_commitments.is_object() {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentsNotObject",
            "thresholdShareCommitments must be a root-bound object, not an array or scalar",
            "setupPackage.thresholdShareCommitments",
        )?));
    }
    // Compact setup path: the threshold-share commitments are a recomputed
    // binding over the proof-verified compact VSS public material. Acceptance is
    // gated purely on recomputing the binding root from the verified compact
    // roots.
    if threshold_share_commitments
        .get("objectType")
        .and_then(Value::as_str)
        == Some(THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE)
    {
        return verify_threshold_share_commitment_binding(
            threshold_share_commitments,
            verified_vss_public_material,
        );
    }
    Ok(Some(threshold_share_refusal(
        "thresholdShareCommitmentSetTypeMismatch",
        "thresholdShareCommitments.objectType must be ThresholdShareCommitmentBinding",
        "setupPackage.thresholdShareCommitments.objectType",
    )?))
}

fn threshold_share_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Some("thresholdShareCommitments"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

// Accept a compact threshold-share commitment binding only when its root
// recomputes from the proof-verified compact VSS public material and the whole
// object matches its canonical form. There is no self-attested field: the
// binding carries only the compact roots the earlier compact-material phase
// already verified, and this phase recomputes their canonical binding root.
fn verify_threshold_share_commitment_binding(
    threshold_share_commitments: &Value,
    verified_vss_public_material: Option<&VerifiedVssPublicMaterial>,
) -> CanonicalResult<Option<Value>> {
    let Some(verified_material) = verified_vss_public_material else {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentBindingRequiresVerifiedMaterial",
            "compact threshold-share commitment binding requires proof-verified compact VSS public material",
            "setupPackage.thresholdShareCommitments",
        )?));
    };
    let Some(threshold_share_commitment_root) = threshold_share_commitments
        .get("thresholdShareCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentBindingRootMissing",
            "compact threshold-share commitment binding must carry a thresholdShareCommitmentRoot",
            "setupPackage.thresholdShareCommitments.thresholdShareCommitmentRoot",
        )?));
    };
    let expected_binding_without_root = json!({
        "objectType": THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE,
        "objectVersion": 1,
        "publicMatrixSeedHash": verified_material.public_matrix_seed_hash.as_str(),
        "participantCount": verified_material.participant_count,
        "thresholdDegree": verified_material.threshold_degree,
        "targetRnsLimbCount": verified_material.target_rns_limb_count,
        "ringDegree": verified_material.ring_degree,
        "aggregateThresholdCommitmentRoot": verified_material
            .aggregate_threshold_commitment_root
            .as_str(),
        "shareLinkageStatementRoot": verified_material.statement_root.as_str(),
        "shareLinkageProofMaterialSetRoot": verified_material.proof_material_set_root.as_str(),
    });
    let expected_threshold_share_commitment_root =
        derive_canonical_object_hash(&expected_binding_without_root)?;
    if expected_threshold_share_commitment_root != threshold_share_commitment_root {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentBindingRootMismatch",
            "compact threshold-share binding root does not match its proof-verified compact VSS roots",
            "setupPackage.thresholdShareCommitments.thresholdShareCommitmentRoot",
        )?));
    }
    let mut expected_binding = expected_binding_without_root;
    expected_binding["thresholdShareCommitmentRoot"] =
        json!(expected_threshold_share_commitment_root);
    if threshold_share_commitments != &expected_binding {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentBindingMismatch",
            "compact threshold-share binding object does not match its canonical form over the verified compact roots",
            "setupPackage.thresholdShareCommitments",
        )?));
    }

    Ok(None)
}
