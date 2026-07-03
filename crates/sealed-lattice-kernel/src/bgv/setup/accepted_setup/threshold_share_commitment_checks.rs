use super::compact_vss_public_material_verification::VerifiedCompactVssPublicMaterial;
use super::*;

const THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE: &str = "ThresholdShareCommitmentSet";
const COMPACT_THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE: &str =
    "CompactThresholdShareCommitmentBinding";

pub(super) fn verify_threshold_share_commitments(
    setup_package: &Value,
    request: &Value,
    verified_compact_vss_public_material: Option<&VerifiedCompactVssPublicMaterial>,
) -> CanonicalResult<Option<Value>> {
    let Some(threshold_share_commitments) = setup_package.get("thresholdShareCommitments") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
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
    let Some(threshold_share_commitment_object_type) = threshold_share_commitments
        .get("objectType")
        .and_then(Value::as_str)
    else {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentSetTypeMismatch",
            "thresholdShareCommitments.objectType must identify the threshold-share commitment binding",
            "setupPackage.thresholdShareCommitments.objectType",
        )?));
    };
    let compact_threshold_share_binding = match threshold_share_commitment_object_type {
        THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE => false,
        COMPACT_THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE => true,
        _ => {
            return Ok(Some(threshold_share_refusal(
                "thresholdShareCommitmentSetTypeMismatch",
                format!(
                    "thresholdShareCommitments.objectType must be {THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE} or {COMPACT_THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE}"
                ),
                "setupPackage.thresholdShareCommitments.objectType",
            )?));
        }
    };
    if threshold_share_commitments
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentSetVersionMismatch",
            "thresholdShareCommitments.objectVersion must be 1",
            "setupPackage.thresholdShareCommitments.objectVersion",
        )?));
    }
    let Some(threshold_share_commitment_root) = threshold_share_commitments
        .get("thresholdShareCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("thresholdShareCommitments"),
            vec!["thresholdShareCommitments.thresholdShareCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        threshold_share_commitment_root,
        "thresholdShareCommitments.thresholdShareCommitmentRoot",
    )?;

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before threshold-share commitment verification",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before threshold-share commitment verification",
            )
        })?;
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before threshold-share commitment verification",
            )
        })?;
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitment material was required before threshold-share commitment verification",
            )
        })?;
    let material_encoding = material_set
        .get("materialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitment material encoding was required before threshold-share commitment verification",
            )
        })?;
    let expected_threshold_share_commitments = if compact_threshold_share_binding {
        match verified_compact_vss_public_material {
            Some(verified_material) => {
                match compact_threshold_share_binding_from_verified_material(
                    threshold_share_commitments,
                    threshold_share_commitment_root,
                    verified_material,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        return Ok(Some(threshold_share_refusal(
                            "compactThresholdShareCommitmentBindingMismatch",
                            format!(
                                "compact threshold-share commitment binding must match proof-verified compact VSS public material: {}",
                                error.message
                            ),
                            "setupPackage.thresholdShareCommitments",
                        )?));
                    }
                }
            }
            None => {
                return Ok(Some(verification_response(
                    VerifierStatus::Pending,
                    Some("thresholdShareCommitments"),
                    vec![
                        "compactVssCoefficientCommitmentSet".to_string(),
                        "compactVssRecipientShareCommitmentSet".to_string(),
                        "compactVssAggregateThresholdCommitmentSet".to_string(),
                        "compactVssShareLinkageStatement".to_string(),
                        "compactVssShareLinkageProofMaterialSet".to_string(),
                    ],
                    Vec::new(),
                    Vec::new(),
                )?));
            }
        }
    } else if material_encoding == "binary-chunked-full-public-setup-commitment-values" {
        let vss_coefficient_commitment_root = material_set
            .get("vssCoefficientCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS coefficient commitment root was required before transported threshold-share verification",
                )
            })?;
        if let Some(verified_material_reference) =
            request.get("verifiedVssCoefficientCommitmentMaterial")
        {
            match threshold_share_commitments_from_verified_vss_material(
                verified_material_reference,
                setup_context,
                public_matrix_seed_hash,
                vss_coefficient_commitment_root,
                material_set,
                threshold_share_commitment_root,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(Some(threshold_share_refusal(
                        "thresholdShareCommitmentVerifiedMaterialMismatch",
                        format!(
                            "thresholdShareCommitments must be derived from stream-verified VSS material: {}",
                            error.message
                        ),
                        "verifiedVssCoefficientCommitmentMaterial",
                    )?));
                }
            }
        } else {
            let Some(transported_material) =
                request.get("transportedVssCoefficientCommitmentMaterial")
            else {
                return Ok(Some(verification_response(
                    VerifierStatus::Pending,
                    Some("thresholdShareCommitments"),
                    vec!["verifiedVssCoefficientCommitmentMaterial".to_string()],
                    Vec::new(),
                    Vec::new(),
                )?));
            };
            if transported_material.get("chunks").is_none() {
                return Ok(Some(verification_response(
                    VerifierStatus::Pending,
                    Some("thresholdShareCommitments"),
                    vec!["verifiedVssCoefficientCommitmentMaterial".to_string()],
                    Vec::new(),
                    Vec::new(),
                )?));
            }
            let transport_result = match derive_threshold_share_commitments_from_transport_request(
                &json!({
                    "setupContext": setup_context,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeCoefficientCommitmentRecords": source_trustee_records,
                    "transportedVssCoefficientCommitmentMaterial": transported_material,
                }),
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(Some(threshold_share_refusal(
                        "thresholdShareCommitmentTransportDerivationMismatch",
                        format!(
                            "thresholdShareCommitments must be derived from verifier-checked transported VSS material: {}",
                            error.message
                        ),
                        "transportedVssCoefficientCommitmentMaterial",
                    )?));
                }
            };
            let derived_material_root = transport_result
                .get("vssCoefficientCommitmentMaterial")
                .and_then(|value| value.get("vssCoefficientCommitmentMaterialRoot"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "transport derivation did not return a material root",
                    )
                })?;
            let package_material_root = material_set
            .get("vssCoefficientCommitmentMaterialRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "package material root was required before transported threshold-share verification",
                )
            })?;
            if derived_material_root != package_material_root {
                return Ok(Some(threshold_share_refusal(
                    "thresholdShareCommitmentTransportMaterialRootMismatch",
                    "transported VSS material root must match setupPackage.vssCoefficientCommitmentMaterial",
                    "setupPackage.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot",
                )?));
            }
            transport_result
                .get("thresholdShareCommitments")
                .cloned()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "transport derivation did not return thresholdShareCommitments",
                    )
                })?
        }
    } else {
        let coefficient_commitments = material_set
            .get("coefficientCommitments")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS coefficient commitment material was required before threshold-share commitment verification",
                )
            })?;
        match derive_threshold_share_commitment_set_from_parts(
            setup_context,
            public_matrix_seed_hash,
            source_trustee_records,
            coefficient_commitments,
        ) {
            Ok(value) => value,
            Err(error) => {
                return Ok(Some(threshold_share_refusal(
                    "thresholdShareCommitmentDerivationMismatch",
                    format!(
                        "thresholdShareCommitments must be derived from accepted public VSS coefficient material: {}",
                        error.message
                    ),
                    "setupPackage.thresholdShareCommitments",
                )?));
            }
        }
    };

    if threshold_share_commitments != &expected_threshold_share_commitments {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentSetMismatch",
            "thresholdShareCommitments must match the verifier-derived threshold-share commitment set",
            "setupPackage.thresholdShareCommitments",
        )?));
    }

    Ok(None)
}

fn compact_threshold_share_binding_from_verified_material(
    threshold_share_commitments: &Value,
    threshold_share_commitment_root: &str,
    verified_material: &VerifiedCompactVssPublicMaterial,
) -> CanonicalResult<Value> {
    let expected_binding_without_root = json!({
        "objectType": COMPACT_THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "publicMatrixSeedHash": verified_material.public_matrix_seed_hash.as_str(),
        "participantCount": verified_material.participant_count,
        "thresholdDegree": verified_material.threshold_degree,
        "targetRnsLimbCount": verified_material.target_rns_limb_count,
        "ringDegree": verified_material.ring_degree,
        "aggregateThresholdCommitmentRoot": verified_material.aggregate_threshold_commitment_root.as_str(),
        "shareLinkageStatementRoot": verified_material.statement_root.as_str(),
        "shareLinkageProofMaterialSetRoot": verified_material.proof_material_set_root.as_str(),
    });
    let expected_threshold_share_commitment_root = derive_protocol_hash(
        "ThresholdShareCommitmentRoot",
        &expected_binding_without_root,
    )?;
    if expected_threshold_share_commitment_root != threshold_share_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact threshold-share binding root does not match its proof-verified compact VSS roots",
        ));
    }

    let mut expected_binding = expected_binding_without_root;
    expected_binding["thresholdShareCommitmentRoot"] =
        json!(expected_threshold_share_commitment_root);
    if threshold_share_commitments != &expected_binding {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "compact threshold-share binding object does not match its canonical form",
        ));
    }

    Ok(expected_binding)
}

fn threshold_share_commitments_from_verified_vss_material(
    verified_material_reference: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    material_set: &Value,
    threshold_share_commitment_root: &str,
) -> CanonicalResult<Value> {
    with_verified_transported_vss_material(verified_material_reference, |verified_material| {
        validate_verified_vss_material_matches_package(
            verified_material,
            setup_context,
            public_matrix_seed_hash,
            vss_coefficient_commitment_root,
            material_set,
        )?;
        let verified_threshold_share_commitment_root = verified_material
            .threshold_share_commitments
            .get("thresholdShareCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "stream-verified VSS material did not retain a threshold-share commitment root",
                )
            })?;
        if verified_threshold_share_commitment_root != threshold_share_commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "stream-verified threshold-share commitment root does not match setupPackage.thresholdShareCommitments",
            ));
        }

        Ok(verified_material.threshold_share_commitments.clone())
    })
}

pub(super) fn validate_verified_vss_material_matches_package(
    verified_material: &super::threshold_share_commitments::VerifiedTransportedVssMaterial,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    material_set: &Value,
) -> CanonicalResult<()> {
    if verified_material.setup_context != *setup_context {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material setup context does not match setupPackage.setupContext",
        ));
    }
    if verified_material.public_matrix_seed_hash != public_matrix_seed_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material publicMatrixSeedHash does not match setupPackage.commonRandomness",
        ));
    }
    if verified_material.vss_coefficient_commitment_root != vss_coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material commitment root does not match setupPackage.vssCoefficientCommitments",
        ));
    }
    if verified_material.material_set != *material_set {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material set does not match setupPackage.vssCoefficientCommitmentMaterial",
        ));
    }

    Ok(())
}

fn threshold_share_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("thresholdShareCommitments"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_threshold_share_binding_accepts_verified_compact_material() -> CanonicalResult<()> {
        let verified_material = verified_compact_vss_public_material();
        let binding = compact_threshold_share_binding(&verified_material)?;
        let setup_package = setup_package_with_threshold_share_commitments(binding);

        let response = verify_threshold_share_commitments(
            &setup_package,
            &json!({}),
            Some(&verified_material),
        )?;

        assert!(response.is_none());
        Ok(())
    }

    #[test]
    fn compact_threshold_share_binding_rejects_wrong_aggregate_root() -> CanonicalResult<()> {
        let verified_material = verified_compact_vss_public_material();
        let mut binding = compact_threshold_share_binding(&verified_material)?;
        binding["aggregateThresholdCommitmentRoot"] = json!("f".repeat(128));
        let setup_package = setup_package_with_threshold_share_commitments(binding);

        let response = verify_threshold_share_commitments(
            &setup_package,
            &json!({}),
            Some(&verified_material),
        )?
        .expect("wrong compact aggregate root must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactThresholdShareCommitmentBindingMismatch")
        );
        Ok(())
    }

    #[test]
    fn compact_threshold_share_binding_requires_verified_compact_material() -> CanonicalResult<()> {
        let verified_material = verified_compact_vss_public_material();
        let binding = compact_threshold_share_binding(&verified_material)?;
        let setup_package = setup_package_with_threshold_share_commitments(binding);

        let response = verify_threshold_share_commitments(&setup_package, &json!({}), None)?
            .expect("compact binding without compact material must pend");

        assert_eq!(response["verifierStatus"], json!("pending"));
        assert_eq!(response["currentPhase"], json!("thresholdShareCommitments"));
        assert!(
            response["missingObjects"]
                .as_array()
                .expect("missing objects")
                .iter()
                .any(|missing| missing == "compactVssAggregateThresholdCommitmentSet")
        );
        Ok(())
    }

    fn verified_compact_vss_public_material() -> VerifiedCompactVssPublicMaterial {
        VerifiedCompactVssPublicMaterial {
            public_matrix_seed_hash: "1".repeat(128),
            aggregate_threshold_commitment_root: "2".repeat(128),
            statement_root: "3".repeat(128),
            proof_material_set_root: "4".repeat(128),
            participant_count: 10,
            target_rns_limb_count: 2,
            threshold_degree: 4,
            ring_degree: 65_536,
        }
    }

    fn compact_threshold_share_binding(
        verified_material: &VerifiedCompactVssPublicMaterial,
    ) -> CanonicalResult<Value> {
        let mut binding = json!({
            "objectType": COMPACT_THRESHOLD_SHARE_COMMITMENT_BINDING_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "publicMatrixSeedHash": verified_material.public_matrix_seed_hash.as_str(),
            "participantCount": verified_material.participant_count,
            "thresholdDegree": verified_material.threshold_degree,
            "targetRnsLimbCount": verified_material.target_rns_limb_count,
            "ringDegree": verified_material.ring_degree,
            "aggregateThresholdCommitmentRoot": verified_material.aggregate_threshold_commitment_root.as_str(),
            "shareLinkageStatementRoot": verified_material.statement_root.as_str(),
            "shareLinkageProofMaterialSetRoot": verified_material.proof_material_set_root.as_str(),
        });
        binding["thresholdShareCommitmentRoot"] = json!(derive_protocol_hash(
            "ThresholdShareCommitmentRoot",
            &binding
        )?);

        Ok(binding)
    }

    fn setup_package_with_threshold_share_commitments(threshold_share_commitments: Value) -> Value {
        json!({
            "setupContext": {
                "ceremonyId": "compact-threshold-binding-test",
                "manifestHash": "5".repeat(128),
                "rosterHash": "6".repeat(128),
                "setupProfileHash": "7".repeat(128),
                "qShareHash": "8".repeat(128),
                "carryAwareVssShareRelationProfileHash": "9".repeat(128),
                "commitmentProfileHash": "a".repeat(128),
                "setupEpoch": "setup-epoch",
            },
            "commonRandomness": {
                "publicMatrixSeedHash": "1".repeat(128),
            },
            "vssCoefficientCommitments": {
                "sourceTrusteeRecords": [],
            },
            "vssCoefficientCommitmentMaterial": {
                "materialEncoding": "binary-chunked-full-public-setup-commitment-values",
                "vssCoefficientCommitmentRoot": "b".repeat(128),
                "vssCoefficientCommitmentMaterialRoot": "c".repeat(128),
            },
            "thresholdShareCommitments": threshold_share_commitments,
        })
    }
}
