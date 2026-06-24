use super::*;

pub(super) fn verify_threshold_share_commitments(
    setup_package: &Value,
    request: &Value,
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
    if threshold_share_commitments
        .get("objectType")
        .and_then(Value::as_str)
        != Some("ThresholdShareCommitmentSet")
    {
        return Ok(Some(threshold_share_refusal(
            "thresholdShareCommitmentSetTypeMismatch",
            "thresholdShareCommitments.objectType must be ThresholdShareCommitmentSet",
            "setupPackage.thresholdShareCommitments.objectType",
        )?));
    }
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
    let expected_threshold_share_commitments = if material_encoding
        == "binary-chunked-full-public-setup-commitment-values"
    {
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
