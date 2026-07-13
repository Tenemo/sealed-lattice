use super::*;

pub(in crate::bgv::setup) fn verify_terminal_setup_transport_policy(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    if !setup_package
        .get("publicKeyShareMaterial")
        .is_some_and(public_key_share_material_uses_transport)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalPublicKeyShareMaterialTransportRequired",
            "terminal accepted setup requires binary-chunked public-key share material",
            "setupPackage.publicKeyShareMaterial",
        )?));
    }
    if let Some(response) = verify_terminal_key_switch_transport_records(
        setup_package
            .get("relinearizationKeyShareRounds")
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearizationKeyShareRounds was required before terminal transport policy verification",
                )
            })?,
        "roundOneRecords",
        "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
    )? {
        return Ok(Some(response));
    }
    if let Some(response) = verify_terminal_key_switch_transport_records(
        setup_package
            .get("relinearizationKeyShareRounds")
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearizationKeyShareRounds was required before terminal transport policy verification",
                )
            })?,
        "roundTwoRecords",
        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
    )? {
        return Ok(Some(response));
    }
    for galois_batch in array_value(setup_package, "galoisKeyShareBatches")? {
        if let Some(response) = verify_terminal_key_switch_transport_records(
            galois_batch,
            "galoisKeyShareMaterialRecords",
            "setupPackage.galoisKeyShareBatches.galoisKeyShareMaterialRecords",
        )? {
            return Ok(Some(response));
        }
    }
    let evaluation_keys = setup_package.get("evaluationKeys").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluationKeys was required before terminal transport policy verification",
        )
    })?;
    if evaluation_keys
        .get("publicEvaluationKeyMaterialRoot")
        .is_none()
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalPublicEvaluationKeyMaterialTransportRequired",
            "terminal accepted setup requires transported public evaluation-key runtime material",
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialRoot",
        )?));
    }
    Ok(None)
}

fn verify_terminal_key_switch_transport_records(
    record_set: &Value,
    records_field_name: &str,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    for proof_record in array_value(record_set, records_field_name)? {
        if proof_record.get("keySwitchComponentVectors").is_some() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalKeySwitchMaterialTransportRequired",
                "terminal accepted setup requires transported key-switch component material",
                format!("{object_path}.keySwitchComponentVectors"),
            )?));
        }
        if proof_record
            .get("keySwitchMaterialEncoding")
            .and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING)
        {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalKeySwitchMaterialTransportRequired",
                "terminal accepted setup requires binary-chunked key-switch component material",
                format!("{object_path}.keySwitchMaterialEncoding"),
            )?));
        }
    }

    Ok(None)
}

fn terminal_transport_policy_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Some("setupPackageVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
