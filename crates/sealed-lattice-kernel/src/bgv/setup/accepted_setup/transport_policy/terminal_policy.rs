use super::*;

pub(in crate::bgv::setup) fn verify_terminal_setup_transport_policy(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    // Embedded VSS coefficient commitment material declares the full-public
    // encoding; the terminal accepted setup requires the binary-chunked transport
    // encoding instead. A missing field or any other encoding is refused too, so
    // the check fails closed and only the transported form passes, mirroring the
    // sibling proof-bytes, key-switch, and public-evaluation-key encoding checks.
    if setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material| material.get("materialEncoding"))
        .and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_TRANSPORT_ENCODING)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalVssMaterialTransportRequired",
            "terminal accepted setup requires binary-chunked VSS coefficient commitment material",
            "setupPackage.vssCoefficientCommitmentMaterial.materialEncoding",
        )?));
    }
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
    for (record_set_name, records_field_name, object_path) in [
        (
            "publicKeyShareSuccinctProofs",
            "proofRecords",
            "setupPackage.publicKeyShareSuccinctProofs.proofRecords",
        ),
        (
            "trusteeEvaluationKeyProofs",
            "proofRecords",
            "setupPackage.trusteeEvaluationKeyProofs.proofRecords",
        ),
    ] {
        if let Some(response) = verify_terminal_proof_material_transport_records(
            setup_package,
            record_set_name,
            records_field_name,
            object_path,
        )? {
            return Ok(Some(response));
        }
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
    for field_name in [
        "publicEvaluationKeyMaterialEncoding",
        "publicEvaluationKeyMaterialRoot",
        "publicEvaluationKeyMaterialChunkCount",
        "publicEvaluationKeyMaterialTotalByteLength",
        "publicEvaluationKeyMaterialFullObjectHash",
        "publicEvaluationKeyMaterialChunkRoot",
        "publicEvaluationKeyMaterialChunkHashes",
    ] {
        if evaluation_keys.get(field_name).is_none() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalPublicEvaluationKeyMaterialTransportRequired",
                "terminal accepted setup requires transported public evaluation-key runtime material",
                format!("setupPackage.evaluationKeys.{field_name}"),
            )?));
        }
    }
    if evaluation_keys
        .get("publicEvaluationKeyMaterialEncoding")
        .and_then(Value::as_str)
        != Some(PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING)
    {
        return Ok(Some(terminal_transport_policy_refusal(
            "terminalPublicEvaluationKeyMaterialEncodingMismatch",
            "terminal accepted setup requires binary-chunked public evaluation-key material",
            "setupPackage.evaluationKeys.publicEvaluationKeyMaterialEncoding",
        )?));
    }
    if let Some(response) = verify_terminal_key_switch_material_handle_policy(request)? {
        return Ok(Some(response));
    }

    Ok(None)
}

// The terminal accepted setup must not carry the raw key-switch component
// material inline in the package: the material streams through the file-backed
// evaluation-key component material transport and the accepted-setup verifier
// reads it transiently from the stream-verified handle. Any inline `chunks`
// array on a transported component material is a raw embedded store and is
// refused.
fn verify_terminal_key_switch_material_handle_policy(
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(material_set) = request.get("transportedEvaluationKeyShareComponentMaterial") else {
        return Ok(None);
    };
    for component_material in array_value(material_set, "componentMaterials")? {
        if component_material.get("chunks").is_some() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalKeySwitchMaterialHandleRequired",
                "terminal accepted setup requires a chunkless key-switch component material reference plus a stream-verified material handle",
                "transportedEvaluationKeyShareComponentMaterial.componentMaterials.chunks",
            )?));
        }
    }

    Ok(None)
}

fn verify_terminal_proof_material_transport_records(
    setup_package: &Value,
    record_set_name: &str,
    records_field_name: &str,
    object_path: &str,
) -> CanonicalResult<Option<Value>> {
    let record_set = setup_package.get(record_set_name).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{record_set_name} was required before terminal transport policy verification"),
        )
    })?;
    for proof_record in array_value(record_set, records_field_name)? {
        if proof_record.get("proofBytesHex").is_some() {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalProofMaterialTransportRequired",
                "terminal accepted setup requires transported setup proof bytes",
                format!("{object_path}.proofBytesHex"),
            )?));
        }
        if proof_record
            .get("proofBytesEncoding")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_MATERIAL_ENCODING)
        {
            return Ok(Some(terminal_transport_policy_refusal(
                "terminalProofMaterialTransportRequired",
                "terminal accepted setup requires binary-chunked setup proof bytes",
                format!("{object_path}.proofBytesEncoding"),
            )?));
        }
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
