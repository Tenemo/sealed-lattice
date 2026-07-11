use super::*;

pub(in crate::bgv::setup) fn public_evaluation_key_material_manifest(
    setup_package: &Value,
    evaluation_keys: &Value,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "PublicEvaluationKeyMaterialManifest",
        "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
        "materialTransportEncoding": PUBLIC_EVALUATION_KEY_TRANSPORT_MATERIAL_ENCODING,
        "ceremonyId": value_string(evaluation_keys, "ceremonyId")?,
        "manifestHash": value_string(evaluation_keys, "manifestHash")?,
        "rosterHash": value_string(evaluation_keys, "rosterHash")?,
        "setupParametersHash": value_string(evaluation_keys, "setupParametersHash")?,
        "setupEpoch": value_string(evaluation_keys, "setupEpoch")?,
        "participantCount": value_u64(evaluation_keys, "participantCount")?,
        "rnsLimbCount": value_u64(evaluation_keys, "rnsLimbCount")?,
        "evaluatorKeyScheduleRoot": value_string(evaluation_keys, "evaluatorKeyScheduleRoot")?,
        "publicKeyShareSuccinctProofSetRoot": value_string(
            evaluation_keys,
            "publicKeyShareSuccinctProofSetRoot",
        )?,
        "relinearizationKeyShareRoundsRoot": value_string(
            evaluation_keys,
            "relinearizationKeyShareRoundsRoot",
        )?,
        "relinearizationLevelSchedule": evaluation_keys["relinearizationLevelSchedule"],
        "relinearizationKeyRoots": evaluation_keys["relinearizationKeyRoots"],
        "relinearizationShareMaterialRoots": relinearization_share_material_manifest(setup_package)?,
        "requiredGaloisSetHash": value_string(evaluation_keys, "requiredGaloisSetHash")?,
        "requiredGaloisKeySchedule": evaluation_keys["requiredGaloisKeySchedule"],
        "galoisKeyShareBatchRoots": evaluation_keys["galoisKeyShareBatchRoots"],
        "galoisKeyRoots": evaluation_keys["galoisKeyRoots"],
        "galoisShareMaterialRoots": galois_share_material_manifest(setup_package)?,
    }))
}

fn relinearization_share_material_manifest(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before public evaluation-key material binding",
            )
        })?;
    let mut entries = Vec::new();
    for (round_label, record_field_name, share_root_field_name, record_root_field_name) in [
        (
            "round-one",
            "roundOneRecords",
            "roundOneShareRoot",
            "roundOneRecordRoot",
        ),
        (
            "round-two",
            "roundTwoRecords",
            "roundTwoShareRoot",
            "roundTwoRecordRoot",
        ),
    ] {
        for record in array_value(rounds, record_field_name)? {
            entries.push((
                value_u64(record, "level")?,
                value_u64(record, "trusteeRosterPosition")?,
                if round_label == "round-one" {
                    0_u8
                } else {
                    1_u8
                },
                json!({
                    "round": round_label,
                    "trusteeIdentity": value_string(record, "trusteeIdentity")?,
                    "trusteeRosterPosition": value_u64(record, "trusteeRosterPosition")?,
                    "level": value_u64(record, "level")?,
                    "keySwitchMaterialEncoding": value_string(record, "keySwitchMaterialEncoding")?,
                    "keySwitchDomain": value_string(record, "keySwitchDomain")?,
                    "keySwitchSeedHex": value_string(record, "keySwitchSeedHex")?,
                    "keySwitchComponentVectorRoot": value_string(
                        record,
                        "keySwitchComponentVectorRoot",
                    )?,
                    "keySwitchComponentMaterialRoot": record
                        .get("keySwitchComponentMaterialRoot")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "shareRoot": value_string(record, share_root_field_name)?,
                    "recordRoot": value_string(record, record_root_field_name)?,
                }),
            ));
        }
    }
    entries.sort_by_key(|(level, trustee_roster_position, round_order, _)| {
        (*level, *round_order, *trustee_roster_position)
    });

    Ok(entries.into_iter().map(|(_, _, _, entry)| entry).collect())
}

fn galois_share_material_manifest(setup_package: &Value) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before public evaluation-key material binding",
            )
        })?;
    let mut entries = Vec::new();
    for batch in batches {
        for proof_record in array_value(batch, "galoisKeyShareMaterialRecords")? {
            entries.push((
                value_u64(proof_record, "rotation")?,
                value_u64(proof_record, "level")?,
                value_u64(proof_record, "trusteeRosterPosition")?,
                json!({
                    "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
                    "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
                    "rotation": value_u64(proof_record, "rotation")?,
                    "level": value_u64(proof_record, "level")?,
                    "keySwitchMaterialEncoding": value_string(
                        proof_record,
                        "keySwitchMaterialEncoding",
                    )?,
                    "keySwitchDomain": value_string(proof_record, "keySwitchDomain")?,
                    "keySwitchSeedHex": value_string(proof_record, "keySwitchSeedHex")?,
                    "keySwitchComponentVectorRoot": value_string(
                        proof_record,
                        "keySwitchComponentVectorRoot",
                    )?,
                    "keySwitchComponentMaterialRoot": proof_record
                        .get("keySwitchComponentMaterialRoot")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "galoisKeyShareRoot": value_string(proof_record, "galoisKeyShareRoot")?,
                }),
            ));
        }
    }
    entries.sort_by_key(|(rotation, level, trustee_roster_position, _)| {
        (*rotation, *level, *trustee_roster_position)
    });

    Ok(entries.into_iter().map(|(_, _, _, entry)| entry).collect())
}

pub(super) fn decode_public_evaluation_key_material_manifest(
    chunks: &[Vec<u8>],
    transport_hashes: &PublicEvaluationKeyMaterialTransportHashes,
) -> CanonicalResult<Value> {
    let total_byte_length = usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public evaluation-key material byte length does not fit usize",
        )
    })?;
    let mut material_bytes = Vec::with_capacity(total_byte_length);
    for chunk in chunks {
        material_bytes.extend_from_slice(chunk);
    }
    if material_bytes.len() < PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()
        || &material_bytes[..PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()]
            != PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material has the wrong format marker",
        ));
    }
    let manifest_bytes = &material_bytes[PUBLIC_EVALUATION_KEY_MATERIAL_MAGIC.len()..];
    let manifest: Value = serde_json::from_slice(manifest_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material manifest is not valid JSON",
        )
    })?;
    if canonical_json(&manifest)?.as_bytes() != manifest_bytes {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public evaluation-key material manifest must use canonical JSON bytes",
        ));
    }

    Ok(manifest)
}
