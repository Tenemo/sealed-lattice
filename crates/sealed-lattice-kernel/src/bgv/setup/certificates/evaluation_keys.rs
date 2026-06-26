use super::*;

pub(super) fn public_rlwe_samples_by_basis(
    participant_count: usize,
    rotation_key_count: usize,
) -> Value {
    let q_data_bits = data_basis_modulus_bits();
    let q_extended_utility_bits = extended_basis_modulus_bits();

    json!({
        "QData": {
            "basisId": BgvBasisKind::Data.basis_id(),
            "modulusBits": q_data_bits,
            "publicKeyShares": participant_count,
            "collectivePublicKey": 1,
            "developmentEncryptionFixtures": 1,
            "relinearizationKeys": DATA_PRIMES.len() - 1,
            "rotationKeys": rotation_key_count,
            "keySwitchKeys": 1,
        },
        "QPPublic": {
            "basisId": BgvBasisKind::Extended.basis_id(),
            "modulusBits": q_extended_utility_bits,
            "relinearizationKeys": 0,
            "rotationKeys": 0,
            "keySwitchKeys": 0,
        },
        "QTarget": {
            "modulusBits": null,
        },
    })
}

pub(super) fn evaluation_key_size_certificate(evaluation_keys: &Value) -> CanonicalResult<Value> {
    let residue_byte_count = 8_usize;
    let polynomial_byte_estimate_data = POLYNOMIAL_DEGREE * DATA_PRIMES.len() * residue_byte_count;
    let polynomial_byte_estimate_extended =
        POLYNOMIAL_DEGREE * (DATA_PRIMES.len() + 1) * residue_byte_count;
    let relinearization_key_record = value_at_path(
        evaluation_keys,
        &[
            "evaluationKeyMaterialCommitment",
            "relinearizationKeyRecord",
        ],
    )?;
    let relinearization_key_bytes = array_at_path(relinearization_key_record, &["levelSchedule"])?
        .iter()
        .map(|level| {
            level
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .map(evaluation_key_stream_bytes_at_level)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "relinearization key level schedule entries must be non-negative integers",
                    )
                })
        })
        .sum::<CanonicalResult<usize>>()?;
    let rotation_key_roots = array_at_path(evaluation_keys, &["rotationKeyRoots"])?;
    let rotation_key_bytes = rotation_key_roots
        .iter()
        .map(|rotation_key| {
            usize_at_path(rotation_key, &["level"]).map(evaluation_key_stream_bytes_at_level)
        })
        .sum::<CanonicalResult<usize>>()?;
    let key_switch_key_bytes = relinearization_key_bytes + rotation_key_bytes;
    let total_evaluation_key_bytes = key_switch_key_bytes;

    Ok(json!({
        "objectType": "EvaluationKeySizeCertificate",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "polynomialDegree": POLYNOMIAL_DEGREE,
        "dataBasisPolynomialByteEstimate": polynomial_byte_estimate_data,
        "extendedBasisPolynomialByteEstimate": polynomial_byte_estimate_extended,
        "relinearizationKeyByteEstimate": relinearization_key_bytes,
        "relinearizationKeyLevelCount": array_at_path(relinearization_key_record, &["levelSchedule"])?.len(),
        "rotationKeyCount": rotation_key_roots.len(),
        "rotationKeyByteEstimate": rotation_key_bytes,
        "keySwitchKeyByteEstimate": key_switch_key_bytes,
        "totalEvaluationKeyByteEstimate": total_evaluation_key_bytes,
        "chunkingStrategy": {
            "chunkSizeBytes": 262144,
            "chunkRootRequired": true,
            "streamingVerificationRequired": true
        },
    }))
}

pub(super) fn evaluation_key_streaming_commitment(
    evaluation_keys: &Value,
) -> CanonicalResult<Value> {
    let stream_record = json!({
        "objectType": "BgvEvaluationKeyMaterialCommitmentStream",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "evaluationKeyRoot": evaluation_keys["evaluationKeyRoot"],
        "rotSetHash": evaluation_keys["rotSetHash"],
        "relinearizationKeyRoot": evaluation_keys["relinearizationKeyRoot"],
        "keySwitchKeyRoot": evaluation_keys["keySwitchKeyRoot"],
        "rotationKeyRoots": evaluation_keys["rotationKeyRoots"],
        "evaluationKeyMaterialCommitmentHash": evaluation_keys["evaluationKeyMaterialCommitmentHash"],
        "evaluationKeyMaterialCommitment": evaluation_keys["evaluationKeyMaterialCommitment"],
        "fullCoefficientStreamMaterializedInSetupPackage": false,
    });
    let stream_bytes = canonical_json(&stream_record)?.into_bytes();
    let chunk_root_value = chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?;
    let commitment_record = json!({
        "objectType": "BgvEvaluationKeyStreamingCommitment",
        "objectVersion": 1,
        "commitmentId": EVALUATION_KEY_STREAMING_COMMITMENT_ID,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "streamRecord": stream_record,
        "canonicalStreamByteLength": stream_bytes.len(),
        "chunkSizeBytes": EVALUATION_KEY_CHUNK_SIZE_BYTES,
        "chunkRoot": chunk_root_value,
        "chunkCount": stream_bytes.len().div_ceil(EVALUATION_KEY_CHUNK_SIZE_BYTES),
        "fullCoefficientStreamMaterializedInSetupPackage": false,
    });
    let commitment_hash = derive_protocol_hash("EvaluationKeySetHash", &commitment_record)?;

    Ok(json!({
        "commitment": commitment_record,
        "commitmentHash": commitment_hash,
    }))
}

fn evaluation_key_stream_bytes_at_level(level: usize) -> usize {
    let active_limb_count = level + 1;
    let component_count = 2;
    let digit_count = active_limb_count;

    digit_count * component_count * active_limb_count * POLYNOMIAL_DEGREE * 8
}
