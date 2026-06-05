use super::*;

pub(super) fn validate_setup_certificates(setup_package: &Value) -> CanonicalResult<()> {
    let certificates = value_at_path(setup_package, &["certificates"])?;
    compare_derived_hash(
        "CollectiveSecretDistributionCertificateHash",
        value_at_path(certificates, &["collectiveSecretDistributionCertificate"])?,
        hash_at_path(
            certificates,
            &["collectiveSecretDistributionCertificateHash"],
        )?,
        "collective secret distribution certificate hash",
    )?;
    compare_derived_hash(
        "ErrorDistributionCertificateHash",
        value_at_path(certificates, &["errorDistributionCertificate"])?,
        hash_at_path(certificates, &["errorDistributionCertificateHash"])?,
        "error distribution certificate hash",
    )?;
    compare_derived_hash(
        "KeySwitchDecompositionHash",
        value_at_path(certificates, &["keySwitchDecomposition"])?,
        hash_at_path(certificates, &["keySwitchDecompositionHash"])?,
        "key-switch decomposition hash",
    )?;
    compare_derived_hash(
        "EvaluationKeySizeProfileHash",
        value_at_path(certificates, &["evaluationKeySizeCertificate"])?,
        hash_at_path(certificates, &["evaluationKeySizeProfileHash"])?,
        "evaluation key size profile hash",
    )?;
    compare_derived_hash(
        "BGVHeSecurityCertificateHash",
        value_at_path(certificates, &["heSecurityCertificate"])?,
        hash_at_path(certificates, &["heSecurityCertificateHash"])?,
        "HE security certificate hash",
    )?;
    let evaluation_key_streaming_commitment_hash =
        validate_evaluation_key_streaming_commitment(certificates)?;
    compare_hash_at_path(
        value_at_path(certificates, &["setupParameterCertificate"])?,
        &["evaluationKeyStreamingCommitmentHash"],
        &evaluation_key_streaming_commitment_hash,
        "setup parameter evaluation key streaming commitment hash",
    )?;
    let expected_target_threshold_decryptability_certificate =
        target_threshold_decryptability_certificate_from_setup_package(setup_package)?;
    let target_threshold_decryptability_certificate =
        value_at_path(certificates, &["targetThresholdDecryptabilityCertificate"])?;
    if target_threshold_decryptability_certificate
        != &expected_target_threshold_decryptability_certificate
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target-threshold decryptability certificate does not match setup key and threshold material",
        ));
    }
    compare_derived_hash(
        "TargetThresholdDecryptabilityCertificateHash",
        target_threshold_decryptability_certificate,
        hash_at_path(
            certificates,
            &["targetThresholdDecryptabilityCertificateHash"],
        )?,
        "target-threshold decryptability certificate hash",
    )?;
    compare_hash_at_path(
        value_at_path(certificates, &["setupParameterCertificate"])?,
        &["targetThresholdDecryptabilityCertificateHash"],
        hash_at_path(
            certificates,
            &["targetThresholdDecryptabilityCertificateHash"],
        )?,
        "setup parameter target-threshold decryptability certificate hash",
    )?;
    compare_hash_at_path(
        value_at_path(certificates, &["setupParameterCertificate"])?,
        &["heSecurityCertificateHash"],
        hash_at_path(certificates, &["heSecurityCertificateHash"])?,
        "setup parameter HE security certificate hash",
    )?;
    compare_derived_hash(
        "BGVSetupParameterCertificateHash",
        value_at_path(certificates, &["setupParameterCertificate"])?,
        hash_at_path(certificates, &["setupParameterCertificateHash"])?,
        "setup parameter certificate hash",
    )?;
    compare_derived_hash(
        "BGVDevelopmentEncryptionFixtureHash",
        value_at_path(setup_package, &["developmentEncryptionFixture", "fixture"])?,
        hash_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureHash"],
        )?,
        "development encryption fixture hash",
    )?;
    validate_development_encryption_fixture(setup_package)?;
    compare_hash_at_path(
        certificates,
        &["developmentEncryptionFixtureHash"],
        hash_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureHash"],
        )?,
        "certificate development encryption fixture hash",
    )
}

fn validate_evaluation_key_streaming_commitment(certificates: &Value) -> CanonicalResult<String> {
    let wrapped_commitment = value_at_path(certificates, &["evaluationKeyStreamingCommitment"])?;
    let commitment_record = value_at_path(wrapped_commitment, &["commitment"])?;
    compare_string_at_path(
        commitment_record,
        &["objectType"],
        "BgvEvaluationKeyStreamingCommitment",
        "evaluation key streaming commitment object type",
    )?;
    compare_string_at_path(
        commitment_record,
        &["commitmentId"],
        EVALUATION_KEY_STREAMING_COMMITMENT_ID,
        "evaluation key streaming commitment id",
    )?;
    if usize_at_path(commitment_record, &["chunkSizeBytes"])? != EVALUATION_KEY_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidChunkSize,
            "evaluation key streaming commitment chunk size changed",
        ));
    }
    let stream_record = value_at_path(commitment_record, &["streamRecord"])?;
    let stream_bytes = canonical_json(stream_record)?.into_bytes();
    if usize_at_path(commitment_record, &["canonicalStreamByteLength"])? != stream_bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation key streaming commitment byte length does not match its stream record",
        ));
    }
    compare_hash_at_path(
        commitment_record,
        &["chunkRoot"],
        &chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?,
        "evaluation key streaming commitment chunk root",
    )?;
    let total_evaluation_key_byte_estimate = usize_at_path(
        commitment_record,
        &["storageQuotaDecision", "totalEvaluationKeyByteEstimate"],
    )?;
    let quota_bytes = usize_at_path(commitment_record, &["storageQuotaDecision", "quotaBytes"])?;
    let accepted = bool_at_path(commitment_record, &["storageQuotaDecision", "accepted"])?;
    if accepted != (total_evaluation_key_byte_estimate <= quota_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation key streaming commitment storage quota decision is inconsistent",
        ));
    }
    let commitment_hash = derive_protocol_hash("EvaluationKeySetHash", commitment_record)?;
    compare_hash_at_path(
        wrapped_commitment,
        &["commitmentHash"],
        &commitment_hash,
        "evaluation key streaming commitment hash",
    )?;

    Ok(commitment_hash)
}

fn validate_development_encryption_fixture(setup_package: &Value) -> CanonicalResult<()> {
    let fixture_record =
        value_at_path(setup_package, &["developmentEncryptionFixture", "fixture"])?;
    compare_string_at_path(
        fixture_record,
        &["fixtureScope"],
        "development-collective-public-key-encryption-fixture",
        "development encryption fixture scope",
    )?;
    if bool_at_path(fixture_record, &["directProofClaim"])?
        || bool_at_path(fixture_record, &["directEvaluatorReplayClaim"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "development encryption fixture must not claim direct proof or evaluator replay closure",
        ));
    }
    compare_hash_at_path(
        fixture_record,
        &["collectivePublicKeyRoot"],
        hash_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "development encryption collective public key root",
    )?;
    compare_hash_at_path(
        fixture_record,
        &["bgvPublicKeyRoot"],
        hash_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "development encryption BGV public key root",
    )?;
    hash_at_path(fixture_record, &["publicKeyMaterialRoot"])?;
    hash_at_path(fixture_record, &["randomnessRoot"])?;
    hash_at_path(fixture_record, &["plaintextRoot"])?;
    hash_at_path(fixture_record, &["ciphertextRoot"])?;
    hash_at_path(fixture_record, &["canonicalBytesHash512"])?;
    if unsigned_at_path(fixture_record, &["canonicalByteLength"])? == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "development encryption fixture canonical byte length must be non-zero",
        ));
    }
    for relation_check in array_at_path(fixture_record, &["sampledPublicRelationChecks"])? {
        if !bool_at_path(relation_check, &["relationMatches"])? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "development encryption fixture contains a failed public relation check",
            ));
        }
    }

    Ok(())
}
