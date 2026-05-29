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
    let evaluation_key_streaming_fixture_hash =
        validate_evaluation_key_streaming_fixture(certificates)?;
    compare_hash_at_path(
        value_at_path(certificates, &["setupParameterCertificate"])?,
        &["evaluationKeyStreamingFixtureHash"],
        &evaluation_key_streaming_fixture_hash,
        "setup parameter evaluation key streaming fixture hash",
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

fn validate_evaluation_key_streaming_fixture(certificates: &Value) -> CanonicalResult<String> {
    let wrapped_fixture = value_at_path(certificates, &["evaluationKeyStreamingFixture"])?;
    let fixture_record = value_at_path(wrapped_fixture, &["fixture"])?;
    compare_string_at_path(
        fixture_record,
        &["objectType"],
        "BgvEvaluationKeyStreamingFixture",
        "evaluation key streaming fixture object type",
    )?;
    compare_string_at_path(
        fixture_record,
        &["fixtureId"],
        EVALUATION_KEY_STREAMING_FIXTURE_ID,
        "evaluation key streaming fixture id",
    )?;
    if usize_at_path(fixture_record, &["chunkSizeBytes"])? != EVALUATION_KEY_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidChunkSize,
            "evaluation key streaming fixture chunk size changed",
        ));
    }
    let stream_record = value_at_path(fixture_record, &["streamRecord"])?;
    let stream_bytes = canonical_json(stream_record)?.into_bytes();
    if usize_at_path(fixture_record, &["canonicalStreamByteLength"])? != stream_bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation key streaming fixture byte length does not match its stream record",
        ));
    }
    compare_hash_at_path(
        fixture_record,
        &["chunkRoot"],
        &chunk_root(&stream_bytes, EVALUATION_KEY_CHUNK_SIZE_BYTES)?,
        "evaluation key streaming fixture chunk root",
    )?;
    let total_evaluation_key_byte_estimate = usize_at_path(
        fixture_record,
        &["storageQuotaFixture", "totalEvaluationKeyByteEstimate"],
    )?;
    let quota_bytes = usize_at_path(fixture_record, &["storageQuotaFixture", "quotaBytes"])?;
    let accepted = bool_at_path(fixture_record, &["storageQuotaFixture", "accepted"])?;
    if accepted != (total_evaluation_key_byte_estimate <= quota_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation key streaming fixture storage quota decision is inconsistent",
        ));
    }
    let fixture_hash = development_fixture_hash(fixture_record)?;
    compare_hash_at_path(
        wrapped_fixture,
        &["fixtureHash"],
        &fixture_hash,
        "evaluation key streaming fixture hash",
    )?;

    Ok(fixture_hash)
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
    if bool_at_path(fixture_record, &["bridgeEncryptionClaim"])?
        || bool_at_path(fixture_record, &["encryptedAggregateEvaluatorClaim"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "development encryption fixture must not claim encrypted aggregate bridge or encrypted aggregate evaluator closure",
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
