use super::*;

pub(super) fn validate_setup_certificates(setup_package: &Value) -> CanonicalResult<()> {
    let certificates = value_at_path(setup_package, &["certificates"])?;
    compare_derived_digest(
        "CollectiveSecretDistributionCertificateDigest",
        value_at_path(certificates, &["collectiveSecretDistributionCertificate"])?,
        digest_at_path(
            certificates,
            &["collectiveSecretDistributionCertificateDigest"],
        )?,
        "collective secret distribution certificate digest",
    )?;
    compare_derived_digest(
        "ErrorDistributionCertificateDigest",
        value_at_path(certificates, &["errorDistributionCertificate"])?,
        digest_at_path(certificates, &["errorDistributionCertificateDigest"])?,
        "error distribution certificate digest",
    )?;
    compare_derived_digest(
        "KeySwitchDecompositionDigest",
        value_at_path(certificates, &["keySwitchDecomposition"])?,
        digest_at_path(certificates, &["keySwitchDecompositionDigest"])?,
        "key-switch decomposition digest",
    )?;
    compare_derived_digest(
        "EvaluationKeySizeProfileDigest",
        value_at_path(certificates, &["evaluationKeySizeCertificate"])?,
        digest_at_path(certificates, &["evaluationKeySizeProfileDigest"])?,
        "evaluation key size profile digest",
    )?;
    let evaluation_key_streaming_fixture_digest =
        validate_evaluation_key_streaming_fixture(certificates)?;
    compare_digest_at_path(
        value_at_path(certificates, &["setupParameterCertificate"])?,
        &["evaluationKeyStreamingFixtureDigest"],
        &evaluation_key_streaming_fixture_digest,
        "setup parameter evaluation key streaming fixture digest",
    )?;
    compare_derived_digest(
        "BGVSetupParameterCertificateDigest",
        value_at_path(certificates, &["setupParameterCertificate"])?,
        digest_at_path(certificates, &["setupParameterCertificateDigest"])?,
        "setup parameter certificate digest",
    )?;
    compare_derived_digest(
        "BGVDevelopmentEncryptionFixtureDigest",
        value_at_path(setup_package, &["developmentEncryptionFixture", "fixture"])?,
        digest_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureDigest"],
        )?,
        "development encryption fixture digest",
    )?;
    validate_development_encryption_fixture(setup_package)?;
    compare_digest_at_path(
        certificates,
        &["developmentEncryptionFixtureDigest"],
        digest_at_path(
            setup_package,
            &["developmentEncryptionFixture", "fixtureDigest"],
        )?,
        "certificate development encryption fixture digest",
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
    compare_digest_at_path(
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
    let fixture_digest = development_fixture_digest(fixture_record)?;
    compare_digest_at_path(
        wrapped_fixture,
        &["fixtureDigest"],
        &fixture_digest,
        "evaluation key streaming fixture digest",
    )?;

    Ok(fixture_digest)
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
    if bool_at_path(fixture_record, &["m9BridgeEncryptionClaim"])?
        || bool_at_path(fixture_record, &["m10EvaluatorClaim"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "development encryption fixture must not claim M9 bridge or M10 evaluator closure",
        ));
    }
    compare_digest_at_path(
        fixture_record,
        &["collectivePublicKeyRoot"],
        digest_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?,
        "development encryption collective public key root",
    )?;
    compare_digest_at_path(
        fixture_record,
        &["bgvPublicKeyRoot"],
        digest_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?,
        "development encryption BGV public key root",
    )?;
    digest_at_path(fixture_record, &["publicKeyMaterialRoot"])?;
    digest_at_path(fixture_record, &["randomnessRoot"])?;
    digest_at_path(fixture_record, &["plaintextRoot"])?;
    digest_at_path(fixture_record, &["ciphertextRoot"])?;
    digest_at_path(fixture_record, &["canonicalBytesHash512"])?;
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
