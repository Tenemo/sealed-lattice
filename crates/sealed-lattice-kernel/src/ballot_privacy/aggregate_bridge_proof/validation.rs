use super::*;

pub(super) const BRIDGE_PROVER_RANDOMNESS_BYTE_LENGTH: usize = 32;
const MAX_BRIDGE_PROOF_BYTE_LENGTH: usize = 96 * 1024 * 1024;

pub(super) fn validate_hex_field(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            format!("{field_name} must be non-empty even-length hex"),
        ));
    }
    decode_hex(value)?;

    Ok(())
}

pub(super) fn validate_prover_randomness_hex(value: &str) -> CanonicalResult<()> {
    validate_hex_field(value, "proverRandomnessHex")?;
    if value.len() != BRIDGE_PROVER_RANDOMNESS_BYTE_LENGTH * 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "proverRandomnessHex must encode exactly 32 bytes",
        ));
    }

    Ok(())
}

pub(super) fn required_protocol_digest_field<'value>(
    value: &'value Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<&'value str> {
    let digest = required_string_field(value, field_name, object_name)?;
    if !is_protocol_digest(digest) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_name}.{field_name} must be a nonzero lowercase protocol digest"),
        ));
    }

    Ok(digest)
}

pub(super) fn parse_bridge_proof_value(proof_bytes_hex: &str) -> CanonicalResult<Value> {
    validate_hex_field(proof_bytes_hex, "bridgeProofBytesHex")?;
    if proof_bytes_hex.len() / 2 > MAX_BRIDGE_PROOF_BYTE_LENGTH {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "bridgeProofBytesHex exceeds the supported bridge proof byte limit",
        ));
    }
    let proof_bytes = decode_hex(proof_bytes_hex)?;
    let proof_json = std::str::from_utf8(&proof_bytes).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("M9 bridge proof bytes are not UTF-8 JSON: {error}"),
        )
    })?;
    let proof_value: Value = serde_json::from_str(proof_json).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("M9 bridge proof bytes are not canonical JSON: {error}"),
        )
    })?;
    if canonical_json(&proof_value)?.as_bytes() != proof_bytes.as_slice() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge proof bytes must use canonical JSON encoding",
        ));
    }

    Ok(proof_value)
}

pub(super) fn require_equal_string(
    value: &Value,
    field_name: &str,
    expected_value: &str,
    label: &str,
) -> CanonicalResult<()> {
    let actual_value = required_string_field(value, field_name, label)?;
    if actual_value != expected_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M9 bridge {label} does not match the expected binding"),
        ));
    }

    Ok(())
}

pub(super) fn require_equal_u64(
    value: &Value,
    field_name: &str,
    expected_value: u64,
    label: &str,
) -> CanonicalResult<()> {
    let actual_value = read_u64_object_field(value, field_name, label)?;
    if actual_value != expected_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M9 bridge {label} does not match the expected binding"),
        ));
    }

    Ok(())
}

pub(super) fn require_matching_string_field(
    value: &Value,
    field_name: &str,
    expected_value: &str,
    label: &str,
) -> CanonicalResult<()> {
    let actual_value = required_string_field(value, field_name, label)?;
    if actual_value != expected_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M9 bridge statement {label} does not match its source object"),
        ));
    }

    Ok(())
}

pub(super) fn required_string_at_path<'a>(
    value: &'a Value,
    path: &[&str],
    object_name: &str,
) -> CanonicalResult<&'a str> {
    let mut current_value = value;
    for path_component in path {
        current_value = current_value.get(path_component).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{} is required", path.join(".")),
            )
        })?;
    }

    current_value.as_str().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_name}.{} must be a string", path.join(".")),
        )
    })
}

pub(super) fn read_u64_at_path(
    value: &Value,
    path: &[&str],
    object_name: &str,
) -> CanonicalResult<u64> {
    let mut current_value = value;
    for path_component in path {
        current_value = current_value.get(path_component).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{} is required", path.join(".")),
            )
        })?;
    }

    current_value.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{object_name}.{} must be a non-negative integer",
                path.join(".")
            ),
        )
    })
}

pub(super) fn validate_bridge_private_material_disclosure(
    proof_value: &Value,
) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(proof_value, "bridgeProof")?;
    let disclosure = required_json_field(proof_value, "privateMaterialDisclosure", "bridgeProof")?;

    validate_bridge_private_material_disclosure_flags(disclosure, "bridgeProof")
}

pub(super) fn validate_bridge_proof_public_shell(proof_value: &Value) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(proof_value, "bridgeProof")?;
    match string_field(proof_value, "objectType") {
        Some("SealedLatticeAggregateBridgeRelationProof") => {
            reject_unexpected_bridge_proof_fields(
                proof_value,
                "bridgeProof",
                &[
                    "aggregateDerivationComponentDigest",
                    "aggregateDerivationStatementDigest",
                    "aggregateQuotientCoordinateCount",
                    "aggregateReducedCoordinateCount",
                    "aggregateRelationChallengeHex",
                    "aggregateRelationCommitmentDigest",
                    "aggregateRelationSubproofHex",
                    "aggregateRelationSubproofSizeBytes",
                    "bgvEncryptionProofSubrelation",
                    "bgvPublicKeyRoot",
                    "bgvRandomnessBoundProofStatusDigest",
                    "bgvRandomnessBoundProofStatusEvidence",
                    "bridgeClaimClosureVerified",
                    "bridgeClaimVerificationStatus",
                    "bridgeProofProfileDigest",
                    "bridgeProofStatement",
                    "bridgeProofStatementDigest",
                    "bridgeProofTargetContractDigest",
                    "bridgeSharedWitnessProof",
                    "bridgeSharedWitnessProofDigest",
                    "bridgeVariantEvidenceStatus",
                    "ciphertextRoot",
                    "collectivePublicKeyRoot",
                    "encryptedAggregateInputRoot",
                    "encryptedAggregateShareCiphertextRoot",
                    "finalBridgeTheoremClosure",
                    "objectType",
                    "objectVersion",
                    "plaintextRoot",
                    "postVotingClosedContextDigest",
                    "privateMaterialDisclosure",
                    "profileId",
                    "proofBackend",
                    "proverRandomnessPublicDigest",
                    "relationScope",
                    "scopedBridgeRelationClosure",
                    "sharedWitnessZeroKnowledgeStatusDigest",
                    "sharedWitnessZeroKnowledgeStatusEvidence",
                    "singleContributionBridgeRelationChecked",
                ],
            )?;
            required_json_field(proof_value, "bridgeSharedWitnessProof", "bridgeProof")?;
        }
        Some("SealedLatticeAggregateBridgeEncryptionEvidence") => {
            reject_unexpected_bridge_proof_fields(
                proof_value,
                "bridgeProof",
                &[
                    "bridgeRelationGapStatus",
                    "objectType",
                    "privateMaterialDisclosure",
                ],
            )?;
            validate_bridge_relation_gap_status(proof_value)?;
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge proof object type is not supported",
            ));
        }
    }
    validate_bridge_private_material_disclosure(proof_value)
}

fn reject_unexpected_bridge_proof_fields(
    value: &Value,
    path: &str,
    allowed_fields: &[&str],
) -> CanonicalResult<()> {
    let object = value.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{path} must be an object"),
        )
    })?;
    for field_name in object.keys() {
        if !allowed_fields.contains(&field_name.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("M9 bridge proof object contains unsupported field {path}.{field_name}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_bridge_relation_gap_status(proof_value: &Value) -> CanonicalResult<()> {
    let relation_gap_status =
        required_json_field(proof_value, "bridgeRelationGapStatus", "bridgeProof")?;
    reject_forbidden_public_bridge_fields(
        relation_gap_status,
        "bridgeProof.bridgeRelationGapStatus",
    )?;
    if string_field(relation_gap_status, "objectType") != Some("AggregateBridgeRelationGapStatus")
        || read_u64_object_field(
            relation_gap_status,
            "objectVersion",
            "bridgeProof.bridgeRelationGapStatus",
        )? != 1
        || relation_gap_status
            .get("scopedBridgeRelationClosure")
            .and_then(Value::as_bool)
            != Some(false)
        || string_field(relation_gap_status, "sharedWitnessBindingStatus")
            != Some(SHARED_WITNESS_BINDING_PENDING_STATUS)
        || string_field(relation_gap_status, "sharedWitnessZeroKnowledgeStatus")
            != Some(SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS)
        || string_field(relation_gap_status, "aggregateToPlaintextBindingStatus")
            != Some(AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS)
        || string_field(relation_gap_status, "bgvEncryptionProofStatus")
            != Some(BGV_ENCRYPTION_PROOF_PENDING_STATUS)
        || string_field(relation_gap_status, "bgvRandomnessBoundProofStatus")
            != Some(BGV_RANDOMNESS_BOUND_PROOF_MISSING_STATUS)
        || string_field(relation_gap_status, "rnsCrtConsistencyProofStatus")
            != Some(RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS)
        || string_field(relation_gap_status, "bridgeClaimClosureStatus")
            != Some(BRIDGE_CLAIM_CLOSURE_STATUS)
        || relation_gap_status
            .get("sampledOnlyBridgeVerificationAccepted")
            .and_then(Value::as_bool)
            != Some(false)
        || string_field(relation_gap_status, "hwangPiopStatus") != Some(HWANG_PIOP_DEFERRED_STATUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof relation gap status must remain pending until the shared-witness proof verifier closes",
        ));
    }

    Ok(())
}

pub(super) fn validate_bridge_encryption_public_shell(
    bridge_encryption: &Value,
) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(bridge_encryption, "bridgeEncryption")?;
    let disclosure = required_json_field(
        bridge_encryption,
        "privateMaterialDisclosure",
        "bridgeEncryption",
    )?;
    validate_bridge_private_material_disclosure_flags(disclosure, "bridgeEncryption")?;
    let bridge_proof_verification_status =
        string_field(bridge_encryption, "bridgeProofVerificationStatus").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "bridgeEncryption.bridgeProofVerificationStatus must be a string",
            )
        })?;
    if bridge_proof_verification_status != BRIDGE_PROOF_PENDING_STATUS
        && bridge_proof_verification_status != BRIDGE_PROOF_CHECKED_STATUS
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge encryption shell has an unsupported bridge proof verification status",
        ));
    }
    validate_sampled_public_relation_check_policy(bridge_encryption)?;

    Ok(())
}

pub(super) fn validate_sampled_public_relation_check_policy(
    bridge_encryption: &Value,
) -> CanonicalResult<()> {
    let relation_checks = required_json_field(
        bridge_encryption,
        "sampledPublicRelationChecks",
        "bridgeEncryption",
    )?
    .as_array()
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "bridgeEncryption.sampledPublicRelationChecks must be an array",
        )
    })?;
    for relation_check in relation_checks {
        if relation_check
            .get("relationMatches")
            .and_then(Value::as_bool)
            != Some(true)
            || relation_check
                .get("acceptedForBridgeProofVerification")
                .and_then(Value::as_bool)
                == Some(true)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge sampled public relation checks are diagnostic only and cannot accept bridge proof verification",
            ));
        }
    }

    let policy = required_json_field(
        bridge_encryption,
        "sampledPublicRelationCheckPolicy",
        "bridgeEncryption",
    )?;
    reject_forbidden_public_bridge_fields(
        policy,
        "bridgeEncryption.sampledPublicRelationCheckPolicy",
    )?;
    if string_field(policy, "objectType") != Some("AggregateBridgeSampledRelationCheckPolicy")
        || read_u64_object_field(
            policy,
            "objectVersion",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )? != 1
        || !read_bool_object_field(
            policy,
            "diagnosticOnly",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || read_bool_object_field(
            policy,
            "acceptedForBridgeProofVerification",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || !read_bool_object_field(
            policy,
            "fullBridgeProofRequired",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || read_bool_object_field(
            policy,
            "sampledOnlyBridgeVerificationAccepted",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || string_field(policy, "relationCheckSource") != Some("first-data-prime-diagnostic")
        || read_u64_object_field(
            policy,
            "sampledRelationCheckCount",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )? != relation_checks.len() as u64
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge sampled public relation check policy must remain diagnostic-only and proof-rejecting",
        ));
    }

    Ok(())
}

pub(super) fn validate_bridge_private_material_disclosure_flags(
    disclosure: &Value,
    object_name: &str,
) -> CanonicalResult<()> {
    for field_name in [
        "aggregateOpeningMaterialExported",
        "aggregateShareMaterialExported",
        "layoutMessageMaterialExported",
        "encodedMessageMaterialExported",
        "encryptionRandomizerMaterialExported",
        "noiseMaterialExported",
    ] {
        if disclosure.get(field_name).and_then(Value::as_bool) != Some(false) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "M9 bridge {object_name} private material disclosure flag {field_name} must be false"
                ),
            ));
        }
    }

    Ok(())
}

pub(super) fn reject_forbidden_public_bridge_fields(
    value: &Value,
    path: &str,
) -> CanonicalResult<()> {
    match value {
        Value::Array(entries) => {
            for (entry_index, entry) in entries.iter().enumerate() {
                reject_forbidden_public_bridge_fields(entry, &format!("{path}[{entry_index}]"))?;
            }
        }
        Value::Object(object) => {
            for (field_name, field_value) in object {
                if forbidden_public_bridge_field_name(field_name) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        format!(
                            "M9 bridge public proof object exposes forbidden field {path}.{field_name}"
                        ),
                    ));
                }
                reject_forbidden_public_bridge_fields(
                    field_value,
                    &format!("{path}.{field_name}"),
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn forbidden_public_bridge_field_name(field_name: &str) -> bool {
    matches!(
        field_name,
        "aggregateIntegerShareVector"
            | "aggregateOpeningRandomness"
            | "aggregateWitness"
            | "aggregateShareWitness"
            | "quotientWitness"
            | "layoutPlaintextWitness"
            | "bgvPlaintext"
            | "encryptionRandomness"
            | "encryptionRandomizer"
            | "encryptionError"
            | "noiseWitness"
            | "sourceWitnessCoefficients"
            | "aggregateHistogram"
            | "aggregateScore"
            | "aggregateScoreBits"
            | "comparisonInputs"
    )
}

pub(super) fn read_bool_object_field(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<bool> {
    value
        .get(field_name)
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be a boolean"),
            )
        })
}

pub(super) fn read_u64_object_field(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be a non-negative integer"),
            )
        })
}

pub(super) fn read_usize_object_field(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<usize> {
    usize::try_from(read_u64_object_field(value, field_name, object_name)?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_name}.{field_name} does not fit usize"),
        )
    })
}

pub(super) fn read_u64_array(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<Vec<u64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be an array"),
            )
        })?
        .iter()
        .map(|entry| {
            entry.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{object_name}.{field_name} entries must be non-negative integers"),
                )
            })
        })
        .collect()
}

pub(super) fn read_i64_array(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<Vec<i64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be an array"),
            )
        })?
        .iter()
        .map(|entry| {
            entry.as_i64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{object_name}.{field_name} entries must be signed integers"),
                )
            })
        })
        .collect()
}
