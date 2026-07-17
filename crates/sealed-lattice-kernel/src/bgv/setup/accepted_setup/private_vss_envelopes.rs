use super::*;

use crate::hashing::derive_canonical_object_hash;

#[derive(Clone)]
pub(super) struct PrivateVssEnvelopeBinding {
    pub(super) source_trustee_identity: String,
    pub(super) recipient_identity: String,
    pub(super) source_trustee_commitment_root: String,
    pub(super) private_envelope_hash: String,
}

pub(super) type PrivateVssEnvelopeBindingMap = BTreeMap<(u64, u64), PrivateVssEnvelopeBinding>;

pub(super) fn verify_private_vss_envelope_commitments(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(commitment_set) = setup_package.get("privateVssEnvelopeCommitments") else {
        return Ok(Some(setup_refusals(
            vec!["privateVssEnvelopeCommitments".to_string()],
            Vec::new(),
        )));
    };
    if !commitment_set.is_object() {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "privateVssEnvelopeCommitmentsNotObject",
            "privateVssEnvelopeCommitments must be a root-bound object, not an array or scalar",
        )));
    }
    if commitment_set.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE)
    {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEnvelopeCommitmentSetTypeMismatch",
            "privateVssEnvelopeCommitments.objectType must be PrivateVssEnvelopeCommitmentSet",
        )));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setupContext was required before private VSS envelope verification",
        )
    })?;
    let roster = super::accepted_roster_from_package(setup_package)?;
    let expected_envelope_count = roster.participant_count * roster.participant_count;
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        &source_trustee_commitment_roots,
    )? {
        Ok(bindings) => {
            if bindings.len() != expected_envelope_count as usize {
                return Ok(Some(single_refusal(
                    crate::foundation::RefusalReason::WrongTypeOrLength,
                    "privateVssEnvelopeCountMismatch",
                    "privateVssEnvelopeCommitments.envelopeReferences must cover every source-trustee-recipient trustee pair",
                )));
            }
        }
        Err(refusal) => {
            return Ok(Some(setup_refusals(Vec::new(), vec![refusal])));
        }
    }

    Ok(None)
}

pub(super) fn private_vss_envelope_commitment_root(
    setup_package: &Value,
) -> CanonicalResult<String> {
    let commitment_set = setup_package
        .get("privateVssEnvelopeCommitments")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "private VSS envelope commitments are required",
            )
        })?;
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setup context is required for the private VSS envelope commitment root",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "public matrix seed hash is required for the private VSS envelope commitment root",
            )
        })?;
    let vss_coefficient_commitment_root = accepted_vss_coefficient_commitment_root(setup_package)?;
    let envelope_references = array_at_path(commitment_set, &["envelopeReferences"])?
        .iter()
        .map(|reference| {
            compare_required_string(
                string_at_path(reference, &["objectType"])?,
                PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE,
                "private VSS envelope commitment objectType",
            )?;
            Ok(json!({
                "objectType": PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE,
                "sourceTrusteeRosterPosition": unsigned_at_path(reference, &["sourceTrusteeRosterPosition"])?,
                "recipientRosterPosition": unsigned_at_path(reference, &["recipientRosterPosition"])?,
                "privateEnvelopeHash": hash_at_path(reference, &["privateEnvelopeHash"])?,
                "encryptedEnvelopeHash": hash_at_path(reference, &["encryptedEnvelopeHash"])?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    derive_canonical_object_hash(&json!({
        "objectType": PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE,
        "setupContextHash": setup_context_hash(setup_context)?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "envelopeReferences": envelope_references,
    }))
}

pub(super) fn private_vss_envelope_bindings_from_package(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<PrivateVssEnvelopeBindingMap> {
    let commitment_set = setup_package
        .get("privateVssEnvelopeCommitments")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "privateVssEnvelopeCommitments was required before private VSS binding extraction",
            )
        })?;
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "setupContext was required before private VSS binding extraction",
        )
    })?;
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        &source_trustee_commitment_roots,
    )? {
        Ok(bindings) => Ok(bindings),
        Err(refusal) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            refusal.message,
        )),
    }
}

fn private_vss_envelope_bindings_from_set(
    commitment_set: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
) -> CanonicalResult<Result<PrivateVssEnvelopeBindingMap, Refusal>> {
    let Some(envelope_references) = commitment_set
        .get("envelopeReferences")
        .and_then(Value::as_array)
    else {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "privateVssEnvelopeReferencesMissing",
            "privateVssEnvelopeCommitments.envelopeReferences must contain every source-trustee-recipient envelope commitment",
        )));
    };
    let roster = super::accepted_roster_from_setup_context(setup_context)?;
    let expected_envelope_count = (roster.participant_count * roster.participant_count) as usize;
    if envelope_references.len() != expected_envelope_count {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEnvelopeReferenceCountMismatch",
            "privateVssEnvelopeCommitments.envelopeReferences must contain one record for every source-trustee-recipient trustee pair",
        )));
    }

    let mut bindings = BTreeMap::new();
    for envelope_reference in envelope_references {
        let binding = match private_vss_envelope_binding_from_reference(
            envelope_reference,
            expected_trustees,
            source_trustee_commitment_roots,
        )? {
            Ok(binding) => binding,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source_trustee_roster_position =
            value_u64(envelope_reference, "sourceTrusteeRosterPosition")?;
        let recipient_roster_position = value_u64(envelope_reference, "recipientRosterPosition")?;
        if bindings
            .insert(
                (source_trustee_roster_position, recipient_roster_position),
                binding,
            )
            .is_some()
        {
            return Ok(Err(Refusal::new(
                crate::foundation::RefusalReason::Equivocation,
                "privateVssEnvelopeReferenceDuplicate",
                "privateVssEnvelopeCommitments.envelopeReferences must have distinct source-trustee-recipient trustee pairs",
            )));
        }
    }

    Ok(Ok(bindings))
}

fn private_vss_envelope_binding_from_reference(
    envelope_reference: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
) -> CanonicalResult<Result<PrivateVssEnvelopeBinding, Refusal>> {
    if envelope_reference.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEnvelopeReferenceTypeMismatch",
            "private VSS envelope commitment objectType must be PrivateVssEnvelopeCommitment",
        )));
    }
    let source_trustee_roster_position = match envelope_reference
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "privateVssEnvelopeSourceTrusteePositionMissing",
                "private VSS envelope commitment must bind sourceTrusteeRosterPosition",
            )));
        }
    };
    let Some(source_trustee_identity) = expected_trustees.get(&source_trustee_roster_position)
    else {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongContext,
            "privateVssEnvelopeSourceTrusteeMismatch",
            "private VSS envelope commitment source roster position must identify a setup-intent trustee",
        )));
    };
    let recipient_roster_position = match envelope_reference
        .get("recipientRosterPosition")
        .and_then(Value::as_u64)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "privateVssEnvelopeRecipientPositionMissing",
                "private VSS envelope commitment must bind recipientRosterPosition",
            )));
        }
    };
    let Some(recipient_identity) = expected_trustees.get(&recipient_roster_position) else {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongContext,
            "privateVssEnvelopeRecipientMismatch",
            "private VSS envelope commitment recipient roster position must identify a setup-intent trustee",
        )));
    };
    let expected_source_trustee_commitment_root = match source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
    {
        Some(value) => value,
        None => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "source trustee commitment root missing for private VSS envelope verification",
            ));
        }
    };
    for field_name in ["privateEnvelopeHash", "encryptedEnvelopeHash"] {
        let Some(hash) = envelope_reference.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "privateVssEnvelopeHashMissing",
                format!("private VSS envelope commitment must bind {field_name}"),
            )));
        };
        validate_hash_string(
            hash,
            &format!("privateVssEnvelopeCommitments.envelopeReferences.{field_name}"),
        )?;
    }

    if let Some(encrypted_envelope) = envelope_reference.get("encryptedEnvelope")
        && let Err(refusal) = verify_encrypted_private_vss_envelope(
            encrypted_envelope,
            value_string(envelope_reference, "encryptedEnvelopeHash")?,
        )?
    {
        return Ok(Err(refusal));
    }

    Ok(Ok(PrivateVssEnvelopeBinding {
        source_trustee_identity: source_trustee_identity.to_string(),
        recipient_identity: recipient_identity.to_string(),
        source_trustee_commitment_root: expected_source_trustee_commitment_root.to_string(),
        private_envelope_hash: value_string(envelope_reference, "privateEnvelopeHash")?.to_string(),
    }))
}

fn verify_encrypted_private_vss_envelope(
    encrypted_envelope: &Value,
    encrypted_envelope_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    if !encrypted_envelope.is_object() {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::MalformedEncoding,
            "privateVssEncryptedEnvelopeNotObject",
            "encryptedEnvelope must be a root-bound object",
        )));
    }
    if encrypted_envelope.get("objectType").and_then(Value::as_str)
        != Some(ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEncryptedEnvelopeTypeMismatch",
            "encryptedEnvelope.objectType must be EncryptedPrivateVssShareEnvelope",
        )));
    }
    let Some(kem_ciphertext_bytes_hex) = encrypted_envelope
        .get("kemCiphertextBytesHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "privateVssEncryptedEnvelopeCiphertextMissing",
            "encryptedEnvelope.kemCiphertextBytesHex must be present",
        )));
    };
    validate_lowercase_hex_length(
        kem_ciphertext_bytes_hex,
        1088,
        "encryptedEnvelope.kemCiphertextBytesHex",
    )?;
    let Some(aead_nonce_hex) = encrypted_envelope
        .get("aeadNonceHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "privateVssEncryptedEnvelopeNonceMissing",
            "encryptedEnvelope.aeadNonceHex must be present",
        )));
    };
    validate_lowercase_hex_length(aead_nonce_hex, 12, "encryptedEnvelope.aeadNonceHex")?;
    let Some(ciphertext_bytes_hex) = encrypted_envelope
        .get("ciphertextBytesHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "privateVssEncryptedEnvelopeCiphertextMissing",
            "encryptedEnvelope.ciphertextBytesHex must be present",
        )));
    };
    validate_lowercase_hex(ciphertext_bytes_hex, "encryptedEnvelope.ciphertextBytesHex")?;

    let expected_encrypted_envelope_hash = derive_canonical_object_hash(&json!({
        "objectType": ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE,
        "kemCiphertextBytesHex": kem_ciphertext_bytes_hex,
        "aeadNonceHex": aead_nonce_hex,
        "ciphertextBytesHex": ciphertext_bytes_hex,
    }))?;
    if encrypted_envelope_hash != expected_encrypted_envelope_hash {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "privateVssEncryptedEnvelopeHashMismatch",
            "encryptedEnvelopeHash does not match the canonical encrypted private VSS envelope object",
        )));
    }

    Ok(Ok(()))
}
