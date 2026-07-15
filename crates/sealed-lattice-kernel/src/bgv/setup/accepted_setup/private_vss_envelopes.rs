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
        return Ok(Some(private_vss_envelope_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "privateVssEnvelopeCommitmentsNotObject",
            "privateVssEnvelopeCommitments must be a root-bound object, not an array or scalar",
            "setupPackage.privateVssEnvelopeCommitments",
        )?));
    }
    if commitment_set.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE)
    {
        return Ok(Some(private_vss_envelope_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEnvelopeCommitmentSetTypeMismatch",
            "privateVssEnvelopeCommitments.objectType must be PrivateVssEnvelopeCommitmentSet",
            "setupPackage.privateVssEnvelopeCommitments.objectType",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before private VSS envelope verification",
        )
    })?;
    let roster = super::accepted_roster_from_package(setup_package)?;
    let expected_envelope_count = roster.participant_count * roster.participant_count;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before private VSS envelope verification",
            )
        })?;
    let vss_coefficient_commitment_root = accepted_vss_coefficient_commitment_root(setup_package)?;
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        trustee_registrations,
        &source_trustee_commitment_roots,
        public_matrix_seed_hash,
        &vss_coefficient_commitment_root,
    )? {
        Ok(bindings) => {
            if bindings.len() != expected_envelope_count as usize {
                return Ok(Some(private_vss_envelope_refusal(
                    crate::foundation::RefusalReason::WrongTypeOrLength,
                    "privateVssEnvelopeCountMismatch",
                    "privateVssEnvelopeCommitments.envelopeReferences must cover every source-trustee-recipient trustee pair",
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
                )?));
            }
        }
        Err(refusal) => {
            return Ok(Some(private_vss_envelope_refusal(
                refusal.refusal_reason,
                refusal.reason_code,
                refusal.message,
                refusal.object_path,
            )?));
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
                CanonicalErrorCode::InvalidFixture,
                "private VSS envelope commitments are required",
            )
        })?;
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setup context is required for the private VSS envelope commitment root",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
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
                "sourceTrusteeIdentity": string_at_path(reference, &["sourceTrusteeIdentity"])?,
                "sourceTrusteeRosterPosition": unsigned_at_path(reference, &["sourceTrusteeRosterPosition"])?,
                "recipientIdentity": string_at_path(reference, &["recipientIdentity"])?,
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
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitments was required before private VSS binding extraction",
            )
        })?;
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before private VSS binding extraction",
        )
    })?;
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before private VSS binding extraction",
            )
        })?;
    let vss_coefficient_commitment_root = accepted_vss_coefficient_commitment_root(setup_package)?;

    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        trustee_registrations,
        &source_trustee_commitment_roots,
        public_matrix_seed_hash,
        &vss_coefficient_commitment_root,
    )? {
        Ok(bindings) => Ok(bindings),
        Err(refusal) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            refusal.message,
        )),
    }
}

fn private_vss_envelope_bindings_from_set(
    commitment_set: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
) -> CanonicalResult<Result<PrivateVssEnvelopeBindingMap, Refusal>> {
    let Some(envelope_references) = commitment_set
        .get("envelopeReferences")
        .and_then(Value::as_array)
    else {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "privateVssEnvelopeReferencesMissing",
            "privateVssEnvelopeCommitments.envelopeReferences must contain every source-trustee-recipient envelope commitment",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
        )));
    };
    let roster = super::accepted_roster_from_setup_context(setup_context)?;
    let expected_envelope_count = (roster.participant_count * roster.participant_count) as usize;
    if envelope_references.len() != expected_envelope_count {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEnvelopeReferenceCountMismatch",
            "privateVssEnvelopeCommitments.envelopeReferences must contain one record for every source-trustee-recipient trustee pair",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
        )));
    }

    let mut bindings = BTreeMap::new();
    for envelope_reference in envelope_references {
        let binding = match private_vss_envelope_binding_from_reference(
            envelope_reference,
            setup_context,
            expected_trustees,
            trustee_registrations,
            source_trustee_commitment_roots,
            public_matrix_seed_hash,
            vss_coefficient_commitment_root,
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
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
            )));
        }
    }

    Ok(Ok(bindings))
}

fn private_vss_envelope_binding_from_reference(
    envelope_reference: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
) -> CanonicalResult<Result<PrivateVssEnvelopeBinding, Refusal>> {
    if envelope_reference.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEnvelopeReferenceTypeMismatch",
            "private VSS envelope commitment objectType must be PrivateVssEnvelopeCommitment",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.objectType",
        )));
    }
    let source_trustee_identity = match envelope_reference
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "privateVssEnvelopeSourceTrusteeMissing",
                "private VSS envelope commitment must bind sourceTrusteeIdentity",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeIdentity",
            )));
        }
    };
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
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeRosterPosition",
            )));
        }
    };
    if expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongContext,
            "privateVssEnvelopeSourceTrusteeMismatch",
            "private VSS envelope commitment source trustee must match the setup-intent trustee identity",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeIdentity",
        )));
    }

    let recipient_identity = match envelope_reference
        .get("recipientIdentity")
        .and_then(Value::as_str)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "privateVssEnvelopeRecipientMissing",
                "private VSS envelope commitment must bind recipientIdentity",
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientIdentity",
            )));
        }
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
                "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientRosterPosition",
            )));
        }
    };
    if expected_trustees
        .get(&recipient_roster_position)
        .map(String::as_str)
        != Some(recipient_identity)
    {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongContext,
            "privateVssEnvelopeRecipientMismatch",
            "private VSS envelope commitment recipient must match the setup-intent trustee identity",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientIdentity",
        )));
    }
    let Some(expected_recipient_registration) =
        trustee_registrations.get(&recipient_roster_position)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupIntent mailbox public key binding missing for private VSS envelope recipient",
        ));
    };
    let expected_recipient_mailbox_public_key_hash = expected_recipient_registration
        .private_vss_mailbox_public_key_hash
        .as_str();
    let expected_source_trustee_commitment_root = match source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
    {
        Some(value) => value,
        None => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
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
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.{field_name}"
                ),
            )));
        };
        validate_hash_string(
            hash,
            &format!("privateVssEnvelopeCommitments.envelopeReferences.{field_name}"),
        )?;
    }

    let expected_aad = private_vss_envelope_aad_value(
        setup_context,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
        source_trustee_identity,
        source_trustee_roster_position,
        recipient_identity,
        recipient_roster_position,
        expected_source_trustee_commitment_root,
    )?;
    if let Some(encrypted_envelope) = envelope_reference.get("encryptedEnvelope")
        && let Err(refusal) = verify_encrypted_private_vss_envelope(
            encrypted_envelope,
            &expected_aad,
            expected_recipient_mailbox_public_key_hash,
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
    expected_aad: &Value,
    expected_recipient_mailbox_public_key_hash: &str,
    encrypted_envelope_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    if !encrypted_envelope.is_object() {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::MalformedEncoding,
            "privateVssEncryptedEnvelopeNotObject",
            "encryptedEnvelope must be a root-bound object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope",
        )));
    }
    if encrypted_envelope.get("objectType").and_then(Value::as_str)
        != Some(ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "privateVssEncryptedEnvelopeTypeMismatch",
            "encryptedEnvelope.objectType must be EncryptedPrivateVssShareEnvelope",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.objectType",
        )));
    }
    if encrypted_envelope
        .get("recipientMailboxPublicKeyHash")
        .and_then(Value::as_str)
        != Some(expected_recipient_mailbox_public_key_hash)
    {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "privateVssEncryptedEnvelopeBindingMismatch",
            "encryptedEnvelope.recipientMailboxPublicKeyHash must match the accepted recipient mailbox key",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.recipientMailboxPublicKeyHash",
        )));
    }
    if encrypted_envelope.get("privateEnvelopeAad") != Some(expected_aad) {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "privateVssEncryptedEnvelopeAadMismatch",
            "encryptedEnvelope.privateEnvelopeAad must match the accepted private envelope associated-data object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.privateEnvelopeAad",
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
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.kemCiphertextBytesHex",
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
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.aeadNonceHex",
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
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.ciphertextBytesHex",
        )));
    };
    validate_lowercase_hex(ciphertext_bytes_hex, "encryptedEnvelope.ciphertextBytesHex")?;

    let expected_encrypted_envelope_hash = derive_canonical_object_hash(encrypted_envelope)?;
    if encrypted_envelope_hash != expected_encrypted_envelope_hash {
        return Ok(Err(Refusal::new(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "privateVssEncryptedEnvelopeHashMismatch",
            "encryptedEnvelopeHash does not match the canonical encrypted private VSS envelope object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelopeHash",
        )));
    }

    Ok(Ok(()))
}

#[allow(clippy::too_many_arguments)]
fn private_vss_envelope_aad_value(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    recipient_identity: &str,
    recipient_roster_position: u64,
    source_trustee_commitment_root: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": PRIVATE_VSS_ENVELOPE_AAD_OBJECT_TYPE,
        "setupContextHash": setup_context_hash(setup_context)?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
    }))
}

fn private_vss_envelope_refusal(
    refusal_reason: crate::foundation::RefusalReason,
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Refusals> {
    Ok(setup_refusals(
        Vec::new(),
        vec![Refusal::new(
            refusal_reason,
            reason_code,
            message,
            object_path,
        )],
    ))
}
