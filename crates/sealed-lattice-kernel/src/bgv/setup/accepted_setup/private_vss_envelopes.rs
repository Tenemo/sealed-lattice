use super::*;

#[derive(Clone)]
pub(super) struct PrivateVssEnvelopeBinding {
    pub(super) source_trustee_identity: String,
    pub(super) recipient_identity: String,
    pub(super) source_trustee_commitment_root: String,
    pub(super) private_envelope_hash: String,
    pub(super) local_verification_root: String,
}

pub(super) type PrivateVssEnvelopeBindingMap = BTreeMap<(u64, u64), PrivateVssEnvelopeBinding>;

struct MailboxPublicKeyBinding {
    public_key_hash: String,
    public_key_bytes_hash: String,
}

fn setup_intent_mailbox_public_key_bindings_from_phase_transcript(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, MailboxPublicKeyBinding>> {
    let phase_transcript = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phaseTranscript was required before mailbox key binding verification",
            )
        })?;
    let setup_intent_phase = phase_transcript
        .iter()
        .find(|phase| phase.get("phaseId").and_then(Value::as_str) == Some("setupIntent"))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent phase was required before mailbox key binding verification",
            )
        })?;
    let participants = setup_intent_phase
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent participant objects were required before mailbox key binding verification",
            )
        })?;
    let mut mailbox_public_key_bindings = BTreeMap::new();
    for participant in participants {
        let roster_position = participant
            .get("rosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind rosterPosition",
                )
            })?;
        let public_key_hash = participant
            .get("privateVssMailboxPublicKeyHash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind privateVssMailboxPublicKeyHash",
                )
            })?;
        let public_key_bytes_hash = participant
            .get("privateVssMailboxPublicKeyBytesHash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind privateVssMailboxPublicKeyBytesHash",
                )
            })?;
        mailbox_public_key_bindings.insert(
            roster_position,
            MailboxPublicKeyBinding {
                public_key_hash: public_key_hash.to_string(),
                public_key_bytes_hash: public_key_bytes_hash.to_string(),
            },
        );
    }

    Ok(mailbox_public_key_bindings)
}

pub(super) fn verify_private_vss_envelope_commitments(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(commitment_set) = setup_package.get("privateVssEnvelopeCommitments") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("privateVssEnvelopeDelivery"),
            vec!["privateVssEnvelopeCommitments".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !commitment_set.is_object() {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentsNotObject",
            "privateVssEnvelopeCommitments must be a root-bound object, not an array or scalar",
            "setupPackage.privateVssEnvelopeCommitments",
        )?));
    }
    if commitment_set.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_SET_OBJECT_TYPE)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentSetTypeMismatch",
            "privateVssEnvelopeCommitments.objectType must be PrivateVssEnvelopeCommitmentSet",
            "setupPackage.privateVssEnvelopeCommitments.objectType",
        )?));
    }
    if commitment_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentSetVersionMismatch",
            "privateVssEnvelopeCommitments.objectVersion must be 1",
            "setupPackage.privateVssEnvelopeCommitments.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before private VSS envelope verification",
        )
    })?;
    if let Err(refusal) = verify_private_vss_envelope_context(
        commitment_set,
        setup_context,
        "setupPackage.privateVssEnvelopeCommitments",
    ) {
        return Ok(Some(private_vss_envelope_refusal(
            refusal.reason_code,
            refusal.message,
            refusal
                .object_path
                .unwrap_or_else(|| "setupPackage.privateVssEnvelopeCommitments".to_string()),
        )?));
    }

    let Some(package_root) = setup_package
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("privateVssEnvelopeDelivery"),
            vec!["privateVssEnvelopeCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(package_root, "privateVssEnvelopeCommitmentRoot")?;
    let Some(set_root) = commitment_set
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("privateVssEnvelopeDelivery"),
            vec!["privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        set_root,
        "privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
    )?;
    if set_root != package_root {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentRootMismatch",
            "privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot must match setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    if commitment_set
        .get("mailboxEncryptionProfileId")
        .and_then(Value::as_str)
        != Some(PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeMailboxProfileMismatch",
            "privateVssEnvelopeCommitments.mailboxEncryptionProfileId must match the accepted private VSS mailbox profile",
            "setupPackage.privateVssEnvelopeCommitments.mailboxEncryptionProfileId",
        )?));
    }
    let roster = super::accepted_roster_from_package(setup_package);
    if commitment_set
        .get("participantCount")
        .and_then(Value::as_u64)
        != Some(roster.participant_count)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeParticipantCountMismatch",
            "privateVssEnvelopeCommitments.participantCount must match the accepted setup profile",
            "setupPackage.privateVssEnvelopeCommitments.participantCount",
        )?));
    }
    let expected_envelope_count = roster.participant_count * roster.participant_count;
    if commitment_set.get("envelopeCount").and_then(Value::as_u64) != Some(expected_envelope_count)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCountMismatch",
            "privateVssEnvelopeCommitments.envelopeCount must cover every source-trustee-recipient trustee pair",
            "setupPackage.privateVssEnvelopeCommitments.envelopeCount",
        )?));
    }
    if commitment_set
        .get("deliveryPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeDeliveryPhaseMismatch",
            "privateVssEnvelopeCommitments.deliveryPhaseNumber must match the private envelope delivery phase",
            "setupPackage.privateVssEnvelopeCommitments.deliveryPhaseNumber",
        )?));
    }
    if commitment_set
        .get("verificationPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeVerificationPhaseMismatch",
            "privateVssEnvelopeCommitments.verificationPhaseNumber must match the recipient verification phase",
            "setupPackage.privateVssEnvelopeCommitments.verificationPhaseNumber",
        )?));
    }

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
    if commitment_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopePublicMatrixSeedMismatch",
            "privateVssEnvelopeCommitments.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash",
            "setupPackage.privateVssEnvelopeCommitments.publicMatrixSeedHash",
        )?));
    }
    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitments.vssCoefficientCommitmentRoot was required before private VSS envelope verification",
            )
        })?;
    if commitment_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeVssCommitmentRootMismatch",
            "privateVssEnvelopeCommitments.vssCoefficientCommitmentRoot must match the accepted VSS coefficient commitments",
            "setupPackage.privateVssEnvelopeCommitments.vssCoefficientCommitmentRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let setup_intent_mailbox_public_key_bindings =
        setup_intent_mailbox_public_key_bindings_from_phase_transcript(setup_package)?;
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        &setup_intent_mailbox_public_key_bindings,
        &source_trustee_commitment_roots,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
    )? {
        Ok(bindings) => {
            if bindings.len() != expected_envelope_count as usize {
                return Ok(Some(private_vss_envelope_refusal(
                    "privateVssEnvelopeCountMismatch",
                    "privateVssEnvelopeCommitments.envelopeReferences must cover every source-trustee-recipient trustee pair",
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
                )?));
            }
        }
        Err(refusal) => {
            return Ok(Some(private_vss_envelope_refusal(
                refusal.reason_code,
                refusal.message,
                refusal
                    .object_path
                    .unwrap_or_else(|| "setupPackage.privateVssEnvelopeCommitments".to_string()),
            )?));
        }
    }

    let mut root_input = commitment_set.clone();
    root_input
        .as_object_mut()
        .expect("private VSS envelope commitment set object was checked")
        .remove("privateVssEnvelopeCommitmentRoot");
    let root_input_object = root_input
        .as_object_mut()
        .expect("private VSS envelope commitment set object was checked");
    if let Some(envelope_references) = root_input_object
        .get_mut("envelopeReferences")
        .and_then(Value::as_array_mut)
    {
        for envelope_reference in envelope_references {
            if let Some(envelope_reference_object) = envelope_reference.as_object_mut() {
                envelope_reference_object.remove("encryptedEnvelope");
            }
        }
    }
    let expected_root = derive_protocol_hash("PrivateVssEnvelopeCommitmentRoot", &root_input)?;
    if set_root != expected_root {
        return Ok(Some(private_vss_envelope_refusal(
            "privateVssEnvelopeCommitmentRootMismatch",
            "privateVssEnvelopeCommitmentRoot does not match the canonical private VSS envelope commitment set",
            "setupPackage.privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    Ok(None)
}

fn verify_private_vss_envelope_context(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> Result<(), Refusal> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(Refusal::new(
                "privateVssEnvelopeContextMismatch",
                format!("{object_path}.{field_name} must match setupContext"),
                format!("{object_path}.{field_name}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn private_vss_envelope_bindings_from_package(
    setup_package: &Value,
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
    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let setup_intent_mailbox_public_key_bindings =
        setup_intent_mailbox_public_key_bindings_from_phase_transcript(setup_package)?;
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
    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitments.vssCoefficientCommitmentRoot was required before private VSS binding extraction",
            )
        })?;

    match private_vss_envelope_bindings_from_set(
        commitment_set,
        setup_context,
        &expected_trustees,
        &setup_intent_mailbox_public_key_bindings,
        &source_trustee_commitment_roots,
        public_matrix_seed_hash,
        vss_coefficient_commitment_root,
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
    setup_intent_mailbox_public_key_bindings: &BTreeMap<u64, MailboxPublicKeyBinding>,
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
) -> CanonicalResult<Result<PrivateVssEnvelopeBindingMap, Refusal>> {
    let Some(envelope_references) = commitment_set
        .get("envelopeReferences")
        .and_then(Value::as_array)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferencesMissing",
            "privateVssEnvelopeCommitments.envelopeReferences must contain every source-trustee-recipient envelope commitment",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
        )));
    };
    let roster = super::accepted_roster_from_setup_context(setup_context);
    let expected_envelope_count = (roster.participant_count * roster.participant_count) as usize;
    if envelope_references.len() != expected_envelope_count {
        return Ok(Err(Refusal::new(
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
            setup_intent_mailbox_public_key_bindings,
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
    setup_intent_mailbox_public_key_bindings: &BTreeMap<u64, MailboxPublicKeyBinding>,
    source_trustee_commitment_roots: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
) -> CanonicalResult<Result<PrivateVssEnvelopeBinding, Refusal>> {
    if envelope_reference.get("objectType").and_then(Value::as_str)
        != Some(PRIVATE_VSS_ENVELOPE_COMMITMENT_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceTypeMismatch",
            "private VSS envelope commitment objectType must be PrivateVssEnvelopeCommitment",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.objectType",
        )));
    }
    if envelope_reference
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceVersionMismatch",
            "private VSS envelope commitment objectVersion must be 1",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.objectVersion",
        )));
    }
    if let Err(refusal) = verify_private_vss_envelope_context(
        envelope_reference,
        setup_context,
        "setupPackage.privateVssEnvelopeCommitments.envelopeReferences",
    ) {
        return Ok(Err(refusal));
    }
    if envelope_reference
        .get("mailboxEncryptionProfileId")
        .and_then(Value::as_str)
        != Some(PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceMailboxProfileMismatch",
            "private VSS envelope commitment must bind the accepted mailbox encryption profile",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.mailboxEncryptionProfileId",
        )));
    }
    if envelope_reference
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferencePublicMatrixSeedMismatch",
            "private VSS envelope commitment publicMatrixSeedHash must match common randomness",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.publicMatrixSeedHash",
        )));
    }
    if envelope_reference
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceVssCommitmentRootMismatch",
            "private VSS envelope commitment must bind the accepted VSS coefficient commitment root",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.vssCoefficientCommitmentRoot",
        )));
    }
    if envelope_reference
        .get("deliveryPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceDeliveryPhaseMismatch",
            "private VSS envelope commitment must bind the private envelope delivery phase",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.deliveryPhaseNumber",
        )));
    }
    if envelope_reference
        .get("verificationPhaseNumber")
        .and_then(Value::as_u64)
        != Some(PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeReferenceVerificationPhaseMismatch",
            "private VSS envelope commitment must bind the recipient verification phase",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.verificationPhaseNumber",
        )));
    }

    let source_trustee_identity = match envelope_reference
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
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
            "privateVssEnvelopeSourceTrusteeMismatch",
            "private VSS envelope commitment source trustee must match the phase transcript trustee identity",
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
            "privateVssEnvelopeRecipientMismatch",
            "private VSS envelope commitment recipient must match the phase transcript trustee identity",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientIdentity",
        )));
    }
    let Some(expected_recipient_mailbox_public_key_binding) =
        setup_intent_mailbox_public_key_bindings.get(&recipient_roster_position)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupIntent mailbox public key binding missing for private VSS envelope recipient",
        ));
    };
    let expected_recipient_mailbox_public_key_hash = expected_recipient_mailbox_public_key_binding
        .public_key_hash
        .as_str();
    let expected_recipient_mailbox_public_key_bytes_hash =
        expected_recipient_mailbox_public_key_binding
            .public_key_bytes_hash
            .as_str();
    let Some(recipient_mailbox_public_key_hash) = envelope_reference
        .get("recipientMailboxPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeMailboxPublicKeyMissing",
            "private VSS envelope commitment must bind recipientMailboxPublicKeyHash",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientMailboxPublicKeyHash",
        )));
    };
    validate_hash_string(
        recipient_mailbox_public_key_hash,
        "privateVssEnvelopeCommitments.envelopeReferences.recipientMailboxPublicKeyHash",
    )?;
    if recipient_mailbox_public_key_hash != expected_recipient_mailbox_public_key_hash {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeMailboxPublicKeyMismatch",
            "private VSS envelope commitment recipientMailboxPublicKeyHash must match the setup-intent mailbox key for the recipient",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.recipientMailboxPublicKeyHash",
        )));
    }
    // Source-major sequence number uniquely identifying the ordered (source, recipient) envelope; it is bound into the AEAD associated data to prevent cross-pair ciphertext replay.
    let roster = super::accepted_roster_from_setup_context(setup_context);
    let expected_sequence_number =
        source_trustee_roster_position * roster.participant_count + recipient_roster_position;
    if envelope_reference
        .get("envelopeSequenceNumber")
        .and_then(Value::as_u64)
        != Some(expected_sequence_number)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeSequenceMismatch",
            "private VSS envelope commitment envelopeSequenceNumber must follow source-trustee-major roster order",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.envelopeSequenceNumber",
        )));
    }

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
    if envelope_reference
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_source_trustee_commitment_root)
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeSourceTrusteeCommitmentRootMismatch",
            "private VSS envelope commitment sourceTrusteeCommitmentRoot must match the accepted source trustee coefficient commitments",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.sourceTrusteeCommitmentRoot",
        )));
    }

    for field_name in [
        "privateEnvelopeHash",
        "localVerificationRoot",
        "privateEnvelopeAadHash",
        "encryptedEnvelopeHash",
    ] {
        let Some(hash) = envelope_reference.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
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
    if envelope_reference
        .get("openingVerificationStatus")
        .and_then(Value::as_str)
        != Some("accepted-local-private-vss-opening")
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeOpeningStatusMismatch",
            "private VSS envelope commitment openingVerificationStatus must be accepted-local-private-vss-opening",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.openingVerificationStatus",
        )));
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
        expected_sequence_number,
    )?;
    let Some(private_envelope_aad) = envelope_reference.get("privateEnvelopeAad") else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeAadMissing",
            "private VSS envelope commitment must publish its AEAD associated-data object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeAad",
        )));
    };
    if private_envelope_aad != &expected_aad {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeAadMismatch",
            "private VSS envelope AEAD associated-data object does not match the accepted setup binding",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeAad",
        )));
    }
    let expected_aad_hash =
        derive_protocol_hash("PrivateVssEnvelopeAadHash", private_envelope_aad)?;
    if envelope_reference
        .get("privateEnvelopeAadHash")
        .and_then(Value::as_str)
        != Some(expected_aad_hash.as_str())
    {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeAadHashMismatch",
            "privateEnvelopeAadHash does not match the canonical private VSS envelope associated-data object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeAadHash",
        )));
    }

    if let Some(encrypted_envelope) = envelope_reference.get("encryptedEnvelope")
        && let Err(refusal) = verify_encrypted_private_vss_envelope(
            encrypted_envelope,
            setup_context,
            &expected_aad,
            &expected_aad_hash,
            public_matrix_seed_hash,
            vss_coefficient_commitment_root,
            source_trustee_identity,
            source_trustee_roster_position,
            recipient_identity,
            recipient_roster_position,
            expected_recipient_mailbox_public_key_hash,
            expected_recipient_mailbox_public_key_bytes_hash,
            expected_source_trustee_commitment_root,
            expected_sequence_number,
            value_string(envelope_reference, "privateEnvelopeHash")?,
            value_string(envelope_reference, "encryptedEnvelopeHash")?,
        )?
    {
        return Ok(Err(refusal));
    }

    let Some(private_envelope_commitment_root) = envelope_reference
        .get("privateEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeCommitmentRecordRootMissing",
            "private VSS envelope commitment must bind privateEnvelopeCommitmentRoot",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeCommitmentRoot",
        )));
    };
    validate_hash_string(
        private_envelope_commitment_root,
        "privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeCommitmentRoot",
    )?;
    let mut record_root_input = envelope_reference.clone();
    record_root_input
        .as_object_mut()
        .expect("private VSS envelope commitment reference object was checked")
        .remove("privateEnvelopeCommitmentRoot");
    // The commitment root binds the envelope metadata but deliberately excludes encryptedEnvelope (bound separately by encryptedEnvelopeHash), so the same commitment covers re-encryptions.
    record_root_input
        .as_object_mut()
        .expect("private VSS envelope commitment reference object was checked")
        .remove("encryptedEnvelope");
    let expected_record_root =
        derive_protocol_hash("PrivateVssEnvelopeCommitmentRoot", &record_root_input)?;
    if private_envelope_commitment_root != expected_record_root {
        return Ok(Err(Refusal::new(
            "privateVssEnvelopeCommitmentRecordRootMismatch",
            "privateEnvelopeCommitmentRoot does not match the canonical private VSS envelope commitment record",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.privateEnvelopeCommitmentRoot",
        )));
    }

    Ok(Ok(PrivateVssEnvelopeBinding {
        source_trustee_identity: source_trustee_identity.to_string(),
        recipient_identity: recipient_identity.to_string(),
        source_trustee_commitment_root: expected_source_trustee_commitment_root.to_string(),
        private_envelope_hash: value_string(envelope_reference, "privateEnvelopeHash")?.to_string(),
        local_verification_root: value_string(envelope_reference, "localVerificationRoot")?
            .to_string(),
    }))
}

#[allow(clippy::too_many_arguments)]
fn verify_encrypted_private_vss_envelope(
    encrypted_envelope: &Value,
    setup_context: &Value,
    expected_aad: &Value,
    expected_aad_hash: &str,
    public_matrix_seed_hash: &str,
    vss_coefficient_commitment_root: &str,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    recipient_identity: &str,
    recipient_roster_position: u64,
    expected_recipient_mailbox_public_key_hash: &str,
    expected_recipient_mailbox_public_key_bytes_hash: &str,
    source_trustee_commitment_root: &str,
    envelope_sequence_number: u64,
    private_envelope_hash: &str,
    encrypted_envelope_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    if !encrypted_envelope.is_object() {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeNotObject",
            "encryptedEnvelope must be a root-bound object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope",
        )));
    }
    if encrypted_envelope.get("objectType").and_then(Value::as_str)
        != Some(ENCRYPTED_PRIVATE_VSS_ENVELOPE_OBJECT_TYPE)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeTypeMismatch",
            "encryptedEnvelope.objectType must be EncryptedPrivateVssShareEnvelope",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.objectType",
        )));
    }
    if encrypted_envelope
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeVersionMismatch",
            "encryptedEnvelope.objectVersion must be 1",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.objectVersion",
        )));
    }
    if let Err(refusal) = verify_private_vss_envelope_context(
        encrypted_envelope,
        setup_context,
        "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope",
    ) {
        return Ok(Err(refusal));
    }

    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        (
            "mailboxEncryptionProfileId",
            PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID,
        ),
        ("ciphertextContentType", "private-vss-share-envelope"),
        ("publicMatrixSeedHash", public_matrix_seed_hash),
        (
            "vssCoefficientCommitmentRoot",
            vss_coefficient_commitment_root,
        ),
        ("sourceTrusteeIdentity", source_trustee_identity),
        ("recipientIdentity", recipient_identity),
        (
            "recipientMailboxPublicKeyHash",
            expected_recipient_mailbox_public_key_hash,
        ),
        (
            "sourceTrusteeCommitmentRoot",
            source_trustee_commitment_root,
        ),
        ("privateEnvelopeHash", private_envelope_hash),
        ("privateEnvelopeAadHash", expected_aad_hash),
    ] {
        if encrypted_envelope.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Err(Refusal::new(
                "privateVssEncryptedEnvelopeBindingMismatch",
                format!(
                    "encryptedEnvelope.{field_name} must match the private envelope commitment binding"
                ),
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.{field_name}"
                ),
            )));
        }
    }
    for (field_name, expected_value) in [
        (
            "sourceTrusteeRosterPosition",
            source_trustee_roster_position,
        ),
        ("recipientRosterPosition", recipient_roster_position),
        ("envelopeSequenceNumber", envelope_sequence_number),
        (
            "deliveryPhaseNumber",
            PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER,
        ),
        (
            "verificationPhaseNumber",
            PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER,
        ),
        ("aeadTagLength", 128),
    ] {
        if encrypted_envelope.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Err(Refusal::new(
                "privateVssEncryptedEnvelopeBindingMismatch",
                format!(
                    "encryptedEnvelope.{field_name} must match the private envelope commitment binding"
                ),
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.{field_name}"
                ),
            )));
        }
    }

    if encrypted_envelope.get("privateEnvelopeAad") != Some(expected_aad) {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeAadMismatch",
            "encryptedEnvelope.privateEnvelopeAad must match the accepted private envelope associated-data object",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.privateEnvelopeAad",
        )));
    }

    for field_name in [
        "recipientMailboxPublicKeyHash",
        "recipientMailboxPublicKeyBytesHash",
        "kemCiphertextHash",
        "ciphertextBytesHash",
    ] {
        let Some(hash) = encrypted_envelope.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
                "privateVssEncryptedEnvelopeHashMissing",
                format!("encryptedEnvelope.{field_name} must be present"),
                format!(
                    "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.{field_name}"
                ),
            )));
        };
        validate_hash_string(hash, &format!("encryptedEnvelope.{field_name}"))?;
    }
    if encrypted_envelope
        .get("recipientMailboxPublicKeyBytesHash")
        .and_then(Value::as_str)
        != Some(expected_recipient_mailbox_public_key_bytes_hash)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeMailboxPublicKeyBytesHashMismatch",
            "encryptedEnvelope.recipientMailboxPublicKeyBytesHash must match the setup-intent mailbox key bytes hash for the recipient",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.recipientMailboxPublicKeyBytesHash",
        )));
    }

    let Some(kem_ciphertext_bytes_hex) = encrypted_envelope
        .get("kemCiphertextBytesHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
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
    let kem_ciphertext_bytes = crate::transcript_core::decode_hex(kem_ciphertext_bytes_hex)?;
    let expected_kem_ciphertext_hash = hash512_hex(
        "sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext-v1",
        &[&kem_ciphertext_bytes],
    );
    if encrypted_envelope
        .get("kemCiphertextHash")
        .and_then(Value::as_str)
        != Some(expected_kem_ciphertext_hash.as_str())
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeKemCiphertextHashMismatch",
            "encryptedEnvelope.kemCiphertextHash must match kemCiphertextBytesHex",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.kemCiphertextHash",
        )));
    }
    let Some(aead_nonce_hex) = encrypted_envelope
        .get("aeadNonceHex")
        .and_then(Value::as_str)
    else {
        return Ok(Err(Refusal::new(
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
            "privateVssEncryptedEnvelopeCiphertextMissing",
            "encryptedEnvelope.ciphertextBytesHex must be present",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.ciphertextBytesHex",
        )));
    };
    validate_lowercase_hex(ciphertext_bytes_hex, "encryptedEnvelope.ciphertextBytesHex")?;
    let ciphertext_bytes = crate::transcript_core::decode_hex(ciphertext_bytes_hex)?;
    let expected_ciphertext_bytes_hash = hash512_hex(
        "sealed-lattice-private-vss-mailbox/aes-256-gcm-ciphertext-v1",
        &[&ciphertext_bytes],
    );
    if encrypted_envelope
        .get("ciphertextBytesHash")
        .and_then(Value::as_str)
        != Some(expected_ciphertext_bytes_hash.as_str())
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeCiphertextBytesHashMismatch",
            "encryptedEnvelope.ciphertextBytesHash must match ciphertextBytesHex",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.ciphertextBytesHash",
        )));
    }
    if encrypted_envelope
        .get("ciphertextByteLength")
        .and_then(Value::as_u64)
        != Some((ciphertext_bytes_hex.len() / 2) as u64)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeCiphertextLengthMismatch",
            "encryptedEnvelope.ciphertextByteLength must match ciphertextBytesHex",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.ciphertextByteLength",
        )));
    }

    if encrypted_envelope
        .get("encryptedEnvelopeHash")
        .and_then(Value::as_str)
        != Some(encrypted_envelope_hash)
    {
        return Ok(Err(Refusal::new(
            "privateVssEncryptedEnvelopeHashMismatch",
            "encryptedEnvelope.encryptedEnvelopeHash must match the commitment reference",
            "setupPackage.privateVssEnvelopeCommitments.envelopeReferences.encryptedEnvelope.encryptedEnvelopeHash",
        )));
    }
    let mut encrypted_envelope_root_input = encrypted_envelope.clone();
    encrypted_envelope_root_input
        .as_object_mut()
        .expect("encrypted envelope object was checked")
        .remove("encryptedEnvelopeHash");
    let expected_encrypted_envelope_hash = derive_protocol_hash(
        "PrivateVssEncryptedEnvelopeHash",
        &encrypted_envelope_root_input,
    )?;
    if encrypted_envelope_hash != expected_encrypted_envelope_hash {
        return Ok(Err(Refusal::new(
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
    envelope_sequence_number: u64,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": PRIVATE_VSS_ENVELOPE_AAD_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "mailboxEncryptionProfileId": PRIVATE_VSS_MAILBOX_ENCRYPTION_PROFILE_ID,
        "privateEnvelopeObjectType": "PrivateVssShareEnvelope",
        "ciphertextContentType": "private-vss-share-envelope",
        "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
        "manifestHash": setup_context_string(setup_context, "manifestHash")?,
        "rosterHash": setup_context_string(setup_context, "rosterHash")?,
        "setupProfileHash": setup_context_string(setup_context, "setupProfileHash")?,
        "qShareHash": setup_context_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": setup_context_string(
            setup_context,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": setup_context_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
        "phaseOrderHash": phase_order_hash()?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
        "envelopeSequenceNumber": envelope_sequence_number,
        "deliveryPhaseNumber": PRIVATE_VSS_ENVELOPE_DELIVERY_PHASE_NUMBER,
        "verificationPhaseNumber": PRIVATE_VSS_ENVELOPE_VERIFICATION_PHASE_NUMBER,
        "recipientVerificationRequirement": "recipient-verifies-private-vss-opening-before-acceptance",
    }))
}

fn private_vss_envelope_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("privateVssEnvelopeDelivery"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
