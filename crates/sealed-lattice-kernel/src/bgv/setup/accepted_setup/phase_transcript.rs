use super::*;

struct PhaseParticipantPayloadInput<'a> {
    phase_identifier: &'a str,
    phase_number: u64,
    setup_context: &'a Value,
    trustee_identity: &'a str,
    roster_position: u64,
    recovery_epoch: u64,
    device_epoch: u64,
    signing_public_key_hash: &'a str,
    private_vss_mailbox_public_key_hash: Option<&'a str>,
    private_vss_mailbox_public_key_bytes_hash: Option<&'a str>,
}

#[derive(Clone)]
pub(super) struct SetupIntentTrusteeRegistration {
    pub(super) trustee_identity: String,
    pub(super) signing_public_key_hash: String,
}

pub(super) fn verify_phase_transcript(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(phase_transcript) = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("rosterFreeze"),
            vec!["phaseTranscript".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };

    let mut seen_phase_hashes = BTreeMap::<String, String>::new();
    let mut seen_phase_numbers = BTreeSet::<u64>::new();
    let mut required_phase_index = 0_usize;
    let mut previous_phase_root: Option<String> = None;
    let mut setup_intent_registrations: Option<BTreeMap<u64, SetupIntentTrusteeRegistration>> =
        None;

    for phase_value in phase_transcript {
        let phase_object_hash = derive_protocol_hash("SetupPhaseObjectHash", phase_value)?;
        let Some(phase_identifier) = phase_value.get("phaseId").and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                None,
                Vec::new(),
                vec![Refusal::new(
                    "phaseIdMissing",
                    "phaseTranscript entries must include phaseId",
                    "setupPackage.phaseTranscript".to_string(),
                )],
                Vec::new(),
            )?));
        };
        let Some(phase_number) = phase_value.get("phaseNumber").and_then(Value::as_u64) else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseNumberMissing",
                    "phaseTranscript entries must include phaseNumber",
                    format!("setupPackage.phaseTranscript.{phase_identifier}"),
                )],
                Vec::new(),
            )?));
        };
        // A byte-identical re-post of a phase is benign idempotency and skipped; any non-identical record for the same phaseId is trustee equivocation and rejected as a fork.
        if let Some(previous_hash) = seen_phase_hashes.get(phase_identifier) {
            if previous_hash == &phase_object_hash {
                continue;
            }
            return Ok(Some(verification_response(
                VerifierStatus::ForkDetected,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseForkDetected",
                    format!("phase {phase_identifier} has two non-identical records"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}"),
                )],
                Vec::new(),
            )?));
        }

        let Some((expected_phase_identifier, expected_phase_number)) =
            REQUIRED_PHASES.get(required_phase_index)
        else {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "unexpectedExtraPhase",
                    format!("phase {phase_identifier} appears after setupPackageVerification"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}"),
                )],
                Vec::new(),
            )?));
        };
        if phase_identifier != *expected_phase_identifier || phase_number != *expected_phase_number
        {
            return Ok(Some(verification_response(
                VerifierStatus::Refused,
                Some(*expected_phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseOrderMismatch",
                    format!(
                        "expected phase {expected_phase_identifier} number {expected_phase_number}, got {phase_identifier} number {phase_number}"
                    ),
                    "setupPackage.phaseTranscript".to_string(),
                )],
                Vec::new(),
            )?));
        }
        if !seen_phase_numbers.insert(phase_number) {
            return Ok(Some(verification_response(
                VerifierStatus::ForkDetected,
                Some(phase_identifier),
                Vec::new(),
                vec![Refusal::new(
                    "phaseNumberForkDetected",
                    format!("phase number {phase_number} is used by more than one phase"),
                    "setupPackage.phaseTranscript".to_string(),
                )],
                Vec::new(),
            )?));
        }
        if let Some(response) = verify_phase_object_binding(
            setup_package,
            phase_value,
            phase_identifier,
            phase_number,
            previous_phase_root.as_deref(),
            setup_intent_registrations.as_ref(),
        )? {
            return Ok(Some(response));
        }
        let phase_root = phase_value
            .get("phaseRoot")
            .and_then(Value::as_str)
            .expect("phase root was checked");
        seen_phase_hashes.insert(phase_identifier.to_string(), phase_object_hash);
        previous_phase_root = Some(phase_root.to_string());
        if phase_identifier == "setupIntent" {
            setup_intent_registrations = Some(setup_intent_trustee_registrations_from_phase_value(
                phase_value,
            )?);
        }
        required_phase_index += 1;
    }

    if required_phase_index < REQUIRED_PHASES.len() {
        let (next_phase_identifier, _) = REQUIRED_PHASES[required_phase_index];
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some(next_phase_identifier),
            vec![format!("phaseTranscript.{next_phase_identifier}")],
            Vec::new(),
            Vec::new(),
        )?));
    }

    Ok(None)
}

fn verify_phase_object_binding(
    setup_package: &Value,
    phase_value: &Value,
    phase_identifier: &str,
    phase_number: u64,
    previous_phase_root: Option<&str>,
    setup_intent_registrations: Option<&BTreeMap<u64, SetupIntentTrusteeRegistration>>,
) -> CanonicalResult<Option<Value>> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before phase transcript verification",
        )
    })?;
    let roster = super::accepted_roster_from_package(setup_package);
    for (field_name, context_field_name) in [
        ("ceremonyId", "ceremonyId"),
        ("manifestHash", "manifestHash"),
        ("rosterHash", "rosterHash"),
        ("setupProfileHash", "setupProfileHash"),
        ("qShareHash", "qShareHash"),
        (
            "carryAwareVssShareRelationProfileHash",
            "carryAwareVssShareRelationProfileHash",
        ),
        ("commitmentProfileHash", "commitmentProfileHash"),
        ("setupEpoch", "setupEpoch"),
    ] {
        let Some(phase_binding) = phase_value.get(field_name) else {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseBindingMissing",
                format!("phase {phase_identifier} must bind {field_name}"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.{field_name}"),
            )?));
        };
        if phase_binding != &setup_context[context_field_name] {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseContextMismatch",
                format!("phase {phase_identifier} {field_name} does not match setupContext"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.{field_name}"),
            )?));
        }
    }

    match previous_phase_root {
        Some(expected_previous_phase_root) => {
            if phase_value.get("previousPhaseRoot").and_then(Value::as_str)
                != Some(expected_previous_phase_root)
            {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "previousPhaseRootMismatch",
                    format!("phase {phase_identifier} must bind the previous accepted phase root"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}.previousPhaseRoot"),
                )?));
            }
        }
        None => {
            // The genesis phase must carry an explicit null predecessor, not an absent field, so no earlier phase can later be spliced into the hash chain.
            if !phase_value
                .get("previousPhaseRoot")
                .is_some_and(Value::is_null)
            {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "previousPhaseRootMismatch",
                    format!("phase {phase_identifier} must bind null as the first phase root"),
                    format!("setupPackage.phaseTranscript.{phase_identifier}.previousPhaseRoot"),
                )?));
            }
        }
    }

    let Some(phase_root) = phase_value.get("phaseRoot").and_then(Value::as_str) else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRootMissing",
            format!("phase {phase_identifier} must include phaseRoot"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.phaseRoot"),
        )?));
    };
    validate_hash_string(
        phase_root,
        &format!("phaseTranscript.{phase_identifier}.phaseRoot"),
    )?;
    let mut root_input = phase_value.clone();
    root_input
        .as_object_mut()
        .expect("phase transcript entry is an object")
        .remove("phaseRoot");
    let expected_phase_root = derive_protocol_hash("SetupPhaseRoot", &root_input)?;
    if phase_root != expected_phase_root {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRootMismatch",
            format!("phase {phase_identifier} root does not match its canonical phase payload"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.phaseRoot"),
        )?));
    }

    let Some(participant_phase_objects) = phase_value
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectsMissing",
            format!("phase {phase_identifier} must include participantPhaseObjects"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    if participant_phase_objects.len() != roster.participant_count as usize {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectCountMismatch",
            format!("phase {phase_identifier} must include one signed root slot per participant"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    for participant_phase_object in participant_phase_objects {
        if let Some(response) = verify_participant_phase_object(
            participant_phase_object,
            phase_identifier,
            phase_number,
            setup_context,
            setup_intent_registrations,
        )? {
            return Ok(Some(response));
        }
        let roster_position = participant_phase_object["rosterPosition"]
            .as_u64()
            .expect("roster position was checked");
        if !seen_roster_positions.insert(roster_position) {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseRosterPositionDuplicate",
                format!("phase {phase_identifier} contains duplicate roster positions"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
            )?));
        }
    }

    Ok(None)
}

fn verify_participant_phase_object(
    participant_phase_object: &Value,
    phase_identifier: &str,
    phase_number: u64,
    setup_context: &Value,
    setup_intent_registrations: Option<&BTreeMap<u64, SetupIntentTrusteeRegistration>>,
) -> CanonicalResult<Option<Value>> {
    let roster = super::accepted_roster_from_setup_context(setup_context);
    if !participant_phase_object.is_object() {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectNotObject",
            format!("phase {phase_identifier} participant entry must be an object"),
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    if participant_phase_object
        .get("objectType")
        .and_then(Value::as_str)
        != Some("SetupPhaseParticipantObject")
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectTypeMismatch",
            "participant phase object must use SetupPhaseParticipantObject",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    if participant_phase_object
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectVersionMismatch",
            "participant phase object version must be 1",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    if participant_phase_object
        .get("phaseId")
        .and_then(Value::as_str)
        != Some(phase_identifier)
        || participant_phase_object
            .get("phaseNumber")
            .and_then(Value::as_u64)
            != Some(phase_number)
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantPhaseMismatch",
            "participant phase object must bind the enclosing phase id and number",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "setupEpoch",
    ] {
        if participant_phase_object.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseParticipantContextMismatch",
                format!("participant phase object {field_name} does not match setupContext"),
                format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
            )?));
        }
    }
    if participant_phase_object
        .get("signerRole")
        .and_then(Value::as_str)
        != Some("Trustee")
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantSignerRoleMismatch",
            "participant phase object signerRole must be Trustee",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    let Some(trustee_identity) = participant_phase_object
        .get("trusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantIdentityMissing",
            "participant phase object must bind trusteeIdentity",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    // Identity must already be NFC so the same trustee cannot appear under two byte-distinct Unicode forms across signatures, roster matching, and hashing.
    if trustee_identity.is_empty() || trustee_identity.nfc().collect::<String>() != trustee_identity
    {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantIdentityMalformed",
            "participant phase object trusteeIdentity must be non-empty NFC text",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    let Some(roster_position) = participant_phase_object
        .get("rosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRosterPositionMissing",
            "participant phase object must bind rosterPosition",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    if roster_position >= roster.participant_count {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseRosterPositionOutsideProfile",
            "participant phase object rosterPosition is outside the first accepted profile",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }
    let Some(recovery_epoch) = participant_phase_object
        .get("recoveryEpoch")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantEpochMissing",
            "participant phase object must bind recoveryEpoch",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    let Some(device_epoch) = participant_phase_object
        .get("deviceEpoch")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantEpochMissing",
            "participant phase object must bind deviceEpoch",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    let Some(signing_public_key_hash) = participant_phase_object
        .get("signingPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind signingPublicKeyHash",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        &format!("phaseTranscript.{phase_identifier}.participantPhaseObjects.signingPublicKeyHash"),
    )?;
    if let Some(registrations) = setup_intent_registrations {
        let Some(registration) = registrations.get(&roster_position) else {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseParticipantRegistrationMissing",
                "participant phase object rosterPosition is missing from setupIntent registrations",
                format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
            )?));
        };
        if registration.trustee_identity != trustee_identity {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseParticipantRegistrationIdentityMismatch",
                "participant phase object trusteeIdentity must match setupIntent registration",
                format!(
                    "setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects.trusteeIdentity"
                ),
            )?));
        }
        if registration.signing_public_key_hash != signing_public_key_hash {
            return Ok(Some(phase_refusal(
                phase_identifier,
                "phaseParticipantSigningKeyMismatch",
                "participant phase object signingPublicKeyHash must match setupIntent registration",
                format!(
                    "setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects.signingPublicKeyHash"
                ),
            )?));
        }
    }
    let (private_vss_mailbox_public_key_hash, private_vss_mailbox_public_key_bytes_hash) =
        if phase_identifier == "setupIntent" {
            let Some(public_key_hash) = participant_phase_object
                .get("privateVssMailboxPublicKeyHash")
                .and_then(Value::as_str)
            else {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "phaseParticipantMailboxKeyMissing",
                    "setup intent participant object must bind privateVssMailboxPublicKeyHash",
                    format!(
                        "setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyHash"
                    ),
                )?));
            };
            validate_hash_string(
                public_key_hash,
                &format!(
                    "phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyHash"
                ),
            )?;
            let Some(public_key_bytes_hash) = participant_phase_object
                .get("privateVssMailboxPublicKeyBytesHash")
                .and_then(Value::as_str)
            else {
                return Ok(Some(phase_refusal(
                    phase_identifier,
                    "phaseParticipantMailboxKeyMissing",
                    "setup intent participant object must bind privateVssMailboxPublicKeyBytesHash",
                    format!(
                        "setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyBytesHash"
                    ),
                )?));
            };
            validate_hash_string(
                public_key_bytes_hash,
                &format!(
                    "phaseTranscript.{phase_identifier}.participantPhaseObjects.privateVssMailboxPublicKeyBytesHash"
                ),
            )?;

            (Some(public_key_hash), Some(public_key_bytes_hash))
        } else {
            (None, None)
        };

    let phase_object_payload = phase_participant_payload_value(PhaseParticipantPayloadInput {
        phase_identifier,
        phase_number,
        setup_context,
        trustee_identity,
        roster_position,
        recovery_epoch,
        device_epoch,
        signing_public_key_hash,
        private_vss_mailbox_public_key_hash,
        private_vss_mailbox_public_key_bytes_hash,
    })?;
    let expected_phase_object_root =
        derive_protocol_hash("SetupPhaseObjectHash", &phase_object_payload)?;
    let expected_phase_object_byte_length =
        u64::try_from(canonical_json(&phase_object_payload)?.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "phase participant payload length does not fit u64",
            )
        })?;
    let expected_phase_signature_context_hash = phase_signature_context_hash(
        phase_identifier,
        phase_number,
        setup_context,
        trustee_identity,
        roster_position,
        &expected_phase_object_root,
    )?;

    let Some(phase_object_root) = participant_phase_object
        .get("phaseObjectRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind phaseObjectRoot",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        phase_object_root,
        &format!("phaseTranscript.{phase_identifier}.participantPhaseObjects.phaseObjectRoot"),
    )?;
    if phase_object_root != expected_phase_object_root {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantObjectRootMismatch",
            "participant phase object root does not match the canonical signed payload",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let Some(phase_object_byte_length) = participant_phase_object
        .get("phaseObjectByteLength")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantByteLengthMissing",
            "participant phase object must bind phaseObjectByteLength",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    if phase_object_byte_length != expected_phase_object_byte_length {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantByteLengthMismatch",
            "participant phase object byte length does not match the canonical signed payload",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let Some(phase_signature_context_hash) = participant_phase_object
        .get("phaseSignatureContextHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind phaseSignatureContextHash",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        phase_signature_context_hash,
        &format!(
            "phaseTranscript.{phase_identifier}.participantPhaseObjects.phaseSignatureContextHash"
        ),
    )?;
    if phase_signature_context_hash != expected_phase_signature_context_hash {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantContextHashMismatch",
            "participant phase signature context hash does not match the setup phase binding",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    }

    let Some(signature_envelope_hash) = participant_phase_object
        .get("signatureEnvelopeHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseParticipantHashMissing",
            "participant phase object must bind signatureEnvelopeHash",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    validate_hash_string(
        signature_envelope_hash,
        &format!(
            "phaseTranscript.{phase_identifier}.participantPhaseObjects.signatureEnvelopeHash"
        ),
    )?;
    let Some(signature_envelope) = participant_phase_object.get("signatureEnvelope") else {
        return Ok(Some(phase_refusal(
            phase_identifier,
            "phaseSignatureEnvelopeMissing",
            "participant phase object must include the signed ML-DSA envelope",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?));
    };
    let manifest_hash = setup_context_string(setup_context, "manifestHash")?;
    let ceremony_id = setup_context_string(setup_context, "ceremonyId")?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: "SetupPhaseParticipantObject",
            object_version: 1,
            signer_role: "Trustee",
            signer_identity: trustee_identity,
            ceremony_id,
            public_key_hash: signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(phase_object_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: phase_signature_context_hash,
            byte_length: phase_object_byte_length,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(verified_signature_hash) if verified_signature_hash == signature_envelope_hash => {
            Ok(None)
        }
        Ok(_) => Ok(Some(phase_refusal(
            phase_identifier,
            "phaseSignatureHashMismatch",
            "participant phase signature envelope hash does not match the verified envelope",
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?)),
        Err(failure) => Ok(Some(phase_refusal(
            phase_identifier,
            failure.reason_code,
            failure.message,
            format!("setupPackage.phaseTranscript.{phase_identifier}.participantPhaseObjects"),
        )?)),
    }
}

fn phase_participant_payload_value(
    input: PhaseParticipantPayloadInput<'_>,
) -> CanonicalResult<Value> {
    let PhaseParticipantPayloadInput {
        phase_identifier,
        phase_number,
        setup_context,
        trustee_identity,
        roster_position,
        recovery_epoch,
        device_epoch,
        signing_public_key_hash,
        private_vss_mailbox_public_key_hash,
        private_vss_mailbox_public_key_bytes_hash,
    } = input;
    let mut payload = json!({
        "objectType": "SetupPhaseParticipantObject",
        "objectVersion": 1,
        "phaseId": phase_identifier,
        "phaseNumber": phase_number,
        "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
        "manifestHash": setup_context_string(setup_context, "manifestHash")?,
        "rosterHash": setup_context_string(setup_context, "rosterHash")?,
        "setupProfileHash": setup_context_string(setup_context, "setupProfileHash")?,
        "commitmentProfileHash": setup_context_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
        "signerRole": "Trustee",
        "trusteeIdentity": trustee_identity,
        "rosterPosition": roster_position,
        "recoveryEpoch": recovery_epoch,
        "deviceEpoch": device_epoch,
        "signingPublicKeyHash": signing_public_key_hash,
    });
    if let Some(public_key_hash) = private_vss_mailbox_public_key_hash {
        payload["privateVssMailboxPublicKeyHash"] = json!(public_key_hash);
    }
    if let Some(public_key_bytes_hash) = private_vss_mailbox_public_key_bytes_hash {
        payload["privateVssMailboxPublicKeyBytesHash"] = json!(public_key_bytes_hash);
    }

    Ok(payload)
}

fn phase_signature_context_hash(
    phase_identifier: &str,
    phase_number: u64,
    setup_context: &Value,
    trustee_identity: &str,
    roster_position: u64,
    phase_object_root: &str,
) -> CanonicalResult<String> {
    // Same hash domain is safe here only because the purpose field and disjoint key sets make the object-root and signature-context preimages non-overlapping.
    derive_protocol_hash(
        "SetupPhaseObjectHash",
        &json!({
            "purpose": "setup-phase-signature-context",
            "phaseId": phase_identifier,
            "phaseNumber": phase_number,
            "ceremonyId": setup_context_string(setup_context, "ceremonyId")?,
            "manifestHash": setup_context_string(setup_context, "manifestHash")?,
            "rosterHash": setup_context_string(setup_context, "rosterHash")?,
            "setupProfileHash": setup_context_string(setup_context, "setupProfileHash")?,
            "qShareHash": setup_context_string(setup_context, "qShareHash")?,
            "carryAwareVssShareRelationProfileHash": setup_context_string(
                setup_context,
                "carryAwareVssShareRelationProfileHash",
            )?,
            "commitmentProfileHash": setup_context_string(
                setup_context,
                "commitmentProfileHash",
            )?,
            "setupEpoch": setup_context_string(setup_context, "setupEpoch")?,
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "phaseObjectRoot": phase_object_root,
        }),
    )
}

pub(super) fn setup_context_string<'a>(
    setup_context: &'a Value,
    field_name: &str,
) -> CanonicalResult<&'a str> {
    setup_context
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setupContext.{field_name} must be a string"),
            )
        })
}

pub(super) fn setup_intent_trustee_registrations_from_phase_transcript(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, SetupIntentTrusteeRegistration>> {
    let phase_transcript = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phaseTranscript was required before setupIntent registration extraction",
            )
        })?;
    let setup_intent_phase = phase_transcript
        .iter()
        .find(|phase| phase.get("phaseId").and_then(Value::as_str) == Some("setupIntent"))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent phase was required before setupIntent registration extraction",
            )
        })?;

    setup_intent_trustee_registrations_from_phase_value(setup_intent_phase)
}

pub(super) fn verify_setup_intent_roster_hash(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before setup roster hash verification",
        )
    })?;
    let roster_hash = setup_context_string(setup_context, "rosterHash")?;
    let registrations = setup_intent_trustee_registrations_from_phase_transcript(setup_package)?;
    let expected_roster_hash = setup_intent_roster_hash_from_registrations(&registrations)?;
    if roster_hash != expected_roster_hash {
        return Ok(Some(verification_response(
            VerifierStatus::Refused,
            Some("setupIntent"),
            Vec::new(),
            vec![Refusal::new(
                "setupRosterHashMismatch",
                "setupContext.rosterHash must match the setupIntent trustee identity and signing-key registrations",
                "setupPackage.setupContext.rosterHash".to_string(),
            )],
            Vec::new(),
        )?));
    }

    Ok(None)
}

pub(super) fn setup_intent_roster_hash_from_registrations(
    registrations: &BTreeMap<u64, SetupIntentTrusteeRegistration>,
) -> CanonicalResult<String> {
    let roster_entries = registrations
        .iter()
        .map(|(roster_position, registration)| {
            json!({
                "objectType": "CollectiveBgvSetupRosterEntry",
                "objectVersion": 1,
                "rosterPosition": roster_position,
                "trusteeIdentity": registration.trustee_identity,
                "signingPublicKeyHash": registration.signing_public_key_hash,
            })
        })
        .collect::<Vec<_>>();

    derive_protocol_hash(
        "CollectiveBgvSetupRosterHash",
        &Value::Array(roster_entries),
    )
}

fn setup_intent_trustee_registrations_from_phase_value(
    setup_intent_phase: &Value,
) -> CanonicalResult<BTreeMap<u64, SetupIntentTrusteeRegistration>> {
    let participants = setup_intent_phase
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent participant objects were required before setupIntent registration extraction",
            )
        })?;
    let mut registrations = BTreeMap::new();
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
        let trustee_identity = participant
            .get("trusteeIdentity")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind trusteeIdentity",
                )
            })?;
        let signing_public_key_hash = participant
            .get("signingPublicKeyHash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "setupIntent participant object must bind signingPublicKeyHash",
                )
            })?;
        if registrations
            .insert(
                roster_position,
                SetupIntentTrusteeRegistration {
                    trustee_identity: trustee_identity.to_string(),
                    signing_public_key_hash: signing_public_key_hash.to_string(),
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupIntent participant objects contain a duplicate rosterPosition",
            ));
        }
    }

    Ok(registrations)
}

pub(super) fn verify_abort_absence(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    if setup_package
        .get("complaints")
        .and_then(Value::as_array)
        .is_some_and(|complaints| !complaints.is_empty())
    {
        return Ok(Some(verification_response(
            VerifierStatus::Aborted,
            Some("vssAcceptanceOrComplaint"),
            Vec::new(),
            vec![Refusal::new(
                "validComplaintPresent",
                "a complaint aborts the first accepted setup profile",
                "setupPackage.complaints".to_string(),
            )],
            Vec::new(),
        )?));
    }
    if setup_package
        .get("abortRecords")
        .and_then(Value::as_array)
        .is_some_and(|abort_records| !abort_records.is_empty())
    {
        return Ok(Some(verification_response(
            VerifierStatus::Aborted,
            None,
            Vec::new(),
            vec![Refusal::new(
                "abortRecordPresent",
                "an abort record prevents first-profile setup acceptance",
                "setupPackage.abortRecords".to_string(),
            )],
            Vec::new(),
        )?));
    }

    Ok(None)
}

fn phase_refusal(
    phase_identifier: &str,
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some(phase_identifier),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
