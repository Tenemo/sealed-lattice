use super::*;

pub(in super::super) fn verify_vss_share_acceptances(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Value>> {
    let Some(acceptance_set) = setup_package.get("vssShareAcceptances") else {
        return Ok(Some(verification_response(
            vec!["vssShareAcceptances".to_string()],
            Vec::new(),
        )?));
    };
    if !acceptance_set.is_object() {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancesNotObject",
            "vssShareAcceptances must be an object, not an array or scalar",
            "setupPackage.vssShareAcceptances",
        )?));
    }
    if acceptance_set.get("objectType").and_then(Value::as_str) != Some("VssShareAcceptanceSet") {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSetTypeMismatch",
            "vssShareAcceptances.objectType must be VssShareAcceptanceSet",
            "setupPackage.vssShareAcceptances.objectType",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS share acceptance verification",
        )
    })?;

    let private_vss_envelope_commitment_root = setup_package
        .get("privateVssEnvelopeCommitments")
        .and_then(|commitments| commitments.get("privateVssEnvelopeCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot was required before VSS share acceptance verification",
            )
        })?;
    validate_hash_string(
        private_vss_envelope_commitment_root,
        "privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
    )?;

    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    let private_vss_envelope_bindings =
        private_vss_envelope_bindings_from_package(setup_package, trustee_registrations)?;
    let verification_context = VssRecordVerificationContext {
        setup_context,
        expected_trustees: &expected_trustees,
        trustee_registrations,
        source_trustee_commitment_roots: &source_trustee_commitment_roots,
        private_vss_envelope_commitment_root,
        private_vss_envelope_bindings: &private_vss_envelope_bindings,
    };
    let Some(acceptance_records) = acceptance_set
        .get("acceptanceRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            vec!["vssShareAcceptances.acceptanceRecords".to_string()],
            Vec::new(),
        )?));
    };
    let roster = super::accepted_roster_from_package(setup_package)?;
    let expected_acceptance_count = (roster.participant_count * roster.participant_count) as usize;
    if acceptance_records.len() != expected_acceptance_count {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceCountMismatch",
            "vssShareAcceptances.acceptanceRecords must contain one record for every source-trustee-recipient trustee pair",
            "setupPackage.vssShareAcceptances.acceptanceRecords",
        )?));
    }

    let mut seen_acceptances = BTreeSet::new();
    for acceptance_record in acceptance_records {
        if let Some(response) = verify_vss_share_acceptance_record(
            acceptance_record,
            &verification_context,
            &mut seen_acceptances,
        )? {
            return Ok(Some(response));
        }
    }

    Ok(None)
}

fn verify_vss_share_acceptance_record(
    acceptance_record: &Value,
    verification_context: &VssRecordVerificationContext<'_>,
    seen_acceptances: &mut BTreeSet<(u64, u64)>,
) -> CanonicalResult<Option<Value>> {
    if acceptance_record.get("objectType").and_then(Value::as_str) != Some("VssShareAcceptance") {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceTypeMismatch",
            "VSS share acceptance objectType must be VssShareAcceptance",
            "setupPackage.vssShareAcceptances.acceptanceRecords.objectType",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if acceptance_record.get(field_name) != verification_context.setup_context.get(field_name) {
            return Ok(Some(vss_share_acceptance_refusal(
                "vssShareAcceptanceContextMismatch",
                format!("VSS share acceptance {field_name} must match setupContext"),
                format!("setupPackage.vssShareAcceptances.acceptanceRecords.{field_name}"),
            )?));
        }
    }
    if acceptance_record
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(verification_context.private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeRootMismatch",
            "VSS share acceptance must bind privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssShareAcceptances.acceptanceRecords.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let Some(source_trustee_identity) = acceptance_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteeMissing",
            "VSS share acceptance must bind sourceTrusteeIdentity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeIdentity",
        )?));
    };
    let Some(source_trustee_roster_position) = acceptance_record
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteePositionMissing",
            "VSS share acceptance must bind sourceTrusteeRosterPosition",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeRosterPosition",
        )?));
    };
    if verification_context
        .expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteeMismatch",
            "VSS share acceptance source trustee must match the phase transcript trustee identity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeIdentity",
        )?));
    }

    let Some(recipient_identity) = acceptance_record
        .get("recipientIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRecipientMissing",
            "VSS share acceptance must bind recipientIdentity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientIdentity",
        )?));
    };
    let Some(recipient_roster_position) = acceptance_record
        .get("recipientRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRecipientPositionMissing",
            "VSS share acceptance must bind recipientRosterPosition",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientRosterPosition",
        )?));
    };
    if verification_context
        .expected_trustees
        .get(&recipient_roster_position)
        .map(String::as_str)
        != Some(recipient_identity)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRecipientMismatch",
            "VSS share acceptance recipient must match the phase transcript trustee identity",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientIdentity",
        )?));
    }
    if !seen_acceptances.insert((source_trustee_roster_position, recipient_roster_position)) {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceDuplicate",
            "VSS share acceptance records must have distinct source-trustee-recipient trustee pairs",
            "setupPackage.vssShareAcceptances.acceptanceRecords",
        )?));
    }

    let expected_source_trustee_commitment_root = verification_context
        .source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee commitment root missing for VSS share acceptance verification",
            )
        })?;
    if acceptance_record
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_source_trustee_commitment_root)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSourceTrusteeCommitmentRootMismatch",
            "VSS share acceptance sourceTrusteeCommitmentRoot must match the accepted source trustee coefficient commitments",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeCommitmentRoot",
        )?));
    }
    let Some(private_vss_envelope_binding) = verification_context
        .private_vss_envelope_bindings
        .get(&(source_trustee_roster_position, recipient_roster_position))
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeBindingMissing",
            "VSS share acceptance must match a private VSS envelope commitment for the source-trustee-recipient pair",
            "setupPackage.vssShareAcceptances.acceptanceRecords.privateEnvelopeHash",
        )?));
    };
    if private_vss_envelope_binding.source_trustee_identity != source_trustee_identity {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeSourceTrusteeMismatch",
            "VSS share acceptance source trustee must match the private VSS envelope commitment source trustee",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeIdentity",
        )?));
    }
    if private_vss_envelope_binding.recipient_identity != recipient_identity {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeRecipientMismatch",
            "VSS share acceptance recipient must match the private VSS envelope commitment recipient",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientIdentity",
        )?));
    }
    if private_vss_envelope_binding.source_trustee_commitment_root
        != expected_source_trustee_commitment_root
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "VSS share acceptance sourceTrusteeCommitmentRoot must match the private VSS envelope commitment source trustee root",
            "setupPackage.vssShareAcceptances.acceptanceRecords.sourceTrusteeCommitmentRoot",
        )?));
    }

    for field_name in ["privateEnvelopeHash", "localVerificationRoot"] {
        let Some(hash) = acceptance_record.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                vec![format!(
                    "vssShareAcceptances.acceptanceRecords.{field_name}"
                )],
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            &format!("vssShareAcceptances.acceptanceRecords.{field_name}"),
        )?;
    }
    if acceptance_record
        .get("privateEnvelopeHash")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_binding.private_envelope_hash.as_str())
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeHashMismatch",
            "VSS share acceptance privateEnvelopeHash must match the private VSS envelope commitment",
            "setupPackage.vssShareAcceptances.acceptanceRecords.privateEnvelopeHash",
        )?));
    }
    if acceptance_record
        .get("localVerificationRoot")
        .and_then(Value::as_str)
        != Some(
            private_vss_envelope_binding
                .local_verification_root
                .as_str(),
        )
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceLocalVerificationRootMismatch",
            "VSS share acceptance localVerificationRoot must match the private VSS envelope commitment",
            "setupPackage.vssShareAcceptances.acceptanceRecords.localVerificationRoot",
        )?));
    }

    let recovery_epoch = acceptance_record
        .get("recoveryEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share acceptance recoveryEpoch must be a non-negative integer",
            )
        })?;
    let device_epoch = acceptance_record
        .get("deviceEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share acceptance deviceEpoch must be a non-negative integer",
            )
        })?;
    let Some(signing_public_key_hash) = acceptance_record
        .get("signingPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSigningKeyMissing",
            "VSS share acceptance must bind signingPublicKeyHash",
            "setupPackage.vssShareAcceptances.acceptanceRecords.signingPublicKeyHash",
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        "vssShareAcceptances.acceptanceRecords.signingPublicKeyHash",
    )?;
    let Some(recipient_registration) = verification_context
        .trustee_registrations
        .get(&recipient_roster_position)
    else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSigningKeyRegistrationMissing",
            "VSS share acceptance recipient is missing from setupIntent registrations",
            "setupPackage.vssShareAcceptances.acceptanceRecords.recipientRosterPosition",
        )?));
    };
    if recipient_registration.signing_public_key_hash != signing_public_key_hash {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSigningKeyMismatch",
            "VSS share acceptance signingPublicKeyHash must match setupIntent registration for the recipient",
            "setupPackage.vssShareAcceptances.acceptanceRecords.signingPublicKeyHash",
        )?));
    }

    let acceptance_payload = vss_share_acceptance_payload_value(acceptance_record)?;
    let expected_acceptance_root = derive_canonical_object_hash(&acceptance_payload)?;
    let Some(acceptance_root) = acceptance_record
        .get("acceptanceRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            vec!["vssShareAcceptances.acceptanceRecords.acceptanceRoot".to_string()],
            Vec::new(),
        )?));
    };
    validate_hash_string(
        acceptance_root,
        "vssShareAcceptances.acceptanceRecords.acceptanceRoot",
    )?;
    if acceptance_root != expected_acceptance_root {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRootMismatch",
            "VSS share acceptance root does not match the canonical acceptance payload",
            "setupPackage.vssShareAcceptances.acceptanceRecords.acceptanceRoot",
        )?));
    }

    let expected_context_hash =
        vss_share_acceptance_signature_context_hash(acceptance_record, acceptance_root)?;
    let Some(signature_envelope) = acceptance_record.get("signatureEnvelope") else {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSignatureMissing",
            "VSS share acceptance must include the signed ML-DSA envelope",
            "setupPackage.vssShareAcceptances.acceptanceRecords.signatureEnvelope",
        )?));
    };
    let manifest_hash = setup_context_string(verification_context.setup_context, "manifestHash")?;
    let ceremony_id = setup_context_string(verification_context.setup_context, "ceremonyId")?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: "VssShareAcceptance",
            signer_role: "Trustee",
            signer_identity: recipient_identity,
            ceremony_id,
            public_key_hash: &recipient_registration.signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(acceptance_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: &expected_context_hash,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(()) => Ok(None),
        Err(failure) => Ok(Some(vss_share_acceptance_refusal(
            failure.reason_code,
            failure.message,
            "setupPackage.vssShareAcceptances.acceptanceRecords.signatureEnvelope",
        )?)),
    }
}

fn vss_share_acceptance_payload_value(acceptance_record: &Value) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "VssShareAcceptance",
        "ceremonyId": value_string(acceptance_record, "ceremonyId")?,
        "manifestHash": value_string(acceptance_record, "manifestHash")?,
        "rosterHash": value_string(acceptance_record, "rosterHash")?,
        "setupParametersHash": value_string(acceptance_record, "setupParametersHash")?,
        "setupEpoch": value_string(acceptance_record, "setupEpoch")?,
        "sourceTrusteeIdentity": value_string(acceptance_record, "sourceTrusteeIdentity")?,
        "sourceTrusteeRosterPosition": value_u64(acceptance_record, "sourceTrusteeRosterPosition")?,
        "recipientIdentity": value_string(acceptance_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(acceptance_record, "recipientRosterPosition")?,
        "sourceTrusteeCommitmentRoot": value_string(acceptance_record, "sourceTrusteeCommitmentRoot")?,
        "privateVssEnvelopeCommitmentRoot": value_string(
            acceptance_record,
            "privateVssEnvelopeCommitmentRoot",
        )?,
        "privateEnvelopeHash": value_string(acceptance_record, "privateEnvelopeHash")?,
        "localVerificationRoot": value_string(acceptance_record, "localVerificationRoot")?,
        "recoveryEpoch": value_u64(acceptance_record, "recoveryEpoch")?,
        "deviceEpoch": value_u64(acceptance_record, "deviceEpoch")?,
        "signingPublicKeyHash": value_string(acceptance_record, "signingPublicKeyHash")?,
    }))
}

fn vss_share_acceptance_signature_context_hash(
    acceptance_record: &Value,
    acceptance_root: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "VssShareAcceptanceSignatureContext",
        "ceremonyId": value_string(acceptance_record, "ceremonyId")?,
        "manifestHash": value_string(acceptance_record, "manifestHash")?,
        "rosterHash": value_string(acceptance_record, "rosterHash")?,
        "setupParametersHash": value_string(acceptance_record, "setupParametersHash")?,
        "setupEpoch": value_string(acceptance_record, "setupEpoch")?,
        "sourceTrusteeIdentity": value_string(acceptance_record, "sourceTrusteeIdentity")?,
        "sourceTrusteeRosterPosition": value_u64(acceptance_record, "sourceTrusteeRosterPosition")?,
        "recipientIdentity": value_string(acceptance_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(acceptance_record, "recipientRosterPosition")?,
        "sourceTrusteeCommitmentRoot": value_string(acceptance_record, "sourceTrusteeCommitmentRoot")?,
        "privateVssEnvelopeCommitmentRoot": value_string(
            acceptance_record,
            "privateVssEnvelopeCommitmentRoot",
        )?,
        "privateEnvelopeHash": value_string(acceptance_record, "privateEnvelopeHash")?,
        "localVerificationRoot": value_string(acceptance_record, "localVerificationRoot")?,
        "acceptanceRoot": acceptance_root,
    }))
}

fn vss_share_acceptance_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    )
}
