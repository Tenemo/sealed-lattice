use super::*;

pub(in super::super) fn verify_vss_complaints(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Value>> {
    let Some(complaint_set) = setup_package.get("vssComplaints") else {
        return Ok(None);
    };
    if !complaint_set.is_object() {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintsNotObject",
            "vssComplaints must be an object, not an array or scalar",
            "setupPackage.vssComplaints",
        )?));
    }
    if complaint_set.get("objectType").and_then(Value::as_str) != Some("VssComplaintSet") {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSetTypeMismatch",
            "vssComplaints.objectType must be VssComplaintSet",
            "setupPackage.vssComplaints.objectType",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS complaint verification",
        )
    })?;

    let private_vss_envelope_commitment_root = setup_package
        .get("privateVssEnvelopeCommitments")
        .and_then(|commitments| commitments.get("privateVssEnvelopeCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot was required before VSS complaint verification",
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
    let Some(complaint_records) = complaint_set
        .get("complaintRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecordsMissing",
            "vssComplaints.complaintRecords must contain at least one signed VSS complaint",
            "setupPackage.vssComplaints.complaintRecords",
        )?));
    };
    if complaint_records.is_empty() {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecordsEmpty",
            "vssComplaints must be omitted unless it contains at least one signed VSS complaint",
            "setupPackage.vssComplaints.complaintRecords",
        )?));
    }

    let mut seen_complaints = BTreeSet::new();
    for complaint_record in complaint_records {
        if let Some(response) = verify_vss_complaint_record(
            complaint_record,
            &verification_context,
            &mut seen_complaints,
        )? {
            return Ok(Some(response));
        }
    }

    // A single valid complaint aborts the ceremony because any provable dealer equivocation is disqualifying, whereas acceptance must be unanimous over all source-by-recipient pairs.
    Ok(Some(verification_response(
        Vec::new(),
        vec![Refusal::new(
            "vssComplaintAcceptedAbort",
            "a valid VSS complaint aborts the foundation-roster setup ceremony",
            "setupPackage.vssComplaints",
        )],
    )?))
}

fn verify_vss_complaint_record(
    complaint_record: &Value,
    verification_context: &VssRecordVerificationContext<'_>,
    seen_complaints: &mut BTreeSet<(u64, u64)>,
) -> CanonicalResult<Option<Value>> {
    if complaint_record.get("objectType").and_then(Value::as_str) != Some("VssShareComplaint") {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintTypeMismatch",
            "VSS complaint objectType must be VssShareComplaint",
            "setupPackage.vssComplaints.complaintRecords.objectType",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if complaint_record.get(field_name) != verification_context.setup_context.get(field_name) {
            return Ok(Some(vss_complaint_refusal(
                "vssComplaintContextMismatch",
                format!("VSS complaint {field_name} must match setupContext"),
                format!("setupPackage.vssComplaints.complaintRecords.{field_name}"),
            )?));
        }
    }
    if complaint_record
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(verification_context.private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeRootMismatch",
            "VSS complaint must bind privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssComplaints.complaintRecords.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let Some(source_trustee_identity) = complaint_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteeMissing",
            "VSS complaint must bind sourceTrusteeIdentity",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeIdentity",
        )?));
    };
    let Some(source_trustee_roster_position) = complaint_record
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteePositionMissing",
            "VSS complaint must bind sourceTrusteeRosterPosition",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeRosterPosition",
        )?));
    };
    if verification_context
        .expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteeMismatch",
            "VSS complaint source trustee must match the phase transcript trustee identity",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeIdentity",
        )?));
    }

    let Some(recipient_identity) = complaint_record
        .get("recipientIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecipientMissing",
            "VSS complaint must bind recipientIdentity",
            "setupPackage.vssComplaints.complaintRecords.recipientIdentity",
        )?));
    };
    let Some(recipient_roster_position) = complaint_record
        .get("recipientRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecipientPositionMissing",
            "VSS complaint must bind recipientRosterPosition",
            "setupPackage.vssComplaints.complaintRecords.recipientRosterPosition",
        )?));
    };
    if verification_context
        .expected_trustees
        .get(&recipient_roster_position)
        .map(String::as_str)
        != Some(recipient_identity)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecipientMismatch",
            "VSS complaint recipient must match the phase transcript trustee identity",
            "setupPackage.vssComplaints.complaintRecords.recipientIdentity",
        )?));
    }
    if !seen_complaints.insert((source_trustee_roster_position, recipient_roster_position)) {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintDuplicate",
            "VSS complaint records must have distinct source-trustee-recipient trustee pairs",
            "setupPackage.vssComplaints.complaintRecords",
        )?));
    }

    let expected_source_trustee_commitment_root = verification_context
        .source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee commitment root missing for VSS complaint verification",
            )
        })?;
    if complaint_record
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(expected_source_trustee_commitment_root)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSourceTrusteeCommitmentRootMismatch",
            "VSS complaint sourceTrusteeCommitmentRoot must match the accepted source trustee coefficient commitments",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeCommitmentRoot",
        )?));
    }
    let Some(private_vss_envelope_binding) = verification_context
        .private_vss_envelope_bindings
        .get(&(source_trustee_roster_position, recipient_roster_position))
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeBindingMissing",
            "VSS complaint must match a private VSS envelope commitment for the source-trustee-recipient pair",
            "setupPackage.vssComplaints.complaintRecords.privateEnvelopeHash",
        )?));
    };
    if private_vss_envelope_binding.source_trustee_identity != source_trustee_identity {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeSourceTrusteeMismatch",
            "VSS complaint source trustee must match the private VSS envelope commitment source trustee",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeIdentity",
        )?));
    }
    if private_vss_envelope_binding.recipient_identity != recipient_identity {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeRecipientMismatch",
            "VSS complaint recipient must match the private VSS envelope commitment recipient",
            "setupPackage.vssComplaints.complaintRecords.recipientIdentity",
        )?));
    }
    if private_vss_envelope_binding.source_trustee_commitment_root
        != expected_source_trustee_commitment_root
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "VSS complaint sourceTrusteeCommitmentRoot must match the private VSS envelope commitment source trustee root",
            "setupPackage.vssComplaints.complaintRecords.sourceTrusteeCommitmentRoot",
        )?));
    }

    for field_name in ["privateEnvelopeHash", "complaintEvidenceRoot"] {
        let Some(hash) = complaint_record.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(vss_complaint_refusal(
                "vssComplaintHashMissing",
                format!("VSS complaint must bind {field_name}"),
                format!("setupPackage.vssComplaints.complaintRecords.{field_name}"),
            )?));
        };
        validate_hash_string(
            hash,
            &format!("vssComplaints.complaintRecords.{field_name}"),
        )?;
    }
    if complaint_record
        .get("privateEnvelopeHash")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_binding.private_envelope_hash.as_str())
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeHashMismatch",
            "VSS complaint privateEnvelopeHash must match the private VSS envelope commitment",
            "setupPackage.vssComplaints.complaintRecords.privateEnvelopeHash",
        )?));
    }
    if complaint_record
        .get("complaintReasonCode")
        .and_then(Value::as_str)
        .filter(|reason_code| !reason_code.is_empty())
        .is_none()
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintReasonMissing",
            "VSS complaint must bind a non-empty complaintReasonCode",
            "setupPackage.vssComplaints.complaintRecords.complaintReasonCode",
        )?));
    }

    let recovery_epoch = complaint_record
        .get("recoveryEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS complaint recoveryEpoch must be a non-negative integer",
            )
        })?;
    let device_epoch = complaint_record
        .get("deviceEpoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS complaint deviceEpoch must be a non-negative integer",
            )
        })?;
    let Some(signing_public_key_hash) = complaint_record
        .get("signingPublicKeyHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSigningKeyMissing",
            "VSS complaint must bind signingPublicKeyHash",
            "setupPackage.vssComplaints.complaintRecords.signingPublicKeyHash",
        )?));
    };
    validate_hash_string(
        signing_public_key_hash,
        "vssComplaints.complaintRecords.signingPublicKeyHash",
    )?;
    let Some(recipient_registration) = verification_context
        .trustee_registrations
        .get(&recipient_roster_position)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSigningKeyRegistrationMissing",
            "VSS complaint recipient is missing from setupIntent registrations",
            "setupPackage.vssComplaints.complaintRecords.recipientRosterPosition",
        )?));
    };
    if recipient_registration.signing_public_key_hash != signing_public_key_hash {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSigningKeyMismatch",
            "VSS complaint signingPublicKeyHash must match setupIntent registration for the recipient",
            "setupPackage.vssComplaints.complaintRecords.signingPublicKeyHash",
        )?));
    }

    let complaint_payload = vss_complaint_payload_value(complaint_record)?;
    let expected_complaint_root = derive_canonical_object_hash(&complaint_payload)?;
    let Some(complaint_root) = complaint_record
        .get("complaintRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMissing",
            "VSS complaint must bind complaintRoot",
            "setupPackage.vssComplaints.complaintRecords.complaintRoot",
        )?));
    };
    validate_hash_string(
        complaint_root,
        "vssComplaints.complaintRecords.complaintRoot",
    )?;
    if complaint_root != expected_complaint_root {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMismatch",
            "VSS complaint root does not match the canonical complaint payload",
            "setupPackage.vssComplaints.complaintRecords.complaintRoot",
        )?));
    }

    let expected_context_hash =
        vss_complaint_signature_context_hash(complaint_record, complaint_root)?;
    let Some(signature_envelope) = complaint_record.get("signatureEnvelope") else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSignatureMissing",
            "VSS complaint must include the signed ML-DSA envelope",
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelope",
        )?));
    };
    let manifest_hash = setup_context_string(verification_context.setup_context, "manifestHash")?;
    let ceremony_id = setup_context_string(verification_context.setup_context, "ceremonyId")?;
    let verification = verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: "VssShareComplaint",
            signer_role: "Trustee",
            // The recipient is the signer of both complaints and acceptances, since only the share recipient can attest whether the dealt share opened correctly.
            signer_identity: recipient_identity,
            ceremony_id,
            public_key_hash: &recipient_registration.signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(complaint_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: &expected_context_hash,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(()) => Ok(None),
        Err(failure) => Ok(Some(vss_complaint_refusal(
            failure.reason_code,
            failure.message,
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelope",
        )?)),
    }
}

fn vss_complaint_payload_value(complaint_record: &Value) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "VssShareComplaint",
        "ceremonyId": value_string(complaint_record, "ceremonyId")?,
        "manifestHash": value_string(complaint_record, "manifestHash")?,
        "rosterHash": value_string(complaint_record, "rosterHash")?,
        "setupParametersHash": value_string(complaint_record, "setupParametersHash")?,
        "setupEpoch": value_string(complaint_record, "setupEpoch")?,
        "sourceTrusteeIdentity": value_string(complaint_record, "sourceTrusteeIdentity")?,
        "sourceTrusteeRosterPosition": value_u64(complaint_record, "sourceTrusteeRosterPosition")?,
        "recipientIdentity": value_string(complaint_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(complaint_record, "recipientRosterPosition")?,
        "sourceTrusteeCommitmentRoot": value_string(complaint_record, "sourceTrusteeCommitmentRoot")?,
        "privateVssEnvelopeCommitmentRoot": value_string(
            complaint_record,
            "privateVssEnvelopeCommitmentRoot",
        )?,
        "privateEnvelopeHash": value_string(complaint_record, "privateEnvelopeHash")?,
        "complaintEvidenceRoot": value_string(complaint_record, "complaintEvidenceRoot")?,
        "complaintReasonCode": value_string(complaint_record, "complaintReasonCode")?,
        "recoveryEpoch": value_u64(complaint_record, "recoveryEpoch")?,
        "deviceEpoch": value_u64(complaint_record, "deviceEpoch")?,
        "signingPublicKeyHash": value_string(complaint_record, "signingPublicKeyHash")?,
    }))
}

fn vss_complaint_signature_context_hash(
    complaint_record: &Value,
    complaint_root: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "VssShareComplaintSignatureContext",
        "ceremonyId": value_string(complaint_record, "ceremonyId")?,
        "manifestHash": value_string(complaint_record, "manifestHash")?,
        "rosterHash": value_string(complaint_record, "rosterHash")?,
        "setupParametersHash": value_string(complaint_record, "setupParametersHash")?,
        "setupEpoch": value_string(complaint_record, "setupEpoch")?,
        "sourceTrusteeIdentity": value_string(complaint_record, "sourceTrusteeIdentity")?,
        "sourceTrusteeRosterPosition": value_u64(complaint_record, "sourceTrusteeRosterPosition")?,
        "recipientIdentity": value_string(complaint_record, "recipientIdentity")?,
        "recipientRosterPosition": value_u64(complaint_record, "recipientRosterPosition")?,
        "sourceTrusteeCommitmentRoot": value_string(complaint_record, "sourceTrusteeCommitmentRoot")?,
        "privateVssEnvelopeCommitmentRoot": value_string(
            complaint_record,
            "privateVssEnvelopeCommitmentRoot",
        )?,
        "privateEnvelopeHash": value_string(complaint_record, "privateEnvelopeHash")?,
        "complaintEvidenceRoot": value_string(complaint_record, "complaintEvidenceRoot")?,
        "complaintReasonCode": value_string(complaint_record, "complaintReasonCode")?,
        "complaintRoot": complaint_root,
    }))
}

fn vss_complaint_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    )
}
