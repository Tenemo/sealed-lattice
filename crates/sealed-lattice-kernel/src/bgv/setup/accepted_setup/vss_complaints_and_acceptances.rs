use super::*;

pub(super) fn verify_vss_complaints(setup_package: &Value) -> CanonicalResult<Option<Value>> {
    let Some(complaint_set) = setup_package.get("vssComplaints") else {
        return Ok(None);
    };
    if !complaint_set.is_object() {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintsNotObject",
            "vssComplaints must be a root-bound object, not an array or scalar",
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
    if complaint_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSetVersionMismatch",
            "vssComplaints.objectVersion must be 1",
            "setupPackage.vssComplaints.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS complaint verification",
        )
    })?;
    if let Err(error) = verify_vss_complaint_context(complaint_set, setup_context) {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintContextMismatch",
            error.message,
            "setupPackage.vssComplaints",
        )?));
    }

    let private_vss_envelope_commitment_root = setup_package
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitmentRoot was required before VSS complaint verification",
            )
        })?;
    validate_hash_string(
        private_vss_envelope_commitment_root,
        "privateVssEnvelopeCommitmentRoot",
    )?;
    if complaint_set
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintPrivateEnvelopeRootMismatch",
            "vssComplaints.privateVssEnvelopeCommitmentRoot must match setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssComplaints.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let trustee_registrations =
        super::phase_transcript::setup_intent_trustee_registrations_from_phase_transcript(
            setup_package,
        )?;
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    let private_vss_envelope_bindings = private_vss_envelope_bindings_from_package(setup_package)?;
    let verification_context = VssRecordVerificationContext {
        setup_context,
        expected_trustees: &expected_trustees,
        trustee_registrations: &trustee_registrations,
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

    let Some(complaint_root) = complaint_set
        .get("vssComplaintRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMissing",
            "vssComplaints.vssComplaintRoot must root-bind the complaint set",
            "setupPackage.vssComplaints.vssComplaintRoot",
        )?));
    };
    validate_hash_string(complaint_root, "vssComplaints.vssComplaintRoot")?;
    let mut root_input = complaint_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS complaint set object was checked")
        .remove("vssComplaintRoot");
    let expected_root = derive_protocol_hash("VssComplaintRoot", &root_input)?;
    if complaint_root != expected_root {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRootMismatch",
            "vssComplaintRoot does not match the canonical VSS complaint set",
            "setupPackage.vssComplaints.vssComplaintRoot",
        )?));
    }

    // A single valid complaint aborts the ceremony because any provable dealer equivocation is disqualifying, whereas acceptance must be unanimous over all source-by-recipient pairs.
    Ok(Some(verification_response(
        VerifierStatus::Aborted,
        Some("vssAcceptanceOrComplaint"),
        Vec::new(),
        vec![Refusal::new(
            "vssComplaintAcceptedAbort",
            "a valid VSS complaint aborts the first-roster setup ceremony",
            "setupPackage.vssComplaints",
        )],
        Vec::new(),
    )?))
}

fn verify_vss_complaint_context(
    complaint_set: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if complaint_set.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("vssComplaints.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

struct VssRecordVerificationContext<'a> {
    setup_context: &'a Value,
    expected_trustees: &'a BTreeMap<u64, String>,
    trustee_registrations:
        &'a BTreeMap<u64, super::phase_transcript::SetupIntentTrusteeRegistration>,
    source_trustee_commitment_roots: &'a BTreeMap<u64, String>,
    private_vss_envelope_commitment_root: &'a str,
    private_vss_envelope_bindings: &'a PrivateVssEnvelopeBindingMap,
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
    if complaint_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintVersionMismatch",
            "VSS complaint objectVersion must be 1",
            "setupPackage.vssComplaints.complaintRecords.objectVersion",
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
            "VSS complaint must bind setupPackage.privateVssEnvelopeCommitmentRoot",
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
    let expected_complaint_root = derive_protocol_hash("VssComplaintRoot", &complaint_payload)?;
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

    let expected_byte_length =
        u64::try_from(canonical_json(&complaint_payload)?.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS complaint payload byte length does not fit u64",
            )
        })?;
    let Some(complaint_byte_length) = complaint_record
        .get("complaintByteLength")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintByteLengthMissing",
            "VSS complaint must bind complaintByteLength",
            "setupPackage.vssComplaints.complaintRecords.complaintByteLength",
        )?));
    };
    if complaint_byte_length != expected_byte_length {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintByteLengthMismatch",
            "VSS complaint byte length does not match the canonical complaint payload",
            "setupPackage.vssComplaints.complaintRecords.complaintByteLength",
        )?));
    }

    let expected_context_hash =
        vss_complaint_signature_context_hash(complaint_record, complaint_root)?;
    let Some(complaint_context_hash) = complaint_record
        .get("complaintContextHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintContextHashMissing",
            "VSS complaint must bind complaintContextHash",
            "setupPackage.vssComplaints.complaintRecords.complaintContextHash",
        )?));
    };
    validate_hash_string(
        complaint_context_hash,
        "vssComplaints.complaintRecords.complaintContextHash",
    )?;
    if complaint_context_hash != expected_context_hash {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintContextHashMismatch",
            "VSS complaint context hash does not match the signed complaint binding",
            "setupPackage.vssComplaints.complaintRecords.complaintContextHash",
        )?));
    }

    let Some(signature_envelope_hash) = complaint_record
        .get("signatureEnvelopeHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSignatureHashMissing",
            "VSS complaint must bind signatureEnvelopeHash",
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelopeHash",
        )?));
    };
    validate_hash_string(
        signature_envelope_hash,
        "vssComplaints.complaintRecords.signatureEnvelopeHash",
    )?;
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
            object_version: 1,
            signer_role: "Trustee",
            // The recipient is the signer of both complaints and acceptances, since only the share recipient can attest whether the dealt share opened correctly.
            signer_identity: recipient_identity,
            ceremony_id,
            public_key_hash: &recipient_registration.signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(complaint_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: complaint_context_hash,
            byte_length: complaint_byte_length,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(verified_signature_hash) if verified_signature_hash == signature_envelope_hash => {
            Ok(None)
        }
        Ok(_) => Ok(Some(vss_complaint_refusal(
            "vssComplaintSignatureHashMismatch",
            "VSS complaint signature envelope hash does not match the verified envelope",
            "setupPackage.vssComplaints.complaintRecords.signatureEnvelopeHash",
        )?)),
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
        "objectVersion": 1,
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
    derive_protocol_hash(
        "VssComplaintRoot",
        &json!({
            "purpose": "vss-share-complaint-signature-context",
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
        }),
    )
}

fn vss_complaint_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssAcceptanceOrComplaint"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn verify_vss_share_acceptances(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(acceptance_set) = setup_package.get("vssShareAcceptances") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !acceptance_set.is_object() {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancesNotObject",
            "vssShareAcceptances must be a root-bound object, not an array or scalar",
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
    if acceptance_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSetVersionMismatch",
            "vssShareAcceptances.objectVersion must be 1",
            "setupPackage.vssShareAcceptances.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS share acceptance verification",
        )
    })?;
    if let Err(error) = verify_vss_share_acceptance_context(acceptance_set, setup_context) {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceContextMismatch",
            error.message,
            "setupPackage.vssShareAcceptances",
        )?));
    }

    let private_vss_envelope_commitment_root = setup_package
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "privateVssEnvelopeCommitmentRoot was required before VSS share acceptance verification",
            )
        })?;
    validate_hash_string(
        private_vss_envelope_commitment_root,
        "privateVssEnvelopeCommitmentRoot",
    )?;
    if acceptance_set
        .get("privateVssEnvelopeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(private_vss_envelope_commitment_root)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptancePrivateEnvelopeRootMismatch",
            "vssShareAcceptances.privateVssEnvelopeCommitmentRoot must match setupPackage.privateVssEnvelopeCommitmentRoot",
            "setupPackage.vssShareAcceptances.privateVssEnvelopeCommitmentRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let trustee_registrations =
        super::phase_transcript::setup_intent_trustee_registrations_from_phase_transcript(
            setup_package,
        )?;
    let source_trustee_commitment_roots =
        source_trustee_commitment_roots_from_vss_commitments(setup_package)?;
    let private_vss_envelope_bindings = private_vss_envelope_bindings_from_package(setup_package)?;
    let verification_context = VssRecordVerificationContext {
        setup_context,
        expected_trustees: &expected_trustees,
        trustee_registrations: &trustee_registrations,
        source_trustee_commitment_roots: &source_trustee_commitment_roots,
        private_vss_envelope_commitment_root,
        private_vss_envelope_bindings: &private_vss_envelope_bindings,
    };
    let Some(acceptance_records) = acceptance_set
        .get("acceptanceRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let roster = super::accepted_roster_from_package(setup_package);
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

    let Some(acceptance_root) = acceptance_set
        .get("vssShareAcceptanceRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.vssShareAcceptanceRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        acceptance_root,
        "vssShareAcceptances.vssShareAcceptanceRoot",
    )?;
    let mut root_input = acceptance_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS share acceptance set object was checked")
        .remove("vssShareAcceptanceRoot");
    let expected_root = derive_protocol_hash("VssShareAcceptanceRoot", &root_input)?;
    if acceptance_root != expected_root {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceRootMismatch",
            "vssShareAcceptanceRoot does not match the canonical VSS share acceptance set",
            "setupPackage.vssShareAcceptances.vssShareAcceptanceRoot",
        )?));
    }

    Ok(None)
}

fn verify_vss_share_acceptance_context(
    acceptance_set: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if acceptance_set.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("vssShareAcceptances.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

pub(super) fn source_trustee_commitment_roots_from_vss_commitments(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before VSS share acceptance verification",
            )
        })?;
    let mut source_trustee_roots = BTreeMap::new();
    for source_trustee_record in source_trustee_records {
        let source_trustee_roster_position = source_trustee_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "source trustee VSS commitment record must bind sourceTrusteeRosterPosition",
                )
            })?;
        let source_trustee_commitment_root = source_trustee_record
            .get("sourceTrusteeCommitmentRoot")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "source trustee VSS commitment record must bind sourceTrusteeCommitmentRoot",
                )
            })?;
        source_trustee_roots.insert(
            source_trustee_roster_position,
            source_trustee_commitment_root.to_string(),
        );
    }

    Ok(source_trustee_roots)
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
    if acceptance_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceVersionMismatch",
            "VSS share acceptance objectVersion must be 1",
            "setupPackage.vssShareAcceptances.acceptanceRecords.objectVersion",
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
            "VSS share acceptance must bind setupPackage.privateVssEnvelopeCommitmentRoot",
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
                VerifierStatus::Pending,
                Some("vssAcceptanceOrComplaint"),
                vec![format!(
                    "vssShareAcceptances.acceptanceRecords.{field_name}"
                )],
                Vec::new(),
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
    let expected_acceptance_root =
        derive_protocol_hash("VssShareAcceptanceRoot", &acceptance_payload)?;
    let Some(acceptance_root) = acceptance_record
        .get("acceptanceRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.acceptanceRoot".to_string()],
            Vec::new(),
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

    let expected_byte_length =
        u64::try_from(canonical_json(&acceptance_payload)?.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS share acceptance payload byte length does not fit u64",
            )
        })?;
    let Some(acceptance_byte_length) = acceptance_record
        .get("acceptanceByteLength")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.acceptanceByteLength".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if acceptance_byte_length != expected_byte_length {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceByteLengthMismatch",
            "VSS share acceptance byte length does not match the canonical acceptance payload",
            "setupPackage.vssShareAcceptances.acceptanceRecords.acceptanceByteLength",
        )?));
    }

    let expected_context_hash =
        vss_share_acceptance_signature_context_hash(acceptance_record, acceptance_root)?;
    let Some(acceptance_context_hash) = acceptance_record
        .get("acceptanceContextHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.acceptanceContextHash".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        acceptance_context_hash,
        "vssShareAcceptances.acceptanceRecords.acceptanceContextHash",
    )?;
    if acceptance_context_hash != expected_context_hash {
        return Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceContextHashMismatch",
            "VSS share acceptance context hash does not match the signed acceptance binding",
            "setupPackage.vssShareAcceptances.acceptanceRecords.acceptanceContextHash",
        )?));
    }

    let Some(signature_envelope_hash) = acceptance_record
        .get("signatureEnvelopeHash")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssAcceptanceOrComplaint"),
            vec!["vssShareAcceptances.acceptanceRecords.signatureEnvelopeHash".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        signature_envelope_hash,
        "vssShareAcceptances.acceptanceRecords.signatureEnvelopeHash",
    )?;
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
            object_version: 1,
            signer_role: "Trustee",
            signer_identity: recipient_identity,
            ceremony_id,
            public_key_hash: &recipient_registration.signing_public_key_hash,
            manifest_hash: Some(manifest_hash),
            object_root: Some(acceptance_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: acceptance_context_hash,
            byte_length: acceptance_byte_length,
            recovery_epoch,
            device_epoch,
        },
    )?;
    match verification {
        Ok(verified_signature_hash) if verified_signature_hash == signature_envelope_hash => {
            Ok(None)
        }
        Ok(_) => Ok(Some(vss_share_acceptance_refusal(
            "vssShareAcceptanceSignatureHashMismatch",
            "VSS share acceptance signature envelope hash does not match the verified envelope",
            "setupPackage.vssShareAcceptances.acceptanceRecords.signatureEnvelopeHash",
        )?)),
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
        "objectVersion": 1,
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
    derive_protocol_hash(
        "VssShareAcceptanceRoot",
        &json!({
            "purpose": "vss-share-acceptance-signature-context",
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
        }),
    )
}

fn vss_share_acceptance_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssAcceptanceOrComplaint"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
