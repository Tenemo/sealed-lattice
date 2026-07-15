use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) struct VssRecordVerificationContext<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) expected_trustees: BTreeMap<u64, String>,
    pub(super) trustee_registrations: &'a setup_intent::SetupIntentTrusteeRegistrationMap,
    pub(super) source_trustee_commitment_roots: BTreeMap<u64, String>,
    pub(super) private_vss_envelope_commitment_root: String,
    pub(super) private_vss_envelope_bindings: PrivateVssEnvelopeBindingMap,
}

impl<'a> VssRecordVerificationContext<'a> {
    pub(super) fn from_package(
        setup_package: &'a Value,
        trustee_registrations: &'a setup_intent::SetupIntentTrusteeRegistrationMap,
    ) -> CanonicalResult<Self> {
        let setup_context = setup_package.get("setupContext").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "setupContext was required before VSS response verification",
            )
        })?;
        let private_vss_envelope_commitment_root =
            private_vss_envelope_commitment_root(setup_package)?;

        Ok(Self {
            setup_context,
            expected_trustees: expected_trustees_from_setup_intent(trustee_registrations),
            trustee_registrations,
            source_trustee_commitment_roots: source_trustee_commitment_roots_from_vss_commitments(
                setup_package,
            )?,
            private_vss_envelope_commitment_root,
            private_vss_envelope_bindings: private_vss_envelope_bindings_from_package(
                setup_package,
                trustee_registrations,
            )?,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum VssResponseKind {
    Complaint,
    Acceptance,
}

impl VssResponseKind {
    fn expected_object_type(self) -> &'static str {
        match self {
            Self::Complaint => "VssShareComplaint",
            Self::Acceptance => "VssShareAcceptance",
        }
    }

    fn record_path(self) -> &'static str {
        match self {
            Self::Complaint => "setupPackage.vssComplaints.complaintRecords",
            Self::Acceptance => "setupPackage.vssShareAcceptances.acceptanceRecords",
        }
    }

    fn refusal(
        self,
        refusal_reason: crate::foundation::RefusalReason,
        complaint_refusal_code: &'static str,
        acceptance_refusal_code: &'static str,
        message: impl Into<String>,
        field_name: Option<&str>,
    ) -> Refusal {
        Refusal::new(
            refusal_reason,
            match self {
                Self::Complaint => complaint_refusal_code,
                Self::Acceptance => acceptance_refusal_code,
            },
            message,
            match field_name {
                Some(field_name) => format!("{}.{field_name}", self.record_path()),
                None => self.record_path().to_string(),
            },
        )
    }

    fn variant_refusal(
        self,
        refusal_reason: crate::foundation::RefusalReason,
        reason_code: &'static str,
        message: impl Into<String>,
        field_name: Option<&str>,
    ) -> Refusal {
        Refusal::new(
            refusal_reason,
            reason_code,
            message,
            match field_name {
                Some(field_name) => format!("{}.{field_name}", self.record_path()),
                None => self.record_path().to_string(),
            },
        )
    }

    fn root_mismatch_reason_code(self) -> &'static str {
        match self {
            Self::Complaint => "vssComplaintRootMismatch",
            Self::Acceptance => "vssShareAcceptanceRootMismatch",
        }
    }

    fn signature_missing_reason_code(self) -> &'static str {
        match self {
            Self::Complaint => "vssComplaintSignatureMissing",
            Self::Acceptance => "vssShareAcceptanceSignatureMissing",
        }
    }
}

pub(super) struct VerifiedVssResponseRecord {
    source_trustee_identity: String,
    source_trustee_roster_position: u64,
    recipient_identity: String,
    recipient_roster_position: u64,
    expected_source_trustee_commitment_root: String,
    expected_private_envelope_hash: String,
}

pub(super) fn verify_vss_response_record_binding(
    record: &Value,
    verification_context: &VssRecordVerificationContext<'_>,
    seen_pairs: &mut BTreeSet<(u64, u64)>,
    kind: VssResponseKind,
) -> CanonicalResult<Result<VerifiedVssResponseRecord, Refusal>> {
    if record.get("objectType").and_then(Value::as_str) != Some(kind.expected_object_type()) {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "vssComplaintTypeMismatch",
            "vssShareAcceptanceTypeMismatch",
            format!(
                "VSS response objectType must be {}",
                kind.expected_object_type()
            ),
            Some("objectType"),
        )));
    }
    let source_trustee_roster_position_value = record.get("sourceTrusteeRosterPosition");
    let Some(source_trustee_roster_position) =
        source_trustee_roster_position_value.and_then(Value::as_u64)
    else {
        return Ok(Err(kind.refusal(
            if source_trustee_roster_position_value.is_some() {
                crate::foundation::RefusalReason::WrongTypeOrLength
            } else {
                crate::foundation::RefusalReason::MissingPrerequisite
            },
            "vssComplaintSourceTrusteePositionMissing",
            "vssShareAcceptanceSourceTrusteePositionMissing",
            "VSS response must bind sourceTrusteeRosterPosition",
            Some("sourceTrusteeRosterPosition"),
        )));
    };
    let Some(source_trustee_identity) = verification_context
        .expected_trustees
        .get(&source_trustee_roster_position)
    else {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::WrongContext,
            "vssComplaintSourceTrusteeMismatch",
            "vssShareAcceptanceSourceTrusteeMismatch",
            "VSS response source trustee position must identify a setup-intent trustee",
            Some("sourceTrusteeRosterPosition"),
        )));
    };

    let recipient_roster_position_value = record.get("recipientRosterPosition");
    let Some(recipient_roster_position) = recipient_roster_position_value.and_then(Value::as_u64)
    else {
        return Ok(Err(kind.refusal(
            if recipient_roster_position_value.is_some() {
                crate::foundation::RefusalReason::WrongTypeOrLength
            } else {
                crate::foundation::RefusalReason::MissingPrerequisite
            },
            "vssComplaintRecipientPositionMissing",
            "vssShareAcceptanceRecipientPositionMissing",
            "VSS response must bind recipientRosterPosition",
            Some("recipientRosterPosition"),
        )));
    };
    let Some(recipient_identity) = verification_context
        .expected_trustees
        .get(&recipient_roster_position)
    else {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::WrongContext,
            "vssComplaintRecipientMismatch",
            "vssShareAcceptanceRecipientMismatch",
            "VSS response recipient position must identify a setup-intent trustee",
            Some("recipientRosterPosition"),
        )));
    };
    if !seen_pairs.insert((source_trustee_roster_position, recipient_roster_position)) {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::Equivocation,
            "vssComplaintDuplicate",
            "vssShareAcceptanceDuplicate",
            "VSS response records must use distinct source-recipient pairs",
            None,
        )));
    }

    let expected_source_trustee_commitment_root = verification_context
        .source_trustee_commitment_roots
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source trustee commitment root missing for VSS response verification",
            )
        })?;
    let Some(private_envelope_binding) = verification_context
        .private_vss_envelope_bindings
        .get(&(source_trustee_roster_position, recipient_roster_position))
    else {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "vssComplaintPrivateEnvelopeBindingMissing",
            "vssShareAcceptancePrivateEnvelopeBindingMissing",
            "VSS response must match a private envelope commitment for its source-recipient pair",
            Some("recipientRosterPosition"),
        )));
    };
    if private_envelope_binding.source_trustee_identity.as_str() != source_trustee_identity.as_str()
    {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::WrongContext,
            "vssComplaintPrivateEnvelopeSourceTrusteeMismatch",
            "vssShareAcceptancePrivateEnvelopeSourceTrusteeMismatch",
            "VSS response source trustee position must match the private envelope commitment",
            Some("sourceTrusteeRosterPosition"),
        )));
    }
    if private_envelope_binding.recipient_identity.as_str() != recipient_identity.as_str() {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::WrongContext,
            "vssComplaintPrivateEnvelopeRecipientMismatch",
            "vssShareAcceptancePrivateEnvelopeRecipientMismatch",
            "VSS response recipient position must match the private envelope commitment",
            Some("recipientRosterPosition"),
        )));
    }
    if private_envelope_binding.source_trustee_commitment_root
        != expected_source_trustee_commitment_root
    {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            "vssComplaintPrivateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "vssShareAcceptancePrivateEnvelopeSourceTrusteeCommitmentRootMismatch",
            "VSS response source commitment root must match the private envelope commitment",
            Some("sourceTrusteeRosterPosition"),
        )));
    }

    Ok(Ok(VerifiedVssResponseRecord {
        source_trustee_identity: source_trustee_identity.clone(),
        source_trustee_roster_position,
        recipient_identity: recipient_identity.clone(),
        recipient_roster_position,
        expected_source_trustee_commitment_root: expected_source_trustee_commitment_root
            .to_string(),
        expected_private_envelope_hash: private_envelope_binding.private_envelope_hash.clone(),
    }))
}

pub(super) fn verify_vss_response_record(
    record: &Value,
    verification_context: &VssRecordVerificationContext<'_>,
    seen_pairs: &mut BTreeSet<(u64, u64)>,
    kind: VssResponseKind,
) -> CanonicalResult<Result<(), Refusal>> {
    let verified_record =
        match verify_vss_response_record_binding(record, verification_context, seen_pairs, kind)? {
            Ok(verified_record) => verified_record,
            Err(refusal) => return Ok(Err(refusal)),
        };

    let Some(signature_envelope) = record.get("signatureEnvelope") else {
        return Ok(Err(kind.variant_refusal(
            crate::foundation::RefusalReason::MissingPrerequisite,
            kind.signature_missing_reason_code(),
            "VSS response must include the signed ML-DSA envelope",
            Some("signatureEnvelope"),
        )));
    };
    if !signature_envelope.is_object() {
        return Ok(Err(kind.variant_refusal(
            crate::foundation::RefusalReason::InvalidSignature,
            "InvalidSignature",
            "VSS response signatureEnvelope must be an object",
            Some("signatureEnvelope"),
        )));
    }
    let Some(signed_root) = signature_envelope
        .get("signedRoot")
        .and_then(Value::as_object)
    else {
        return Ok(Err(kind.variant_refusal(
            crate::foundation::RefusalReason::InvalidSignature,
            "InvalidSignedRoot",
            "VSS response signatureEnvelope must include a signedRoot object",
            Some("signatureEnvelope.signedRoot"),
        )));
    };
    let Some(record_root) = signed_root.get("objectRoot").and_then(Value::as_str) else {
        return Ok(Err(kind.variant_refusal(
            crate::foundation::RefusalReason::InvalidSignature,
            "InvalidSignedRoot",
            "VSS response signedRoot must bind objectRoot",
            Some("signatureEnvelope.signedRoot.objectRoot"),
        )));
    };
    validate_hash_string(
        record_root,
        "VSS response signatureEnvelope.signedRoot.objectRoot",
    )?;
    let Some(recipient_registration) = verification_context
        .trustee_registrations
        .get(&verified_record.recipient_roster_position)
    else {
        return Ok(Err(kind.refusal(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "vssComplaintSigningKeyRegistrationMissing",
            "vssShareAcceptanceSigningKeyRegistrationMissing",
            "VSS response recipient is missing from setupIntent registrations",
            Some("recipientRosterPosition"),
        )));
    };
    let recovery_epoch = recipient_registration.recovery_epoch;
    let device_epoch = recipient_registration.device_epoch;

    let payload = vss_response_payload_value(
        verification_context,
        &verified_record,
        kind,
        recovery_epoch,
        device_epoch,
    )?;
    let expected_root = derive_canonical_object_hash(&payload)?;
    if record_root != expected_root {
        return Ok(Err(kind.variant_refusal(
            crate::foundation::RefusalReason::WrongHashOrRoot,
            kind.root_mismatch_reason_code(),
            "VSS response signed object root does not match its canonical payload",
            Some("signatureEnvelope.signedRoot.objectRoot"),
        )));
    }

    match verify_protocol_signature_envelope(
        signature_envelope,
        &ProtocolSignatureExpectation {
            object_type: kind.expected_object_type(),
            public_key_hash: &recipient_registration.signing_public_key_hash,
            object_root: &expected_root,
        },
    )? {
        Ok(()) => Ok(Ok(())),
        Err(failure) => Ok(Err(kind.variant_refusal(
            protocol_signature_refusal_reason(failure.reason_code),
            failure.reason_code,
            failure.message,
            Some("signatureEnvelope"),
        ))),
    }
}

fn vss_response_payload_value(
    verification_context: &VssRecordVerificationContext<'_>,
    verified_record: &VerifiedVssResponseRecord,
    kind: VssResponseKind,
    recovery_epoch: u64,
    device_epoch: u64,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": kind.expected_object_type(),
        "setupContextHash": setup_context_hash(verification_context.setup_context)?,
        "sourceTrusteeIdentity": verified_record.source_trustee_identity.as_str(),
        "sourceTrusteeRosterPosition": verified_record.source_trustee_roster_position,
        "recipientIdentity": verified_record.recipient_identity.as_str(),
        "recipientRosterPosition": verified_record.recipient_roster_position,
        "sourceTrusteeCommitmentRoot": verified_record.expected_source_trustee_commitment_root.as_str(),
        "privateVssEnvelopeCommitmentRoot": verification_context.private_vss_envelope_commitment_root.as_str(),
        "privateEnvelopeHash": verified_record.expected_private_envelope_hash.as_str(),
        "recoveryEpoch": recovery_epoch,
        "deviceEpoch": device_epoch,
    }))
}

pub(super) fn source_trustee_commitment_roots_from_vss_commitments(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    // Each source trustee is identified by its coefficient commitment set root:
    // the per-source-trustee root over that trustee's coefficient commitments,
    // which the private envelopes and share acceptances bind against.
    let source_trustee_records = setup_package
        .get("vssPublicCoefficientCommitmentSet")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before VSS share acceptance verification",
            )
        })?;
    let mut source_trustee_roots = BTreeMap::new();
    for (source_trustee_roster_position, source_trustee_record) in
        source_trustee_records.iter().enumerate()
    {
        let source_trustee_commitment_root =
            crate::bgv::setup::vss_commitment::vss_public_source_coefficient_record_root(
                source_trustee_record,
            )?;
        source_trustee_roots.insert(
            source_trustee_roster_position as u64,
            source_trustee_commitment_root,
        );
    }

    Ok(source_trustee_roots)
}

mod acceptances;
mod complaints;

pub(super) use acceptances::verify_vss_share_acceptances;
pub(super) use complaints::verify_vss_complaints;
