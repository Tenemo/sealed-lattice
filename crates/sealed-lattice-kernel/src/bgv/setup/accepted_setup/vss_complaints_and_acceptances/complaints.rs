use super::*;

pub(in super::super) fn verify_vss_complaints(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(complaint_set) = setup_package.get("vssComplaints") else {
        return Ok(None);
    };
    if !complaint_set.is_object() {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "vssComplaintsNotObject",
            "vssComplaints must be an object, not an array or scalar",
        )));
    }
    if complaint_set.get("objectType").and_then(Value::as_str) != Some("VssComplaintSet") {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "vssComplaintSetTypeMismatch",
            "vssComplaints.objectType must be VssComplaintSet",
        )));
    }

    let verification_context =
        VssRecordVerificationContext::from_package(setup_package, trustee_registrations)?;
    let Some(complaint_records) = complaint_set
        .get("complaintRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::MissingPrerequisite,
            "vssComplaintRecordsMissing",
            "vssComplaints.complaintRecords must contain at least one signed VSS complaint",
        )));
    };
    if complaint_records.is_empty() {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "vssComplaintRecordsEmpty",
            "vssComplaints must be omitted unless it contains at least one signed VSS complaint",
        )));
    }

    let mut seen_complaints = BTreeSet::new();
    for complaint_record in complaint_records {
        if let Err(refusal) = verify_vss_response_record(
            complaint_record,
            &verification_context,
            &mut seen_complaints,
            VssResponseKind::Complaint,
        )? {
            return Ok(Some(setup_refusals(Vec::new(), vec![refusal])));
        }
    }

    // Any verified complaint is sufficient to abort setup.
    Ok(Some(setup_refusals(
        Vec::new(),
        vec![Refusal::new(
            crate::foundation::RefusalReason::InvalidArithmeticRelation,
            "vssComplaintAcceptedAbort",
            "a valid VSS complaint aborts the foundation-roster setup ceremony",
        )],
    )))
}
