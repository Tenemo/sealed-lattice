use super::*;

pub(in super::super) fn verify_vss_complaints(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(complaint_set) = setup_package.get("vssComplaints") else {
        return Ok(None);
    };
    if !complaint_set.is_object() {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintsNotObject",
            "vssComplaints must be an object, not an array or scalar",
            "setupPackage.vssComplaints",
        )));
    }
    if complaint_set.get("objectType").and_then(Value::as_str) != Some("VssComplaintSet") {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintSetTypeMismatch",
            "vssComplaints.objectType must be VssComplaintSet",
            "setupPackage.vssComplaints.objectType",
        )));
    }

    let verification_context =
        VssRecordVerificationContext::from_package(setup_package, trustee_registrations)?;
    let Some(complaint_records) = complaint_set
        .get("complaintRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecordsMissing",
            "vssComplaints.complaintRecords must contain at least one signed VSS complaint",
            "setupPackage.vssComplaints.complaintRecords",
        )));
    };
    if complaint_records.is_empty() {
        return Ok(Some(vss_complaint_refusal(
            "vssComplaintRecordsEmpty",
            "vssComplaints must be omitted unless it contains at least one signed VSS complaint",
            "setupPackage.vssComplaints.complaintRecords",
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
            "vssComplaintAcceptedAbort",
            "a valid VSS complaint aborts the foundation-roster setup ceremony",
            "setupPackage.vssComplaints",
        )],
    )))
}

fn vss_complaint_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> Refusals {
    setup_refusals(
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
    )
}
