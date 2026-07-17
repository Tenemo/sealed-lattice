use super::*;

pub(in super::super) fn verify_vss_share_acceptances(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(acceptance_set) = setup_package.get("vssShareAcceptances") else {
        return Ok(Some(setup_refusals(
            vec!["vssShareAcceptances".to_string()],
            Vec::new(),
        )));
    };
    if !acceptance_set.is_object() {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "vssShareAcceptancesNotObject",
            "vssShareAcceptances must be an object, not an array or scalar",
        )));
    }
    if acceptance_set.get("objectType").and_then(Value::as_str) != Some("VssShareAcceptanceSet") {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "vssShareAcceptanceSetTypeMismatch",
            "vssShareAcceptances.objectType must be VssShareAcceptanceSet",
        )));
    }

    let verification_context =
        VssRecordVerificationContext::from_package(setup_package, trustee_registrations)?;
    let Some(acceptance_records) = acceptance_set
        .get("acceptanceRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(setup_refusals(
            vec!["vssShareAcceptances.acceptanceRecords".to_string()],
            Vec::new(),
        )));
    };
    let roster = super::accepted_roster_from_package(setup_package)?;
    let expected_acceptance_count = (roster.participant_count * roster.participant_count) as usize;
    if acceptance_records.len() != expected_acceptance_count {
        return Ok(Some(single_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "vssShareAcceptanceCountMismatch",
            "vssShareAcceptances.acceptanceRecords must contain one record for every source-trustee-recipient trustee pair",
        )));
    }

    let mut seen_acceptances = BTreeSet::new();
    for acceptance_record in acceptance_records {
        if let Err(refusal) = verify_vss_response_record(
            acceptance_record,
            &verification_context,
            &mut seen_acceptances,
            VssResponseKind::Acceptance,
        )? {
            return Ok(Some(setup_refusals(Vec::new(), vec![refusal])));
        }
    }

    Ok(None)
}
