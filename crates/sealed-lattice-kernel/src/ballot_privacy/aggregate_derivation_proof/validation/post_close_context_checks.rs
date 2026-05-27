use super::*;

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_post_close_context_refusals(
    close_record: Option<&Value>,
    contributor_action_context: Option<&Value>,
    component: &Value,
) -> Vec<Value> {
    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects = Vec::new();
    let Some(statement) = component.get("statement") else {
        return refused_objects;
    };

    if let Some(close_record_value) = close_record {
        refused_objects.extend(collect_aggregate_close_record_refusals(
            close_record_value,
            statement,
            object_digest,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires closeRecord evidence for the voting-closed board head.",
            object_digest,
        ));
    }

    if let Some(action_context_value) = contributor_action_context {
        refused_objects.extend(collect_aggregate_action_context_refusals(
            action_context_value,
            statement,
            object_digest,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires contributorActionContext evidence.",
            object_digest,
        ));
    }

    refused_objects
}

fn derive_close_record_digest_from_value(close_record: &Value) -> Option<String> {
    derive_digest(
        "CloseRecordDigest",
        &json!({
            "boardPosition": u64_object_field(close_record, "boardPosition")?,
            "boardSequence": u64_object_field(close_record, "boardSequence")?,
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeKind": string_field(close_record, "closeKind")?,
            "closedBoardHeadDigest": string_field(close_record, "closedBoardHeadDigest")?,
            "electionManifestDigest": string_field(close_record, "electionManifestDigest")?,
            "objectType": string_field(close_record, "objectType")?,
            "objectVersion": u64_object_field(close_record, "objectVersion")?,
            "organizerIdentity": string_field(close_record, "organizerIdentity")?
        }),
    )
}

fn derive_post_voting_closed_context_digest_from_value(close_record: &Value) -> Option<String> {
    derive_digest(
        "PostVotingClosedContextDigest",
        &json!({
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeRecordDigest": string_field(close_record, "closeRecordDigest")?,
            "electionManifestDigest": string_field(close_record, "electionManifestDigest")?,
            "votingClosedBoardHeadDigest": string_field(close_record, "closedBoardHeadDigest")?
        }),
    )
}

fn collect_aggregate_close_record_refusals(
    close_record: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let close_record_digest = string_field(close_record, "closeRecordDigest");
    let mut refused_objects = Vec::new();
    let close_record_shape_is_valid = string_field(close_record, "objectType")
        == Some("CloseRecord")
        && u64_object_field(close_record, "objectVersion") == Some(1)
        && string_field(close_record, "closeKind") == Some("VotingClosed")
        && string_field(close_record, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(close_record, "electionManifestDigest").is_some()
        && string_field(close_record, "closedBoardHeadDigest").is_some()
        && string_field(close_record, "postVotingClosedContextDigest").is_some()
        && u64_object_field(close_record, "boardSequence").is_some()
        && u64_object_field(close_record, "boardPosition").is_some()
        && string_field(close_record, "organizerIdentity").is_some_and(|value| !value.is_empty());
    if !close_record_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence must be a canonical VotingClosed close record.",
            close_record_digest.or(object_digest),
        ));

        return refused_objects;
    }

    if derive_close_record_digest_from_value(close_record).as_deref() != close_record_digest {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord digest does not match its canonical payload.",
            close_record_digest.or(object_digest),
        ));
    }
    let expected_post_context_digest =
        derive_post_voting_closed_context_digest_from_value(close_record);
    if expected_post_context_digest.as_deref()
        != string_field(close_record, "postVotingClosedContextDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord does not bind the canonical post-voting closed context digest.",
            close_record_digest.or(object_digest),
        ));
    }
    if string_field(close_record, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(close_record, "electionManifestDigest")
            != string_field(statement, "manifestDigest")
        || close_record_digest != string_field(statement, "closeRecordDigest")
        || string_field(close_record, "closedBoardHeadDigest")
            != string_field(statement, "votingClosedBoardHeadDigest")
        || string_field(close_record, "postVotingClosedContextDigest")
            != string_field(statement, "postVotingClosedContextDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence is not bound to the aggregate statement voting-closed context.",
            close_record_digest.or(object_digest),
        ));
    }

    refused_objects
}

fn derive_action_context_digest_from_value(action_context: &Value) -> Option<String> {
    derive_digest(
        "ActionContextDigest",
        &json!({
            "acceptedRecoveryEpochUpdateDigest": action_context.get("acceptedRecoveryEpochUpdateDigest")?.clone(),
            "actionSequence": u64_object_field(action_context, "actionSequence")?,
            "boardHeadDigest": string_field(action_context, "boardHeadDigest")?,
            "boardSequence": u64_object_field(action_context, "boardSequence")?,
            "ceremonyId": string_field(action_context, "ceremonyId")?,
            "contextDigest": string_field(action_context, "contextDigest")?,
            "deviceEpoch": u64_object_field(action_context, "deviceEpoch")?,
            "electionManifestDigest": string_field(action_context, "electionManifestDigest")?,
            "recoveryEpoch": u64_object_field(action_context, "recoveryEpoch")?,
            "recoveryPolicyDigest": string_field(action_context, "recoveryPolicyDigest")?,
            "rosterExternalAcceptanceDigest": action_context.get("rosterExternalAcceptanceDigest")?.clone(),
            "signerIdentity": string_field(action_context, "signerIdentity")?
        }),
    )
}

fn collect_aggregate_action_context_refusals(
    action_context: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let action_context_digest = string_field(action_context, "actionContextDigest");
    let mut refused_objects = Vec::new();
    let action_context_shape_is_valid = action_context_digest.is_some()
        && string_field(action_context, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "electionManifestDigest").is_some()
        && string_field(action_context, "signerIdentity").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "boardHeadDigest").is_some()
        && u64_object_field(action_context, "boardSequence").is_some()
        && u64_object_field(action_context, "recoveryEpoch").is_some()
        && u64_object_field(action_context, "deviceEpoch").is_some()
        && u64_object_field(action_context, "actionSequence").is_some()
        && string_field(action_context, "recoveryPolicyDigest").is_some()
        && action_context
            .get("acceptedRecoveryEpochUpdateDigest")
            .is_some()
        && action_context
            .get("rosterExternalAcceptanceDigest")
            .is_some()
        && string_field(action_context, "contextDigest").is_some();
    if !action_context_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence must be canonical.",
            action_context_digest.or(object_digest),
        ));

        return refused_objects;
    }

    if derive_action_context_digest_from_value(action_context).as_deref() != action_context_digest {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext digest does not match its canonical payload.",
            action_context_digest.or(object_digest),
        ));
    }
    if action_context_digest != string_field(statement, "contributorActionContextDigest")
        || string_field(action_context, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(action_context, "electionManifestDigest")
            != string_field(statement, "manifestDigest")
        || string_field(action_context, "signerIdentity")
            != string_field(statement, "contributorIdentity")
        || string_field(action_context, "boardHeadDigest")
            != string_field(statement, "votingClosedBoardHeadDigest")
        || string_field(action_context, "contextDigest")
            != string_field(statement, "postVotingClosedContextDigest")
        || action_context
            .get("rosterExternalAcceptanceDigest")
            .and_then(Value::as_str)
            != string_field(statement, "contributorRosterExternalAcceptanceDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence is not bound to the aggregate statement contributor and post-close context.",
            action_context_digest.or(object_digest),
        ));
    }

    refused_objects
}
