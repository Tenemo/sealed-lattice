use super::*;

pub(in crate::ballot_privacy::aggregate_derivation_proof) fn collect_aggregate_post_close_context_refusals(
    close_record: Option<&Value>,
    contributor_action_context: Option<&Value>,
    component: &Value,
) -> Vec<Value> {
    let object_hash = string_field(component, "aggregateDerivationComponentHash");
    let mut refused_objects = Vec::new();
    let Some(statement) = component.get("statement") else {
        return refused_objects;
    };

    if let Some(close_record_value) = close_record {
        refused_objects.extend(collect_aggregate_close_record_refusals(
            close_record_value,
            statement,
            object_hash,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires closeRecord evidence for the voting-closed board head.",
            object_hash,
        ));
    }

    if let Some(action_context_value) = contributor_action_context {
        refused_objects.extend(collect_aggregate_action_context_refusals(
            action_context_value,
            statement,
            object_hash,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires contributorActionContext evidence.",
            object_hash,
        ));
    }

    refused_objects
}

fn derive_close_record_hash_from_value(close_record: &Value) -> Option<String> {
    derive_hash(
        "CloseRecordHash",
        &json!({
            "boardPosition": u64_object_field(close_record, "boardPosition")?,
            "boardSequence": u64_object_field(close_record, "boardSequence")?,
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeKind": string_field(close_record, "closeKind")?,
            "closedBoardHeadHash": string_field(close_record, "closedBoardHeadHash")?,
            "electionManifestHash": string_field(close_record, "electionManifestHash")?,
            "objectType": string_field(close_record, "objectType")?,
            "objectVersion": u64_object_field(close_record, "objectVersion")?,
            "organizerIdentity": string_field(close_record, "organizerIdentity")?
        }),
    )
}

fn derive_post_voting_closed_context_hash_from_value(close_record: &Value) -> Option<String> {
    derive_hash(
        "PostVotingClosedContextHash",
        &json!({
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeRecordHash": string_field(close_record, "closeRecordHash")?,
            "electionManifestHash": string_field(close_record, "electionManifestHash")?,
            "votingClosedBoardHeadHash": string_field(close_record, "closedBoardHeadHash")?
        }),
    )
}

fn collect_aggregate_close_record_refusals(
    close_record: &Value,
    statement: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let close_record_hash = string_field(close_record, "closeRecordHash");
    let mut refused_objects = Vec::new();
    let close_record_shape_is_valid = string_field(close_record, "objectType")
        == Some("CloseRecord")
        && u64_object_field(close_record, "objectVersion") == Some(1)
        && string_field(close_record, "closeKind") == Some("VotingClosed")
        && string_field(close_record, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(close_record, "electionManifestHash").is_some()
        && string_field(close_record, "closedBoardHeadHash").is_some()
        && string_field(close_record, "postVotingClosedContextHash").is_some()
        && u64_object_field(close_record, "boardSequence").is_some()
        && u64_object_field(close_record, "boardPosition").is_some()
        && string_field(close_record, "organizerIdentity").is_some_and(|value| !value.is_empty());
    if !close_record_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence must be a canonical VotingClosed close record.",
            close_record_hash.or(object_hash),
        ));

        return refused_objects;
    }

    if derive_close_record_hash_from_value(close_record).as_deref() != close_record_hash {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord hash does not match its canonical payload.",
            close_record_hash.or(object_hash),
        ));
    }
    let expected_post_context_hash =
        derive_post_voting_closed_context_hash_from_value(close_record);
    if expected_post_context_hash.as_deref()
        != string_field(close_record, "postVotingClosedContextHash")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord does not bind the canonical post-voting closed context hash.",
            close_record_hash.or(object_hash),
        ));
    }
    if string_field(close_record, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(close_record, "electionManifestHash")
            != string_field(statement, "manifestHash")
        || close_record_hash != string_field(statement, "closeRecordHash")
        || string_field(close_record, "closedBoardHeadHash")
            != string_field(statement, "votingClosedBoardHeadHash")
        || string_field(close_record, "postVotingClosedContextHash")
            != string_field(statement, "postVotingClosedContextHash")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence is not bound to the aggregate statement voting-closed context.",
            close_record_hash.or(object_hash),
        ));
    }

    refused_objects
}

fn derive_action_context_hash_from_value(action_context: &Value) -> Option<String> {
    derive_hash(
        "ActionContextHash",
        &json!({
            "acceptedRecoveryEpochUpdateHash": action_context.get("acceptedRecoveryEpochUpdateHash")?.clone(),
            "actionSequence": u64_object_field(action_context, "actionSequence")?,
            "boardHeadHash": string_field(action_context, "boardHeadHash")?,
            "boardSequence": u64_object_field(action_context, "boardSequence")?,
            "ceremonyId": string_field(action_context, "ceremonyId")?,
            "contextHash": string_field(action_context, "contextHash")?,
            "deviceEpoch": u64_object_field(action_context, "deviceEpoch")?,
            "electionManifestHash": string_field(action_context, "electionManifestHash")?,
            "recoveryEpoch": u64_object_field(action_context, "recoveryEpoch")?,
            "recoveryPolicyHash": string_field(action_context, "recoveryPolicyHash")?,
            "rosterExternalAcceptanceHash": action_context.get("rosterExternalAcceptanceHash")?.clone(),
            "signerIdentity": string_field(action_context, "signerIdentity")?
        }),
    )
}

fn collect_aggregate_action_context_refusals(
    action_context: &Value,
    statement: &Value,
    object_hash: Option<&str>,
) -> Vec<Value> {
    let action_context_hash = string_field(action_context, "actionContextHash");
    let mut refused_objects = Vec::new();
    let action_context_shape_is_valid = action_context_hash.is_some()
        && string_field(action_context, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "electionManifestHash").is_some()
        && string_field(action_context, "signerIdentity").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "boardHeadHash").is_some()
        && u64_object_field(action_context, "boardSequence").is_some()
        && u64_object_field(action_context, "recoveryEpoch").is_some()
        && u64_object_field(action_context, "deviceEpoch").is_some()
        && u64_object_field(action_context, "actionSequence").is_some()
        && string_field(action_context, "recoveryPolicyHash").is_some()
        && action_context
            .get("acceptedRecoveryEpochUpdateHash")
            .is_some()
        && action_context.get("rosterExternalAcceptanceHash").is_some()
        && string_field(action_context, "contextHash").is_some();
    if !action_context_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence must be canonical.",
            action_context_hash.or(object_hash),
        ));

        return refused_objects;
    }

    if derive_action_context_hash_from_value(action_context).as_deref() != action_context_hash {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext hash does not match its canonical payload.",
            action_context_hash.or(object_hash),
        ));
    }
    if action_context_hash != string_field(statement, "contributorActionContextHash")
        || string_field(action_context, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(action_context, "electionManifestHash")
            != string_field(statement, "manifestHash")
        || string_field(action_context, "signerIdentity")
            != string_field(statement, "contributorIdentity")
        || string_field(action_context, "boardHeadHash")
            != string_field(statement, "votingClosedBoardHeadHash")
        || string_field(action_context, "contextHash")
            != string_field(statement, "postVotingClosedContextHash")
        || action_context
            .get("rosterExternalAcceptanceHash")
            .and_then(Value::as_str)
            != string_field(statement, "contributorRosterExternalAcceptanceHash")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence is not bound to the aggregate statement contributor and post-close context.",
            action_context_hash.or(object_hash),
        ));
    }

    refused_objects
}
