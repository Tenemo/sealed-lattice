use serde_json::{Value, json};

use crate::{
    bgv::setup_helpers::{
        hash_string_field, object_field, string_field, usize_field, validate_hash_string,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};

use super::accepted_setup::{
    accepted_roster_from_setup_context, setup_context_hash, setup_parameters_hash_for_roster,
};

const LOCAL_STATE_OBJECT_TYPE: &str = "LocalTrusteeSetupStateCommitment";
pub(crate) fn verify_local_trustee_setup_state_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_context = object_field(request, "setupContext")?;
    verify_setup_context(setup_context)?;
    let local_state = object_field(request, "localStateCommitment")?;
    verify_local_state_header(local_state, setup_context)?;
    let trustee_roster_position = usize_field(local_state, "trusteeRosterPosition")?;

    for field_name in [
        "thresholdShareCommitmentRecipientRoot",
        "aggregateThresholdShareRoot",
    ] {
        validate_hash_string(
            hash_string_field(local_state, field_name)?,
            &format!("localStateCommitment.{field_name}"),
        )?;
    }
    let local_state_root = local_state_commitment_root(local_state)?;
    let expected_local_state_root = hash_string_field(local_state, "localStateRoot")?;
    if local_state_root != expected_local_state_root {
        return Err(invalid_local_state_input(
            "localStateCommitment.localStateRoot does not match the canonical local state commitment",
        ));
    }

    Ok(json!({
        "trusteeIdentity": string_field(local_state, "trusteeIdentity")?,
        "trusteeRosterPosition": trustee_roster_position,
        "localStateRoot": local_state_root,
    }))
}

fn verify_setup_context(setup_context: &Value) -> CanonicalResult<()> {
    for field_name in setup_context_field_names() {
        if setup_context.get(field_name).is_none() {
            return Err(invalid_local_state_input(format!(
                "setupContext.{field_name} is required"
            )));
        }
    }
    for field_name in ["manifestHash", "rosterHash", "setupParametersHash"] {
        validate_hash_string(
            hash_string_field(setup_context, field_name)?,
            &format!("setupContext.{field_name}"),
        )?;
    }
    string_field(setup_context, "ceremonyId")?;
    string_field(setup_context, "setupEpoch")?;
    // The setup parameters hash is a roster family, so it must match the hash
    // derived from this setup context's roster. It binds the thresholds,
    // Q_share, evaluator key schedule, and BGV parameters.
    let roster = accepted_roster_from_setup_context(setup_context)?;
    if setup_context
        .get("setupParametersHash")
        .and_then(Value::as_str)
        != Some(setup_parameters_hash_for_roster(&roster)?.as_str())
    {
        return Err(invalid_local_state_input(
            "setupContext.setupParametersHash does not match the roster-derived setup parameters",
        ));
    }

    Ok(())
}

fn verify_local_state_header(local_state: &Value, setup_context: &Value) -> CanonicalResult<()> {
    if local_state.get("objectType").and_then(Value::as_str) != Some(LOCAL_STATE_OBJECT_TYPE) {
        return Err(invalid_local_state_input(
            "localStateCommitment.objectType must be LocalTrusteeSetupStateCommitment",
        ));
    }
    compare_context_fields(local_state, setup_context, "localStateCommitment")?;
    string_field(local_state, "trusteeIdentity")?;

    Ok(())
}

pub(super) fn local_state_commitment_root(local_state: &Value) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": string_field(local_state, "objectType")?,
        "setupContextHash": hash_string_field(local_state, "setupContextHash")?,
        "trusteeIdentity": string_field(local_state, "trusteeIdentity")?,
        "trusteeRosterPosition": usize_field(local_state, "trusteeRosterPosition")?,
        "thresholdShareCommitmentRecipientRoot": hash_string_field(
            local_state,
            "thresholdShareCommitmentRecipientRoot",
        )?,
        "aggregateThresholdShareRoot": hash_string_field(
            local_state,
            "aggregateThresholdShareRoot",
        )?,
    }))
}

fn compare_context_fields(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> CanonicalResult<()> {
    if hash_string_field(value, "setupContextHash")? != setup_context_hash(setup_context)? {
        return Err(invalid_local_state_input(format!(
            "{object_path}.setupContextHash must match setupContext"
        )));
    }

    Ok(())
}

fn setup_context_field_names() -> [&'static str; 5] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ]
}

fn invalid_local_state_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
