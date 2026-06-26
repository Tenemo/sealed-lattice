use serde_json::{Value, json};

use crate::{
    bgv::profile::DATA_PRIMES,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
};

use super::{
    accepted_setup::{
        COLLECTIVE_BGV_SETUP_PROFILE_ID, accepted_q_share_hash, accepted_roster_from_setup_context,
        setup_profile_hash_for_roster,
    },
    commitment::setup_commitment_profile_hash,
    sharing::canonical_trustee_point,
    vss::carry_aware_vss_share_relation_profile_hash,
};

const LOCAL_STATE_OBJECT_TYPE: &str = "LocalTrusteeSetupStateCommitment";
const LOCAL_STATE_DELETION_RECEIPT_OBJECT_TYPE: &str = "LocalTrusteeSetupStateDeletionReceipt";

pub(crate) fn verify_local_trustee_setup_state_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_context = object_field(request, "setupContext")?;
    verify_setup_context(setup_context)?;
    let local_state = object_field(request, "localStateCommitment")?;
    verify_local_state_header(local_state, setup_context)?;
    let trustee_roster_position = usize_field(local_state, "trusteeRosterPosition")?;
    let trustee_point = u64_field(local_state, "trusteePoint")?;
    if canonical_trustee_point(trustee_roster_position, DATA_PRIMES[0])? != trustee_point {
        return Err(invalid_local_state_input(
            "localStateCommitment.trusteePoint must equal roster position plus one",
        ));
    }

    let deletion_receipt = object_field(local_state, "deletionReceipt")?;
    verify_deletion_receipt(deletion_receipt, setup_context, local_state, trustee_point)?;
    let deletion_receipt_root = hash_string_field(local_state, "deletionReceiptRoot")?;
    let expected_deletion_receipt_root = local_state_deletion_receipt_root(deletion_receipt)?;
    if deletion_receipt_root != expected_deletion_receipt_root {
        return Err(invalid_local_state_input(
            "localStateCommitment.deletionReceiptRoot does not match deletionReceipt",
        ));
    }

    for field_name in [
        "thresholdShareCommitmentRecipientRoot",
        "aggregateThresholdShareRoot",
        "targetDecryptionProofWitnessRoot",
        "issuedVssAcceptanceRoot",
    ] {
        validate_hash_string(
            hash_string_field(local_state, field_name)?,
            &format!("localStateCommitment.{field_name}"),
        )?;
    }
    let issued_complaint_roots = array_field(local_state, "issuedVssComplaintRoots")?;
    for complaint_root in issued_complaint_roots {
        let Some(complaint_root) = complaint_root.as_str() else {
            return Err(invalid_local_state_input(
                "localStateCommitment.issuedVssComplaintRoots must contain protocol hashes",
            ));
        };
        validate_hash_string(
            complaint_root,
            "localStateCommitment.issuedVssComplaintRoots",
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
        "ok": true,
        "operation": "verifyLocalTrusteeSetupState",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "trusteeIdentity": string_field(local_state, "trusteeIdentity")?,
        "trusteeRosterPosition": trustee_roster_position,
        "trusteePoint": trustee_point,
        "localStateRoot": local_state_root,
        "deletionReceiptRoot": deletion_receipt_root,
        "targetDecryptionProofWitnessRoot": hash_string_field(local_state, "targetDecryptionProofWitnessRoot")?,
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
    for field_name in [
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
    ] {
        validate_hash_string(
            hash_string_field(setup_context, field_name)?,
            &format!("setupContext.{field_name}"),
        )?;
    }
    string_field(setup_context, "ceremonyId")?;
    string_field(setup_context, "setupEpoch")?;
    // The setup profile hash is a roster family, so it must match the hash
    // derived from this setup context's roster, not the first-closure n = 10
    // hash.
    let roster = accepted_roster_from_setup_context(setup_context);
    if setup_context
        .get("setupProfileHash")
        .and_then(Value::as_str)
        != Some(setup_profile_hash_for_roster(&roster)?.as_str())
    {
        return Err(invalid_local_state_input(
            "setupContext.setupProfileHash does not match CollectiveBgvSetup-v1",
        ));
    }
    if setup_context.get("qShareHash").and_then(Value::as_str)
        != Some(accepted_q_share_hash()?.as_str())
    {
        return Err(invalid_local_state_input(
            "setupContext.qShareHash does not match the accepted Q_share prime list",
        ));
    }
    if setup_context
        .get("carryAwareVssShareRelationProfileHash")
        .and_then(Value::as_str)
        != Some(carry_aware_vss_share_relation_profile_hash()?.as_str())
    {
        return Err(invalid_local_state_input(
            "setupContext.carryAwareVssShareRelationProfileHash does not match the accepted carry-aware VSS relation profile",
        ));
    }
    if setup_context
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Err(invalid_local_state_input(
            "setupContext.commitmentProfileHash does not match the accepted setup commitment profile",
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
    if local_state.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_local_state_input(
            "localStateCommitment.objectVersion must be 1",
        ));
    }
    compare_context_fields(local_state, setup_context, "localStateCommitment")?;
    if local_state.get("setupProfileId").and_then(Value::as_str)
        != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
    {
        return Err(invalid_local_state_input(
            "localStateCommitment.setupProfileId must be CollectiveBgvSetup-v1",
        ));
    }
    string_field(local_state, "trusteeIdentity")?;

    Ok(())
}

fn verify_deletion_receipt(
    deletion_receipt: &Value,
    setup_context: &Value,
    local_state: &Value,
    trustee_point: u64,
) -> CanonicalResult<()> {
    if deletion_receipt.get("objectType").and_then(Value::as_str)
        != Some(LOCAL_STATE_DELETION_RECEIPT_OBJECT_TYPE)
    {
        return Err(invalid_local_state_input(
            "deletionReceipt.objectType must be LocalTrusteeSetupStateDeletionReceipt",
        ));
    }
    if deletion_receipt
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Err(invalid_local_state_input(
            "deletionReceipt.objectVersion must be 1",
        ));
    }
    compare_context_fields(deletion_receipt, setup_context, "deletionReceipt")?;
    if deletion_receipt.get("trusteeIdentity") != local_state.get("trusteeIdentity")
        || deletion_receipt.get("trusteeRosterPosition") != local_state.get("trusteeRosterPosition")
    {
        return Err(invalid_local_state_input(
            "deletionReceipt trustee binding must match localStateCommitment",
        ));
    }
    if deletion_receipt.get("trusteePoint").and_then(Value::as_u64) != Some(trustee_point) {
        return Err(invalid_local_state_input(
            "deletionReceipt.trusteePoint must match localStateCommitment.trusteePoint",
        ));
    }
    Ok(())
}

fn local_state_deletion_receipt_root(deletion_receipt: &Value) -> CanonicalResult<String> {
    if !deletion_receipt.is_object() {
        return Err(invalid_local_state_input(
            "deletionReceipt must be an object",
        ));
    }
    derive_protocol_hash("LocalTrusteeDeletionReceiptRoot", deletion_receipt)
}

fn local_state_commitment_root(local_state: &Value) -> CanonicalResult<String> {
    let mut root_input = local_state.clone();
    let object = root_input
        .as_object_mut()
        .ok_or_else(|| invalid_local_state_input("localStateCommitment must be an object"))?;
    object.remove("localStateRoot");
    derive_protocol_hash("LocalTrusteeSetupStateRoot", &root_input)
}

fn compare_context_fields(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> CanonicalResult<()> {
    for field_name in setup_context_field_names() {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(invalid_local_state_input(format!(
                "{object_path}.{field_name} must match setupContext"
            )));
        }
    }

    Ok(())
}

fn setup_context_field_names() -> [&'static str; 8] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ]
}

fn object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| invalid_local_state_input(format!("{field_name} must be an object")))
}

fn array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_local_state_input(format!("{field_name} must be an array")))
}

fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_local_state_input(format!("{field_name} must be a non-empty string"))
        })
}

fn hash_string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_local_state_input(format!("{field_name} must be a protocol hash")))
}

fn u64_field(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_local_state_input(format!("{field_name} must be a non-negative integer"))
        })
}

fn usize_field(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    usize::try_from(u64_field(value, field_name)?)
        .map_err(|_| invalid_local_state_input(format!("{field_name} does not fit usize")))
}

fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_local_state_input(format!(
        "{field_name} must be a lowercase 512-bit hex protocol hash"
    )))
}

fn invalid_local_state_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
