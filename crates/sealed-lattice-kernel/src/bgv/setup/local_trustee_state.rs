use serde_json::{Value, json};

use crate::{
    bgv::{profile::DATA_PRIMES, validation::reject_unexpected_bgv_request_fields},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
};

use super::{
    accepted_setup::{
        COLLECTIVE_BGV_SETUP_PROFILE_ID, accepted_q_share_hash, accepted_setup_profile_hash,
    },
    commitment::setup_commitment_profile_hash,
    sharing::canonical_trustee_point,
    vss::carry_aware_vss_share_relation_profile_hash,
};

const LOCAL_STATE_OBJECT_TYPE: &str = "LocalTrusteeSetupStateCommitment";
const LOCAL_STATE_DELETION_RECEIPT_OBJECT_TYPE: &str = "LocalTrusteeSetupStateDeletionReceipt";
const LOCAL_STATE_EXPORT_POLICY: &str = "roots-only-no-raw-share-or-opening-export";
const LOCAL_STATE_STORAGE_PROFILE: &str = "encrypted-local-device-state-required";
const DELETION_BOUNDARY: &str = "after-private-vss-aggregation";

const FORBIDDEN_LOCAL_STATE_FIELD_NAMES: &[&str] = &[
    "rawSecret",
    "rawSecretShare",
    "rawAggregateThresholdShare",
    "rawVssOpening",
    "rawShamirShare",
    "rawShamirShares",
    "rawShare",
    "rawShares",
    "proofWitness",
    "proofWitnesses",
    "setupSeed",
    "setupPrivateWitness",
    "privateSetupSeedHash",
    "decryptionShareWitness",
    "coefficientMessage",
    "randomnessByColumn",
    "shareValues",
    "carryWitnessesDecimal",
    "privateEnvelope",
    "privateEnvelopes",
];

const DELETED_MATERIAL_CLASSES: &[&str] = &[
    "raw-per-dealer-vss-shares",
    "raw-per-dealer-vss-openings",
    "private-vss-envelope-payloads-after-aggregation",
];

const RETAINED_MATERIAL_CLASSES: &[&str] = &[
    "aggregate-threshold-share-sealed",
    "aggregate-threshold-opening-sealed",
    "issued-vss-acceptance-roots",
    "issued-vss-complaint-roots",
    "setup-context",
];

pub(crate) fn verify_local_trustee_setup_state_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &["setupContext", "localStateCommitment"],
        "verifyLocalTrusteeSetupState",
    )?;
    reject_forbidden_local_state_fields(request, "request")?;

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
        "aggregateOpeningRoot",
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
        "exportPolicy": LOCAL_STATE_EXPORT_POLICY,
        "storageProfile": LOCAL_STATE_STORAGE_PROFILE,
        "deletionBoundary": DELETION_BOUNDARY,
        "statusLabels": [
            "LocalTrusteeSetupStateCommitmentVerified",
            "RawDealerShareOpeningDeletionRecorded",
            "RootsOnlyStateExport"
        ],
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
    if setup_context
        .get("setupProfileHash")
        .and_then(Value::as_str)
        != Some(accepted_setup_profile_hash()?.as_str())
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
    reject_unexpected_fields(
        local_state,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "trusteePoint",
            "thresholdShareCommitmentRecipientRoot",
            "aggregateThresholdShareRoot",
            "aggregateOpeningRoot",
            "issuedVssAcceptanceRoot",
            "issuedVssComplaintRoots",
            "deletionReceiptRoot",
            "deletionReceipt",
            "exportPolicy",
            "storageProfile",
            "localStateRoot",
        ],
        "localStateCommitment",
    )?;
    compare_context_fields(local_state, setup_context, "localStateCommitment")?;
    if local_state.get("setupProfileId").and_then(Value::as_str)
        != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
    {
        return Err(invalid_local_state_input(
            "localStateCommitment.setupProfileId must be CollectiveBgvSetup-v1",
        ));
    }
    if local_state.get("exportPolicy").and_then(Value::as_str) != Some(LOCAL_STATE_EXPORT_POLICY) {
        return Err(invalid_local_state_input(
            "localStateCommitment.exportPolicy must forbid raw share and opening export",
        ));
    }
    if local_state.get("storageProfile").and_then(Value::as_str)
        != Some(LOCAL_STATE_STORAGE_PROFILE)
    {
        return Err(invalid_local_state_input(
            "localStateCommitment.storageProfile must require encrypted local device state",
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
    reject_unexpected_fields(
        deletion_receipt,
        &[
            "objectType",
            "objectVersion",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "trusteePoint",
            "deletionBoundary",
            "deletedMaterialClasses",
            "retainedMaterialClasses",
            "deletionReceiptRoot",
        ],
        "deletionReceipt",
    )?;
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
    if deletion_receipt
        .get("deletionBoundary")
        .and_then(Value::as_str)
        != Some(DELETION_BOUNDARY)
    {
        return Err(invalid_local_state_input(
            "deletionReceipt.deletionBoundary must match the accepted private VSS aggregation boundary",
        ));
    }
    if string_array_field(deletion_receipt, "deletedMaterialClasses")? != DELETED_MATERIAL_CLASSES {
        return Err(invalid_local_state_input(
            "deletionReceipt.deletedMaterialClasses must record raw dealer share and opening deletion",
        ));
    }
    if string_array_field(deletion_receipt, "retainedMaterialClasses")? != RETAINED_MATERIAL_CLASSES
    {
        return Err(invalid_local_state_input(
            "deletionReceipt.retainedMaterialClasses must retain only sealed aggregate state and roots",
        ));
    }

    Ok(())
}

fn local_state_deletion_receipt_root(deletion_receipt: &Value) -> CanonicalResult<String> {
    let mut root_input = deletion_receipt.clone();
    root_input
        .as_object_mut()
        .ok_or_else(|| invalid_local_state_input("deletionReceipt must be an object"))?
        .remove("deletionReceiptRoot");
    derive_protocol_hash("LocalTrusteeDeletionReceiptRoot", &root_input)
}

fn local_state_commitment_root(local_state: &Value) -> CanonicalResult<String> {
    let mut root_input = local_state.clone();
    let object = root_input
        .as_object_mut()
        .ok_or_else(|| invalid_local_state_input("localStateCommitment must be an object"))?;
    object.remove("localStateRoot");
    derive_protocol_hash("LocalTrusteeSetupStateRoot", &root_input)
}

fn reject_forbidden_local_state_fields(value: &Value, object_path: &str) -> CanonicalResult<()> {
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_forbidden_local_state_fields(item, &format!("{object_path}[{index}]"))?;
            }
        }
        Value::Object(fields) => {
            for (field_name, field_value) in fields {
                if FORBIDDEN_LOCAL_STATE_FIELD_NAMES.contains(&field_name.as_str()) {
                    return Err(invalid_local_state_input(format!(
                        "{object_path}.{field_name} is raw local trustee material and cannot appear in a roots-only state commitment"
                    )));
                }
                reject_forbidden_local_state_fields(
                    field_value,
                    &format!("{object_path}.{field_name}"),
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn reject_unexpected_fields(
    value: &Value,
    allowed_fields: &[&str],
    object_path: &str,
) -> CanonicalResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_local_state_input(format!("{object_path} must be an object")))?;
    for field_name in object.keys() {
        if !allowed_fields.contains(&field_name.as_str()) {
            return Err(invalid_local_state_input(format!(
                "{object_path}.{field_name} is not allowed by the local trustee state schema"
            )));
        }
    }
    for field_name in allowed_fields {
        if !object.contains_key(*field_name) {
            return Err(invalid_local_state_input(format!(
                "{object_path}.{field_name} is required by the local trustee state schema"
            )));
        }
    }

    Ok(())
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

fn string_array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<Vec<&'a str>> {
    array_field(value, field_name)?
        .iter()
        .map(|item| {
            item.as_str().ok_or_else(|| {
                invalid_local_state_input(format!("{field_name} must contain only strings"))
            })
        })
        .collect()
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
