use super::common::*;

use super::proofs::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn verify_public_key_shares(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(share_set) = setup_package.get("publicKeyShares") else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !share_set.is_object() {
        return Ok(Some(public_key_share_refusal(
            "publicKeySharesNotObject",
            "publicKeyShares must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShares",
        )?));
    }
    if share_set.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetTypeMismatch",
            "publicKeyShares.objectType must be PublicKeyShareSet",
            "setupPackage.publicKeyShares.objectType",
        )?));
    }
    if share_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetVersionMismatch",
            "publicKeyShares.objectVersion must be 1",
            "setupPackage.publicKeyShares.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(share_set, setup_context) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShares",
        )?));
    }
    for (field_name, expected_value) in [("proofBindingStatus", "public-key-share-proof-required")]
    {
        if share_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareSetParametersMismatch",
                format!("publicKeyShares.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.{field_name}"),
            )?));
        }
    }
    let roster = super::accepted_roster_from_package(setup_package);
    for (field_name, expected_value) in [
        ("participantCount", roster.participant_count),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if share_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareSetCountMismatch",
                format!("publicKeyShares.{field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.{field_name}"),
            )?));
        }
    }

    let common_binding = public_key_common_binding(setup_package)?;
    if let Some(response) = verify_public_key_common_fields(
        share_set,
        &common_binding,
        "publicKeyShares",
        PublicKeyRefusalKind::Share,
    )? {
        return Ok(Some(response));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if share_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretRootMismatch",
            "publicKeyShares.sameSecretConsistencyRoot must match accepted same-secret statements",
            "setupPackage.publicKeyShares.sameSecretConsistencyRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let same_secret_bindings = same_secret_statement_bindings_from_package(setup_package)?;
    let Some(share_records) = share_set.get("shareRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if share_records.len() != roster.participant_count as usize {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareCountMismatch",
            "publicKeyShares.shareRecords must contain one share per trustee",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    let mut public_key_share_roots = Vec::new();
    for share_record in share_records {
        if let Some(response) = verify_public_key_share_record(
            share_record,
            setup_context,
            &expected_trustees,
            &same_secret_bindings,
            &common_binding,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
        public_key_share_roots.push(json!({
            "trusteeIdentity": value_string(share_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(share_record, "trusteeRosterPosition")?,
            "publicKeyShareRoot": value_string(share_record, "publicKeyShareRoot")?,
        }));
    }
    if share_set.get("publicKeyShareRoots") != Some(&Value::Array(public_key_share_roots)) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRootListMismatch",
            "publicKeyShares.publicKeyShareRoots must match the ordered share records",
            "setupPackage.publicKeyShares.publicKeyShareRoots",
        )?));
    }

    let Some(public_key_share_set_root) = share_set
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.publicKeyShareSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_set_root,
        "publicKeyShares.publicKeyShareSetRoot",
    )?;
    let mut root_input = share_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share set object was checked")
        .remove("publicKeyShareSetRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if public_key_share_set_root != expected_root {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSetRootMismatch",
            "publicKeyShareSetRoot does not match the canonical public-key share set",
            "setupPackage.publicKeyShares.publicKeyShareSetRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_record(
    share_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    same_secret_bindings: &BTreeMap<u64, SameSecretStatementBinding>,
    common_binding: &PublicKeyCommonBinding,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !share_record.is_object() {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareNotObject",
            "public-key share records must be objects",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if share_record.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareTypeMismatch",
            "public-key share objectType must be PublicKeyShare",
            "setupPackage.publicKeyShares.shareRecords.objectType",
        )?));
    }
    if share_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareVersionMismatch",
            "public-key share objectVersion must be 1",
            "setupPackage.publicKeyShares.shareRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(share_record, setup_context) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareContextMismatch",
            error.message,
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    for (field_name, expected_value) in [
        ("shareComponent", "component-zero-b_i"),
        ("proofBindingStatus", "public-key-share-proof-required"),
    ] {
        if share_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_refusal(
                "publicKeyShareParametersMismatch",
                format!("public-key share {field_name} must be {expected_value}"),
                format!("setupPackage.publicKeyShares.shareRecords.{field_name}"),
            )?));
        }
    }
    if share_record.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRnsLimbCountMismatch",
            "public-key share rnsLimbCount must match Q_share",
            "setupPackage.publicKeyShares.shareRecords.rnsLimbCount",
        )?));
    }
    if let Some(response) = verify_public_key_common_fields(
        share_record,
        common_binding,
        "publicKeyShares.shareRecords",
        PublicKeyRefusalKind::Share,
    )? {
        return Ok(Some(response));
    }

    let trustee_identity = value_string(share_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareDuplicate",
            "public-key share records must have distinct trustee roster positions",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if expected_trustees
        .get(&trustee_roster_position)
        .map(String::as_str)
        != Some(trustee_identity)
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareTrusteeMismatch",
            "public-key share trustee identity must match the accepted setup roster",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
        )?));
    }
    let Some(same_secret_binding) = same_secret_bindings.get(&trustee_roster_position) else {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretMissing",
            "public-key share must reference an accepted same-secret statement",
            "setupPackage.publicKeyShares.shareRecords.trusteeRosterPosition",
        )?));
    };
    if same_secret_binding.trustee_identity != trustee_identity {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretTrusteeMismatch",
            "public-key share trustee must match the same-secret statement trustee",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
        )?));
    }
    if share_record
        .get("trusteeSecretCommitmentRoot")
        .and_then(Value::as_str)
        != Some(same_secret_binding.trustee_secret_commitment_root.as_str())
        || share_record
            .get("sameSecretStatementRoot")
            .and_then(Value::as_str)
            != Some(same_secret_binding.same_secret_statement_root.as_str())
    {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareSameSecretBindingMismatch",
            "public-key share must bind the accepted trustee secret and same-secret statement roots",
            "setupPackage.publicKeyShares.shareRecords.sameSecretStatementRoot",
        )?));
    }
    if let Some(response) = verify_public_key_share_limb_hashes(
        share_record
            .get("shareCoefficientVectorHash512ByLimb")
            .and_then(Value::as_array),
    )? {
        return Ok(Some(response));
    }

    let Some(public_key_share_root) = share_record
        .get("publicKeyShareRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["publicKeyShares.shareRecords.publicKeyShareRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        public_key_share_root,
        "publicKeyShares.shareRecords.publicKeyShareRoot",
    )?;
    let mut root_input = share_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share object was checked")
        .remove("publicKeyShareRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if public_key_share_root != expected_root {
        return Ok(Some(public_key_share_refusal(
            "publicKeyShareRootMismatch",
            "publicKeyShareRoot does not match the canonical public-key share",
            "setupPackage.publicKeyShares.shareRecords.publicKeyShareRoot",
        )?));
    }

    Ok(None)
}

pub(in super::super) fn public_key_share_records_by_roster_position(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, Value>> {
    let share_records = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("shareRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShares.shareRecords were required before public-key share succinct proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for share_record in share_records {
        let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
        if records
            .insert(trustee_roster_position, share_record.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share records contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}
