use super::common::*;

use super::*;
use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn verify_public_key_shares(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Value>> {
    let Some(share_set) = setup_package.get("publicKeyShares") else {
        return Ok(Some(verification_response(
            vec!["publicKeyShares".to_string()],
            Vec::new(),
        )?));
    };
    if !share_set.is_object() {
        return Ok(Some(public_key_refusal(
            "publicKeySharesNotObject",
            "publicKeyShares must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShares",
        )?));
    }
    if share_set.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSetTypeMismatch",
            "publicKeyShares.objectType must be PublicKeyShareSet",
            "setupPackage.publicKeyShares.objectType",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before public-key share verification",
        )
    })?;
    if let Err(error) = verify_context_fields_match(share_set, setup_context, "publicKeyShares") {
        return Ok(Some(public_key_refusal(
            "publicKeyShareSetContextMismatch",
            error.message,
            "setupPackage.publicKeyShares",
        )?));
    }
    let roster = super::accepted_roster_from_package(setup_package)?;
    let common_binding = public_key_common_binding(setup_package)?;
    if let Some(response) =
        verify_public_key_common_fields(share_set, &common_binding, "publicKeyShares")?
    {
        return Ok(Some(response));
    }
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let Some(share_records) = share_set.get("shareRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            vec!["publicKeyShares.shareRecords".to_string()],
            Vec::new(),
        )?));
    };
    if share_records.len() != roster.participant_count as usize {
        return Ok(Some(public_key_refusal(
            "publicKeyShareCountMismatch",
            "publicKeyShares.shareRecords must contain one share per trustee",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    let mut seen_roster_positions = BTreeSet::new();
    for share_record in share_records {
        if let Some(response) = verify_public_key_share_record(
            share_record,
            setup_context,
            &expected_trustees,
            &common_binding,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(public_key_share_set_root) = share_set
        .get("publicKeyShareSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            vec!["publicKeyShares.publicKeyShareSetRoot".to_string()],
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
        return Ok(Some(public_key_refusal(
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
    common_binding: &PublicKeyCommonBinding,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !share_record.is_object() {
        return Ok(Some(public_key_refusal(
            "publicKeyShareNotObject",
            "public-key share records must be objects",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if share_record.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_OBJECT_TYPE)
    {
        return Ok(Some(public_key_refusal(
            "publicKeyShareTypeMismatch",
            "public-key share objectType must be PublicKeyShare",
            "setupPackage.publicKeyShares.shareRecords.objectType",
        )?));
    }
    if let Err(error) =
        verify_context_fields_match(share_record, setup_context, "publicKeyShares.shareRecords")
    {
        return Ok(Some(public_key_refusal(
            "publicKeyShareContextMismatch",
            error.message,
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if let Some(response) = verify_public_key_common_fields(
        share_record,
        common_binding,
        "publicKeyShares.shareRecords",
    )? {
        return Ok(Some(response));
    }

    let trustee_identity = value_string(share_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(public_key_refusal(
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
        return Ok(Some(public_key_refusal(
            "publicKeyShareTrusteeMismatch",
            "public-key share trustee identity must match the accepted setup roster",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
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
            vec!["publicKeyShares.shareRecords.publicKeyShareRoot".to_string()],
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
        return Ok(Some(public_key_refusal(
            "publicKeyShareRootMismatch",
            "publicKeyShareRoot does not match the canonical public-key share",
            "setupPackage.publicKeyShares.shareRecords.publicKeyShareRoot",
        )?));
    }

    Ok(None)
}

fn verify_public_key_share_limb_hashes(
    limb_hashes: Option<&Vec<Value>>,
) -> CanonicalResult<Option<Value>> {
    const LIMB_HASHES_PATH: &str =
        "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb";
    const LIMB_HASHES_OBJECT_PATH: &str =
        "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb";

    let Some(limb_hashes) = limb_hashes else {
        return Ok(Some(verification_response(
            vec![LIMB_HASHES_PATH.to_string()],
            Vec::new(),
        )?));
    };
    if limb_hashes.len() != DATA_PRIMES.len() {
        return Ok(Some(public_key_refusal(
            "publicKeyShareCoefficientLimbCountMismatch",
            "public-key share must bind one coefficient hash for every Q_share limb",
            LIMB_HASHES_OBJECT_PATH,
        )?));
    }

    for limb_hash in limb_hashes {
        validate_hash_string(
            value_string(limb_hash, "coefficientVectorHash512")?,
            &format!("{LIMB_HASHES_PATH}.coefficientVectorHash512"),
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_limb_hashes() -> Vec<Value> {
        DATA_PRIMES
            .iter()
            .map(|_| {
                serde_json::json!({
                    "coefficientVectorHash512": "0".repeat(128),
                })
            })
            .collect()
    }

    fn refusal_reason(response: Option<Value>) -> String {
        response
            .expect("malformed limb hashes must be refused")
            .get("refusedObjects")
            .and_then(Value::as_array)
            .and_then(|refusals| refusals.first())
            .and_then(|refusal| refusal.get("reasonCode"))
            .and_then(Value::as_str)
            .expect("typed refusal reason")
            .to_string()
    }

    #[test]
    fn public_key_share_limb_hashes_follow_the_selected_rns_catalog() {
        let valid_hashes = valid_limb_hashes();
        assert!(
            verify_public_key_share_limb_hashes(Some(&valid_hashes))
                .expect("valid limb hashes")
                .is_none()
        );

        assert_eq!(
            refusal_reason(
                verify_public_key_share_limb_hashes(None).expect("missing limb hashes response")
            ),
            "setupObjectMissing"
        );

        let mut missing_last_limb = valid_hashes.clone();
        missing_last_limb.pop();
        assert_eq!(
            refusal_reason(
                verify_public_key_share_limb_hashes(Some(&missing_last_limb))
                    .expect("limb count response")
            ),
            "publicKeyShareCoefficientLimbCountMismatch"
        );
    }

    #[test]
    fn public_key_share_limb_hashes_reject_malformed_protocol_hashes() {
        for malformed_hash in [
            "0".repeat(127),
            "0".repeat(129),
            format!("{}G", "0".repeat(127)),
        ] {
            let mut limb_hashes = valid_limb_hashes();
            limb_hashes[DATA_PRIMES.len() - 1]["coefficientVectorHash512"] =
                serde_json::json!(malformed_hash);
            let error = verify_public_key_share_limb_hashes(Some(&limb_hashes))
                .expect_err("malformed coefficient hash must fail closed");
            assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
            assert!(error.message.contains("coefficientVectorHash512"));
        }
    }
}
