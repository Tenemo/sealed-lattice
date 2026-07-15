use super::common::*;

use super::*;
use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn verify_public_key_shares(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(share_set) = setup_package.get("publicKeyShares") else {
        return Ok(Some(setup_refusals(
            vec!["publicKeyShares".to_string()],
            Vec::new(),
        )));
    };
    if !share_set.is_object() {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "publicKeySharesNotObject",
            "publicKeyShares must be a root-bound object, not an array or scalar",
            "setupPackage.publicKeyShares",
        )?));
    }
    if share_set.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_SET_OBJECT_TYPE)
    {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "publicKeyShareSetTypeMismatch",
            "publicKeyShares.objectType must be PublicKeyShareSet",
            "setupPackage.publicKeyShares.objectType",
        )?));
    }

    let roster = super::accepted_roster_from_package(setup_package)?;
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let Some(share_records) = share_set.get("shareRecords").and_then(Value::as_array) else {
        return Ok(Some(setup_refusals(
            vec!["publicKeyShares.shareRecords".to_string()],
            Vec::new(),
        )));
    };
    if share_records.len() != roster.participant_count as usize {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "publicKeyShareCountMismatch",
            "publicKeyShares.shareRecords must contain one share per trustee",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    for (expected_roster_position, share_record) in share_records.iter().enumerate() {
        if let Some(response) = verify_public_key_share_record(
            share_record,
            expected_roster_position as u64,
            &expected_trustees,
        )? {
            return Ok(Some(response));
        }
    }

    Ok(None)
}

fn verify_public_key_share_record(
    share_record: &Value,
    expected_roster_position: u64,
    expected_trustees: &BTreeMap<u64, String>,
) -> CanonicalResult<Option<Refusals>> {
    if !share_record.is_object() {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "publicKeyShareNotObject",
            "public-key share records must be objects",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if share_record.get("objectType").and_then(Value::as_str) != Some(PUBLIC_KEY_SHARE_OBJECT_TYPE)
    {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "publicKeyShareTypeMismatch",
            "public-key share objectType must be PublicKeyShare",
            "setupPackage.publicKeyShares.shareRecords.objectType",
        )?));
    }
    let trustee_identity = value_string(share_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(share_record, "trusteeRosterPosition")?;
    if trustee_roster_position != expected_roster_position {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "publicKeyShareOrderMismatch",
            "public-key share records must follow canonical roster order",
            "setupPackage.publicKeyShares.shareRecords",
        )?));
    }
    if expected_trustees
        .get(&trustee_roster_position)
        .map(String::as_str)
        != Some(trustee_identity)
    {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::WrongContext,
            "publicKeyShareTrusteeMismatch",
            "public-key share trustee identity must match the accepted setup roster",
            "setupPackage.publicKeyShares.shareRecords.trusteeIdentity",
        )?));
    }
    let share_coefficient_hashes = share_record
        .get("shareCoefficientVectorHash512ByLimb")
        .and_then(Value::as_array);
    if let Some(response) = verify_public_key_share_limb_hashes(share_coefficient_hashes)? {
        return Ok(Some(response));
    }

    Ok(None)
}

pub(in crate::bgv::setup) fn derive_public_key_share_root(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    share_record: &Value,
) -> CanonicalResult<String> {
    let share_coefficient_hashes = share_record
        .get("shareCoefficientVectorHash512ByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share coefficient hashes are required to derive the share root",
            )
        })?;
    derive_canonical_object_hash(&json!({
        "objectType": PUBLIC_KEY_SHARE_OBJECT_TYPE,
        "setupContextHash": setup_context_hash(setup_context)?,
        "trusteeIdentity": value_string(share_record, "trusteeIdentity")?,
        "trusteeRosterPosition": value_u64(share_record, "trusteeRosterPosition")?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "shareCoefficientVectorHash512ByLimb": share_coefficient_hashes,
    }))
}

pub(in crate::bgv::setup) fn derive_public_key_share_set_root(
    setup_package: &Value,
) -> CanonicalResult<String> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext is required to derive the public-key share set root",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicMatrixSeedHash is required to derive the public-key share set root",
            )
        })?;
    let share_records = setup_package
        .get("publicKeyShares")
        .and_then(|share_set| share_set.get("shareRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share records are required to derive the share set root",
            )
        })?;
    derive_canonical_object_hash(&json!({
        "objectType": PUBLIC_KEY_SHARE_SET_OBJECT_TYPE,
        "setupContextHash": setup_context_hash(setup_context)?,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "shareRecords": share_records,
    }))
}

fn verify_public_key_share_limb_hashes(
    limb_hashes: Option<&Vec<Value>>,
) -> CanonicalResult<Option<Refusals>> {
    const LIMB_HASHES_PATH: &str =
        "publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb";
    const LIMB_HASHES_OBJECT_PATH: &str =
        "setupPackage.publicKeyShares.shareRecords.shareCoefficientVectorHash512ByLimb";

    let Some(limb_hashes) = limb_hashes else {
        return Ok(Some(setup_refusals(
            vec![LIMB_HASHES_PATH.to_string()],
            Vec::new(),
        )));
    };
    if limb_hashes.len() != DATA_PRIMES.len() {
        return Ok(Some(public_key_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
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

    fn refusal_reason(refusals: Option<Refusals>) -> String {
        refusals
            .expect("malformed limb hashes must be refused")
            .first()
            .map(|refusal| refusal.reason_code)
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
