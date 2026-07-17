use super::*;

pub(super) fn read_partial_decryption_share(
    share: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
) -> CanonicalResult<()> {
    if string_at_path(share, &["objectType"])? != "BgvTargetDecryptionShare" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target decryption accepts only BgvTargetDecryptionShare records",
        ));
    }
    let trustee_roster_position = usize_at_path(share, &["trusteeRosterPosition"])?;
    let participant = setup_binding
        .participants
        .get(trustee_roster_position)
        .filter(|candidate| candidate.roster_position == trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "target decryption share roster position is not in the setup roster",
            )
        })?;
    compare_share_record_fields(share, target_accepted, participant)?;
    let payload = value_at_path(share, &["sharePayload"])?;
    target_decryption_share_hash(share)?;
    read_partial_limb_set(payload, "targetId", target_ciphertexts.target_id.level)?;
    read_partial_limb_set(
        payload,
        "targetOrder",
        target_ciphertexts.target_order.level,
    )?;

    Ok(())
}

pub(super) fn compare_share_record_fields(
    share: &Value,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
) -> CanonicalResult<()> {
    compare_unsigned_field(
        share,
        "trusteeRosterPosition",
        participant.roster_position as u64,
        "target share trustee roster position",
    )?;
    compare_hash_field(
        share,
        "targetAcceptedRecordHash",
        &target_accepted.target_accepted_record_hash,
        "target share accepted record",
    )?;

    Ok(())
}

pub(super) fn share_payload(
    target_id_partials: &[Vec<u64>],
    target_order_partials: &[Vec<u64>],
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvTargetDecryptionSharePayload",
        "targetId": partial_limb_records(target_id_partials)?,
        "targetOrder": partial_limb_records(target_order_partials)?,
    }))
}

pub(super) fn partial_limb_records(partials: &[Vec<u64>]) -> CanonicalResult<Vec<Value>> {
    partials
        .iter()
        .map(|coefficients| {
            if coefficients.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target partial-decryption limb has the wrong coefficient count",
                ));
            }
            Ok(json!({
                "partialDecryptionLeHex": coefficient_vector_le_hex(coefficients),
            }))
        })
        .collect()
}

pub(super) fn read_partial_limb_set(
    payload: &Value,
    role: &str,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if string_at_path(payload, &["objectType"])? != "BgvTargetDecryptionSharePayload" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target share payload object type is not canonical",
        ));
    }
    let records = array_at_path(payload, &[role])?;
    if records.len() != level + 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target share payload must include one partial-decryption limb per active prime",
        ));
    }
    records
        .iter()
        .enumerate()
        .map(|(limb_index, record)| {
            let coefficients = coefficient_vector_from_le_hex(
                string_at_path(record, &["partialDecryptionLeHex"])?,
                POLYNOMIAL_DEGREE,
                "target partial-decryption coefficient vector byte length does not match the selected ring degree",
            )?;
            let modulus = DATA_PRIMES[limb_index];
            if coefficients.iter().any(|coefficient| *coefficient >= modulus) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "target partial-decryption limb contains a non-canonical residue",
                ));
            }

            Ok(coefficients)
        })
        .collect()
}

pub(super) fn target_decryption_share_hash(share: &Value) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": string_at_path(share, &["objectType"])?,
        "trusteeRosterPosition": unsigned_at_path(share, &["trusteeRosterPosition"])?,
        "targetAcceptedRecordHash": hash_at_path(share, &["targetAcceptedRecordHash"])?,
        "sharePayload": value_at_path(share, &["sharePayload"])?,
    }))
}
