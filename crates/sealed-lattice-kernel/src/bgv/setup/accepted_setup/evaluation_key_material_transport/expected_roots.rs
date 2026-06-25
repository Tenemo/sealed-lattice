use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn expected_relinearization_key_roots_for_evaluation_keys(
    setup_package: &Value,
    binding: &EvaluationKeyProofCommonBinding,
) -> CanonicalResult<Vec<Value>> {
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required before evaluation-key assembly",
            )
        })?;
    let relinearization_key_share_rounds_root =
        value_string(rounds, "relinearizationKeyShareRoundsRoot")?;
    let round_one_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneAggregateRoot",
    )?;
    let round_two_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoAggregateRoot",
    )?;

    scheduled_relinearization_levels()?
        .into_iter()
        .map(|level| {
            let round_one_aggregate_root =
                round_one_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-one aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let round_two_aggregate_root =
                round_two_aggregate_roots
                    .get(&level)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "relinearization round-two aggregate root was required before evaluation-key assembly",
                        )
                    })?;
            let decomposition_digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "relinearization level overflowed while deriving evaluation-key assembly",
                )
            })?;
            let key_root = derive_canonical_object_hash(
                &json!({
                    "objectType": "RelinearizationKeyAggregate",
                    "objectVersion": 1,
                    "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
                    "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                    "sameSecretProofFamilyBindingRoot": binding
                        .same_secret_proof_family_binding_root
                        .as_str(),
                    "publicKeyShareSuccinctProofSetRoot": binding
                        .public_key_share_succinct_proof_set_root
                        .as_str(),
                    "relinearizationKeyShareRoundsRoot": relinearization_key_share_rounds_root,
                    "level": level,
                    "decompositionDigitCount": decomposition_digit_count,
                    "rnsLimbCount": decomposition_digit_count,
                    "roundOneAggregateRoot": round_one_aggregate_root,
                    "roundTwoAggregateRoot": round_two_aggregate_root,
                }),
            )?;

            Ok(json!({
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "roundOneAggregateRoot": round_one_aggregate_root,
                "roundTwoAggregateRoot": round_two_aggregate_root,
                "relinearizationKeyRoot": key_root,
            }))
        })
        .collect()
}

pub(super) fn expected_galois_batch_roots_for_evaluation_keys(
    setup_package: &Value,
) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before evaluation-key assembly",
            )
        })?;
    let mut batch_roots = BTreeMap::<u64, Value>::new();
    for batch in batches {
        let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
        let trustee_identity = value_string(batch, "trusteeIdentity")?;
        let galois_key_share_batch_root = value_string(batch, "galoisKeyShareBatchRoot")?;
        if batch_roots
            .insert(
                trustee_roster_position,
                json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "galoisKeyShareBatchRoot": galois_key_share_batch_root,
                }),
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batches must not repeat a trustee roster position",
            ));
        }
    }

    Ok(batch_roots.into_values().collect())
}

pub(super) fn expected_galois_key_roots_for_evaluation_keys(
    setup_package: &Value,
    binding: &EvaluationKeyProofCommonBinding,
) -> CanonicalResult<Vec<Value>> {
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required before evaluation-key assembly",
            )
        })?;
    let expected_schedule = expected_required_galois_key_schedule()?;
    let expected_schedule = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "required Galois key schedule must be an array",
        )
    })?;
    let mut ordered_batches = batches
        .iter()
        .map(|batch| Ok((value_u64(batch, "trusteeRosterPosition")?, batch)))
        .collect::<CanonicalResult<Vec<_>>>()?;
    ordered_batches.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);

    expected_schedule
        .iter()
        .map(|schedule_entry| {
            let rotation = value_u64(schedule_entry, "rotation")?;
            let level = value_u64(schedule_entry, "level")?;
            let decomposition_digit_count = level.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "Galois key level overflowed while deriving evaluation-key assembly",
                )
            })?;
            let mut contributing_share_roots = Vec::new();
            for (_, batch) in &ordered_batches {
                let trustee_identity = value_string(batch, "trusteeIdentity")?;
                let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
                let material_record =
                    galois_key_share_material_for_schedule(batch, rotation, level)?;
                contributing_share_roots.push(json!({
                    "trusteeIdentity": trustee_identity,
                    "trusteeRosterPosition": trustee_roster_position,
                    "galoisKeyShareRoot": value_string(material_record, "galoisKeyShareRoot")?,
                }));
            }
            let galois_key_root = derive_canonical_object_hash(&json!({
                "objectType": "GaloisKeyAggregate",
                "objectVersion": 1,
                "materialEncoding": PUBLIC_EVALUATION_KEY_MATERIAL_ENCODING,
                "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                "sameSecretProofFamilyBindingRoot": binding
                    .same_secret_proof_family_binding_root
                    .as_str(),
                "publicKeyShareSuccinctProofSetRoot": binding
                    .public_key_share_succinct_proof_set_root
                    .as_str(),
                "galoisKeyCrpRoot": binding.galois_key_crp_root.as_str(),
                "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
                "rotation": rotation,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "contributingShareRoots": contributing_share_roots,
            }))?;

            Ok(json!({
                "rotation": rotation,
                "level": level,
                "decompositionDigitCount": decomposition_digit_count,
                "rnsLimbCount": decomposition_digit_count,
                "galoisKeyRoot": galois_key_root,
                "contributingShareRoots": contributing_share_roots,
            }))
        })
        .collect()
}

pub(super) fn accepted_setup_evaluation_key_records_use_full_ring(
    setup_package: &Value,
) -> CanonicalResult<bool> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(false);
    };
    for field_name in ["roundOneRecords", "roundTwoRecords"] {
        for record in array_value(rounds, field_name)? {
            if value_u64(record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Ok(false);
            }
        }
    }
    let Some(galois_batches) = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
    else {
        return Ok(false);
    };
    for batch in galois_batches {
        for material_record in array_value(batch, "galoisKeyShareMaterialRecords")? {
            if value_u64(material_record, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
