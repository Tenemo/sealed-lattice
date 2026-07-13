use super::*;

use crate::hashing::derive_canonical_object_hash;

// Share-record containers for the trustee evaluation-key proof path. The
// records carry the public key-switch component material (the runtime key
// shares); the parent container and accepted setup package supply the ceremony
// and schedule bindings. The per-trustee succinct argument over every record
// is verified by
// verify_trustee_evaluation_key_proofs, which rebuilds each statement from
// these records, so the records themselves carry no proof fields.

pub(super) fn verify_relinearization_key_share_rounds(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(Some(setup_refusals(
            vec!["relinearizationKeyShareRounds".to_string()],
            Vec::new(),
        )));
    };
    if !rounds.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsNotObject",
            "relinearizationKeyShareRounds must be an object",
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    if rounds.as_object().is_some_and(serde_json::Map::is_empty) {
        return Ok(Some(setup_refusals(
            vec!["relinearizationKeyShareRounds".to_string()],
            Vec::new(),
        )));
    }
    if rounds.get("objectType").and_then(Value::as_str)
        != Some(RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsTypeMismatch",
            "relinearizationKeyShareRounds.objectType must be RelinearizationKeyShareRounds",
            "setupPackage.relinearizationKeyShareRounds.objectType",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before relinearization share-record verification",
        )
    })?;
    let roster = super::accepted_roster_from_package(setup_package)?;
    if let Err(error) =
        verify_context_fields_match(rounds, setup_context, "relinearizationKeyShareRounds")
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsContextMismatch",
            error.message,
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "publicKeyShareSetRoot",
            binding.public_key_share_set_root.as_str(),
        ),
        (
            "publicKeyShareSuccinctProofSetRoot",
            binding.public_key_share_succinct_proof_set_root.as_str(),
        ),
    ] {
        if rounds.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationKeyShareRoundsBindingMismatch",
                format!(
                    "relinearizationKeyShareRounds.{field_name} must match the accepted setup binding"
                ),
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}"),
            )?));
        }
    }
    let expected_levels = scheduled_relinearization_levels()?;
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let round_one_records = array_value(rounds, "roundOneRecords")?;
    let round_two_records = array_value(rounds, "roundTwoRecords")?;
    let expected_record_count = expected_levels.len() * roster.participant_count as usize;
    if round_one_records.len() != expected_record_count
        || round_two_records.len() != expected_record_count
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundCountMismatch",
            "relinearization round-one and round-two records must contain one record per trustee and scheduled level",
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }

    let mut seen_round_one_records = BTreeSet::new();
    for record in round_one_records {
        let (level, trustee_roster_position) =
            match verify_relinearization_round_one_record(record, &expected_trustees) {
                Ok(verified_record) => verified_record,
                Err(error) => {
                    return Ok(Some(evaluation_key_material_refusal(
                        "evaluationKeyMaterialVerificationFailed",
                        error.message,
                        "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
                    )?));
                }
            };
        if !expected_levels.contains(&level) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneLevelOutsideSchedule",
                "relinearization round-one record level is not in the frozen schedule",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords.level",
            )?));
        }
        if !seen_round_one_records.insert((level, trustee_roster_position)) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneDuplicate",
                "relinearization round-one records must not repeat a trustee and level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        }
    }

    let mut seen_round_two_records = BTreeSet::new();
    for record in round_two_records {
        let (level, trustee_roster_position) =
            match verify_relinearization_round_two_record(record, &expected_trustees) {
                Ok(verified_record) => verified_record,
                Err(error) => {
                    return Ok(Some(evaluation_key_material_refusal(
                        "evaluationKeyMaterialVerificationFailed",
                        error.message,
                        "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
                    )?));
                }
            };
        if !expected_levels.contains(&level) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoLevelOutsideSchedule",
                "relinearization round-two record level is not in the frozen schedule",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords.level",
            )?));
        }
        if !seen_round_two_records.insert((level, trustee_roster_position)) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoDuplicate",
                "relinearization round-two records must not repeat a trustee and level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        }
    }
    Ok(None)
}

pub(super) fn verify_galois_key_share_batches(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let roster = super::accepted_roster_from_package(setup_package)?;
    let Some(batches) = setup_package.get("galoisKeyShareBatches") else {
        return Ok(Some(setup_refusals(
            vec!["galoisKeyShareBatches".to_string()],
            Vec::new(),
        )));
    };
    let Some(batches) = batches.as_array() else {
        return Ok(Some(evaluation_key_material_refusal(
            "galoisKeyShareBatchesNotArray",
            "galoisKeyShareBatches must be an array of trustee batches",
            "setupPackage.galoisKeyShareBatches",
        )?));
    };
    if batches.is_empty() {
        return Ok(Some(setup_refusals(
            vec!["galoisKeyShareBatches".to_string()],
            Vec::new(),
        )));
    }
    if batches.len() != roster.participant_count as usize {
        return Ok(Some(evaluation_key_material_refusal(
            "galoisKeyShareBatchCountMismatch",
            "galoisKeyShareBatches must contain one batch per trustee",
            "setupPackage.galoisKeyShareBatches",
        )?));
    }
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let expected_schedule = expected_required_galois_key_schedule()?;
    let mut seen_roster_positions = BTreeSet::new();
    for batch in batches {
        if let Err(error) = verify_galois_key_share_batch(
            batch,
            &expected_trustees,
            &expected_schedule,
            &mut seen_roster_positions,
        ) {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeyMaterialVerificationFailed",
                error.message,
                "setupPackage.galoisKeyShareBatches",
            )?));
        }
    }

    Ok(None)
}

pub(super) fn galois_key_share_material_for_schedule(
    batch: &Value,
    rotation: u64,
    level: u64,
) -> CanonicalResult<&Value> {
    array_value(batch, "galoisKeyShareMaterialRecords")?
        .iter()
        .find(|material_record| {
            material_record.get("rotation").and_then(Value::as_u64) == Some(rotation)
                && material_record.get("level").and_then(Value::as_u64) == Some(level)
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batch does not contain a required scheduled material record",
            )
        })
}

pub(super) struct EvaluationKeyProofCommonBinding {
    pub(super) evaluator_key_schedule_root: String,
    pub(super) public_matrix_seed_hash: String,
    pub(super) public_key_share_set_root: String,
    pub(super) public_key_share_succinct_proof_set_root: String,
}

pub(super) fn evaluation_key_proof_common_binding(
    setup_package: &Value,
) -> CanonicalResult<EvaluationKeyProofCommonBinding> {
    let evaluator_key_schedule = setup_package.get("evaluatorKeySchedule").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluatorKeySchedule was required before evaluation-key share verification",
        )
    })?;
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before evaluation-key share verification",
        )
    })?;
    Ok(EvaluationKeyProofCommonBinding {
        evaluator_key_schedule_root: value_string(
            evaluator_key_schedule,
            "evaluatorKeyScheduleRoot",
        )?
        .to_string(),
        public_matrix_seed_hash: value_string(common_randomness, "publicMatrixSeedHash")?
            .to_string(),
        public_key_share_set_root: setup_package
            .get("publicKeyShares")
            .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShareSetRoot was required before evaluation-key share verification",
                )
            })?
            .to_string(),
        public_key_share_succinct_proof_set_root: setup_package
            .get("publicKeyShareSuccinctProofs")
            .and_then(|proof_set| proof_set.get("publicKeyShareSuccinctProofSetRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShareSuccinctProofSetRoot was required before evaluation-key share verification",
                )
            })?
            .to_string(),
    })
}

// The scheduled relinearization key levels, read from the frozen evaluator
// schedule: one truncated key per round at the selected working level.
pub(super) fn scheduled_relinearization_levels() -> CanonicalResult<Vec<u64>> {
    expected_relinearization_level_schedule()
        .as_array()
        .expect("relinearization level schedule is an array")
        .iter()
        .map(|entry| {
            entry.get("level").and_then(Value::as_u64).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearization level schedule entry is missing its level",
                )
            })
        })
        .collect()
}

// Binds the shared public sampler directly to accepted common randomness and
// the exact schedule slot. The component-material sampler expands this seed per
// gadget digit and RNS limb.
pub(super) fn expected_relinearization_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "RelinearizationKeySwitchPublicSampleSeed",
        "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
        "publicMatrixSeedHash": binding.public_matrix_seed_hash.as_str(),
        "round": round,
        "level": level,
    }))
}

pub(super) fn expected_galois_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "GaloisKeySwitchPublicSampleSeed",
        "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
        "publicMatrixSeedHash": binding.public_matrix_seed_hash.as_str(),
        "rotation": rotation,
        "level": level,
    }))
}

pub(super) fn verify_relinearization_key_switch_sample_binding(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<DecodedEvaluationKeyShareComponentMaterial> {
    if value_u64(record, "level")? != level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "relinearization key-switch sample level does not match the scheduled level",
        ));
    }
    let key_switch_seed_hex = expected_relinearization_key_switch_seed(binding, round, level)?;
    component_b_vectors_from_record(
        EvaluationKeyShareProofFamily::Relinearization,
        record,
        EvaluationKeyShareDerivedMaterialBinding {
            trustee_identity: value_string(record, "trusteeIdentity")?,
            trustee_roster_position: value_u64(record, "trusteeRosterPosition")?,
            key_switch_domain: "relinearization",
            key_switch_seed_hex: &key_switch_seed_hex,
        },
        accepted_setup_session,
    )
}

pub(super) fn verify_galois_key_switch_sample_binding(
    batch: &Value,
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<DecodedEvaluationKeyShareComponentMaterial> {
    if value_u64(record, "rotation")? != rotation || value_u64(record, "level")? != level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "Galois key-switch sample does not match the scheduled rotation and level",
        ));
    }
    let key_switch_domain = format!("galois-{rotation}");
    let key_switch_seed_hex = expected_galois_key_switch_seed(binding, rotation, level)?;
    component_b_vectors_from_record(
        EvaluationKeyShareProofFamily::Galois,
        record,
        EvaluationKeyShareDerivedMaterialBinding {
            trustee_identity: value_string(batch, "trusteeIdentity")?,
            trustee_roster_position: value_u64(batch, "trusteeRosterPosition")?,
            key_switch_domain: &key_switch_domain,
            key_switch_seed_hex: &key_switch_seed_hex,
        },
        accepted_setup_session,
    )
}

// A share record binds the canonical streamed component material by root. The
// material is decoded and verified when the trustee proof statement is rebuilt.
fn verify_evaluation_key_component_material_encoding(record: &Value) -> CanonicalResult<()> {
    validate_hash_string(
        value_string(record, "keySwitchComponentVectorRoot")?,
        "evaluationKeyShareRecord.keySwitchComponentVectorRoot",
    )?;
    validate_hash_string(
        value_string(record, "keySwitchComponentMaterialRoot")?,
        "evaluationKeyShareRecord.keySwitchComponentMaterialRoot",
    )?;

    Ok(())
}

fn verify_relinearization_round_one_record(
    record: &Value,
    expected_trustees: &BTreeMap<u64, String>,
) -> CanonicalResult<(u64, u64)> {
    verify_evaluation_key_record_object(record, RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE)?;
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_trustee(record, expected_trustees, trustee_roster_position)?;
    verify_evaluation_key_component_material_encoding(record)?;

    Ok((level, trustee_roster_position))
}

fn verify_relinearization_round_two_record(
    record: &Value,
    expected_trustees: &BTreeMap<u64, String>,
) -> CanonicalResult<(u64, u64)> {
    verify_evaluation_key_record_object(record, RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE)?;
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_trustee(record, expected_trustees, trustee_roster_position)?;
    verify_evaluation_key_component_material_encoding(record)?;

    Ok((level, trustee_roster_position))
}

fn verify_galois_key_share_batch(
    batch: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    expected_schedule: &Value,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    verify_evaluation_key_record_object(batch, GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE)?;
    let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share batches must not repeat a trustee roster position",
        ));
    }
    verify_evaluation_key_record_trustee(batch, expected_trustees, trustee_roster_position)?;
    let expected_entries = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "expected Galois key schedule must be an array",
        )
    })?;
    let material_records = array_value(batch, "galoisKeyShareMaterialRecords")?;
    if material_records.len() != expected_entries.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "Galois key share batch must contain one material record per required schedule entry",
        ));
    }
    for (material_record, expected_entry) in material_records.iter().zip(expected_entries) {
        verify_galois_key_share_material_record(material_record, expected_entry)?;
    }

    Ok(())
}

fn verify_galois_key_share_material_record(
    material_record: &Value,
    expected_schedule_entry: &Value,
) -> CanonicalResult<()> {
    if !material_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share material record must be an object",
        ));
    }
    if material_record.get("objectType").and_then(Value::as_str)
        != Some(GALOIS_KEY_SHARE_MATERIAL_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share material objectType must be GaloisKeyShareMaterial",
        ));
    }
    if material_record.get("rotation") != expected_schedule_entry.get("rotation")
        || material_record.get("level") != expected_schedule_entry.get("level")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "Galois key share material must bind the scheduled rotation and level",
        ));
    }
    verify_evaluation_key_component_material_encoding(material_record)?;

    Ok(())
}

fn verify_evaluation_key_record_object(
    record: &Value,
    expected_object_type: &str,
) -> CanonicalResult<()> {
    if !record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key share record must be an object",
        ));
    }
    if record.get("objectType").and_then(Value::as_str) != Some(expected_object_type) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("evaluation-key share objectType must be {expected_object_type}"),
        ));
    }
    Ok(())
}

fn verify_evaluation_key_record_trustee(
    record: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    trustee_roster_position: u64,
) -> CanonicalResult<()> {
    let Some(expected_trustee_identity) = expected_trustees.get(&trustee_roster_position) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "evaluation-key share trusteeRosterPosition must reference an accepted trustee",
        ));
    };
    if record.get("trusteeIdentity").and_then(Value::as_str)
        != Some(expected_trustee_identity.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "evaluation-key share trusteeIdentity must match the accepted trustee",
        ));
    }

    Ok(())
}
