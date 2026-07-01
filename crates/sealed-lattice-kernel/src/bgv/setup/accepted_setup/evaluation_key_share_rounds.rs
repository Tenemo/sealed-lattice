use super::*;

use crate::hashing::derive_canonical_object_hash;

// Share-record containers for the trustee evaluation-key proof path. The
// records carry the public key-switch component material (the runtime key
// shares), the ceremony context, and the same-secret anchors; the per-trustee
// succinct argument over every record is verified by
// verify_trustee_evaluation_key_proofs, which rebuilds each statement from
// these records, so the records themselves carry no proof fields.

pub(super) fn verify_relinearization_key_share_rounds(
    setup_package: &Value,
    _request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(Some(verification_response(
            Some("relinearizationRoundOne"),
            vec!["relinearizationKeyShareRounds".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !rounds.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsNotObject",
            "relinearizationKeyShareRounds must be a root-bound object",
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    if rounds.as_object().is_some_and(serde_json::Map::is_empty) {
        return Ok(None);
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
    if rounds.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsVersionMismatch",
            "relinearizationKeyShareRounds.objectVersion must be 1",
            "setupPackage.relinearizationKeyShareRounds.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before relinearization share-record verification",
        )
    })?;
    let roster = super::accepted_roster_from_package(setup_package);
    if let Err(error) =
        verify_context_fields_match(rounds, setup_context, "relinearizationKeyShareRounds")
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsContextMismatch",
            error.message,
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    for (field_name, expected_value) in [("proofFamily", "relinearization-key-share")] {
        if rounds.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationKeyShareRoundsParametersMismatch",
                format!("relinearizationKeyShareRounds.{field_name} must be {expected_value}"),
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", roster.participant_count),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if rounds.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationKeyShareRoundsCountMismatch",
                format!("relinearizationKeyShareRounds.{field_name} must be {expected_value}"),
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}"),
            )?));
        }
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "sameSecretConsistencyRoot",
            binding.same_secret_consistency_root.as_str(),
        ),
        (
            "sameSecretProofSetRoot",
            binding.same_secret_proof_set_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            binding.same_secret_proof_family_binding_root.as_str(),
        ),
        (
            "publicKeyShareSetRoot",
            binding.public_key_share_set_root.as_str(),
        ),
        (
            "publicKeyShareSuccinctProofSetRoot",
            binding.public_key_share_succinct_proof_set_root.as_str(),
        ),
        (
            "relinearizationCrpRoot",
            binding.relinearization_crp_root.as_str(),
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
    let expected_level_schedule = expected_relinearization_level_schedule();
    if rounds.get("relinearizationLevelSchedule") != Some(&expected_level_schedule) {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsScheduleMismatch",
            "relinearizationKeyShareRounds.relinearizationLevelSchedule must match the frozen evaluator schedule",
            "setupPackage.relinearizationKeyShareRounds.relinearizationLevelSchedule",
        )?));
    }
    let expected_levels = scheduled_relinearization_levels()?;
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
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

    let mut round_one_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut round_one_record_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_share_roots = BTreeMap::<(u64, u64), String>::new();
    for record in round_one_records {
        let (level, trustee_roster_position, record_root, share_root) =
            match verify_relinearization_round_one_record(
                record,
                &binding,
                &same_secret_proof_bindings,
            ) {
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
        if round_one_record_roots
            .insert((level, trustee_roster_position), record_root.clone())
            .is_some()
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneDuplicate",
                "relinearization round-one records must not repeat a trustee and level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        }
        round_one_share_roots.insert((level, trustee_roster_position), share_root);
        let trustee_identity = same_secret_proof_bindings
            .get(&trustee_roster_position)
            .expect("same-secret proof binding exists after record verification")
            .trustee_identity
            .clone();
        round_one_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "roundOneRecordRoot": record_root,
            }));
    }

    let supplied_round_one_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneAggregateRoot",
    )?;
    for level in &expected_levels {
        let Some(record_roots) = round_one_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneLevelMissing",
                "relinearization round-one records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        };
        let expected_root = derive_canonical_object_hash(&json!({
            "objectType": "RelinearizationRoundOneAggregate",
            "objectVersion": 1,
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "level": level,
            "roundOneRecordRoots": record_roots,
        }))?;
        if supplied_round_one_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneAggregateRootMismatch",
                "relinearization round-one aggregate root must be derived from the ordered round-one records",
                "setupPackage.relinearizationKeyShareRounds.roundOneAggregateRoots",
            )?));
        }
    }

    let mut round_two_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut seen_round_two_records = BTreeSet::new();
    let round_one_state = RelinearizationRoundOneVerificationState {
        record_roots: &round_one_record_roots,
        share_roots: &round_one_share_roots,
        aggregate_roots: &supplied_round_one_aggregate_roots,
    };
    for record in round_two_records {
        let (level, trustee_roster_position, record_root) =
            match verify_relinearization_round_two_record(
                record,
                &binding,
                &same_secret_proof_bindings,
                &round_one_state,
            ) {
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
        let trustee_identity = same_secret_proof_bindings
            .get(&trustee_roster_position)
            .expect("same-secret proof binding exists after record verification")
            .trustee_identity
            .clone();
        round_two_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "roundTwoRecordRoot": record_root,
            }));
    }
    let supplied_round_two_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoAggregateRoot",
    )?;
    for level in &expected_levels {
        let Some(record_roots) = round_two_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoLevelMissing",
                "relinearization round-two records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        };
        let expected_root = derive_canonical_object_hash(&json!({
            "objectType": "RelinearizationRoundTwoAggregate",
            "objectVersion": 1,
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "level": level,
            // Chaining round two onto the accepted round-one aggregate root binds the rounds together, so round-two material proven against a substituted or rolled-back round-one transcript cannot verify.
            "roundOneAggregateRoot": supplied_round_one_aggregate_roots
                .get(level)
                .expect("round-one aggregate root exists after verification"),
            "roundTwoRecordRoots": record_roots,
        }))?;
        if supplied_round_two_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoAggregateRootMismatch",
                "relinearization round-two aggregate root must be derived from the ordered round-two records and round-one aggregate root",
                "setupPackage.relinearizationKeyShareRounds.roundTwoAggregateRoots",
            )?));
        }
    }

    // Self-hash: the root commits to every other field of this object; the root field is excluded to avoid self-reference.
    let supplied_root = value_string(rounds, "relinearizationKeyShareRoundsRoot")?;
    let mut root_input = rounds.clone();
    root_input
        .as_object_mut()
        .expect("relinearization rounds object was checked")
        .remove("relinearizationKeyShareRoundsRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if supplied_root != expected_root {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsRootMismatch",
            "relinearizationKeyShareRoundsRoot does not match the canonical relinearization share-record container",
            "setupPackage.relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot",
        )?));
    }

    Ok(None)
}

pub(super) fn verify_galois_key_share_batches(
    setup_package: &Value,
    _request: &Value,
) -> CanonicalResult<Option<Value>> {
    let roster = super::accepted_roster_from_package(setup_package);
    let Some(batches) = setup_package.get("galoisKeyShareBatches") else {
        return Ok(Some(verification_response(
            Some("galoisKeyShareBatches"),
            vec!["galoisKeyShareBatches".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let Some(batches) = batches.as_array() else {
        return Ok(Some(evaluation_key_material_refusal(
            "galoisKeyShareBatchesNotArray",
            "galoisKeyShareBatches must be an array of root-bound trustee batches",
            "setupPackage.galoisKeyShareBatches",
        )?));
    };
    if batches.is_empty() {
        return Ok(None);
    }
    if batches.len() != roster.participant_count as usize {
        return Ok(Some(evaluation_key_material_refusal(
            "galoisKeyShareBatchCountMismatch",
            "galoisKeyShareBatches must contain one batch per trustee",
            "setupPackage.galoisKeyShareBatches",
        )?));
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
    let expected_schedule = expected_required_galois_key_schedule()?;
    let mut seen_roster_positions = BTreeSet::new();
    for batch in batches {
        if let Err(error) = verify_galois_key_share_batch(
            batch,
            &binding,
            &same_secret_proof_bindings,
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
    pub(super) same_secret_consistency_root: String,
    pub(super) same_secret_proof_set_root: String,
    pub(super) same_secret_proof_family_binding_root: String,
    pub(super) public_key_share_set_root: String,
    pub(super) public_key_share_succinct_proof_set_root: String,
    pub(super) relinearization_crp_root: String,
    pub(super) galois_key_crp_root: String,
    pub(super) required_galois_set_hash: String,
}

struct RelinearizationRoundOneVerificationState<'a> {
    record_roots: &'a BTreeMap<(u64, u64), String>,
    share_roots: &'a BTreeMap<(u64, u64), String>,
    aggregate_roots: &'a BTreeMap<u64, String>,
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
    let public_derivations = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicDerivations"))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicDerivations was required before evaluation-key share verification",
            )
        })?;
    let crp_roots = public_derivations.get("crpRoots").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations.crpRoots was required before evaluation-key share verification",
        )
    })?;

    Ok(EvaluationKeyProofCommonBinding {
        evaluator_key_schedule_root: value_string(
            evaluator_key_schedule,
            "evaluatorKeyScheduleRoot",
        )?
        .to_string(),
        same_secret_consistency_root: same_secret_consistency_root_from_package(setup_package)?,
        same_secret_proof_set_root: same_secret_proof_set_root_from_package(setup_package)?,
        same_secret_proof_family_binding_root: same_secret_proof_family_binding_root()?,
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
        relinearization_crp_root: value_string(crp_roots, "relinearizationCrpRoot")?.to_string(),
        galois_key_crp_root: value_string(crp_roots, "galoisKeyCrpRoot")?.to_string(),
        required_galois_set_hash: value_string(evaluator_key_schedule, "requiredGaloisSetHash")?
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

pub(super) fn relinearization_aggregate_roots_by_level(
    rounds: &Value,
    field_name: &str,
    root_field_name: &str,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let mut roots = BTreeMap::new();
    for entry in array_value(rounds, field_name)? {
        let level = value_u64(entry, "level")?;
        let root = value_string(entry, root_field_name)?;
        validate_hash_string(root, root_field_name)?;
        if roots.insert(level, root.to_string()).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} contains duplicate relinearization levels"),
            ));
        }
    }

    Ok(roots)
}

// Binds the shared public sampler a to the accepted CRP root and the exact
// schedule slot (round and level), so every trustee derives the same a and no
// party can choose it adaptively; the downstream component-material sampler then
// expands this single seed per gadget digit and RNS limb.
pub(super) fn expected_relinearization_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "RelinearizationKeySwitchPublicSampleSeed",
        "objectVersion": 1,
        "proofFamily": "relinearization-key-share",
        "keySwitchSampleScope": "shared-by-scheduled-level-and-round",
        "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
        "relinearizationCrpRoot": binding.relinearization_crp_root.as_str(),
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
        "objectVersion": 1,
        "proofFamily": "galois-key-share",
        "keySwitchSampleScope": "shared-by-scheduled-rotation-and-level",
        "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
        "galoisKeyCrpRoot": binding.galois_key_crp_root.as_str(),
        "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
        "rotation": rotation,
        "level": level,
    }))
}

pub(super) fn verify_relinearization_key_switch_sample_binding(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<()> {
    if value_string(record, "keySwitchDomain")? != "relinearization" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "relinearization key-switch domain must be shared relinearization material",
        ));
    }
    let expected_seed = expected_relinearization_key_switch_seed(binding, round, level)?;
    if value_string(record, "keySwitchSeedHex")? != expected_seed {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "relinearization key-switch seed must be shared by scheduled level and round",
        ));
    }

    Ok(())
}

pub(super) fn verify_galois_key_switch_sample_binding(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
) -> CanonicalResult<()> {
    let expected_domain = format!("galois-{rotation}");
    if value_string(record, "keySwitchDomain")? != expected_domain {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "Galois key-switch domain must match the scheduled rotation",
        ));
    }
    let expected_seed = expected_galois_key_switch_seed(binding, rotation, level)?;
    if value_string(record, "keySwitchSeedHex")? != expected_seed {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "Galois key-switch seed must be shared by scheduled rotation and level",
        ));
    }

    Ok(())
}

// Structural checks for the public key-switch component material carried by a
// share record: exactly one of the embedded and the transported encodings,
// with a valid component vector root. The full material content is decoded
// and verified against these roots when the trustee evaluation-key proof
// statements are rebuilt.
fn verify_evaluation_key_component_material_encoding(record: &Value) -> CanonicalResult<()> {
    let material_encoding = record
        .get("keySwitchMaterialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "evaluation-key share record keySwitchMaterialEncoding is required",
            )
        })?;
    match material_encoding {
        "embedded-full-key-switch-component-vectors" => {
            if record.get("keySwitchComponentVectors").is_none()
                || record.get("keySwitchComponentMaterialRoot").is_some()
                || record.get("keySwitchComponentChunkSizeBytes").is_some()
                || record.get("keySwitchComponentChunkCount").is_some()
                || record.get("keySwitchComponentTotalByteLength").is_some()
                || record.get("keySwitchComponentFullObjectHash").is_some()
                || record.get("keySwitchComponentChunkRoot").is_some()
                || record.get("keySwitchComponentChunkHashes").is_some()
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "embedded evaluation-key share material must include component vectors and no component transport reference",
                ));
            }
        }
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING => {
            if record.get("keySwitchComponentVectors").is_some() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "binary evaluation-key share material must not embed keySwitchComponentVectors",
                ));
            }
            for field_name in [
                "keySwitchComponentMaterialRoot",
                "keySwitchComponentChunkSizeBytes",
                "keySwitchComponentChunkCount",
                "keySwitchComponentTotalByteLength",
                "keySwitchComponentFullObjectHash",
                "keySwitchComponentChunkRoot",
                "keySwitchComponentChunkHashes",
            ] {
                if record.get(field_name).is_none() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        format!("binary evaluation-key share material requires {field_name}"),
                    ));
                }
            }
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "evaluation-key share keySwitchMaterialEncoding is not accepted",
            ));
        }
    }
    validate_hash_string(
        value_string(record, "keySwitchComponentVectorRoot")?,
        "evaluationKeyShareRecord.keySwitchComponentVectorRoot",
    )?;
    if let Some(material_root) = record
        .get("keySwitchComponentMaterialRoot")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            material_root,
            "evaluationKeyShareRecord.keySwitchComponentMaterialRoot",
        )?;
    }

    Ok(())
}

fn verify_relinearization_round_one_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
) -> CanonicalResult<(u64, u64, String, String)> {
    verify_evaluation_key_record_object(
        record,
        RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE,
        "relinearization-key-share",
    )?;
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_common_bindings(
        record,
        binding,
        same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    verify_relinearization_key_switch_sample_binding(record, binding, "round-one", level)?;
    verify_evaluation_key_component_material_encoding(record)?;
    let round_one_share_root = value_string(record, "roundOneShareRoot")?;
    validate_hash_string(round_one_share_root, "roundOneShareRoot")?;
    if record
        .get("keySwitchComponentVectorRoot")
        .and_then(Value::as_str)
        != Some(round_one_share_root)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "relinearization round-one share root must match the key-switch component vector root",
        ));
    }
    let supplied_root = value_string(record, "roundOneRecordRoot")?;
    let mut root_input = record.clone();
    root_input
        .as_object_mut()
        .expect("relinearization round-one record object was checked")
        .remove("roundOneRecordRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "roundOneRecordRoot does not match the canonical relinearization round-one record",
        ));
    }

    Ok((
        level,
        trustee_roster_position,
        supplied_root.to_string(),
        round_one_share_root.to_string(),
    ))
}

fn verify_relinearization_round_two_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
    round_one_state: &RelinearizationRoundOneVerificationState<'_>,
) -> CanonicalResult<(u64, u64, String)> {
    verify_evaluation_key_record_object(
        record,
        RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE,
        "relinearization-key-share",
    )?;
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_common_bindings(
        record,
        binding,
        same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    verify_relinearization_key_switch_sample_binding(record, binding, "round-two", level)?;
    verify_evaluation_key_component_material_encoding(record)?;
    for field_name in [
        "roundOneShareRoot",
        "roundOneRecordRoot",
        "roundOneAggregateRoot",
        "roundTwoShareRoot",
    ] {
        validate_hash_string(value_string(record, field_name)?, field_name)?;
    }
    let key = (level, trustee_roster_position);
    if round_one_state.record_roots.get(&key).map(String::as_str)
        != Some(value_string(record, "roundOneRecordRoot")?)
        || round_one_state.share_roots.get(&key).map(String::as_str)
            != Some(value_string(record, "roundOneShareRoot")?)
        || round_one_state
            .aggregate_roots
            .get(&level)
            .map(String::as_str)
            != Some(value_string(record, "roundOneAggregateRoot")?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "relinearization round-two record must bind the accepted round-one record, share, and aggregate roots",
        ));
    }
    if record
        .get("keySwitchComponentVectorRoot")
        .and_then(Value::as_str)
        != Some(value_string(record, "roundTwoShareRoot")?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "relinearization round-two share root must match the key-switch component vector root",
        ));
    }
    let supplied_root = value_string(record, "roundTwoRecordRoot")?;
    let mut root_input = record.clone();
    root_input
        .as_object_mut()
        .expect("relinearization round-two record object was checked")
        .remove("roundTwoRecordRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "roundTwoRecordRoot does not match the canonical relinearization round-two record",
        ));
    }

    Ok((level, trustee_roster_position, supplied_root.to_string()))
}

fn verify_galois_key_share_batch(
    batch: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
    expected_schedule: &Value,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    verify_evaluation_key_record_object(
        batch,
        GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE,
        "galois-key-share",
    )?;
    let trustee_roster_position = value_u64(batch, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share batches must not repeat a trustee roster position",
        ));
    }
    verify_evaluation_key_record_common_bindings(
        batch,
        binding,
        same_secret_proof_bindings,
        trustee_roster_position,
        "galoisKeyCrpRoot",
        binding.galois_key_crp_root.as_str(),
    )?;
    if batch.get("requiredGaloisSetHash").and_then(Value::as_str)
        != Some(binding.required_galois_set_hash.as_str())
        || batch.get("requiredGaloisKeySchedule") != Some(expected_schedule)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "Galois key share batch must bind the exact frozen RequiredGaloisSetHash and schedule",
        ));
    }
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
        verify_galois_key_share_material_record(material_record, batch, binding, expected_entry)?;
    }
    let supplied_root = value_string(batch, "galoisKeyShareBatchRoot")?;
    let mut root_input = batch.clone();
    root_input
        .as_object_mut()
        .expect("Galois key share batch object was checked")
        .remove("galoisKeyShareBatchRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "galoisKeyShareBatchRoot does not match the canonical Galois key share batch",
        ));
    }

    Ok(())
}

fn verify_galois_key_share_material_record(
    material_record: &Value,
    batch: &Value,
    binding: &EvaluationKeyProofCommonBinding,
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
    if material_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share material objectVersion must be 1",
        ));
    }
    for field_name in ["proofFamily", "trusteeIdentity", "trusteeRosterPosition"] {
        if material_record.get(field_name) != batch.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("Galois key share material {field_name} must match the parent batch"),
            ));
        }
    }
    validate_hash_string(
        value_string(material_record, "galoisKeyShareRoot")?,
        "galoisKeyShareRoot",
    )?;
    if material_record.get("rotation") != expected_schedule_entry.get("rotation")
        || material_record.get("level") != expected_schedule_entry.get("level")
        || material_record.get("keySwitchComponentVectorRoot")
            != material_record.get("galoisKeyShareRoot")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "Galois key share material must bind the scheduled rotation, level, and share root",
        ));
    }
    let rotation = value_u64(material_record, "rotation")?;
    let level = value_u64(material_record, "level")?;
    verify_galois_key_switch_sample_binding(material_record, binding, rotation, level)?;
    verify_evaluation_key_component_material_encoding(material_record)?;

    Ok(())
}

fn verify_evaluation_key_record_object(
    record: &Value,
    expected_object_type: &str,
    expected_proof_family: &str,
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
    if record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key share objectVersion must be 1",
        ));
    }
    for (field_name, expected_value) in [("proofFamily", expected_proof_family)] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("evaluation-key share {field_name} must be {expected_value}"),
            ));
        }
    }

    Ok(())
}

fn verify_evaluation_key_record_common_bindings(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    same_secret_proof_bindings: &BTreeMap<u64, SameSecretProofBinding>,
    trustee_roster_position: u64,
    crp_root_field_name: &str,
    expected_crp_root: &str,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "sameSecretConsistencyRoot",
            binding.same_secret_consistency_root.as_str(),
        ),
        (
            "sameSecretProofSetRoot",
            binding.same_secret_proof_set_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            binding.same_secret_proof_family_binding_root.as_str(),
        ),
        (
            "publicKeyShareSuccinctProofSetRoot",
            binding.public_key_share_succinct_proof_set_root.as_str(),
        ),
        (crp_root_field_name, expected_crp_root),
    ] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("evaluation-key share {field_name} must match the accepted setup binding"),
            ));
        }
    }
    let Some(same_secret_binding) = same_secret_proof_bindings.get(&trustee_roster_position) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "evaluation-key share trusteeRosterPosition must reference an accepted same-secret proof",
        ));
    };
    for (field_name, expected_value) in [
        (
            "trusteeIdentity",
            same_secret_binding.trustee_identity.as_str(),
        ),
        (
            "trusteeSecretCommitmentRoot",
            same_secret_binding.trustee_secret_commitment_root.as_str(),
        ),
        (
            "sameSecretStatementRoot",
            same_secret_binding.same_secret_statement_root.as_str(),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            same_secret_binding
                .same_secret_proof_family_binding_root
                .as_str(),
        ),
        (
            "sameSecretProofRoot",
            same_secret_binding.same_secret_proof_root.as_str(),
        ),
    ] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!(
                    "evaluation-key share {field_name} must match the accepted trustee secret binding"
                ),
            ));
        }
    }

    Ok(())
}
