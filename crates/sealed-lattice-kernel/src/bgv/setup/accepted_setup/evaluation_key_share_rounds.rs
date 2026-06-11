use super::*;

pub(super) fn verify_relinearization_key_share_rounds(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
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
    if let Some(unexpected_field) = unexpected_relinearization_key_share_rounds_field(rounds) {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsUnexpectedField",
            format!("relinearizationKeyShareRounds contains unexpected field {unexpected_field}"),
            format!("setupPackage.relinearizationKeyShareRounds.{unexpected_field}"),
        )?));
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
            "setupContext was required before relinearization proof verification",
        )
    })?;
    if let Err(error) =
        verify_context_fields_match(rounds, setup_context, "relinearizationKeyShareRounds")
    {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsContextMismatch",
            error.message,
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "relinearization-key-share"),
        (
            "proofVerificationStatus",
            RELINEARIZATION_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", RELINEARIZATION_PROOF_MODEL_STATUS),
    ] {
        if rounds.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationKeyShareRoundsProfileMismatch",
                format!("relinearizationKeyShareRounds.{field_name} must be {expected_value}"),
                format!("setupPackage.relinearizationKeyShareRounds.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
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
            "publicKeyShareLnpProofSetRoot",
            binding.public_key_share_lnp_proof_set_root.as_str(),
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
    let expected_levels = expected_relinearization_levels();
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
    let same_secret_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let proof_context = EvaluationKeyProofVerificationContext {
        setup_package,
        request,
        same_secret_proof_bindings: &same_secret_proof_bindings,
        same_secret_records: &same_secret_records,
        transported_constant_commitments: &transported_constant_commitments,
        transported_key_switch_component_material: request
            .get("transportedEvaluationKeyShareComponentMaterial")
            .or(transported_key_switch_component_material.as_ref()),
    };
    let round_one_records = array_value(rounds, "roundOneRecords")?;
    let round_two_records = array_value(rounds, "roundTwoRecords")?;
    let expected_record_count = expected_levels.len() * FIRST_PROFILE_PARTICIPANT_COUNT as usize;
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
    let mut round_one_source_square_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut round_one_record_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_share_roots = BTreeMap::<(u64, u64), String>::new();
    let mut round_one_source_square_binding_roots = BTreeMap::<(u64, u64), String>::new();
    for record in round_one_records {
        let (level, trustee_roster_position, record_root, share_root, source_square_binding_root) =
            match verify_relinearization_round_one_record(record, &binding, &proof_context) {
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
        round_one_source_square_binding_roots.insert(
            (level, trustee_roster_position),
            source_square_binding_root.clone(),
        );
        let trustee_identity = same_secret_proof_bindings
            .get(&trustee_roster_position)
            .expect("same-secret proof binding exists after record verification")
            .trustee_identity
            .clone();
        round_one_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity.clone(),
                "trusteeRosterPosition": trustee_roster_position,
                "roundOneRecordRoot": record_root,
            }));
        round_one_source_square_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "sourceSquareBindingRoot": source_square_binding_root,
            }));
    }

    let supplied_round_one_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundOneAggregateRoots",
        "roundOneAggregateRoot",
    )?;
    let supplied_round_one_source_square_aggregate_roots =
        relinearization_aggregate_roots_by_level(
            rounds,
            "roundOneAggregateRoots",
            "roundOneSourceSquareAggregateRoot",
        )?;
    for level in &expected_levels {
        let Some(record_roots) = round_one_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneLevelMissing",
                "relinearization round-one records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        };
        let Some(source_square_roots) = round_one_source_square_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneSourceSquareLevelMissing",
                "relinearization round-one records must cover source-square roots for every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundOneRecords",
            )?));
        };
        let expected_source_square_aggregate_root = relinearization_source_square_aggregate_root(
            "round-one",
            binding.evaluator_key_schedule_root.as_str(),
            *level,
            source_square_roots,
            None,
        )?;
        if supplied_round_one_source_square_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_source_square_aggregate_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundOneSourceSquareAggregateRootMismatch",
                "relinearization round-one source-square aggregate root must be derived from the ordered round-one source-square bindings",
                "setupPackage.relinearizationKeyShareRounds.roundOneAggregateRoots",
            )?));
        }
        let expected_root = derive_protocol_hash(
            "RelinearizationRoundOneAggregateRoot",
            &json!({
                "objectType": "RelinearizationRoundOneAggregate",
                "objectVersion": 1,
                "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                "level": level,
                "roundOneSourceSquareAggregateRoot": expected_source_square_aggregate_root,
                "roundOneRecordRoots": record_roots,
            }),
        )?;
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
    let mut round_two_source_square_roots_by_level = BTreeMap::<u64, Vec<Value>>::new();
    let mut seen_round_two_records = BTreeSet::new();
    let round_one_state = RelinearizationRoundOneVerificationState {
        record_roots: &round_one_record_roots,
        share_roots: &round_one_share_roots,
        source_square_binding_roots: &round_one_source_square_binding_roots,
        aggregate_roots: &supplied_round_one_aggregate_roots,
        source_square_aggregate_roots: &supplied_round_one_source_square_aggregate_roots,
    };
    for record in round_two_records {
        let (level, trustee_roster_position, record_root, source_square_binding_root) =
            match verify_relinearization_round_two_record(
                record,
                &binding,
                &proof_context,
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
                "trusteeIdentity": trustee_identity.clone(),
                "trusteeRosterPosition": trustee_roster_position,
                "roundTwoRecordRoot": record_root,
            }));
        round_two_source_square_roots_by_level
            .entry(level)
            .or_default()
            .push(json!({
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "sourceSquareBindingRoot": source_square_binding_root,
            }));
    }
    let supplied_round_two_aggregate_roots = relinearization_aggregate_roots_by_level(
        rounds,
        "roundTwoAggregateRoots",
        "roundTwoAggregateRoot",
    )?;
    let supplied_round_two_source_square_aggregate_roots =
        relinearization_aggregate_roots_by_level(
            rounds,
            "roundTwoAggregateRoots",
            "roundTwoSourceSquareAggregateRoot",
        )?;
    for level in &expected_levels {
        let Some(record_roots) = round_two_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoLevelMissing",
                "relinearization round-two records must cover every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        };
        let Some(source_square_roots) = round_two_source_square_roots_by_level.get(level) else {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoSourceSquareLevelMissing",
                "relinearization round-two records must cover source-square roots for every scheduled level",
                "setupPackage.relinearizationKeyShareRounds.roundTwoRecords",
            )?));
        };
        let round_one_source_square_aggregate_root = supplied_round_one_source_square_aggregate_roots
            .get(level)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "round-one source-square aggregate root was required before round-two verification",
                )
            })?;
        let expected_source_square_aggregate_root = relinearization_source_square_aggregate_root(
            "round-two",
            binding.evaluator_key_schedule_root.as_str(),
            *level,
            source_square_roots,
            Some(round_one_source_square_aggregate_root),
        )?;
        if supplied_round_two_source_square_aggregate_roots
            .get(level)
            .map(String::as_str)
            != Some(expected_source_square_aggregate_root.as_str())
        {
            return Ok(Some(evaluation_key_material_refusal(
                "relinearizationRoundTwoSourceSquareAggregateRootMismatch",
                "relinearization round-two source-square aggregate root must bind the ordered round-two bindings and the round-one source-square aggregate root",
                "setupPackage.relinearizationKeyShareRounds.roundTwoAggregateRoots",
            )?));
        }
        let expected_root = derive_protocol_hash(
            "RelinearizationRoundTwoAggregateRoot",
            &json!({
                "objectType": "RelinearizationRoundTwoAggregate",
                "objectVersion": 1,
                "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
                "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
                "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
                "level": level,
                "roundOneAggregateRoot": supplied_round_one_aggregate_roots
                    .get(level)
                    .expect("round-one aggregate root exists after verification"),
                "roundOneSourceSquareAggregateRoot": round_one_source_square_aggregate_root,
                "roundTwoSourceSquareAggregateRoot": expected_source_square_aggregate_root,
                "roundTwoRecordRoots": record_roots,
            }),
        )?;
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

    let supplied_root = value_string(rounds, "relinearizationKeyShareRoundsRoot")?;
    let mut root_input = rounds.clone();
    root_input
        .as_object_mut()
        .expect("relinearization rounds object was checked")
        .remove("relinearizationKeyShareRoundsRoot");
    let expected_root = derive_protocol_hash("RelinearizationKeyShareRoundsRoot", &root_input)?;
    if supplied_root != expected_root {
        return Ok(Some(evaluation_key_material_refusal(
            "relinearizationKeyShareRoundsRootMismatch",
            "relinearizationKeyShareRoundsRoot does not match the canonical relinearization proof container",
            "setupPackage.relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot",
        )?));
    }

    Ok(None)
}

pub(super) fn verify_galois_key_share_batches(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(batches) = setup_package.get("galoisKeyShareBatches") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("galoisKeyBatchProofs"),
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
    if batches.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(evaluation_key_material_refusal(
            "galoisKeyShareBatchCountMismatch",
            "galoisKeyShareBatches must contain one batch per trustee",
            "setupPackage.galoisKeyShareBatches",
        )?));
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let same_secret_proof_bindings = same_secret_proof_bindings_from_package(setup_package)?;
    let same_secret_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let proof_context = EvaluationKeyProofVerificationContext {
        setup_package,
        request,
        same_secret_proof_bindings: &same_secret_proof_bindings,
        same_secret_records: &same_secret_records,
        transported_constant_commitments: &transported_constant_commitments,
        transported_key_switch_component_material: request
            .get("transportedEvaluationKeyShareComponentMaterial")
            .or(transported_key_switch_component_material.as_ref()),
    };
    let expected_schedule = expected_required_galois_key_schedule()?;
    let mut seen_roster_positions = BTreeSet::new();
    for batch in batches {
        if let Err(error) = verify_galois_key_share_batch(
            batch,
            &binding,
            &proof_context,
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

pub(super) fn galois_key_share_proof_for_schedule(
    batch: &Value,
    rotation: u64,
    level: u64,
) -> CanonicalResult<&Value> {
    array_value(batch, "galoisKeyShareProofs")?
        .iter()
        .find(|proof| {
            proof.get("rotation").and_then(Value::as_u64) == Some(rotation)
                && proof.get("level").and_then(Value::as_u64) == Some(level)
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batch does not contain a required scheduled proof",
            )
        })
}

pub(super) struct EvaluationKeyProofCommonBinding {
    pub(super) evaluator_key_schedule_root: String,
    same_secret_consistency_root: String,
    same_secret_proof_set_root: String,
    pub(super) same_secret_proof_family_binding_root: String,
    public_key_share_set_root: String,
    pub(super) public_key_share_lnp_proof_set_root: String,
    relinearization_crp_root: String,
    pub(super) galois_key_crp_root: String,
    pub(super) required_galois_set_hash: String,
}

pub(super) struct EvaluationKeyProofVerificationContext<'a> {
    pub(super) setup_package: &'a Value,
    pub(super) request: &'a Value,
    same_secret_proof_bindings: &'a BTreeMap<u64, SameSecretProofBinding>,
    pub(super) same_secret_records: &'a BTreeMap<u64, Value>,
    pub(super) transported_constant_commitments:
        &'a BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
    pub(super) transported_key_switch_component_material: Option<&'a Value>,
}

struct RelinearizationRoundOneVerificationState<'a> {
    record_roots: &'a BTreeMap<(u64, u64), String>,
    share_roots: &'a BTreeMap<(u64, u64), String>,
    source_square_binding_roots: &'a BTreeMap<(u64, u64), String>,
    aggregate_roots: &'a BTreeMap<u64, String>,
    source_square_aggregate_roots: &'a BTreeMap<u64, String>,
}

pub(super) fn evaluation_key_proof_common_binding(
    setup_package: &Value,
) -> CanonicalResult<EvaluationKeyProofCommonBinding> {
    let evaluator_key_schedule = setup_package.get("evaluatorKeySchedule").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluatorKeySchedule was required before evaluation-key proof verification",
        )
    })?;
    let public_derivations = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicDerivations"))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicDerivations was required before evaluation-key proof verification",
            )
        })?;
    let crp_roots = public_derivations.get("crpRoots").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations.crpRoots was required before evaluation-key proof verification",
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
                    "publicKeyShareSetRoot was required before evaluation-key proof verification",
                )
            })?
            .to_string(),
        public_key_share_lnp_proof_set_root: setup_package
            .get("publicKeyShareLnpProofs")
            .and_then(|proof_set| proof_set.get("publicKeyShareLnpProofSetRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShareLnpProofSetRoot was required before evaluation-key proof verification",
                )
            })?
            .to_string(),
        relinearization_crp_root: value_string(crp_roots, "relinearizationCrpRoot")?.to_string(),
        galois_key_crp_root: value_string(crp_roots, "galoisKeyCrpRoot")?.to_string(),
        required_galois_set_hash: value_string(evaluator_key_schedule, "requiredGaloisSetHash")?
            .to_string(),
    })
}

pub(super) fn expected_relinearization_levels() -> Vec<u64> {
    (1..DATA_PRIMES.len()).map(|level| level as u64).collect()
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

pub(super) fn expected_relinearization_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "RelinearizationKeyShareSeed",
        &json!({
            "objectType": "RelinearizationKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "relinearization-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-level-and-round",
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "relinearizationCrpRoot": binding.relinearization_crp_root.as_str(),
            "round": round,
            "level": level,
        }),
    )
}

pub(super) fn expected_galois_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "GaloisKeyShareSeed",
        &json!({
            "objectType": "GaloisKeySwitchPublicSampleSeed",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "galois-key-share",
            "keySwitchSampleScope": "shared-by-scheduled-rotation-and-level",
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "galoisKeyCrpRoot": binding.galois_key_crp_root.as_str(),
            "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
            "rotation": rotation,
            "level": level,
        }),
    )
}

pub(super) fn verify_relinearization_key_switch_sample_binding(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<()> {
    if value_string(record, "keySwitchDomain")? != "relinearization" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization key-switch domain must be shared relinearization material",
        ));
    }
    let expected_seed = expected_relinearization_key_switch_seed(binding, round, level)?;
    if value_string(record, "keySwitchSeedHex")? != expected_seed {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
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
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key-switch domain must match the scheduled rotation",
        ));
    }
    let expected_seed = expected_galois_key_switch_seed(binding, rotation, level)?;
    if value_string(record, "keySwitchSeedHex")? != expected_seed {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key-switch seed must be shared by scheduled rotation and level",
        ));
    }

    Ok(())
}

fn verify_relinearization_round_one_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
) -> CanonicalResult<(u64, u64, String, String, String)> {
    verify_evaluation_key_record_object(
        record,
        RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE,
        "relinearization-key-share",
        RELINEARIZATION_PROOF_VERIFICATION_STATUS,
        RELINEARIZATION_PROOF_MODEL_STATUS,
    )?;
    if let Some(unexpected_field) = unexpected_relinearization_round_one_record_field(record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "relinearization round-one record contains unexpected field {unexpected_field}"
            ),
        ));
    }
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_common_bindings(
        record,
        binding,
        proof_context.same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    verify_relinearization_key_switch_sample_binding(record, binding, "round-one", level)?;
    let round_one_share_root = value_string(record, "roundOneShareRoot")?;
    validate_hash_string(round_one_share_root, "roundOneShareRoot")?;
    let source_square_binding_root = value_string(record, "sourceSquareBindingRoot")?;
    validate_hash_string(source_square_binding_root, "sourceSquareBindingRoot")?;
    let round_one_proof_root = value_string(record, "roundOneProofRoot")?;
    validate_hash_string(round_one_proof_root, "roundOneProofRoot")?;
    verify_relinearization_key_share_lnp_proof_record(
        record,
        proof_context,
        "roundOneProofRoot",
        round_one_proof_root,
    )?;
    let expected_source_square_binding_root =
        relinearization_source_square_binding_root(record, "round-one", round_one_share_root)?;
    if source_square_binding_root != expected_source_square_binding_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sourceSquareBindingRoot does not match the canonical relinearization source-square binding",
        ));
    }
    let supplied_root = value_string(record, "roundOneRecordRoot")?;
    let mut root_input = record.clone();
    root_input
        .as_object_mut()
        .expect("relinearization round-one record object was checked")
        .remove("roundOneRecordRoot");
    let expected_root = derive_protocol_hash("RelinearizationRoundOneRecordRoot", &root_input)?;
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
        source_square_binding_root.to_string(),
    ))
}

fn verify_relinearization_round_two_record(
    record: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
    round_one_state: &RelinearizationRoundOneVerificationState<'_>,
) -> CanonicalResult<(u64, u64, String, String)> {
    verify_evaluation_key_record_object(
        record,
        RELINEARIZATION_KEY_SHARE_ROUND_TWO_OBJECT_TYPE,
        "relinearization-key-share",
        RELINEARIZATION_PROOF_VERIFICATION_STATUS,
        RELINEARIZATION_PROOF_MODEL_STATUS,
    )?;
    if let Some(unexpected_field) = unexpected_relinearization_round_two_record_field(record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "relinearization round-two record contains unexpected field {unexpected_field}"
            ),
        ));
    }
    let level = value_u64(record, "level")?;
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    verify_evaluation_key_record_common_bindings(
        record,
        binding,
        proof_context.same_secret_proof_bindings,
        trustee_roster_position,
        "relinearizationCrpRoot",
        binding.relinearization_crp_root.as_str(),
    )?;
    verify_relinearization_key_switch_sample_binding(record, binding, "round-two", level)?;
    for field_name in [
        "roundOneShareRoot",
        "roundOneRecordRoot",
        "roundOneAggregateRoot",
        "roundOneSourceSquareBindingRoot",
        "roundOneSourceSquareAggregateRoot",
        "roundTwoShareRoot",
        "sourceSquareBindingRoot",
        "roundTwoProofRoot",
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
        || round_one_state
            .source_square_binding_roots
            .get(&key)
            .map(String::as_str)
            != Some(value_string(record, "roundOneSourceSquareBindingRoot")?)
        || round_one_state
            .source_square_aggregate_roots
            .get(&level)
            .map(String::as_str)
            != Some(value_string(record, "roundOneSourceSquareAggregateRoot")?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization round-two record must bind the accepted round-one record, share, aggregate, and source-square roots",
        ));
    }
    let round_two_proof_root = value_string(record, "roundTwoProofRoot")?;
    verify_relinearization_key_share_lnp_proof_record(
        record,
        proof_context,
        "roundTwoProofRoot",
        round_two_proof_root,
    )?;
    let source_square_binding_root = value_string(record, "sourceSquareBindingRoot")?;
    let expected_source_square_binding_root = relinearization_source_square_binding_root(
        record,
        "round-two",
        value_string(record, "roundTwoShareRoot")?,
    )?;
    if source_square_binding_root != expected_source_square_binding_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sourceSquareBindingRoot does not match the canonical relinearization source-square binding",
        ));
    }
    let supplied_root = value_string(record, "roundTwoRecordRoot")?;
    let mut root_input = record.clone();
    root_input
        .as_object_mut()
        .expect("relinearization round-two record object was checked")
        .remove("roundTwoRecordRoot");
    let expected_root = derive_protocol_hash("RelinearizationRoundTwoRecordRoot", &root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "roundTwoRecordRoot does not match the canonical relinearization round-two record",
        ));
    }

    Ok((
        level,
        trustee_roster_position,
        supplied_root.to_string(),
        source_square_binding_root.to_string(),
    ))
}

fn verify_galois_key_share_batch(
    batch: &Value,
    binding: &EvaluationKeyProofCommonBinding,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
    expected_schedule: &Value,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    verify_evaluation_key_record_object(
        batch,
        GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE,
        "galois-key-share",
        GALOIS_PROOF_VERIFICATION_STATUS,
        GALOIS_PROOF_MODEL_STATUS,
    )?;
    if let Some(unexpected_field) = unexpected_galois_key_share_batch_field(batch) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("Galois key share batch contains unexpected field {unexpected_field}"),
        ));
    }
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
        proof_context.same_secret_proof_bindings,
        trustee_roster_position,
        "galoisKeyCrpRoot",
        binding.galois_key_crp_root.as_str(),
    )?;
    if batch.get("requiredGaloisSetHash").and_then(Value::as_str)
        != Some(binding.required_galois_set_hash.as_str())
        || batch.get("requiredGaloisKeySchedule") != Some(expected_schedule)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key share batch must bind the exact frozen RequiredGaloisSetHash and schedule",
        ));
    }
    let key_roots = array_value(batch, "galoisKeyShareRoots")?;
    let expected_entries = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "expected Galois key schedule must be an array",
        )
    })?;
    if key_roots.len() != expected_entries.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "Galois key share batch must contain one share root per required schedule entry",
        ));
    }
    for (root_entry, expected_entry) in key_roots.iter().zip(expected_entries) {
        if root_entry.get("rotation") != expected_entry.get("rotation")
            || root_entry.get("level") != expected_entry.get("level")
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "Galois key share roots must follow the frozen Galois key schedule order",
            ));
        }
        validate_hash_string(
            value_string(root_entry, "galoisKeyShareRoot")?,
            "galoisKeyShareRoot",
        )?;
    }
    let proof_records = array_value(batch, "galoisKeyShareProofs")?;
    if proof_records.len() != expected_entries.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "Galois key share batch must contain one proof record per required schedule entry",
        ));
    }
    let mut proof_roots = Vec::new();
    for ((proof_record, root_entry), expected_entry) in proof_records
        .iter()
        .zip(key_roots.iter())
        .zip(expected_entries)
    {
        let rotation = value_u64(expected_entry, "rotation")?;
        let level = value_u64(expected_entry, "level")?;
        verify_galois_key_switch_sample_binding(proof_record, binding, rotation, level)?;
        let proof_root = verify_galois_key_share_lnp_proof_record(
            proof_record,
            batch,
            proof_context,
            root_entry,
            expected_entry,
        )?;
        proof_roots.push(json!({
            "rotation": value_u64(proof_record, "rotation")?,
            "level": value_u64(proof_record, "level")?,
            "galoisKeyShareProofRoot": proof_root,
        }));
    }
    let supplied_batch_proof_root = value_string(batch, "galoisKeyBatchProofRoot")?;
    let expected_batch_proof_root = derive_protocol_hash(
        "GaloisKeyBatchProofRoot",
        &json!({
            "objectType": "GaloisKeyBatchProofAggregate",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "galois-key-share",
            "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
            "requiredGaloisSetHash": binding.required_galois_set_hash.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "proofRoots": proof_roots,
        }),
    )?;
    if supplied_batch_proof_root != expected_batch_proof_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "galoisKeyBatchProofRoot must be derived from the verified Galois proof records",
        ));
    }
    let supplied_root = value_string(batch, "galoisKeyShareBatchRoot")?;
    let mut root_input = batch.clone();
    root_input
        .as_object_mut()
        .expect("Galois key share batch object was checked")
        .remove("galoisKeyShareBatchRoot");
    let expected_root = derive_protocol_hash("GaloisKeyShareBatchRoot", &root_input)?;
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "galoisKeyShareBatchRoot does not match the canonical Galois key share batch",
        ));
    }

    Ok(())
}

fn verify_evaluation_key_record_object(
    record: &Value,
    expected_object_type: &str,
    expected_proof_family: &str,
    expected_proof_verification_status: &str,
    expected_proof_model_status: &str,
) -> CanonicalResult<()> {
    if !record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key proof record must be an object",
        ));
    }
    if record.get("objectType").and_then(Value::as_str) != Some(expected_object_type) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("evaluation-key proof objectType must be {expected_object_type}"),
        ));
    }
    if record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key proof objectVersion must be 1",
        ));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", expected_proof_family),
        (
            "proofVerificationStatus",
            expected_proof_verification_status,
        ),
        ("proofModelStatus", expected_proof_model_status),
    ] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("evaluation-key proof {field_name} must be {expected_value}"),
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
            "publicKeyShareLnpProofSetRoot",
            binding.public_key_share_lnp_proof_set_root.as_str(),
        ),
        (crp_root_field_name, expected_crp_root),
    ] {
        if record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("evaluation-key proof {field_name} must match the accepted setup binding"),
            ));
        }
    }
    let Some(same_secret_binding) = same_secret_proof_bindings.get(&trustee_roster_position) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation-key proof trusteeRosterPosition must reference an accepted same-secret proof",
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
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "evaluation-key proof {field_name} must match the accepted trustee secret binding"
                ),
            ));
        }
    }

    Ok(())
}

fn unexpected_relinearization_key_share_rounds_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareLnpProofSetRoot",
            "relinearizationCrpRoot",
            "relinearizationLevelSchedule",
            "roundOneAggregateRoots",
            "roundOneRecords",
            "roundTwoAggregateRoots",
            "roundTwoRecords",
            "relinearizationKeyShareRoundsRoot",
        ],
    )
}

fn unexpected_relinearization_round_one_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
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
            "level",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofRoot",
            "relinearizationCrpRoot",
            "roundOneShareRoot",
            "sourceSquareBindingRoot",
            "roundOneProofRoot",
            "proofProfileId",
            "setupProofBinding",
            "keySwitchMaterialEncoding",
            "keySwitchDomain",
            "keySwitchSeedHex",
            "ringDegree",
            "keySwitchComponentVectorRoot",
            "keySwitchComponentVectors",
            "keySwitchComponentMaterialRoot",
            "keySwitchComponentChunkSizeBytes",
            "keySwitchComponentChunkCount",
            "keySwitchComponentTotalByteLength",
            "keySwitchComponentFullObjectHash",
            "keySwitchComponentChunkRoot",
            "keySwitchComponentChunkHashes",
            "relinearizationKeyShareTboxParameterProfileHash",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesHex",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "roundOneRecordRoot",
        ],
    )
}

fn unexpected_relinearization_round_two_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
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
            "level",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofRoot",
            "relinearizationCrpRoot",
            "roundOneShareRoot",
            "roundOneRecordRoot",
            "roundOneAggregateRoot",
            "roundOneSourceSquareBindingRoot",
            "roundOneSourceSquareAggregateRoot",
            "roundTwoShareRoot",
            "sourceSquareBindingRoot",
            "roundTwoProofRoot",
            "proofProfileId",
            "setupProofBinding",
            "keySwitchMaterialEncoding",
            "keySwitchDomain",
            "keySwitchSeedHex",
            "ringDegree",
            "keySwitchComponentVectorRoot",
            "keySwitchComponentVectors",
            "keySwitchComponentMaterialRoot",
            "keySwitchComponentChunkSizeBytes",
            "keySwitchComponentChunkCount",
            "keySwitchComponentTotalByteLength",
            "keySwitchComponentFullObjectHash",
            "keySwitchComponentChunkRoot",
            "keySwitchComponentChunkHashes",
            "relinearizationKeyShareTboxParameterProfileHash",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesHex",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "roundTwoRecordRoot",
        ],
    )
}

fn unexpected_galois_key_share_batch_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
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
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofRoot",
            "galoisKeyCrpRoot",
            "requiredGaloisSetHash",
            "requiredGaloisKeySchedule",
            "galoisKeyShareRoots",
            "galoisKeyShareProofs",
            "galoisKeyBatchProofRoot",
            "galoisKeyShareBatchRoot",
        ],
    )
}
