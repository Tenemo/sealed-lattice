use super::*;

pub(in super::super) fn setup_parameters_hash_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&setup_parameters_value(roster)?)
}

// The single canonical identity for the roster-parameterized collective BGV
// setup parameter set. It binds the participant count, evaluator schedule, and
// canonical BGV parameters (including the exact ordered data-prime basis).
pub(super) fn setup_parameters_value(roster: &AcceptedRosterParameters) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupParameters",
        "participantCount": roster.participant_count,
        "bgvParametersHash": bgv_parameters_hash()?,
        "evaluatorKeySchedule": evaluator_key_schedule_value()?,
        "boundedDomainEvaluator": bounded_domain_evaluator_value_for_roster(roster)?,
    }))
}

// The bounded-domain evaluator profile binding: the score-difference domain the
// comparison polynomial is interpolated over is a deterministic function of the
// roster (score span times ballot count, ballots being full-roster), so binding
// it here makes the evaluator comparison domain part of the setup-parameter
// identity instead of an unbound runtime argument.
pub(super) fn bounded_domain_evaluator_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    let score_span =
        crate::bgv::direct_ballots::MAXIMUM_SCORE - crate::bgv::direct_ballots::MINIMUM_SCORE;
    let score_difference_bound = score_span
        .checked_mul(roster.participant_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "score-difference bound does not fit u64",
            )
        })?;
    Ok(json!({
        "objectType": "BoundedDomainEvaluatorParameters",
        "scoreDifferenceBound": score_difference_bound,
        "directComparisonOutputLevel": crate::bgv::evaluator::top_k::DIRECT_COMPARISON_OUTPUT_LEVEL,
        "tiePolicy": crate::bgv::evaluator::top_k::TIE_POLICY,
    }))
}

pub(super) fn evaluator_key_schedule_value() -> CanonicalResult<Value> {
    let required_galois_key_schedule = expected_required_galois_key_schedule()?;
    let required_galois_set_hash =
        expected_required_galois_set_hash(&required_galois_key_schedule)?;

    Ok(json!({
        "objectType": "EvaluatorKeySchedule",
        "relinearizationLevelSchedule": expected_relinearization_level_schedule(),
        "requiredGaloisKeySchedule": required_galois_key_schedule,
        "requiredGaloisSetHash": required_galois_set_hash,
    }))
}

// One relinearization key per round at the selected evaluator working level:
// lower levels reuse the same key through CRT-idempotent truncation, so the
// schedule carries no per-level entries.
pub(super) fn expected_relinearization_level_schedule() -> Value {
    Value::Array(vec![json!({
        "level": SELECTED_EVALUATOR_WORKING_LEVEL,
    })])
}

pub(super) fn expected_required_galois_key_schedule() -> CanonicalResult<Value> {
    let mut entries_by_rotation_and_level = BTreeSet::new();
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert((rotation, SELECTED_EVALUATOR_WORKING_LEVEL));
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert((rotation, SELECTED_EVALUATOR_WORKING_LEVEL));
    }
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert((rotation, SELECTED_EVALUATOR_WORKING_LEVEL));
    }

    Ok(Value::Array(
        entries_by_rotation_and_level
            .into_iter()
            .map(|(rotation, level)| {
                json!({
                    "rotation": rotation,
                    "level": level,
                })
            })
            .collect(),
    ))
}

pub(super) fn expected_required_galois_set_hash(
    required_galois_key_schedule: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&required_galois_set_value(
        required_galois_key_schedule.clone(),
    ))
}

pub(super) fn required_galois_set_value(required_galois_key_schedule: Value) -> Value {
    json!({
        "objectType": REQUIRED_GALOIS_SET_OBJECT_TYPE,
        "rnsLimbCount": DATA_PRIMES.len(),
        "entries": required_galois_key_schedule,
    })
}
