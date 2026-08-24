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

// The bounded-domain evaluator profile binding. The roster fixes the complete
// ten-ballot pair-character product and therefore its score-difference domain.
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
        "pairCharacterOutputLevel": crate::bgv::evaluator::top_k::CHARACTER_OUTPUT_LEVEL,
    }))
}

pub(super) fn evaluator_key_schedule_value() -> CanonicalResult<Value> {
    let required_galois_key_schedule = expected_required_galois_key_schedule()?;

    Ok(json!({
        "objectType": "EvaluatorKeySchedule",
        "relinearizationLevelSchedule": expected_relinearization_level_schedule(),
        "requiredGaloisKeySchedule": required_galois_key_schedule,
    }))
}

// One relinearization key per round at the highest multiplication level;
// lower levels reuse it through CRT-idempotent truncation.
pub(super) fn expected_relinearization_level_schedule() -> Value {
    Value::Array(vec![json!({
        "level": crate::bgv::evaluator::top_k::SELECTED_RELINEARIZATION_KEY_LEVEL,
    })])
}

pub(in crate::bgv::setup) fn expected_required_galois_key_schedule() -> CanonicalResult<Value> {
    Ok(Value::Array(
        crate::bgv::evaluator::top_k::selected_evaluator_rotation_key_schedule(
            MAXIMUM_OPTION_COUNT,
        )?
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
