use super::*;
use std::collections::BTreeSet;

// The consumed relinearization schedule: one key at the selected evaluator
// working level. Every lower level the evaluator reaches uses the same key
// through CRT-idempotent truncation, so no per-level keys are generated,
// published, or proven.
pub(super) fn selected_relinearization_levels() -> CanonicalResult<Vec<usize>> {
    if SELECTED_EVALUATOR_WORKING_LEVEL >= DATA_PRIMES.len()
        || DIRECT_COMPARISON_OUTPUT_LEVEL > SELECTED_EVALUATOR_WORKING_LEVEL
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "selected evaluator schedule levels must fit the data basis",
        ));
    }

    Ok(vec![SELECTED_EVALUATOR_WORKING_LEVEL])
}

pub(super) fn selected_rotation_schedule_entries() -> CanonicalResult<Vec<RotationScheduleEntry>> {
    let mut entries_by_rotation_and_level = BTreeSet::new();
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert((rotation, SELECTED_EVALUATOR_WORKING_LEVEL));
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert((rotation, SELECTED_EVALUATOR_WORKING_LEVEL));
    }
    // Inverse-basis rotations run at the working level and at the comparison
    // output level; one key at the working level serves both via truncation.
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert((rotation, SELECTED_EVALUATOR_WORKING_LEVEL));
    }

    Ok(entries_by_rotation_and_level
        .into_iter()
        .map(|(rotation, level)| RotationScheduleEntry { rotation, level })
        .collect())
}

pub(super) fn selected_rotation_set() -> CanonicalResult<Value> {
    let rotations = selected_rotation_schedule_entries()?
        .into_iter()
        .map(|entry| i64::try_from(entry.rotation).expect("Galois element fits i64"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(json!({
        "objectType": "BgvRotationSet",
        "rotations": rotations,
    }))
}

pub(in crate::bgv::setup) fn evaluation_key_stream_seed(
    setup_seed_hash: &str,
    key_kind: &str,
    level: usize,
    rotation: Option<usize>,
) -> String {
    let level_text = level.to_string();
    let rotation_text = rotation
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string());

    hash512_hex(
        "sealed-lattice-bgv-rns/evaluation-key-stream-seed",
        &[
            setup_seed_hash.as_bytes(),
            key_kind.as_bytes(),
            level_text.as_bytes(),
            rotation_text.as_bytes(),
        ],
    )
}

pub(super) fn evaluation_key_stream_hash(
    stream_label: &str,
    stream_record: &Value,
) -> CanonicalResult<String> {
    let canonical_stream_record = canonical_json(stream_record)?;

    Ok(hash512_hex(
        "sealed-lattice-bgv-rns/evaluation-key-stream-hash",
        &[stream_label.as_bytes(), canonical_stream_record.as_bytes()],
    ))
}
