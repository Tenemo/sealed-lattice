use super::*;

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
    let mut entries_by_rotation_and_level = BTreeMap::new();
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, SELECTED_EVALUATOR_WORKING_LEVEL),
            "direct-score-packing-generator-basis",
        );
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level
            .entry((rotation, SELECTED_EVALUATOR_WORKING_LEVEL))
            .or_insert("generator-ordered-packed-rank-forward-basis");
    }
    // Inverse-basis rotations run at the working level and at the comparison
    // output level; one key at the working level serves both via truncation.
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, SELECTED_EVALUATOR_WORKING_LEVEL),
            "generator-ordered-packed-rank-return-basis",
        );
    }

    Ok(entries_by_rotation_and_level
        .into_iter()
        .map(|((rotation, level), purpose)| RotationScheduleEntry {
            rotation,
            level,
            purpose,
        })
        .collect())
}

pub(super) fn total_digit_count(levels: &[usize]) -> usize {
    levels.iter().map(|level| level + 1).sum()
}

pub(super) fn selected_rotation_set() -> CanonicalResult<Value> {
    let direct_score_packing_rotations =
        direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)?
            .into_iter()
            .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
            .collect::<Vec<_>>();
    let packed_rank_forward_rotations =
        packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)?
            .into_iter()
            .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
            .collect::<Vec<_>>();
    let packed_rank_return_rotations =
        packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)?
            .into_iter()
            .map(|rotation| i64::try_from(rotation).expect("Galois element fits i64"))
            .collect::<Vec<_>>();
    let rotations = direct_score_packing_rotations
        .iter()
        .chain(packed_rank_forward_rotations.iter())
        .chain(packed_rank_return_rotations.iter())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(json!({
        "objectType": "BgvRotationSet",
        "generatedFor": "direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing",
        "finalizedBy": "encrypted-aggregate-evaluator-closure",
        "rotations": rotations.clone(),
        "dependencies": [
            "direct-encrypted-ballot-aggregation",
            "direct-score-packing",
            "direct-encrypted-score-comparison",
            "generator-ordered-packed-rank-accumulation",
            "encrypted-sparse-target-projection"
        ],
        "requiredRotationGroups": [
            {
                "purpose": "direct-score-packing-generator-basis",
                "rotations": direct_score_packing_rotations
            },
            {
                "purpose": "generator-ordered-packed-rank-forward-basis",
                "rotations": packed_rank_forward_rotations
            },
            {
                "purpose": "generator-ordered-packed-rank-return-basis",
                "rotations": packed_rank_return_rotations
            }
        ],
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
