use super::*;

pub(super) fn selected_relinearization_levels() -> CanonicalResult<Vec<usize>> {
    if DIRECT_COMPARISON_OUTPUT_LEVEL >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct comparison output level must fit the selected data basis",
        ));
    }

    Ok((1..DATA_PRIMES.len()).collect())
}

pub(super) fn selected_rotation_schedule_entries() -> CanonicalResult<Vec<RotationScheduleEntry>> {
    let mut entries_by_rotation_and_level = BTreeMap::new();
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, DATA_PRIMES.len() - 1),
            "direct-score-packing-generator-basis",
        );
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level
            .entry((rotation, DATA_PRIMES.len() - 1))
            .or_insert("generator-ordered-packed-rank-forward-basis");
    }
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, DIRECT_COMPARISON_OUTPUT_LEVEL),
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
        "rotSetId": SELECTED_ROT_SET_ID,
        "generatedFor": "direct-score-packing-compact-generator-basis-direct-encrypted-score-comparison-generator-ordered-rank-packing",
        "finalizedBy": "encrypted-aggregate-evaluator-closure",
        "regeneratePassiveSetupKeysIfChanged": true,
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
