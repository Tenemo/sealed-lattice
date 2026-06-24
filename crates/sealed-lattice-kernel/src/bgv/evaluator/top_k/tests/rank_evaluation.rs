use super::*;

#[test]
fn top_k_order_polynomial_masks_unselected_ranks() {
    let context = EvaluatorContext::new("top-k-order-value", 4).expect("context");
    let rank_values = [0_u64, 1, 2, 3, 4];
    let encrypted_ranks = context
        .key()
        .encrypt_slots(&rank_values, "rank-order")
        .expect("rank ciphertext");
    let order_values =
        top_k_order_value(&context, &encrypted_ranks, rank_values.len(), 2).expect("order");
    let decrypted = context
        .key()
        .decrypt_to_slots(&order_values)
        .expect("decrypt order");

    assert_eq!(&decrypted[..rank_values.len()], &[1, 2, 0, 0, 0]);
}

#[test]
fn sparse_target_projection_normalizes_full_target_to_canonical_level() {
    let context = EvaluatorContext::new(
        "sparse-target-canonical-full",
        CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1,
    )
    .expect("context");
    let packed_ranks = encrypted_packed_option_slots(&context, &[0, 1, 2, 3, 4], "full-ranks");
    let rank_evaluation = PackedRankEvaluation {
        packed_ranks,
        exact_rank_indicators: Vec::new(),
    };

    let target =
        project_packed_sparse_target_from_rank_evaluation(&context, &rank_evaluation, 5, 5)
            .expect("sparse target");

    validate_canonical_target_ciphertext(&target.target_id, "target id ciphertext")
        .expect("canonical target id");
    validate_canonical_target_ciphertext(&target.target_order, "target order ciphertext")
        .expect("canonical target order");
    assert_eq!(target.target_id.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);
    assert_eq!(target.target_order.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);
}

#[test]
fn sparse_target_projection_normalizes_exact_indicators_to_canonical_level() {
    let context = EvaluatorContext::new(
        "sparse-target-canonical-indicators",
        CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1,
    )
    .expect("context");
    let packed_ranks = encrypted_packed_option_slots(&context, &[0, 0, 0, 0, 0], "dummy-ranks");
    let first_rank_indicator =
        encrypted_packed_option_slots(&context, &[0, 1, 0, 0, 0], "first-rank-indicator");
    let second_rank_indicator =
        encrypted_packed_option_slots(&context, &[0, 0, 0, 1, 0], "second-rank-indicator");
    let rank_evaluation = PackedRankEvaluation {
        packed_ranks,
        exact_rank_indicators: vec![first_rank_indicator, second_rank_indicator],
    };

    let target =
        project_packed_sparse_target_from_rank_evaluation(&context, &rank_evaluation, 5, 2)
            .expect("sparse target");

    validate_canonical_target_ciphertext(&target.target_id, "target id ciphertext")
        .expect("canonical target id");
    validate_canonical_target_ciphertext(&target.target_order, "target order ciphertext")
        .expect("canonical target order");
    let target_id_slots = context
        .key()
        .decrypt_to_slots(&target.target_id)
        .expect("decrypt target ids");
    let target_order_slots = context
        .key()
        .decrypt_to_slots(&target.target_order)
        .expect("decrypt target orders");
    assert_eq!(target_id_slots[packed_score_slot(1)], 2);
    assert_eq!(target_order_slots[packed_score_slot(1)], 1);
    assert_eq!(target_id_slots[packed_score_slot(3)], 4);
    assert_eq!(target_order_slots[packed_score_slot(3)], 2);
    assert_eq!(target_id_slots[packed_score_slot(0)], 0);
    assert_eq!(target_order_slots[packed_score_slot(0)], 0);
}

fn encrypted_packed_option_slots(
    context: &EvaluatorContext,
    option_values: &[u64],
    seed: &str,
) -> Ciphertext {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    for (option, value) in option_values.iter().enumerate() {
        slots[packed_score_slot(option)] = *value;
    }
    let encrypted = context.key().encrypt_slots(&slots, seed).expect("encrypt");
    modulus_switch_to(&encrypted, CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1)
        .expect("working-level ciphertext")
}

// Manual consumed-schedule instrumentation: runs the real packing, batched-pair
// rank, and sparse-target pipeline at the selected working level and reports
// every relinearization level and (rotation, level) pair the evaluator
// requested, asserting the frozen key schedule covers all of them through
// truncation. This is the empirical evidence behind the consumed schedule.
// It is #[ignore]d because the full-pipeline replay at the working level is far
// too slow for the default lane; run it explicitly with --ignored. To
// instrument another level, add a wrapper that calls
// assert_consumed_schedule_within_frozen with that level.
//
//   cargo test -p sealed-lattice-kernel --release --lib \
//     consumed_key_schedule_instrumentation -- --ignored --nocapture
#[test]
#[ignore = "manual consumed key schedule instrumentation"]
fn consumed_key_schedule_instrumentation() {
    assert_consumed_schedule_within_frozen(SELECTED_EVALUATOR_WORKING_LEVEL);
}

// Runs the bounded-domain top-k pipeline at `working_level` and asserts every
// relinearization level and (rotation, level) pair the evaluator consumes is
// covered by the frozen key schedule through truncation.
fn assert_consumed_schedule_within_frozen(working_level: usize) {
    let option_count = 20_usize;
    // First-profile comparison domain: ten ballots with score span nine.
    let score_domain_max = 90_u64;
    let context =
        EvaluatorContext::new("consumed-schedule-instrumentation", working_level).expect("context");
    // Aggregate score slots inside the first-profile domain [10, 100].
    let aggregate_scores = (0..option_count)
        .map(|option| 10 + ((option * 7) % 91) as u64)
        .collect::<Vec<_>>();
    let aggregate = crate::bgv::evaluator::circuit::modulus_switch_to(
        &context
            .key()
            .encrypt_slots(&aggregate_scores, "consumed-schedule-aggregate")
            .expect("aggregate ciphertext"),
        working_level,
    )
    .expect("aggregate at working level");

    let packed = pack_direct_score_slots(&context, &aggregate, option_count, "consumed-schedule")
        .expect("score packing");
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed,
        option_count,
        score_domain_max,
        "consumed-schedule",
    )
    .expect("rank evaluation");
    for top_count in [1_usize, 10, 20] {
        project_packed_sparse_target_from_rank_evaluation(
            &context,
            &rank_evaluation,
            option_count,
            top_count,
        )
        .expect("sparse target");
    }

    let (consumed_relinearization_levels, consumed_rotations) = context.consumed_key_schedule();
    println!("consumed key schedule at working level {working_level}");
    println!("  relinearization levels: {consumed_relinearization_levels:?}");
    println!("  rotations: {consumed_rotations:?}");

    assert!(
        consumed_relinearization_levels
            .iter()
            .all(|level| *level <= SELECTED_EVALUATOR_WORKING_LEVEL),
        "every consumed relinearization level must be covered by the schedule key"
    );
    let schedule = selected_evaluator_rotation_key_schedule(option_count).expect("schedule");
    let mut schedule_level_by_rotation = std::collections::BTreeMap::new();
    for (rotation, level) in schedule {
        let entry = schedule_level_by_rotation.entry(rotation).or_insert(level);
        *entry = (*entry).max(level);
    }
    for (rotation, level) in &consumed_rotations {
        let schedule_level = schedule_level_by_rotation.get(rotation).unwrap_or_else(|| {
            panic!("rotation {rotation} consumed at level {level} is outside the frozen schedule")
        });
        assert!(
            schedule_level >= level,
            "rotation {rotation} consumed at level {level} above its schedule level {schedule_level}"
        );
    }
}
