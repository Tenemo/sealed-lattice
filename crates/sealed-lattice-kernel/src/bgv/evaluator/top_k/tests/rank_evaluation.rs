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

// Gated consumed-schedule instrumentation: runs the real packing, batched-pair
// rank, and sparse-target pipeline at the selected working level and reports
// every relinearization level and (rotation, level) pair the evaluator
// requested, asserting the frozen key schedule covers all of them through
// truncation. This is the empirical evidence behind the consumed schedule.
//
//   SEALED_LATTICE_RUN_CONSUMED_SCHEDULE_INSTRUMENTATION=1 \
//   cargo test -p sealed-lattice-kernel --release --lib \
//     consumed_key_schedule_instrumentation -- --nocapture
#[test]
fn consumed_key_schedule_instrumentation() {
    if std::env::var("SEALED_LATTICE_RUN_CONSUMED_SCHEDULE_INSTRUMENTATION").is_err() {
        return;
    }
    let working_level = std::env::var("SEALED_LATTICE_CONSUMED_SCHEDULE_WORKING_LEVEL")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(SELECTED_EVALUATOR_WORKING_LEVEL);
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
