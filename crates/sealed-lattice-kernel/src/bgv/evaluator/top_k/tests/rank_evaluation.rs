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
fn packed_rank_evaluation_decrypts_expected_ranks_and_tie_policy() {
    let context = EvaluatorContext::new(
        "packed-rank-evaluation-decrypts-expected-ranks",
        SELECTED_EVALUATOR_WORKING_LEVEL,
    )
    .expect("context");
    let score_domain_max = 2;
    let score_values = [0_u64, 2, 2];
    let expected_rank_values = [2_u64, 0, 1];
    let encrypted_scores = context
        .key()
        .encrypt_slots(&score_values, "boundary-tie-scores")
        .expect("score ciphertext");
    let packed_scores = pack_direct_score_slots(
        &context,
        &encrypted_scores,
        score_values.len(),
        "boundary-tie-pack",
    )
    .expect("packed scores");
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        score_values.len(),
        score_domain_max,
        "boundary-tie-rank",
    )
    .expect("rank evaluation");
    let decrypted_slots = context
        .key()
        .decrypt_to_slots(&rank_evaluation.packed_ranks)
        .expect("rank slots");
    let decrypted_rank_values = (0..score_values.len())
        .map(|logical_index| decrypted_slots[packed_score_slot(logical_index)])
        .collect::<Vec<_>>();

    assert_eq!(
        decrypted_rank_values, expected_rank_values,
        "packed ranks should follow higher-score-first and lower-index tie ordering"
    );
}

#[test]
fn sparse_target_projection_decrypts_selected_ids_and_orders() {
    let context = EvaluatorContext::new(
        "sparse-target-projection-decrypts-selected-values",
        SELECTED_EVALUATOR_WORKING_LEVEL,
    )
    .expect("context");
    let score_domain_max = 2;
    let top_count = 2;
    let score_values = [0_u64, 2, 2, 1];
    let expected_target_ids = [0_u64, 2, 3, 0];
    let expected_target_orders = [0_u64, 1, 2, 0];
    let encrypted_scores = context
        .key()
        .encrypt_slots(&score_values, "sparse-target-scores")
        .expect("score ciphertext");
    let packed_scores = pack_direct_score_slots(
        &context,
        &encrypted_scores,
        score_values.len(),
        "sparse-target-pack",
    )
    .expect("packed scores");
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        score_values.len(),
        score_domain_max,
        "sparse-target-rank",
    )
    .expect("rank evaluation");
    let sparse_target = project_packed_sparse_target_from_rank_evaluation(
        &context,
        &rank_evaluation,
        score_values.len(),
        top_count,
    )
    .expect("sparse target");
    let decrypted_target_id_slots = context
        .key()
        .decrypt_to_slots(&sparse_target.target_id)
        .expect("target id slots");
    let decrypted_target_order_slots = context
        .key()
        .decrypt_to_slots(&sparse_target.target_order)
        .expect("target order slots");
    let decrypted_target_ids = (0..score_values.len())
        .map(|logical_index| decrypted_target_id_slots[packed_score_slot(logical_index)])
        .collect::<Vec<_>>();
    let decrypted_target_orders = (0..score_values.len())
        .map(|logical_index| decrypted_target_order_slots[packed_score_slot(logical_index)])
        .collect::<Vec<_>>();

    assert_eq!(
        decrypted_target_ids, expected_target_ids,
        "sparse target should keep only selected option identifiers"
    );
    assert_eq!(
        decrypted_target_orders, expected_target_orders,
        "sparse target should encode one-based rank order for selected options"
    );
}

#[test]
fn packed_rank_plain_reference_covers_strict_ties_and_boundaries() {
    let cases = [
        ("strict order", vec![2_u64, 1, 0], vec![0_u64, 1, 2]),
        ("middle tie", vec![1_u64, 2, 1], vec![1_u64, 0, 2]),
        ("all equal", vec![1_u64, 1, 1], vec![0_u64, 1, 2]),
    ];

    for (case_label, score_values, expected_rank_values) in cases {
        let rank_values = score_values
            .iter()
            .enumerate()
            .map(|(option_index, score)| {
                score_values
                    .iter()
                    .enumerate()
                    .filter(|(other_option_index, other_score)| {
                        *other_score > score
                            || (*other_score == score && *other_option_index < option_index)
                    })
                    .count() as u64
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rank_values, expected_rank_values,
            "{case_label}: plain reference should follow higher-score-first and lower-index tie ordering"
        );
    }
}
