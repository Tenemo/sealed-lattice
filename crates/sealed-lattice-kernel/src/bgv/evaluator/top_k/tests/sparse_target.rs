use super::*;

#[test]
#[ignore = "heavy packed sparse-target smoke test; run with --ignored"]
fn packed_sparse_target_matches_two_option_oracle() {
    let context = EvaluatorContext::new("packed-target-seed", 15).expect("context");
    let scores = [170_u64, 88];
    let score_ciphertexts = scores
        .iter()
        .enumerate()
        .map(|(option, value)| {
            encrypt_broadcast(&context, *value, &format!("packed-target-score-{option}"))
        })
        .collect::<Vec<_>>();
    let unpacked_outputs = evaluate_top_k_via_difference(&context, &score_ciphertexts, 1, 200)
        .expect("unpacked ranks");
    let unpacked_rank_slots = context
        .key()
        .decrypt_to_slots(&unpacked_outputs.ranks[0])
        .expect("unpacked rank slots");
    assert_eq!(unpacked_rank_slots[0], 0);

    let packed_scores = pack_broadcast_scores(&score_ciphertexts).expect("packed scores");
    let shifted_scores = context
        .rotate_ciphertext(
            &packed_scores,
            galois_power(1),
            packed_scores.level,
            "packed-target-debug-shift",
        )
        .expect("shifted scores");
    let shifted_difference = add_plaintext_coefficients(
        &normalize_scaling(
            &ciphertext_sub(&packed_scores, &shifted_scores).expect("score difference"),
        )
        .expect("normalized difference"),
        &broadcast_constant(200),
    )
    .expect("shifted difference");
    let shifted_slots = context
        .key()
        .decrypt_to_slots(&shifted_difference)
        .expect("shifted difference slots");
    assert_eq!(
        &[
            shifted_slots[packed_score_slot(0)],
            shifted_slots[packed_score_slot(1)]
        ],
        &[282, 118]
    );

    let packed_rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores(
        &context,
        &packed_scores,
        scores.len(),
        200,
        "packed-target-test",
        1,
    )
    .expect("packed rank evaluation");
    let rank_slots = context
        .key()
        .decrypt_to_slots(&packed_rank_evaluation.packed_ranks)
        .expect("packed rank slots");
    assert_eq!(
        (0..scores.len())
            .map(|option| rank_slots[packed_score_slot(option)])
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let target = project_packed_sparse_target_from_rank_evaluation(
        &context,
        &packed_rank_evaluation,
        scores.len(),
        1,
    )
    .expect("target");
    let id_slots = context
        .key()
        .decrypt_to_slots(&target.target_id)
        .expect("decrypt packed id");
    let order_slots = context
        .key()
        .decrypt_to_slots(&target.target_order)
        .expect("decrypt packed order");
    let target_ids = (0..scores.len())
        .map(|option| id_slots[packed_score_slot(option)])
        .collect::<Vec<_>>();
    let target_orders = (0..scores.len())
        .map(|option| order_slots[packed_score_slot(option)])
        .collect::<Vec<_>>();

    assert_eq!(target_ids, vec![1, 0]);
    assert_eq!(target_orders, vec![1, 0]);
}

#[test]
#[ignore = "heavy packed sparse-target tie test; run with --ignored"]
fn packed_sparse_target_matches_four_option_oracle_with_tie() {
    let context = EvaluatorContext::new("packed-target-four-option", 10).expect("context");
    let key = context.key();
    let scores = [2_u64, 4, 4, 1];
    let score_ciphertexts = scores
        .iter()
        .enumerate()
        .map(|(option, score)| encrypt_broadcast(&context, *score, &format!("score-{option}")))
        .collect::<Vec<_>>();
    let packed_scores = pack_broadcast_scores(&score_ciphertexts).expect("packed scores");
    let packed_rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores(
        &context,
        &packed_scores,
        scores.len(),
        4,
        "packed-rank-target-four",
        2,
    )
    .expect("ranks");
    let packed_target = project_packed_sparse_target_from_rank_evaluation(
        &context,
        &packed_rank_evaluation,
        scores.len(),
        2,
    )
    .expect("target");
    let target_id_slots = key
        .decrypt_to_slots(&packed_target.target_id)
        .expect("target id");
    let target_order_slots = key
        .decrypt_to_slots(&packed_target.target_order)
        .expect("target order");
    let target_ids = (0..scores.len())
        .map(|option| target_id_slots[packed_score_slot(option)])
        .collect::<Vec<_>>();
    let target_orders = (0..scores.len())
        .map(|option| target_order_slots[packed_score_slot(option)])
        .collect::<Vec<_>>();

    assert_eq!(target_ids, vec![0, 2, 3, 0]);
    assert_eq!(target_orders, vec![0, 1, 2, 0]);
}

#[test]
#[ignore = "heavy full-rank-domain projection tail; run with --ignored"]
fn full_rank_domain_projection_tail_decrypts_with_headroom() {
    let context = EvaluatorContext::new("full-rank-domain-tail", 6).expect("context");
    let key = context.key();
    let rank_ciphertext = modulus_switch_to(
        &key.encrypt_slots(&[0, 1, 9, 10, 19], "full-rank-domain-values")
            .expect("encrypt ranks"),
        6,
    )
    .expect("level");
    let indicator = top_k_indicator(&context, &rank_ciphertext, 20, 10).expect("indicator");
    let order_value = top_k_order_value(&context, &rank_ciphertext, 20, 10).expect("order");
    let indicator_slots = key.decrypt_to_slots(&indicator).expect("indicator slots");
    let order_slots = key.decrypt_to_slots(&order_value).expect("order slots");

    assert_eq!(&indicator_slots[..5], &[1, 1, 1, 0, 0]);
    assert_eq!(&order_slots[..5], &[1, 2, 10, 0, 0]);
    assert_eq!(indicator.level, 1);
    assert_eq!(order_value.level, 1);
}
