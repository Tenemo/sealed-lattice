use super::*;

#[test]
#[ignore = "heavy full-ring top-k pipeline; run with --ignored"]
fn encrypted_top_k_matches_plaintext_oracle() {
    let context = EvaluatorContext::new("top-k-e2e-v1", 9).expect("evaluator context");
    let key = context.key();
    let score_domain_max = 3_u64;
    let scores = [3_u64, 1_u64];
    let option_count = scores.len();
    let top_count = 1_usize;
    let bit_polynomials = bit_extraction_polynomials(score_domain_max).expect("bit polynomials");

    let score_ciphertexts = scores
        .iter()
        .enumerate()
        .map(|(option, value)| encrypt_broadcast(&context, *value, &format!("score-{option}")))
        .collect::<Vec<_>>();
    let bits = score_ciphertexts
        .iter()
        .map(|score| derive_score_bits(&context, score, &bit_polynomials).expect("bits"))
        .collect::<Vec<_>>();

    let mut ranks = Vec::with_capacity(option_count);
    for option in 0..option_count {
        let mut ahead = Vec::new();
        for challenger in 0..option_count {
            if challenger == option {
                continue;
            }
            let (greater_than, equal) =
                bit_sliced_greater_than_and_equal(&context, &bits[challenger], &bits[option])
                    .expect("compare");
            ahead.push(ahead_indicator(&greater_than, &equal, challenger, option).expect("ahead"));
        }
        ranks.push(accumulate_rank(&ahead).expect("rank"));
    }

    assert_eq!(
        key.decrypt_to_slots(&ranks[0]).expect("decrypt rank 0")[0],
        0
    );
    assert_eq!(
        key.decrypt_to_slots(&ranks[1]).expect("decrypt rank 1")[0],
        1
    );

    let indicators = ranks
        .iter()
        .map(|rank| top_k_indicator(&context, rank, option_count, top_count).expect("indicator"))
        .collect::<Vec<_>>();
    let target = project_sparse_target(&context, &ranks, &indicators, top_count).expect("project");
    let id_slots = key.decrypt_to_slots(&target.target_id).expect("decrypt id");
    let order_slots = key
        .decrypt_to_slots(&target.target_order)
        .expect("decrypt order");
    assert_eq!(&id_slots[..option_count], &[1, 0]);
    assert_eq!(&order_slots[..option_count], &[1, 0]);
}

#[test]
#[ignore = "heavy comparison-input top-k pipeline; run with --ignored"]
fn comparison_input_evaluator_matches_oracle_with_tie() {
    // m = 3 with a tie between options 0 and 2 broken by the lower index,
    // K_top = 2. The comparison-input path is correct at this profile with
    // enough tail level for the rank-prefix target projection.
    let context = EvaluatorContext::new("comparison-input-tie", 9).expect("context");
    let key = context.key();
    let scores = [2_u64, 3, 2];
    let option_count = scores.len();
    let score_ciphertexts = scores
        .iter()
        .enumerate()
        .map(|(option, value)| encrypt_broadcast(&context, *value, &format!("cmp-{option}")))
        .collect::<Vec<_>>();
    let outputs =
        evaluate_top_k_via_difference(&context, &score_ciphertexts, 2, 3).expect("evaluate");
    let ranks = outputs
        .ranks
        .iter()
        .map(|rank| key.decrypt_to_slots(rank).expect("rank")[0])
        .collect::<Vec<_>>();
    assert_eq!(ranks, vec![1, 0, 2]);
    let id_slots = key.decrypt_to_slots(&outputs.target.target_id).expect("id");
    let order_slots = key
        .decrypt_to_slots(&outputs.target.target_order)
        .expect("order");
    assert_eq!(&id_slots[..option_count], &[1, 2, 0]);
    assert_eq!(&order_slots[..option_count], &[2, 1, 0]);
}

#[test]
#[ignore = "heavy packed batched-pair evaluator smoke; run selectively"]
fn packed_batched_pair_ranks_match_oracle_with_tie() {
    let context = EvaluatorContext::new("packed-batched-pair-target-tie", 7).expect("context");
    let key = context.key();
    let scores = [10_u64, 7, 10, 1];
    let option_count = scores.len();
    let score_ciphertexts = scores
        .iter()
        .enumerate()
        .map(|(option, value)| {
            encrypt_broadcast(&context, *value, &format!("packed-batched-score-{option}"))
        })
        .collect::<Vec<_>>();
    let packed_scores = pack_broadcast_scores(&score_ciphertexts).expect("packed scores");

    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        option_count,
        9,
        "packed-batched-pair-target",
    )
    .expect("batched rank evaluation");

    let rank_slots = key
        .decrypt_to_slots(&rank_evaluation.packed_ranks)
        .expect("decrypt ranks");
    let decoded_ranks = (0..option_count)
        .map(|option| rank_slots[packed_score_slot(option)])
        .collect::<Vec<_>>();
    assert_eq!(decoded_ranks, vec![0, 2, 1, 3]);
    let target = project_packed_sparse_target_from_rank_evaluation(
        &context,
        &rank_evaluation,
        option_count,
        option_count,
    )
    .expect("target");
    let target_id_slots = key.decrypt_to_slots(&target.target_id).expect("target ids");
    let target_order_slots = key
        .decrypt_to_slots(&target.target_order)
        .expect("target orders");
    let decoded_target_ids = (0..option_count)
        .map(|option| target_id_slots[packed_score_slot(option)])
        .collect::<Vec<_>>();
    let decoded_target_orders = (0..option_count)
        .map(|option| target_order_slots[packed_score_slot(option)])
        .collect::<Vec<_>>();
    assert_eq!(decoded_target_ids, vec![1, 2, 3, 4]);
    assert_eq!(decoded_target_orders, vec![1, 3, 2, 4]);
}

#[test]
#[ignore = "heavy full-domain direct-comparison polynomial; run with --ignored"]
fn direct_comparison_full_domain_polynomial_decrypts() {
    let context = EvaluatorContext::new("comparison-input-full-domain-depth", 15).expect("context");
    let key = context.key();
    let score_domain_max = 200_u64;
    let shifted_difference = key
        .encrypt_slots(&[400, 282, 200, 118, 0], "full-domain-comparison-inputs")
        .expect("comparison inputs");
    let (greater_polynomial, greater_or_equal_polynomial) =
        comparison_polynomials(score_domain_max).expect("comparison polynomial");
    let greater =
        evaluate_direct_comparison_polynomial(&context, &shifted_difference, &greater_polynomial)
            .expect("greater");
    let greater_or_equal = evaluate_direct_comparison_polynomial(
        &context,
        &shifted_difference,
        &greater_or_equal_polynomial,
    )
    .expect("greater or equal");
    assert_eq!(
        &key.decrypt_to_slots(&greater).expect("greater slots")[..5],
        &[1, 1, 0, 0, 0]
    );
    assert_eq!(
        &key.decrypt_to_slots(&greater_or_equal)
            .expect("greater-or-equal slots")[..5],
        &[1, 1, 1, 0, 0]
    );
    assert_eq!(greater.level, DIRECT_COMPARISON_OUTPUT_LEVEL);
    assert_eq!(greater_or_equal.level, DIRECT_COMPARISON_OUTPUT_LEVEL);
}

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
#[ignore = "heavy packed direct-comparison rank pipeline; run with --ignored"]
fn packed_difference_ranks_match_oracle_with_tie() {
    let context = EvaluatorContext::new("packed-rank-seed", 7).expect("context");
    let scores = [2_u64, 4, 4, 1];
    let score_ciphertexts = scores
        .iter()
        .enumerate()
        .map(|(option, value)| {
            encrypt_broadcast(&context, *value, &format!("packed-score-{option}"))
        })
        .collect::<Vec<_>>();
    let packed_ranks =
        evaluate_packed_ranks_via_difference(&context, &score_ciphertexts, 4, "packed-rank-test")
            .expect("packed ranks");
    let decrypted = context
        .key()
        .decrypt_to_slots(&packed_ranks)
        .expect("decrypt packed ranks");
    let rank_slots = (0..scores.len())
        .map(|option| decrypted[packed_score_slot(option)])
        .collect::<Vec<_>>();

    assert_eq!(rank_slots, vec![2, 0, 1, 3]);
}

#[test]
#[ignore = "exact-rank indicator headroom check; run selectively"]
fn clean_full_option_exact_rank_indicator_decrypts() {
    let context = EvaluatorContext::new("clean-full-option-exact-rank", 15).expect("context");
    let key = context.key();
    let expected_rank = 8;
    let exact_rank_count = 10;
    for input_level in [10_usize, 12] {
        let ahead_terms = (0..19)
            .map(|ahead_index| {
                let bit = u64::from(ahead_index < expected_rank);
                let encrypted_bit = key
                    .encrypt_slots(
                        &[bit; 4],
                        &format!("clean-ahead-bit-{input_level}-{ahead_index}"),
                    )
                    .expect("encrypted clean ahead bit");

                modulus_switch_to(&encrypted_bit, input_level).expect("clean ahead bit level")
            })
            .collect::<Vec<_>>();
        let indicators = exact_rank_indicators_for_option(&context, &ahead_terms, exact_rank_count)
            .expect("exact rank indicators");
        let decrypted = indicators
            .iter()
            .map(|indicator| key.decrypt_to_slots(indicator).expect("indicator slots")[0])
            .collect::<Vec<_>>();

        assert_eq!(
            decrypted,
            vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
            "exact rank indicators must decrypt from clean bits at level {input_level}",
        );
    }
}
