use super::*;
use crate::bgv::evaluator::engine::ciphertext_add;

// The foundation-profile guard for the multi-ballot comparison handoff: a genuine
// ten-ballot aggregate at the full score-difference domain (D = 90) must
// produce ranks that decrypt correctly. The packing construction leaves the
// comparison input structurally noisy and the comparison evaluation fails as
// a cliff when that noise exceeds its input ceiling, so tiny-domain coverage
// (score_domain_max = 2) cannot stand in for this case; this test exists so a
// saturating handoff can never ship silently again. It runs one full
// foundation-profile-domain comparison, which costs a couple of minutes.
#[test]
#[ignore = "heavy Rust kernel evaluator test; run pnpm run test:rust:kernel:heavy"]
fn heavy_rust_kernel_foundation_profile_domain_multiballot_rank_evaluation_decrypts() {
    let context = EvaluatorContext::new(
        "foundation-profile-domain-multiballot-rank",
        SELECTED_EVALUATOR_WORKING_LEVEL,
    )
    .expect("context");
    let option_count = 6usize;
    let ballot_count = 10usize;
    let score_domain_max = 9 * ballot_count as u64;

    let ballots: Vec<Vec<u64>> = (0..ballot_count)
        .map(|ballot_index| {
            (0..option_count)
                .map(|option_index| 1 + ((option_index + ballot_index) % 10) as u64)
                .collect()
        })
        .collect();
    let aggregate_scores: Vec<u64> = (0..option_count)
        .map(|option_index| ballots.iter().map(|ballot| ballot[option_index]).sum())
        .collect();
    let expected_rank_values: Vec<u64> = (0..option_count)
        .map(|option_index| {
            (0..option_count)
                .filter(|&other_index| {
                    aggregate_scores[other_index] > aggregate_scores[option_index]
                        || (aggregate_scores[other_index] == aggregate_scores[option_index]
                            && other_index < option_index)
                })
                .count() as u64
        })
        .collect();

    let mut aggregate_ciphertext = context
        .key()
        .encrypt_slots(&ballots[0], "foundation-profile-domain-ballot-0")
        .expect("ballot ciphertext");
    for (ballot_index, ballot) in ballots.iter().enumerate().skip(1) {
        let ballot_ciphertext = context
            .key()
            .encrypt_slots(
                ballot,
                &format!("foundation-profile-domain-ballot-{ballot_index}"),
            )
            .expect("ballot ciphertext");
        aggregate_ciphertext =
            ciphertext_add(&aggregate_ciphertext, &ballot_ciphertext).expect("aggregate sum");
    }

    let packed_scores = pack_direct_score_slots(
        &context,
        &aggregate_ciphertext,
        option_count,
        "foundation-profile-domain-pack",
    )
    .expect("packed scores");
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        option_count,
        score_domain_max,
        "foundation-profile-domain-rank",
    )
    .expect("rank evaluation");
    let decrypted_slots = context
        .key()
        .decrypt_to_slots(&rank_evaluation.packed_ranks)
        .expect("rank slots");
    let decrypted_rank_values = (0..option_count)
        .map(|logical_index| decrypted_slots[packed_score_slot(logical_index)])
        .collect::<Vec<_>>();

    assert_eq!(
        decrypted_rank_values, expected_rank_values,
        "the foundation-profile-domain multi-ballot handoff must decrypt to the tie-policy ranks"
    );
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
#[ignore = "heavy Rust kernel evaluator test; run pnpm run test:rust:kernel:heavy"]
fn heavy_rust_kernel_packed_rank_evaluation_decrypts_expected_ranks_and_tie_policy() {
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
#[ignore = "heavy Rust kernel evaluator test; run pnpm run test:rust:kernel:heavy"]
fn heavy_rust_kernel_sparse_target_projection_decrypts_selected_ids_and_orders() {
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
