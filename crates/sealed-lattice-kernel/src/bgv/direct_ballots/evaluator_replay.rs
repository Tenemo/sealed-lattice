use crate::bgv::target_decryption::direct_target_ciphertext_hash;
use crate::hashing::derive_canonical_object_hash;

use super::*;

fn usize_to_u64(value: usize, name: &str) -> CanonicalResult<u64> {
    u64::try_from(value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{name} does not fit u64"),
        )
    })
}

fn setup_package_hash(setup_package: &Value) -> CanonicalResult<String> {
    crate::bgv::setup::derive_collective_setup_package_hash(setup_package)
}

pub(crate) struct DirectBallotPackedBatchedPairEvaluatorInput<'a> {
    pub(crate) setup_package: &'a Value,
    pub(crate) evaluator_key: &'a DevelopmentBgvKey,
    pub(crate) aggregate_ciphertext: &'a Ciphertext,
    pub(crate) ballot_count: usize,
    pub(crate) top_counts: &'a [usize],
}

pub(crate) fn run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
    input: DirectBallotPackedBatchedPairEvaluatorInput<'_>,
) -> CanonicalResult<Vec<(Value, EncryptedSparseTarget)>> {
    let DirectBallotPackedBatchedPairEvaluatorInput {
        setup_package,
        evaluator_key,
        aggregate_ciphertext,
        ballot_count,
        top_counts,
    } = input;

    if top_counts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot evaluator requires at least one top count",
        ));
    }
    let score_domain_max = direct_ballot_comparison_domain_max(ballot_count)?;
    let aggregate_ciphertext_root = ciphertext_object_root(aggregate_ciphertext)?;
    let top_count_seed = top_counts
        .iter()
        .map(|top_count| top_count.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let replay_seed = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/packed-batched-pair-evaluator-seed",
        &[
            aggregate_ciphertext_root.as_bytes(),
            top_count_seed.as_bytes(),
        ],
    );
    let working_level = direct_ballot_evaluator_working_level(ballot_count);
    let context = EvaluatorContext::from_key(evaluator_key.clone(), &replay_seed, working_level)?;
    let working_aggregate = modulus_switch_to(aggregate_ciphertext, context.working_level())?;
    let packed_scores = pack_direct_score_slots(&context, &working_aggregate, OPTION_COUNT)?;
    drop(working_aggregate);
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        OPTION_COUNT,
        score_domain_max,
    )?;
    drop(packed_scores);

    let mut evaluations = Vec::with_capacity(top_counts.len());
    for top_count in top_counts {
        let target_layout_root = target_layout_hash(OPTION_COUNT)?;
        let target = project_packed_sparse_target_from_rank_evaluation(
            &context,
            &rank_evaluation,
            OPTION_COUNT,
            *top_count,
        )?;
        let target_id_root = ciphertext_object_root(&target.target_id)?;
        let target_order_root = ciphertext_object_root(&target.target_order)?;
        let target_ciphertext_hash = direct_target_ciphertext_hash(
            &aggregate_ciphertext_root,
            *top_count,
            &target_layout_root,
            &target_id_root,
            &target_order_root,
        )?;
        let evaluator_replay_record_hash = direct_ballot_evaluator_replay_record_hash(
            DirectBallotEvaluatorReplayRecordHashInput {
                setup_package,
                ballot_count,
                target_ciphertext_hash: &target_ciphertext_hash,
            },
        )?;
        let evaluator_replay_record = json!({
            "topCount": top_count,
            "targetLayoutHash": target_layout_root,
            "targetIdRoot": target_id_root,
            "targetOrderRoot": target_order_root,
            "targetCiphertextHash": target_ciphertext_hash,
            "evaluatorReplayRecordHash": evaluator_replay_record_hash
        });
        evaluations.push((evaluator_replay_record, target));
    }

    Ok(evaluations)
}

fn direct_ballot_evaluator_working_level(ballot_count: usize) -> usize {
    if ballot_count == 1 {
        SINGLE_BALLOT_TARGET_WORKING_LEVEL
    } else {
        DEFAULT_EVALUATOR_WORKING_LEVEL
    }
}

fn direct_ballot_comparison_domain_max(ballot_count: usize) -> CanonicalResult<u64> {
    let ballot_count_u64 = usize_to_u64(ballot_count, "ballot count")?;
    let score_span = MAXIMUM_SCORE - MINIMUM_SCORE;

    score_span.checked_mul(ballot_count_u64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot comparison domain overflowed",
        )
    })
}

#[cfg(test)]
pub(crate) fn direct_ballot_plaintext_target_slots(
    aggregate_scores: &[u64],
    top_count: usize,
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    if aggregate_scores.len() != OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot target oracle requires twenty aggregate scores",
        ));
    }
    if top_count == 0 || top_count > OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount must be between one and the direct ballot option count",
        ));
    }

    let mut ranked_options = aggregate_scores
        .iter()
        .enumerate()
        .collect::<Vec<(usize, &u64)>>();
    ranked_options.sort_by(|(left_option, left_score), (right_option, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_option.cmp(right_option))
    });
    let mut ranks_by_option = [0_usize; OPTION_COUNT];
    for (rank, (option_index, _)) in ranked_options.iter().enumerate() {
        ranks_by_option[*option_index] = rank;
    }
    let mut target_ids = vec![0_u64; OPTION_COUNT];
    let mut target_orders = vec![0_u64; OPTION_COUNT];
    for (option_index, rank) in ranks_by_option.iter().enumerate() {
        if *rank < top_count {
            target_ids[option_index] = usize_to_u64(option_index + 1, "option identifier")?;
            target_orders[option_index] = usize_to_u64(rank + 1, "target order")?;
        }
    }

    Ok((target_ids, target_orders))
}

pub(super) struct DirectBallotEvaluatorReplayRecordHashInput<'a> {
    setup_package: &'a Value,
    ballot_count: usize,
    target_ciphertext_hash: &'a str,
}

pub(super) fn direct_ballot_evaluator_replay_record_hash(
    input: DirectBallotEvaluatorReplayRecordHashInput<'_>,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluatorReplayRecord",
        "setupPackageHash": setup_package_hash(input.setup_package)?,
        "ballotCount": input.ballot_count,
        "targetCiphertextHash": input.target_ciphertext_hash,
    }))
}
