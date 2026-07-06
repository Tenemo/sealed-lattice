use crate::bgv::target_decryption::direct_target_ciphertext_hash;
use crate::hashing::derive_canonical_object_hash;

use super::*;

pub(crate) struct DirectBallotPackedBatchedPairEvaluatorInput<'a> {
    pub(crate) setup_package: &'a Value,
    pub(crate) evaluator_key: &'a DevelopmentBgvKey,
    pub(crate) aggregate_ciphertext: &'a Ciphertext,
    pub(crate) aggregate_scores: &'a [u64],
    pub(crate) ballot_count: usize,
    pub(crate) top_counts: &'a [usize],
    pub(crate) public_evaluation_key_material: Option<&'a Value>,
    pub(crate) target_finality_policy_hash: Option<&'a str>,
}

pub(crate) fn run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
    input: DirectBallotPackedBatchedPairEvaluatorInput<'_>,
) -> CanonicalResult<Vec<Value>> {
    let DirectBallotPackedBatchedPairEvaluatorInput {
        setup_package,
        evaluator_key,
        aggregate_ciphertext,
        aggregate_scores,
        ballot_count,
        top_counts,
        public_evaluation_key_material,
        target_finality_policy_hash,
    } = input;

    if top_counts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot evaluator requires at least one top count",
        ));
    }
    let score_domain_max = direct_ballot_comparison_domain_max(ballot_count)?;
    let aggregate_ciphertext_root = ciphertext_object_root(aggregate_ciphertext)?;
    let aggregate_ciphertext_canonical_byte_length =
        ciphertext_canonical_bytes_hex(aggregate_ciphertext)?.len() / 2;
    let top_count_seed = top_counts
        .iter()
        .map(|top_count| top_count.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let replay_seed = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/packed-batched-pair-evaluator-seed-v1",
        &[
            aggregate_ciphertext_root.as_bytes(),
            top_count_seed.as_bytes(),
        ],
    );
    let working_level = direct_ballot_evaluator_working_level(ballot_count);
    let (context, evaluation_key_material_source, public_evaluation_key_material_hash) =
        match public_evaluation_key_material {
            Some(material) => (
                EvaluatorContext::from_passive_setup_public_material(
                    setup_package,
                    material,
                    working_level,
                )?,
                "supplied public evaluation-key material",
                Some(required_string_path(
                    material,
                    &["publicEvaluationKeyMaterialHash"],
                )?),
            ),
            None => (
                EvaluatorContext::from_key(evaluator_key.clone(), &replay_seed, working_level)?,
                "development private setup witness key synthesis",
                None,
            ),
        };
    let working_aggregate = modulus_switch_to(aggregate_ciphertext, context.working_level())?;
    let replay_started = DirectBallotTimingStart::now();
    let packed_scores =
        pack_direct_score_slots(&context, &working_aggregate, OPTION_COUNT, &replay_seed)?;
    drop(working_aggregate);
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        OPTION_COUNT,
        score_domain_max,
        &replay_seed,
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
        let replay_time_milliseconds = replay_started.elapsed_milliseconds();
        let target_id_root = ciphertext_object_root(&target.target_id)?;
        let target_order_root = ciphertext_object_root(&target.target_order)?;
        let target_ciphertext_hash = direct_target_ciphertext_hash(
            &aggregate_ciphertext_root,
            *top_count,
            &target_layout_root,
            &target_id_root,
            &target_order_root,
        )?;
        let evaluator_replay_context_hash = direct_ballot_evaluator_replay_context_hash(
            DirectBallotEvaluatorReplayContextHashInput {
                setup_package,
                aggregate_ciphertext_root: &aggregate_ciphertext_root,
                aggregate_ciphertext_canonical_byte_length,
                ballot_count,
                top_count: *top_count,
                score_domain_max,
                working_level: context.working_level(),
                target_layout_hash: &target_layout_root,
                evaluation_key_material_source,
                public_evaluation_key_material_hash,
            },
        )?;
        let evaluator_replay_record_hash = direct_ballot_evaluator_replay_record_hash(
            setup_package,
            &aggregate_ciphertext_root,
            &evaluator_replay_context_hash,
            &target_ciphertext_hash,
            &target_layout_root,
        )?;
        let target_id_slots = evaluator_key.decrypt_to_slots(&target.target_id)?;
        let target_order_slots = evaluator_key.decrypt_to_slots(&target.target_order)?;
        let decoded_target_ids = direct_packed_option_slots(&target_id_slots);
        let decoded_target_orders = direct_packed_option_slots(&target_order_slots);
        let (oracle_target_ids, oracle_target_orders) =
            direct_ballot_plaintext_target_slots(aggregate_scores, *top_count)?;
        if decoded_target_ids != oracle_target_ids || decoded_target_orders != oracle_target_orders
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "direct encrypted ballot packed batched-pair evaluator did not match the plaintext target oracle",
            ));
        }
        let target_proposal = direct_ballot_target_proposal(
            setup_package,
            &aggregate_ciphertext_root,
            &evaluator_replay_context_hash,
            &evaluator_replay_record_hash,
            &target_ciphertext_hash,
            &target_layout_root,
            target_finality_policy_hash,
        )?;

        let mut evaluation = json!({
            "topCount": top_count,
            "scoreDomainMax": score_domain_max,
            "tiePolicy": TIE_POLICY,
            "workingLevel": context.working_level(),
            "evaluationKeyMaterialSource": evaluation_key_material_source,
            "targetLayoutHash": target_layout_root,
            "targetIdRoot": target_id_root,
            "targetOrderRoot": target_order_root,
            "targetCiphertextHash": target_ciphertext_hash,
            "evaluatorReplayContextHash": evaluator_replay_context_hash,
            "evaluatorReplayRecordHash": evaluator_replay_record_hash,
            "targetProposal": target_proposal,
            "replayTimeMilliseconds": direct_ballot_timing_report_value(replay_time_milliseconds)
        });
        if let Some(material_hash) = public_evaluation_key_material_hash {
            evaluation["publicEvaluationKeyMaterialHash"] = json!(material_hash);
        }
        evaluations.push(evaluation);
    }

    Ok(evaluations)
}

pub(super) fn direct_packed_option_slots(slots: &[u64]) -> Vec<u64> {
    (0..OPTION_COUNT)
        .map(|option| slots[packed_score_slot(option)])
        .collect()
}

pub(crate) fn direct_ballot_evaluator_working_level(ballot_count: usize) -> usize {
    if ballot_count == 1 {
        SINGLE_BALLOT_TARGET_WORKING_LEVEL
    } else {
        DEFAULT_EVALUATOR_WORKING_LEVEL
    }
}

pub(crate) fn direct_ballot_comparison_domain_max(ballot_count: usize) -> CanonicalResult<u64> {
    let ballot_count_u64 = usize_to_u64(ballot_count, "ballot count")?;
    let score_span = MAXIMUM_SCORE - MINIMUM_SCORE;

    score_span.checked_mul(ballot_count_u64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot comparison domain overflowed",
        )
    })
}

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

pub(super) struct DirectBallotEvaluatorReplayContextHashInput<'a> {
    setup_package: &'a Value,
    aggregate_ciphertext_root: &'a str,
    aggregate_ciphertext_canonical_byte_length: usize,
    ballot_count: usize,
    top_count: usize,
    score_domain_max: u64,
    working_level: usize,
    target_layout_hash: &'a str,
    evaluation_key_material_source: &'a str,
    public_evaluation_key_material_hash: Option<&'a str>,
}

pub(super) fn direct_ballot_evaluator_replay_context_hash(
    input: DirectBallotEvaluatorReplayContextHashInput<'_>,
) -> CanonicalResult<String> {
    let mut evaluation_key_material = json!({
        "source": input.evaluation_key_material_source,
    });
    if let Some(material_hash) = input.public_evaluation_key_material_hash {
        evaluation_key_material["publicEvaluationKeyMaterialHash"] = json!(material_hash);
    }

    derive_canonical_object_hash(&json!({
        "objectType": "DirectEncryptedBallotEvaluatorReplayContext",
        "objectVersion": 1,
        "setupPackageHash": setup_package_hash(input.setup_package)?,
        "ceremonyId": required_string_path(input.setup_package, &["setupInputs", "ceremonyId"])?,
        "manifestHash": required_string_path(input.setup_package, &["setupInputs", "manifestHash"])?,
        "thresholdParametersHash": required_string_path(input.setup_package, &["setupInputs", "thresholdParametersHash"])?,
        "aggregateCiphertextRoot": input.aggregate_ciphertext_root,
        "aggregateCiphertextCanonicalByteLength": input.aggregate_ciphertext_canonical_byte_length,
        "ballotCount": input.ballot_count,
        "topCount": input.top_count,
        "scoreDomainMax": input.score_domain_max,
        "tiePolicy": TIE_POLICY,
        "workingLevel": input.working_level,
        "bgvParametersHash": bgv_parameters_hash()?,
        "evaluationKeyMaterial": evaluation_key_material,
        "targetLayoutHash": input.target_layout_hash,
    }))
}

pub(super) fn direct_ballot_evaluator_replay_record_hash(
    setup_package: &Value,
    aggregate_ciphertext_root: &str,
    evaluator_replay_context_hash: &str,
    target_ciphertext_hash: &str,
    target_layout_hash: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluatorReplayRecord",
        "objectVersion": 1,
        "ceremonyId": required_string_path(setup_package, &["setupInputs", "ceremonyId"])?,
        "electionManifestHash": required_string_path(setup_package, &["setupInputs", "manifestHash"])?,
        "encryptedBallotAggregateHash": aggregate_ciphertext_root,
        "bgvParametersHash": bgv_parameters_hash()?,
        "evaluatorReplayContextHash": evaluator_replay_context_hash,
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash,
    }))
}
