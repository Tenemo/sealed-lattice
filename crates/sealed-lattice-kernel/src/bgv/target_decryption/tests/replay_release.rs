use super::*;

use crate::bgv::direct_ballots::{
    DirectBallotPackedBatchedPairEvaluatorInput, direct_ballot_comparison_domain_max,
    direct_ballot_evaluator_working_level, direct_ballot_plaintext_target_slots,
    run_direct_ballot_packed_batched_pair_evaluator_for_top_counts,
};
use crate::bgv::evaluator::circuit::{EvaluatorContext, modulus_switch_to};
use crate::bgv::evaluator::engine::{ciphertext_add, ciphertext_object_root};
use crate::bgv::evaluator::top_k::{
    evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs, pack_direct_score_slots,
    project_packed_sparse_target_from_rank_evaluation,
};
use crate::hashing::hash512_hex;

#[test]
#[ignore = "long-running foundation-profile evidence; run via the focused full-profile-evidence runner"]
fn foundation_profile_replay_target_release_matches_plaintext_oracle() {
    let started = std::time::Instant::now();
    let phase = |message: &str| {
        eprintln!(
            "replay-release-phase [+{}s] {message}",
            started.elapsed().as_secs()
        );
    };

    let setup_package = accepted_setup_package();
    let evaluator_key = target_decryption_evaluator_key();
    let ballot_count = 10_usize;
    let option_count = MAXIMUM_OPTION_COUNT;
    let top_count = MAXIMUM_OPTION_COUNT;

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
    let (oracle_target_ids, oracle_target_orders) =
        direct_ballot_plaintext_target_slots(&aggregate_scores, top_count)
            .expect("plaintext target oracle");

    phase("encrypting ten genuine ballots and summing the aggregate");
    let mut aggregate_ciphertext = evaluator_key
        .encrypt_slots(&ballots[0], "replay-release-ballot-0")
        .expect("ballot ciphertext");
    for (ballot_index, ballot) in ballots.iter().enumerate().skip(1) {
        let ballot_ciphertext = evaluator_key
            .encrypt_slots(ballot, &format!("replay-release-ballot-{ballot_index}"))
            .expect("ballot ciphertext");
        aggregate_ciphertext =
            ciphertext_add(&aggregate_ciphertext, &ballot_ciphertext).expect("aggregate sum");
    }

    phase("running the production packed batched-pair evaluator replay");
    let evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
        DirectBallotPackedBatchedPairEvaluatorInput {
            setup_package: &setup_package,
            evaluator_key: &evaluator_key,
            aggregate_ciphertext: &aggregate_ciphertext,
            ballot_count,
            top_counts: &[top_count],
        },
    )
    .expect("production evaluator replay");
    assert_eq!(evaluations.len(), 1, "one top-count evaluation record");
    let evaluation = &evaluations[0];

    phase("reproducing the deterministic pipeline to recover the target pair");
    let aggregate_ciphertext_root =
        ciphertext_object_root(&aggregate_ciphertext).expect("aggregate root");
    let replay_seed = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/packed-batched-pair-evaluator-seed",
        &[
            aggregate_ciphertext_root.as_bytes(),
            top_count.to_string().as_bytes(),
        ],
    );
    let working_level = direct_ballot_evaluator_working_level(ballot_count);
    let context = EvaluatorContext::from_key(evaluator_key.clone(), &replay_seed, working_level)
        .expect("replay context");
    let working_aggregate = modulus_switch_to(&aggregate_ciphertext, context.working_level())
        .expect("working aggregate");
    let packed_scores =
        pack_direct_score_slots(&context, &working_aggregate, option_count, &replay_seed)
            .expect("packed scores");
    let score_domain_max =
        direct_ballot_comparison_domain_max(ballot_count).expect("comparison domain");
    let rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
        &context,
        &packed_scores,
        option_count,
        score_domain_max,
        &replay_seed,
    )
    .expect("rank evaluation");
    let target = project_packed_sparse_target_from_rank_evaluation(
        &context,
        &rank_evaluation,
        option_count,
        top_count,
    )
    .expect("target projection");
    let target_id_root = ciphertext_object_root(&target.target_id).expect("target id root");
    let target_order_root =
        ciphertext_object_root(&target.target_order).expect("target order root");
    // Byte-identity with the production replay: the reproduced pair must carry
    // exactly the ciphertext roots the production evaluator recorded, so the
    // pair released below is the pair the production path produced.
    assert_eq!(
        Some(target_id_root.as_str()),
        evaluation["targetIdRoot"].as_str(),
        "reproduced target-id root must match the production replay record"
    );
    assert_eq!(
        Some(target_order_root.as_str()),
        evaluation["targetOrderRoot"].as_str(),
        "reproduced target-order root must match the production replay record"
    );
    assert_eq!(
        target.target_id.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        "genuine target pair must land on the canonical target ciphertext level"
    );
    assert_eq!(target.target_order.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);
    // Release the evaluator context before share proving: its rotation-key
    // cache holds tens of gigabytes after packing, and each share proof below
    // budgets its own multi-gigabyte prover working set.
    drop(rank_evaluation);
    drop(packed_scores);
    drop(working_aggregate);
    drop(context);

    phase("binding the genuine pair into the accepted target record");
    let target_layout = target_layout_hash(option_count).expect("target layout hash");
    let target_ciphertext_hash = direct_target_ciphertext_hash(
        &aggregate_ciphertext_root,
        top_count,
        &target_layout,
        &target_id_root,
        &target_order_root,
    )
    .expect("target ciphertext hash");
    let accepted = accepted_record(&setup_package, &target_ciphertext_hash);
    let target_ciphertext_binding = json!({
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "topCount": top_count,
        "targetLayoutHash": target_layout,
    });
    let target_ciphertexts = json!({
        "targetIdCanonicalBytesHex":
            crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target.target_id)
                .expect("target id hex"),
        "targetOrderCanonicalBytesHex":
            crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target.target_order)
                .expect("target order hex"),
    });
    let target_share_profile_value = target_share_profile(&setup_package);
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    let target_share_profile_binding =
        read_target_share_profile(&target_share_profile_value, &setup_binding)
            .expect("target share profile");
    let quorum = target_share_profile_binding.decryption_share_quorum;

    phase("generating the proof-backed share quorum with real succinct proofs");
    let mut target_share_proofs = Vec::with_capacity(quorum);
    for participant in setup_binding.participants.iter().take(quorum) {
        let trustee_identity = participant.trustee_identity.as_str();
        let local_target_share_witness_value = local_target_share_witness(
            &setup_package,
            &accepted,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            trustee_identity,
        );
        let target_decryption_share = generate_local_share(
            &setup_package,
            &accepted,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &local_target_share_witness_value,
            trustee_identity,
        );
        let proof_statement = derive_share_proof_statement(TargetShareProofStatementInput {
            setup_package: &setup_package,
            accepted_record: &accepted,
            target_ciphertext_binding: &target_ciphertext_binding,
            target_ciphertexts: &target_ciphertexts,
            target_share_profile: &target_share_profile_value,
            local_target_share_witness_value: &local_target_share_witness_value,
            target_decryption_share: &target_decryption_share,
            trustee_identity,
        })
        .expect("target share proof statement");
        let proof_material =
            with_staged_aggregate_opening_material(&local_target_share_witness_value, || {
                generate_bgv_target_decryption_share_proof_material_from_local_witness_request(
                    &json!({
                        "setupPackage": setup_package,
                        "localTargetShareWitness": local_target_share_witness_value,
                        "targetAcceptedRecord": accepted,
                        "targetCiphertextBinding": target_ciphertext_binding,
                        "targetCiphertexts": target_ciphertexts,
                        "targetShareProfile": target_share_profile_value,
                        "trusteeIdentity": trustee_identity,
                        "targetDecryptionShare": target_decryption_share,
                        "proofStatement": proof_statement,
                        "proofRandomnessSeedHex": hash512_hex(
                            "sealed-lattice/tests/replay-release-proof-randomness-seed",
                            &[trustee_identity.as_bytes()],
                        ),
                        "proofRandomnessNonceHex": hash512_hex(
                            "sealed-lattice/tests/replay-release-proof-randomness-nonce",
                            &[trustee_identity.as_bytes()],
                        ),
                    }),
                )
            })
            .expect("target share proof material");
        target_share_proofs.push(json!({
            "targetDecryptionShare": target_decryption_share,
            "proofStatement": proof_statement,
            "proofMaterial": proof_material,
        }));
        phase(&format!("proved share for {trustee_identity}"));
    }

    phase("releasing the genuine target through the staged session");
    let release_verification_id = "replay-release-foundation-profile";
    let release_result = staged_target_result_release(
        &setup_package,
        &accepted,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        target_share_proofs,
        release_verification_id,
    )
    .expect("staged release over the genuine target pair");

    let released_target_ids = release_result["targetIdByOption"]
        .as_array()
        .expect("released target ids")
        .iter()
        .map(|value| value.as_u64().expect("released target id"))
        .collect::<Vec<_>>();
    let released_target_orders = release_result["targetOrderByOption"]
        .as_array()
        .expect("released target orders")
        .iter()
        .map(|value| value.as_u64().expect("released target order"))
        .collect::<Vec<_>>();
    assert_eq!(
        released_target_ids, oracle_target_ids,
        "released per-option identifiers must equal the plaintext oracle"
    );
    assert_eq!(
        released_target_orders, oracle_target_orders,
        "released per-option orders must equal the plaintext oracle"
    );

    phase("verifying a finished session cannot finish twice");
    finish_bgv_target_decryption_result_release_from_request(&json!({
        "releaseVerificationId": release_verification_id,
    }))
    .expect_err("a consumed release session must refuse a second finish");

    phase("done");
}
