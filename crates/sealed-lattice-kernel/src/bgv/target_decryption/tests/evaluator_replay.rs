use super::*;

use crate::bgv::direct_ballots::{
    DirectBallotPackedBatchedPairEvaluatorInput, direct_ballot_plaintext_target_slots,
    run_direct_ballot_packed_batched_pair_evaluator_for_top_counts,
};
use crate::bgv::evaluator::engine::{ciphertext_add, ciphertext_object_root};

#[test]
#[ignore = "long-running prototype-profile evaluator evidence; run via the focused full-profile-evidence runner"]
fn prototype_profile_evaluator_replay_matches_plaintext_oracle_and_binds_target_roots() {
    let started = std::time::Instant::now();
    let phase = |message: &str| {
        eprintln!(
            "evaluator-replay-phase [+{}s] {message}",
            started.elapsed().as_secs()
        );
    };

    let setup_fixture = prototype_accepted_setup_fixture();
    let setup_package = setup_fixture.setup_package.clone();
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    assert_eq!(
        setup_binding.participants.len(),
        usize::from(PROTOTYPE_PARTICIPANT_COUNT),
        "prototype-profile evidence must use all ten trustees"
    );
    let evaluator_key = target_decryption_evaluator_key();
    let ballot_count = usize::from(PROTOTYPE_PARTICIPANT_COUNT);
    let option_count = MAXIMUM_OPTION_COUNT;
    let top_count = MAXIMUM_OPTION_COUNT;

    let ballots: Vec<Vec<u64>> = (0..ballot_count)
        .map(|ballot_index| {
            (0..option_count)
                .map(|option_index| {
                    1 + ((option_index + ballot_index)
                        % usize::from(FOUNDATION_PROFILE.maximum_score))
                        as u64
                })
                .collect()
        })
        .collect();
    let aggregate_scores: Vec<u64> = (0..option_count)
        .map(|option_index| ballots.iter().map(|ballot| ballot[option_index]).sum())
        .collect();
    let (oracle_target_ids, oracle_target_orders) =
        direct_ballot_plaintext_target_slots(&aggregate_scores, top_count)
            .expect("plaintext target oracle");

    phase("encrypting the prototype-profile ballots and summing the aggregate");
    let mut aggregate_ciphertext = evaluator_key
        .encrypt_slots(&ballots[0], "evaluator-replay-ballot-0")
        .expect("ballot ciphertext");
    for (ballot_index, ballot) in ballots.iter().enumerate().skip(1) {
        let ballot_ciphertext = evaluator_key
            .encrypt_slots(ballot, &format!("evaluator-replay-ballot-{ballot_index}"))
            .expect("ballot ciphertext");
        aggregate_ciphertext =
            ciphertext_add(&aggregate_ciphertext, &ballot_ciphertext).expect("aggregate sum");
    }

    phase("running the production packed batched-pair evaluator replay");
    let mut evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
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
    let (evaluation_record, target) = evaluations.pop().expect("one top-count evaluation");

    phase("checking the production target pair against its replay record");
    let aggregate_ciphertext_root =
        ciphertext_object_root(&aggregate_ciphertext).expect("aggregate root");
    let target_id_root = ciphertext_object_root(&target.target_id).expect("target id root");
    let target_order_root =
        ciphertext_object_root(&target.target_order).expect("target order root");
    assert_eq!(
        Some(target_id_root.as_str()),
        evaluation_record["targetIdRoot"].as_str(),
        "production target-id root must match the replay record"
    );
    assert_eq!(
        Some(target_order_root.as_str()),
        evaluation_record["targetOrderRoot"].as_str(),
        "production target-order root must match the replay record"
    );
    assert_eq!(
        target.target_id.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        "genuine target pair must land on the canonical target ciphertext level"
    );
    assert_eq!(target.target_order.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);

    phase("binding the genuine pair into the evaluator record");
    let target_layout = target_layout_hash(option_count).expect("target layout hash");
    let target_ciphertext_hash = direct_target_ciphertext_hash(
        &aggregate_ciphertext_root,
        top_count,
        &target_layout,
        &target_id_root,
        &target_order_root,
    )
    .expect("target ciphertext hash");
    assert_eq!(
        Some(target_ciphertext_hash.as_str()),
        evaluation_record["targetCiphertextHash"].as_str(),
        "production target ciphertext hash must match the replay record"
    );

    phase("checking the evaluator output against the plaintext oracle");
    let decrypted_target_ids = evaluator_key
        .decrypt_to_slots(&target.target_id)
        .expect("decrypted target identifiers");
    let decrypted_target_orders = evaluator_key
        .decrypt_to_slots(&target.target_order)
        .expect("decrypted target orders");
    assert_eq!(
        &decrypted_target_ids[..option_count],
        oracle_target_ids.as_slice(),
        "evaluator target identifiers must equal the plaintext oracle"
    );
    assert_eq!(
        &decrypted_target_orders[..option_count],
        oracle_target_orders.as_slice(),
        "evaluator target orders must equal the plaintext oracle"
    );

    phase("done");
}
