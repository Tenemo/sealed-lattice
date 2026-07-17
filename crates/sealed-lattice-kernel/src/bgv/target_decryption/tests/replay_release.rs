use super::*;

use crate::bgv::direct_ballots::{
    DirectBallotPackedBatchedPairEvaluatorInput, direct_ballot_plaintext_target_slots,
    run_direct_ballot_packed_batched_pair_evaluator_for_top_counts,
};
use crate::bgv::evaluator::engine::{ciphertext_add, ciphertext_object_root};
use crate::hashing::hash512_hex;

#[test]
#[ignore = "long-running prototype-profile evidence; run via the focused full-profile-evidence runner"]
fn prototype_profile_replay_target_release_matches_plaintext_oracle() {
    let started = std::time::Instant::now();
    let phase = |message: &str| {
        eprintln!(
            "replay-release-phase [+{}s] {message}",
            started.elapsed().as_secs()
        );
    };

    let setup_fixture = prototype_accepted_setup_fixture();
    let setup_package = setup_fixture.setup_package.clone();
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
    assert_eq!(
        Some(target_ciphertext_hash.as_str()),
        evaluation_record["targetCiphertextHash"].as_str(),
        "production target ciphertext hash must match the replay record"
    );
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
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    assert_eq!(
        setup_binding.participants.len(),
        usize::from(PROTOTYPE_PARTICIPANT_COUNT),
        "prototype-profile evidence must use all ten trustees"
    );
    let required_share_count =
        decryption_threshold_for_roster_length(setup_binding.participants.len())
            .expect("target decryption share threshold");
    assert_eq!(
        required_share_count,
        usize::from(FOUNDATION_PROFILE.reconstruction_threshold),
        "prototype-profile evidence must require four target-decryption shares"
    );
    phase("generating the proof-backed share quorum with real succinct proofs");
    let mut target_share_proofs = Vec::with_capacity(required_share_count);
    let selected_participants = setup_binding
        .participants
        .iter()
        .step_by(2)
        .take(required_share_count)
        .collect::<Vec<_>>();
    assert_eq!(selected_participants.len(), required_share_count);
    for participant in selected_participants {
        let trustee_identity = participant.trustee_identity.as_str();
        let local_target_share_witness_value = local_target_share_witness_for_fixture(
            setup_fixture,
            &setup_package,
            &accepted,
            &target_ciphertext_binding,
            &target_ciphertexts,
            trustee_identity,
        );
        let target_share_proof = with_staged_aggregate_opening_material_for_fixture(
            setup_fixture,
            &local_target_share_witness_value,
            || {
                generate_bgv_target_decryption_share_proof_request_for_test(&json!({
                    "setupPackage": setup_package,
                    "localTargetShareWitness": local_target_share_witness_value,
                    "targetAcceptedRecord": accepted,
                    "targetCiphertextBinding": target_ciphertext_binding,
                    "targetCiphertexts": target_ciphertexts,
                    "trusteeRosterPosition": participant.roster_position,
                    "proofRandomnessSeedHex": hash512_hex(
                        "sealed-lattice/tests/replay-release-proof-randomness-seed",
                        &[trustee_identity.as_bytes()],
                    ),
                }))
            },
        )
        .expect("target share proof");
        target_share_proofs.push(target_share_proof);
        phase(&format!("proved share for {trustee_identity}"));
    }

    phase("releasing the genuine target through the staged session");
    let release_verification_id = "replay-release-prototype-profile";
    let release_result = staged_target_result_release(
        &setup_package,
        &accepted,
        &target_ciphertext_binding,
        &target_ciphertexts,
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
    finish_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": release_verification_id,
    }))
    .expect_err("a consumed release session must refuse a second finish");

    phase("done");
}
