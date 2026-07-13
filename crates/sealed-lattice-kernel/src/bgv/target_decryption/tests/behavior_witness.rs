use super::*;

#[test]
fn target_decryption_smudging_zero_shares_cancel_for_interpolation_quorum() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    let target_share_profile_binding =
        read_target_share_profile(&target_share_profile_value, &setup_binding)
            .expect("target share profile");
    let target_accepted =
        read_target_accepted_binding(&accepted_record, &setup_binding).expect("target accepted");
    let target_ciphertext_pair = read_target_ciphertext_pair(
        &target_ciphertexts,
        &target_ciphertext_binding,
        &target_accepted,
    )
    .expect("target ciphertext pair");
    let selected_participants = setup_binding
        .participants
        .iter()
        .take(target_share_profile_binding.minimum_shares_for_interpolation)
        .collect::<Vec<_>>();
    assert_eq!(
        selected_participants.len(),
        target_share_profile_binding.minimum_shares_for_interpolation,
        "fixture must include enough participants for interpolation"
    );

    let mut interpolation_points = Vec::with_capacity(selected_participants.len());
    let mut target_id_smudging_by_participant = Vec::with_capacity(selected_participants.len());
    let mut target_order_smudging_by_participant = Vec::with_capacity(selected_participants.len());
    for participant in selected_participants {
        interpolation_points.push(
            participant
                .interpolation_point()
                .expect("participant interpolation point"),
        );
        let local_target_share_witness_value = local_target_share_witness(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &participant.trustee_identity,
        );
        let local_witness =
            with_staged_aggregate_opening_material(&local_target_share_witness_value, || {
                read_local_target_decryption_share_witness(
                    &local_target_share_witness_value,
                    &setup_binding,
                    &target_accepted,
                    &target_ciphertext_pair,
                    &target_share_profile_binding,
                    participant,
                )
                .expect("local target-share witness")
            });
        let local_share = generate_local_share(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &local_target_share_witness_value,
            &participant.trustee_identity,
        );

        let released_target_id_partials = read_partial_limb_set(
            &local_share["sharePayload"],
            "targetId",
            target_ciphertext_pair.target_id.level,
        )
        .expect("released target-id partials");
        let released_target_order_partials = read_partial_limb_set(
            &local_share["sharePayload"],
            "targetOrder",
            target_ciphertext_pair.target_order.level,
        )
        .expect("released target-order partials");
        let unsmudged_target_id_partials = partial_decryption_by_limb(
            &target_ciphertext_pair.target_id,
            &local_witness.secret_share_by_limb,
        )
        .expect("unsmudged target-id partials");
        let unsmudged_target_order_partials = partial_decryption_by_limb(
            &target_ciphertext_pair.target_order,
            &local_witness.secret_share_by_limb,
        )
        .expect("unsmudged target-order partials");

        target_id_smudging_by_participant.push(
            limbwise_difference(&released_target_id_partials, &unsmudged_target_id_partials)
                .expect("target-id smudging difference"),
        );
        target_order_smudging_by_participant.push(
            limbwise_difference(
                &released_target_order_partials,
                &unsmudged_target_order_partials,
            )
            .expect("target-order smudging difference"),
        );
    }

    assert_smudging_recombines_to_zero(
        "target-id",
        &interpolation_points,
        &target_id_smudging_by_participant,
    );
    assert_smudging_recombines_to_zero(
        "target-order",
        &interpolation_points,
        &target_order_smudging_by_participant,
    );
}

#[test]
fn target_decryption_quorum_release_recovers_target_slots() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    let target_share_profile_binding =
        read_target_share_profile(&target_share_profile_value, &setup_binding)
            .expect("target share profile");
    let target_accepted =
        read_target_accepted_binding(&accepted_record, &setup_binding).expect("target accepted");
    let target_ciphertext_pair = read_target_ciphertext_pair(
        &target_ciphertexts,
        &target_ciphertext_binding,
        &target_accepted,
    )
    .expect("target ciphertext pair");

    let selected_participants = setup_binding
        .participants
        .iter()
        .take(target_share_profile_binding.minimum_shares_for_interpolation)
        .collect::<Vec<_>>();
    assert_eq!(
        selected_participants.len(),
        target_share_profile_binding.minimum_shares_for_interpolation,
        "fixture must include enough participants for interpolation"
    );
    let mut interpolation_points = Vec::with_capacity(selected_participants.len());
    let mut target_id_partials_by_share = Vec::with_capacity(selected_participants.len());
    let mut target_order_partials_by_share = Vec::with_capacity(selected_participants.len());
    for participant in selected_participants {
        let local_target_share_witness_value = local_target_share_witness(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &participant.trustee_identity,
        );
        let local_share = generate_local_share(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &local_target_share_witness_value,
            &participant.trustee_identity,
        );
        interpolation_points.push(
            participant
                .interpolation_point()
                .expect("participant interpolation point"),
        );
        target_id_partials_by_share.push(
            read_partial_limb_set(
                &local_share["sharePayload"],
                "targetId",
                target_ciphertext_pair.target_id.level,
            )
            .expect("target-id partials"),
        );
        target_order_partials_by_share.push(
            read_partial_limb_set(
                &local_share["sharePayload"],
                "targetOrder",
                target_ciphertext_pair.target_order.level,
            )
            .expect("target-order partials"),
        );
    }
    assert_eq!(
        target_id_partials_by_share.len(),
        target_share_profile_binding.minimum_shares_for_interpolation
    );

    let target_id_partial_refs = target_id_partials_by_share
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let target_order_partial_refs = target_order_partials_by_share
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let target_id_slots = release_target_role_slots(
        &target_ciphertext_pair.target_id,
        &interpolation_points,
        &target_id_partial_refs,
    )
    .expect("target-id release");
    let target_order_slots = release_target_role_slots(
        &target_ciphertext_pair.target_order,
        &interpolation_points,
        &target_order_partial_refs,
    )
    .expect("target-order release");

    let mut expected_target_ids = vec![0_u64; MAXIMUM_OPTION_COUNT];
    let mut expected_target_orders = vec![0_u64; MAXIMUM_OPTION_COUNT];
    expected_target_ids[0] = 1;
    expected_target_ids[2] = 3;
    expected_target_orders[0] = 1;
    expected_target_orders[2] = 2;
    assert_eq!(
        packed_target_option_values(&target_id_slots, target_ciphertext_pair.top_count)
            .expect("target-id options"),
        expected_target_ids
    );
    assert_eq!(
        packed_target_option_values(&target_order_slots, target_ciphertext_pair.top_count)
            .expect("target-order options"),
        expected_target_orders
    );

    let mut tampered_target_id_partials_by_share = target_id_partials_by_share;
    tampered_target_id_partials_by_share[0][0][0] = add_mod_fast(
        tampered_target_id_partials_by_share[0][0][0],
        1,
        DATA_PRIMES[0],
    );
    let tampered_target_id_partial_refs = tampered_target_id_partials_by_share
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let tampered_target_id_slots = release_target_role_slots(
        &target_ciphertext_pair.target_id,
        &interpolation_points,
        &tampered_target_id_partial_refs,
    )
    .expect("tampered target-id release");
    assert_ne!(
        packed_target_option_values(&tampered_target_id_slots, target_ciphertext_pair.top_count)
            .expect("tampered target-id options"),
        expected_target_ids
    );
}

#[test]
fn target_result_release_requires_proof_backed_quorum() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let error = staged_target_result_release(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        Vec::new(),
        "rust-target-release-empty",
    )
    .expect_err("target result release must require a quorum");

    assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    assert!(error.message.contains("share quorum"));

    let raw_share = generate_share_from_fresh_local_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-1",
    );
    let error = staged_target_result_release(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        vec![
            json!({ "targetDecryptionShare": raw_share.clone() }),
            json!({ "targetDecryptionShare": raw_share }),
        ],
        "rust-target-release-proofless",
    )
    .expect_err("target result release must reject proofless shares");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("proofStatement"));
}
