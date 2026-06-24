use super::*;

#[test]
fn target_partdec_recombines_selected_sparse_target() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let first_share = generate_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let third_share = generate_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-3",
    );

    let recombined = recombine_bgv_target_decryption_shares_from_request(&json!({
        "setupPackage": setup_package,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "decryptionShares": [third_share, first_share],
    }))
    .expect("recombine target");

    let decoded_ids = recombined["decodedTargetIds"]
        .as_array()
        .expect("target ids")
        .iter()
        .map(|value| value.as_u64().expect("id"))
        .collect::<Vec<_>>();
    let decoded_orders = recombined["decodedTargetOrders"]
        .as_array()
        .expect("target orders")
        .iter()
        .map(|value| value.as_u64().expect("order"))
        .collect::<Vec<_>>();

    assert_eq!(decoded_ids[0], 1);
    assert_eq!(decoded_ids[1], 0);
    assert_eq!(decoded_ids[2], 3);
    assert_eq!(decoded_orders[0], 1);
    assert_eq!(decoded_orders[1], 0);
    assert_eq!(decoded_orders[2], 2);
    assert_eq!(recombined["decryptScaling"], json!(1));
    assert_eq!(recombined["selectedBoardPositions"], json!([2, 3]));
    assert_eq!(recombined["selectedRosterPositions"], json!([2, 0]));
    assert_eq!(
        recombined["recombinationInputReport"]["objectType"],
        "TargetDecryptionRecombinationInputReport"
    );
    assert_eq!(
        recombined["recombinationInputReport"]["selectedShareCount"],
        json!(2_u64)
    );
    assert_eq!(
        recombined["recombinationInputReport"]["selectedShares"][0]["boardPosition"],
        json!(2_u64)
    );
    assert_eq!(
        recombined["recombinationInputReport"]["selectedShares"][0]["smudgingInputReportHash"],
        third_share["sharePayload"]["smudgingInputReportHash"]
    );
    assert_eq!(
        recombined["recombinationInputReport"]["selectedShares"][1]["smudgingInputReportHash"],
        first_share["sharePayload"]["smudgingInputReportHash"]
    );
    assert_eq!(
        recombined["recombinationInputReport"]["smudgingProfileId"],
        json!(TARGET_DECRYPTION_SMUDGING_PROFILE_ID)
    );
    assert_eq!(
        recombined["recombinationInputReport"]["smudgingCombinationRule"],
        json!(TARGET_DECRYPTION_SMUDGING_ZERO_SHARING_RULE)
    );
    assert_eq!(
        recombined["recombinationInputReport"]["activeRnsLimbCount"],
        json!(7_u64)
    );
    assert_eq!(
        recombined["recombinationInputReportHash"],
        json!(
            derive_protocol_hash(
                "TargetDecryptionRecombinationInputReportHash",
                &recombined["recombinationInputReport"]
            )
            .expect("recombination input report hash")
        )
    );
    let first_limb_report = &recombined["recombinationInputReport"]["activeRnsLimbReports"][0];
    let rns_prime = first_limb_report["rnsPrime"]
        .as_u64()
        .expect("recombination limb prime");
    assert_eq!(
        first_limb_report["lagrangeTerms"]
            .as_array()
            .expect("first limb Lagrange terms")
            .len(),
        2
    );
    for lagrange_term in first_limb_report["lagrangeTerms"]
        .as_array()
        .expect("first limb Lagrange terms")
    {
        let denominator = lagrange_term["denominatorProductModuloPrime"]
            .as_u64()
            .expect("denominator product");
        let coefficient = lagrange_term["lagrangeCoefficientModuloPrime"]
            .as_u64()
            .expect("Lagrange coefficient");
        let numerator = lagrange_term["numeratorProductModuloPrime"]
            .as_u64()
            .expect("numerator product");
        assert_eq!(
            ((u128::from(denominator) * u128::from(coefficient)) % u128::from(rns_prime)) as u64,
            numerator
        );
    }
    assert!(
        recombined["recombinationInputReport"]["decodingMargin"]["centeredPositiveMargin"]
            .as_u64()
            .expect("centered positive margin")
            > 0
    );
    assert_eq!(profile_hash().expect("profile hash").len(), 128);
}

#[test]
fn target_recombination_selects_first_valid_shares_in_board_order() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let first_share = generate_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let second_share = generate_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-2",
    );
    let third_share = generate_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-3",
    );

    let recombined = recombine_bgv_target_decryption_shares_from_request(&json!({
        "setupPackage": setup_package,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "decryptionShares": [first_share, third_share, second_share],
    }))
    .expect("recombine target");

    assert_eq!(recombined["selectedBoardPositions"], json!([1, 2]));
    assert_eq!(recombined["selectedRosterPositions"], json!([1, 2]));
}

#[test]
fn target_recombination_rejects_wrong_target_and_duplicate_trustee() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let first_share = generate_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let mut wrong_record = accepted_record.clone();
    wrong_record["targetCiphertextHash"] = json!("0".repeat(128));

    assert!(
        generate_bgv_target_decryption_share_from_request(&json!({
            "setupPackage": setup_package,
            "setupPrivateWitness": {
                "setupSeed": "target-decryption-setup-seed",
            },
            "targetAcceptedRecord": wrong_record,
            "targetCiphertextBinding": target_ciphertext_binding,
            "targetCiphertexts": target_ciphertexts,
            "targetShareProfile": target_share_profile,
            "trusteeIdentity": "trustee-2",
        }))
        .is_err()
    );

    assert!(
        recombine_bgv_target_decryption_shares_from_request(&json!({
            "setupPackage": setup_package,
            "targetAcceptedRecord": accepted_record,
            "targetCiphertextBinding": target_ciphertext_binding,
            "targetCiphertexts": target_ciphertexts,
            "targetShareProfile": target_share_profile,
            "decryptionShares": [first_share.clone(), first_share],
        }))
        .is_err()
    );
}

#[test]
fn target_decryption_rejects_noncanonical_target_ciphertext_level() {
    let (setup_package, accepted_record, target_ciphertext_binding, mut target_ciphertexts) =
        target_fixture();
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        "target-decryption-setup-seed",
    )
    .expect("evaluator key");
    let mut ids = vec![0_u64; MAXIMUM_OPTION_COUNT];
    let mut orders = vec![0_u64; MAXIMUM_OPTION_COUNT];
    ids[0] = 1;
    ids[2] = 3;
    orders[0] = 1;
    orders[2] = 2;
    let (target_id_slots, target_order_slots) = sparse_target_slots(&ids, &orders);
    let target_id = level_zero_ciphertext(&evaluator_key, &target_id_slots, "level-zero-id");
    let target_order =
        level_zero_ciphertext(&evaluator_key, &target_order_slots, "level-zero-order");
    target_ciphertexts["targetIdCanonicalBytesHex"] = json!(
        crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_id)
            .expect("target id hex")
    );
    target_ciphertexts["targetOrderCanonicalBytesHex"] = json!(
        crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_order)
            .expect("target order hex")
    );
    let target_share_profile = target_share_profile(&setup_package);

    let result = generate_bgv_target_decryption_share_from_request(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": "target-decryption-setup-seed",
        },
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }));

    let error = result.expect_err("noncanonical target ciphertext level must be refused");
    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("must use the canonical target ciphertext level")
    );
}

#[test]
fn target_share_profile_rejects_threshold_downgrade() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let mut downgraded_profile = target_share_profile(&setup_package);
    downgraded_profile["decryptionThreshold"] = json!(1);
    downgraded_profile["minimumSharesForInterpolation"] = json!(1);
    downgraded_profile["decryptionShareQuorum"] = json!(1);
    let mut hash_input = downgraded_profile.clone();
    hash_input
        .as_object_mut()
        .expect("target share profile object")
        .remove("targetShareProfileHash");
    downgraded_profile["targetShareProfileHash"] = json!(
        derive_protocol_hash("TargetDecryptionShareProfileHash", &hash_input)
            .expect("downgraded profile hash")
    );

    let result = generate_bgv_target_decryption_share_from_request(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": "target-decryption-setup-seed",
        },
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": downgraded_profile,
        "trusteeIdentity": "trustee-1",
    }));

    let error = result.expect_err("downgraded target share profile must be refused");
    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("decryptionThreshold must match the setup roster-derived threshold")
    );
}
