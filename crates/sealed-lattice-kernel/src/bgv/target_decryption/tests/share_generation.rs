use super::*;

#[test]
fn target_share_generation_rejects_wrong_target_record() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-2",
    );
    let mut wrong_record = accepted_record.clone();
    wrong_record["targetCiphertextHash"] = json!("0".repeat(128));

    assert!(
        generate_bgv_target_decryption_share_from_local_share_request(&json!({
            "setupPackage": setup_package,
            "localTargetShareWitness": local_target_share_witness_value,
            "targetAcceptedRecord": wrong_record,
            "targetCiphertextBinding": target_ciphertext_binding,
            "targetCiphertexts": target_ciphertexts,
            "targetShareProfile": target_share_profile,
            "trusteeIdentity": "trustee-2",
        }))
        .is_err()
    );
}

#[test]
fn target_decryption_rejects_noncanonical_target_ciphertext_level() {
    let (setup_package, accepted_record, target_ciphertext_binding, mut target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let evaluator_key = target_decryption_evaluator_key();
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

    let result = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": local_target_share_witness_value,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }));

    // A non-canonical target ciphertext level is rejected because the accepted
    // target record binds the canonical-level (level 6) ciphertext roots through
    // targetCiphertextHash: level-zero ciphertexts hash to different roots, so the
    // pair no longer matches the accepted ciphertext hash. The level is enforced
    // by that binding, not by a standalone level assertion.
    let error = result.expect_err("noncanonical target ciphertext level must be refused");
    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(
        error
            .message
            .contains("target ciphertext pair does not match the accepted target ciphertext hash"),
        "{}",
        error.message
    );
}

#[test]
fn target_share_profile_rejects_threshold_downgrade() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let mut downgraded_profile = target_share_profile;
    downgraded_profile["decryptionThreshold"] = json!(1);
    downgraded_profile["minimumSharesForInterpolation"] = json!(1);
    downgraded_profile["decryptionShareQuorum"] = json!(1);
    let mut hash_input = downgraded_profile.clone();
    hash_input
        .as_object_mut()
        .expect("target share profile object")
        .remove("targetShareProfileHash");
    downgraded_profile["targetShareProfileHash"] =
        json!(derive_canonical_object_hash(&hash_input).expect("downgraded profile hash"));

    let result = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": local_target_share_witness_value,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": downgraded_profile,
        "trusteeIdentity": "trustee-1",
    }));

    let error = result.expect_err("downgraded target share profile must be refused");
    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(
        error
            .message
            .contains("decryptionThreshold must match the setup roster-derived threshold")
    );
}
