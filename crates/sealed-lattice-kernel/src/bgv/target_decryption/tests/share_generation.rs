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
        "setupPackage": setup_package.clone(),
        "localTargetShareWitness": local_target_share_witness_value,
        "targetAcceptedRecord": accepted_record.clone(),
        "targetCiphertextBinding": target_ciphertext_binding.clone(),
        "targetCiphertexts": target_ciphertexts.clone(),
        "targetShareProfile": target_share_profile.clone(),
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

#[test]
fn target_share_generation_uses_the_setup_aggregate_opening_handoff() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-2",
    );
    let first_credential = &local_witness["aggregateOpening"]["aggregateOpeningCredentials"][0];
    let accepted_record_for_trustee = &setup_package["vssPublicAggregateThresholdCommitmentSet"]["recipientRecords"]
        [CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1];
    assert_eq!(
        first_credential["aggregateCommitmentRoot"],
        accepted_record_for_trustee["aggregateCommitmentRoot"]
    );
    assert_eq!(
        first_credential["aggregateOpeningRoot"],
        accepted_record_for_trustee["aggregateOpeningRoot"]
    );

    generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_witness,
        "trustee-2",
    );
}

#[test]
fn target_share_generation_rejects_tampered_aggregate_opening_credentials() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    let mut seed_tampered_witness = local_witness.clone();
    seed_tampered_witness["aggregateOpening"]["aggregateOpeningCredentials"][0]["aggregateMaterialSeedHex"] =
        json!("0".repeat(128));
    let seed_error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package.clone(),
        "localTargetShareWitness": seed_tampered_witness,
        "targetAcceptedRecord": accepted_record.clone(),
        "targetCiphertextBinding": target_ciphertext_binding.clone(),
        "targetCiphertexts": target_ciphertexts.clone(),
        "targetShareProfile": target_share_profile.clone(),
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("a changed aggregate material seed must be refused");
    assert_eq!(seed_error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(seed_error.message.contains("credential commitment root"));

    let mut message_tampered_witness = local_witness.clone();
    let credential =
        &mut message_tampered_witness["aggregateOpening"]["aggregateOpeningCredentials"][0];
    let mut message_coefficients = coefficient_vector_from_le_hex(
        credential["aggregateCommitmentMessageValuesLeHex"]
            .as_str()
            .expect("aggregate commitment message"),
        POLYNOMIAL_DEGREE,
        "aggregate opening credential message byte length must match ringDegree",
    )
    .expect("aggregate commitment message coefficients");
    message_coefficients[0] = add_mod_fast(message_coefficients[0], 1, DATA_PRIMES[0]);
    credential["aggregateCommitmentMessageValuesLeHex"] =
        json!(coefficient_vector_le_hex(&message_coefficients));
    let message_error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package.clone(),
        "localTargetShareWitness": message_tampered_witness,
        "targetAcceptedRecord": accepted_record.clone(),
        "targetCiphertextBinding": target_ciphertext_binding.clone(),
        "targetCiphertexts": target_ciphertexts.clone(),
        "targetShareProfile": target_share_profile.clone(),
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("a changed aggregate material column must be refused");
    assert_eq!(message_error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(message_error.message.contains("credential commitment root"));

    let mut merkle_root_tampered_setup_package = setup_package;
    let aggregate_record = &mut merkle_root_tampered_setup_package["vssPublicAggregateThresholdCommitmentSet"]
        ["recipientRecords"][0];
    let material_root_hex =
        aggregate_record["commitment"]["commitmentFields"][0]["materialRootHex"]
            .as_str()
            .expect("aggregate material root")
            .to_string();
    let replacement_prefix = if material_root_hex.starts_with("00") {
        "01"
    } else {
        "00"
    };
    let mut tampered_material_root_hex = material_root_hex;
    tampered_material_root_hex.replace_range(0..2, replacement_prefix);
    aggregate_record["commitment"]["commitmentFields"][0]["materialRootHex"] =
        json!(tampered_material_root_hex);
    aggregate_record["aggregateCommitmentRoot"] = json!(
        derive_canonical_object_hash(&aggregate_record["commitment"])
            .expect("tampered aggregate commitment root")
    );
    let aggregate_set =
        &mut merkle_root_tampered_setup_package["vssPublicAggregateThresholdCommitmentSet"];
    let mut aggregate_set_without_root = aggregate_set
        .as_object()
        .expect("aggregate threshold commitment set")
        .clone();
    aggregate_set_without_root.remove("aggregateThresholdCommitmentRoot");
    aggregate_set["aggregateThresholdCommitmentRoot"] = json!(
        derive_canonical_object_hash(&Value::Object(aggregate_set_without_root))
            .expect("tampered aggregate threshold commitment root")
    );
    let mut merkle_root_tampered_witness = local_witness;
    merkle_root_tampered_witness["aggregateOpening"]["aggregateThresholdCommitmentRoot"] =
        aggregate_set["aggregateThresholdCommitmentRoot"].clone();
    merkle_root_tampered_witness["targetDecryptionSmudging"]["setupPackageHash"] = json!(
        read_setup_binding(&merkle_root_tampered_setup_package)
            .expect("tampered setup package binding")
            .setup_package_hash
    );
    let merkle_root_error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": merkle_root_tampered_setup_package,
        "localTargetShareWitness": merkle_root_tampered_witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("a changed aggregate Merkle root must be refused");
    assert_eq!(
        merkle_root_error.code,
        CanonicalErrorCode::ComponentMismatch
    );
    assert!(
        merkle_root_error
            .message
            .contains("does not match the accepted aggregate commitment record"),
        "{}",
        merkle_root_error.message
    );
}
