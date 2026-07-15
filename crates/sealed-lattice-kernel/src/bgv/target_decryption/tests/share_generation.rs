use super::*;

#[test]
fn private_flooding_seed_controls_only_private_noise_and_its_commitment() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let first_witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let mut second_witness = first_witness.clone();
    second_witness["privateFloodingSeedHex"] = json!("a5".repeat(64));

    let first_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &first_witness,
        "trustee-1",
    );
    let repeated_first_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &first_witness,
        "trustee-1",
    );
    let second_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &second_witness,
        "trustee-1",
    );

    assert_eq!(first_share, repeated_first_share);
    assert_ne!(first_share["sharePayload"], second_share["sharePayload"]);

    let first_statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &first_witness,
        target_decryption_share: &first_share,
        trustee_identity: "trustee-1",
    })
    .expect("first proof statement");
    let second_statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &second_witness,
        target_decryption_share: &second_share,
        trustee_identity: "trustee-1",
    })
    .expect("second proof statement");
    assert_ne!(
        target_decryption_smudging_commitment_set_root(&first_statement["smudgingCommitmentSet"])
            .expect("first smudging commitment set root"),
        target_decryption_smudging_commitment_set_root(&second_statement["smudgingCommitmentSet"])
            .expect("second smudging commitment set root")
    );
    assert!(!first_statement
        .to_string()
        .contains("privateFloodingSeedHex"));
}

#[test]
fn private_flooding_seed_must_be_full_lowercase_hex() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    for invalid_seed in [String::new(), "00".repeat(63), "AA".repeat(64)] {
        let mut invalid_witness = witness.clone();
        invalid_witness["privateFloodingSeedHex"] = json!(invalid_seed);
        let error = with_staged_aggregate_opening_material(&invalid_witness, || {
            generate_bgv_target_decryption_share_from_local_share_request(&json!({
                "setupPackage": setup_package,
                "localTargetShareWitness": invalid_witness,
                "targetAcceptedRecord": accepted_record,
                "targetCiphertextBinding": target_ciphertext_binding,
                "targetCiphertexts": target_ciphertexts,
                "targetShareProfile": target_share_profile,
                "trusteeIdentity": "trustee-1",
            }))
        })
        .expect_err("malformed private flooding seed must reject");
        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(error.message.contains("64 lowercase-hexadecimal bytes"));
    }
}

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

    let error = result.expect_err("noncanonical target ciphertext level must be refused");
    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(
        error
            .message
            .contains("target ciphertexts must use the canonical target BGV level"),
        "{}",
        error.message
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
    let accepted_record_for_trustee = &setup_package["vssPublicAggregateThresholdCommitmentSet"]
        ["recipientRecords"][CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1];
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
    seed_tampered_witness["aggregateOpening"]["aggregateOpeningCredentials"][0]
        ["aggregateMaterialSeedHex"] = json!("0".repeat(128));
    let seed_error = with_staged_aggregate_opening_material(&seed_tampered_witness, || {
        generate_bgv_target_decryption_share_from_local_share_request(&json!({
            "setupPackage": setup_package.clone(),
            "localTargetShareWitness": seed_tampered_witness,
            "targetAcceptedRecord": accepted_record.clone(),
            "targetCiphertextBinding": target_ciphertext_binding.clone(),
            "targetCiphertexts": target_ciphertexts.clone(),
            "targetShareProfile": target_share_profile.clone(),
            "trusteeIdentity": "trustee-1",
        }))
    })
    .expect_err("a changed aggregate material seed must be refused");
    assert_eq!(seed_error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(seed_error.message.contains("credential commitment root"));

    let message_error = with_staged_aggregate_opening_material_transform(
        &local_witness,
        |aggregate_opening_root, material| {
            if aggregate_opening_root
                == local_witness["aggregateOpening"]["aggregateOpeningCredentials"][0]
                    ["aggregateOpeningRoot"]
                    .as_str()
                    .expect("first aggregate opening root")
            {
                let mut first_value =
                    u64::from_le_bytes(material[..8].try_into().expect("first aggregate value"));
                first_value = add_mod_fast(first_value, 1, DATA_PRIMES[0]);
                material[..8].copy_from_slice(&first_value.to_le_bytes());
            }
        },
        || {
            generate_bgv_target_decryption_share_from_local_share_request(&json!({
                "setupPackage": setup_package.clone(),
                "localTargetShareWitness": local_witness.clone(),
                "targetAcceptedRecord": accepted_record.clone(),
                "targetCiphertextBinding": target_ciphertext_binding.clone(),
                "targetCiphertexts": target_ciphertexts.clone(),
                "targetShareProfile": target_share_profile.clone(),
                "trusteeIdentity": "trustee-1",
            }))
        },
    )
    .expect_err("a changed aggregate material column must be refused");
    assert_eq!(message_error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(message_error.message.contains("credential commitment root"));

    let mut merkle_root_tampered_setup_package = setup_package;
    let aggregate_record = &mut merkle_root_tampered_setup_package
        ["vssPublicAggregateThresholdCommitmentSet"]["recipientRecords"][0];
    let material_root_hex = aggregate_record["commitment"]["commitmentFields"][0]
        ["materialRootHex"]
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
    aggregate_record["aggregateCommitmentRoot"] = json!(derive_canonical_object_hash(
        &aggregate_record["commitment"]
    )
    .expect("tampered aggregate commitment root"));
    let aggregate_set =
        &mut merkle_root_tampered_setup_package["vssPublicAggregateThresholdCommitmentSet"];
    let mut aggregate_set_without_root = aggregate_set
        .as_object()
        .expect("aggregate threshold commitment set")
        .clone();
    aggregate_set_without_root.remove("aggregateThresholdCommitmentRoot");
    aggregate_set["aggregateThresholdCommitmentRoot"] = json!(derive_canonical_object_hash(
        &Value::Object(aggregate_set_without_root)
    )
    .expect("tampered aggregate threshold commitment root"));
    let merkle_root_tampered_witness = local_witness;
    let merkle_root_error =
        with_staged_aggregate_opening_material(&merkle_root_tampered_witness, || {
            generate_bgv_target_decryption_share_from_local_share_request(&json!({
                "setupPackage": merkle_root_tampered_setup_package,
                "localTargetShareWitness": merkle_root_tampered_witness,
                "targetAcceptedRecord": accepted_record,
                "targetCiphertextBinding": target_ciphertext_binding,
                "targetCiphertexts": target_ciphertexts,
                "targetShareProfile": target_share_profile,
                "trusteeIdentity": "trustee-1",
            }))
        })
        .expect_err("a changed aggregate Merkle root must be refused");
    assert_eq!(
        merkle_root_error.code,
        CanonicalErrorCode::ComponentMismatch
    );
    assert!(
        merkle_root_error
            .message
            .contains("does not match its target decryption binding"),
        "{}",
        merkle_root_error.message
    );
}
