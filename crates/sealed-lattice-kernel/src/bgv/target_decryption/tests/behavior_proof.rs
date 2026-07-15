use super::*;

#[test]
fn target_share_proof_statement_binds_local_witness_and_share() {
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
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );

    let statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    let accepted_binding = read_target_accepted_binding(&accepted_record, &setup_binding)
        .expect("target accepted binding");
    let target_ciphertext_pair = read_target_ciphertext_pair(
        &target_ciphertexts,
        &target_ciphertext_binding,
        &accepted_binding,
    )
    .expect("target ciphertext pair");
    let participant = setup_binding
        .participants
        .iter()
        .find(|participant| participant.trustee_identity == "trustee-1")
        .expect("target decryption participant");
    let proof_request =
        target_decryption_share_all_active_limbs_proof_statement_from_public_inputs(
            TargetDecryptionShareAllActiveLimbsProofStatementInput {
                setup_binding: &setup_binding,
                target_ciphertexts: &target_ciphertext_pair,
                participant,
                target_decryption_share: &local_share,
                proof_statement: &statement,
            },
        )
        .expect("target share succinct proof request");

    assert_eq!(
        statement["objectType"],
        json!("BgvTargetDecryptionShareProofStatement")
    );
    assert_eq!(
        proof_request["context"]["setupContextHash"],
        json!(setup_binding.setup_context_hash)
    );
    assert_eq!(
        statement["targetDecryptionShareHash"],
        json!(target_decryption_share_hash(&local_share).expect("target share hash"))
    );
    assert_eq!(
        statement["aggregateOpeningCredentials"]
            .as_array()
            .expect("aggregate opening credentials")
            .len(),
        CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1
    );

    assert_eq!(
        proof_request["context"]["targetShareProofStatementRoot"],
        json!(target_decryption_share_proof_statement_root(&statement).expect("statement root"))
    );
}

#[test]
fn target_share_proof_relation_rejects_wrong_partial_decryption() {
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
    let mut local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );
    change_first_partial_decryption_coefficient(&mut local_share);

    let error = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect_err("rebound wrong partial decryption must not satisfy the relation");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("restored local witness relation"));
}

#[test]
fn target_share_proof_statement_binding_rejects_wrong_aggregate_commitment_body() {
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
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );
    let mut statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");
    let first_material_root = statement["aggregateOpeningCredentials"][0]["aggregateCommitment"]
        ["commitmentFields"][0]["materialRootHex"]
        .as_str()
        .expect("first aggregate commitment material root")
        .to_string();
    let mut tampered_material_root_bytes = crate::transcript_core::decode_hex(&first_material_root)
        .expect("aggregate material root bytes");
    tampered_material_root_bytes[0] ^= 0x01;
    statement["aggregateOpeningCredentials"][0]["aggregateCommitment"]["commitmentFields"][0]
        ["materialRootHex"] = json!(crate::transcript_core::encode_hex(
        &tampered_material_root_bytes
    ));
    let error = verify_share_proof_statement_binding(TargetShareProofStatementBindingInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        target_decryption_share: &local_share,
        proof_statement: &statement,
    })
    .expect_err("wrong aggregate commitment body must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("commitment body"));
}

#[test]
fn target_result_release_rejects_wrong_target_ciphertext_before_proof_bytes() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let first_share_proof = statement_backed_target_share_with_malformed_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-1",
    );
    let second_share_proof = statement_backed_target_share_with_malformed_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-2",
    );
    let mut wrong_target_record = accepted_record.clone();
    wrong_target_record["targetCiphertextHash"] = json!("8".repeat(128));

    let error = staged_target_result_release(
        &setup_package,
        &wrong_target_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        vec![first_share_proof, second_share_proof],
        "rust-target-release-wrong-context",
    )
    .expect_err("target result release must reject shares bound to another target ciphertext");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("target ciphertext pair"));
}

fn statement_backed_target_share_with_malformed_proof_material(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    trustee_identity: &str,
) -> Value {
    let local_target_share_witness_value = local_target_share_witness(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        trustee_identity,
    );
    let target_decryption_share = generate_local_share(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        &local_target_share_witness_value,
        trustee_identity,
    );
    let proof_statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &target_decryption_share,
        trustee_identity,
    })
    .expect("target share proof statement");

    let proof_bytes = [1_u8, 2, 3, 4, 5];
    let proof_material = json!({
        "objectType": "BgvTargetDecryptionShareProofMaterial",
        "proofBytesHash": hash512_hex(
            "sealed-lattice/target-decryption/share-proof/proof-bytes",
            &[&proof_bytes],
        ),
    });
    json!({
        "targetDecryptionShare": target_decryption_share,
        "proofStatement": proof_statement,
        "proofMaterial": proof_material,
    })
}
