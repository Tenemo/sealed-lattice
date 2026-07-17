use super::*;

const TEST_TARGET_SHARE_PROOF_BYTES: [u8; 5] = [1, 2, 3, 4, 5];
const TEST_OTHER_FAMILY_PROOF_BYTES: [u8; 7] = [9, 8, 7, 6, 5, 4, 3];

#[test]
fn target_share_proof_statement_binds_local_witness_and_share() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        "trustee-1",
    );
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &local_target_share_witness_value,
        "trustee-1",
    );

    let statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
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
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        "trustee-1",
    );
    let mut local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &local_target_share_witness_value,
        "trustee-1",
    );
    change_first_partial_decryption_coefficient(&mut local_share);

    let error = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
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
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        "trustee-1",
    );
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &local_target_share_witness_value,
        "trustee-1",
    );
    let mut statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");
    let first_material_root =
        statement["aggregateOpeningCredentials"][0]["aggregateCommitment"]["materialRootHex"]
            .as_str()
            .expect("first aggregate commitment material root")
            .to_string();
    let mut tampered_material_root_bytes = crate::transcript_core::decode_hex(&first_material_root)
        .expect("aggregate material root bytes");
    tampered_material_root_bytes[0] ^= 0x01;
    statement["aggregateOpeningCredentials"][0]["aggregateCommitment"]["materialRootHex"] = json!(
        crate::transcript_core::encode_hex(&tampered_material_root_bytes)
    );
    let error = verify_share_proof_statement_binding(TargetShareProofStatementBindingInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
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
    let first_share_proof = statement_backed_target_share_with_test_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        "trustee-1",
    );
    let second_share_proof = statement_backed_target_share_with_test_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        "trustee-2",
    );
    let mut wrong_target_record = accepted_record.clone();
    wrong_target_record["targetCiphertextHash"] = json!("8".repeat(128));

    let error = staged_target_result_release(
        &setup_package,
        &wrong_target_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        vec![first_share_proof, second_share_proof],
        "rust-target-release-wrong-context",
    )
    .expect_err("target result release must reject shares bound to another target ciphertext");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("target ciphertext pair"));
}

#[test]
fn target_result_release_consumes_proof_material_only_at_the_active_verification_boundary() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_proof = statement_backed_target_share_with_test_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        "trustee-1",
    );
    let proof_bytes_hash = target_share_proof["proofMaterial"]["proofBytesHash"]
        .as_str()
        .expect("target share proof bytes hash");
    crate::bgv::setup::authenticate_setup_proof_material_stream_for_test(
        crate::bgv::setup::TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        proof_bytes_hash,
        &TEST_TARGET_SHARE_PROOF_BYTES,
    )
    .expect("authenticate target share proof material");

    let inactive_session_error =
        absorb_bgv_target_decryption_result_release_share_for_test(&json!({
            "releaseVerificationId": "rust-target-release-proof-lifecycle-inactive",
            "targetShareProof": target_share_proof.clone(),
        }))
        .expect_err("an inactive release session must refuse the share");
    assert_eq!(
        inactive_session_error.code,
        CanonicalErrorCode::InvalidProtocolObject
    );
    assert!(inactive_session_error.message.contains("is not active"));

    begin_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": "rust-target-release-proof-lifecycle-first",
        "setupPackage": setup_package,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
    }))
    .expect("begin first target release verification");
    let verification_error = absorb_bgv_target_decryption_result_release_share_for_test(&json!({
        "releaseVerificationId": "rust-target-release-proof-lifecycle-first",
        "targetShareProof": target_share_proof.clone(),
    }))
    .expect_err("the pending common proof suite must refuse the proof");
    assert_eq!(
        verification_error.code,
        CanonicalErrorCode::InvalidProtocolObject
    );
    assert!(verification_error.message.contains("common proof suite"));
    let first_aborted_session_error =
        finish_bgv_target_decryption_result_release_for_test(&json!({
            "releaseVerificationId": "rust-target-release-proof-lifecycle-first",
        }))
        .expect_err("the failed verification must abort its release session");
    assert!(
        first_aborted_session_error
            .message
            .contains("is not active")
    );

    begin_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": "rust-target-release-proof-lifecycle-second",
        "setupPackage": setup_package,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
    }))
    .expect("begin second target release verification");
    let consumed_material_error =
        absorb_bgv_target_decryption_result_release_share_for_test(&json!({
            "releaseVerificationId": "rust-target-release-proof-lifecycle-second",
            "targetShareProof": target_share_proof,
        }))
        .expect_err("the first verification attempt must consume the proof material");
    assert_eq!(
        consumed_material_error.code,
        CanonicalErrorCode::InvalidProtocolObject
    );
    assert!(
        consumed_material_error
            .message
            .contains("missing canonical stream-authenticated bytes")
    );
    let aborted_session_error = finish_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": "rust-target-release-proof-lifecycle-second",
    }))
    .expect_err("a refused share must abort its release session");
    assert!(aborted_session_error.message.contains("is not active"));
}

#[test]
fn target_result_release_does_not_consume_another_proof_family() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let mut target_share_proof = statement_backed_target_share_with_test_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        "trustee-1",
    );
    let public_key_share_proof_bytes_hash = hash512_hex(
        "sealed-lattice/setup/public-key-share/succinct-proof-bytes",
        &[&TEST_OTHER_FAMILY_PROOF_BYTES],
    );
    target_share_proof["proofMaterial"]["proofBytesHash"] =
        json!(public_key_share_proof_bytes_hash.clone());
    crate::bgv::setup::authenticate_setup_proof_material_stream_for_test(
        "public-key-share",
        &public_key_share_proof_bytes_hash,
        &TEST_OTHER_FAMILY_PROOF_BYTES,
    )
    .expect("authenticate another proof family's material");

    begin_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": "rust-target-release-wrong-proof-family",
        "setupPackage": setup_package,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
    }))
    .expect("begin target release verification");
    let verification_error = absorb_bgv_target_decryption_result_release_share_for_test(&json!({
        "releaseVerificationId": "rust-target-release-wrong-proof-family",
        "targetShareProof": target_share_proof,
    }))
    .expect_err("a target share must refuse another proof family's material");
    assert_eq!(
        verification_error.code,
        CanonicalErrorCode::ComponentMismatch
    );
    assert!(
        verification_error
            .message
            .contains("different proof family")
    );

    let retained_material = crate::bgv::setup::take_authenticated_canonical_proof_material_bytes(
        "public-key-share",
        &public_key_share_proof_bytes_hash,
    )
    .expect("look up another proof family's material");
    assert!(
        retained_material.is_some(),
        "a target verification attempt must not evict another proof family's bytes"
    );
    let aborted_session_error = finish_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": "rust-target-release-wrong-proof-family",
    }))
    .expect_err("a refused share must abort its release session");
    assert!(aborted_session_error.message.contains("is not active"));
}

fn statement_backed_target_share_with_test_proof_material(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    trustee_identity: &str,
) -> Value {
    let local_target_share_witness_value = local_target_share_witness(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        trustee_identity,
    );
    let target_decryption_share = generate_local_share(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        &local_target_share_witness_value,
        trustee_identity,
    );
    let proof_statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &target_decryption_share,
        trustee_identity,
    })
    .expect("target share proof statement");

    let proof_material = json!({
        "objectType": "BgvTargetDecryptionShareProofMaterial",
        "proofBytesHash": hash512_hex(
            "sealed-lattice/target-decryption/share-proof/proof-bytes",
            &[&TEST_TARGET_SHARE_PROOF_BYTES],
        ),
    });
    json!({
        "targetDecryptionShare": target_decryption_share,
        "proofStatement": proof_statement,
        "proofMaterial": proof_material,
    })
}
