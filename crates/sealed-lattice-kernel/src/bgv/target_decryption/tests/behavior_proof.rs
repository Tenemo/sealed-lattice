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

    assert_eq!(
        statement["objectType"],
        json!("BgvTargetDecryptionShareProofStatement")
    );
    assert_eq!(
        statement["targetDecryptionShareHash"],
        local_share["targetDecryptionShareHash"]
    );
    assert_eq!(statement["shareRoot"], local_share["shareRoot"]);
    assert_eq!(
        statement["setupEpoch"],
        setup_package["setupContext"]["setupEpoch"]
    );
    assert_eq!(
        statement["aggregateOpeningBinding"]["publicMatrixSeedHash"],
        setup_package["commonRandomness"]["publicMatrixSeedHash"]
    );
    assert_eq!(
        statement["aggregateOpeningBinding"]["shareLinkageStatementRoot"],
        setup_package["vssShareLinkageStatement"]["statementRoot"]
    );
    assert_eq!(
        statement["aggregateOpeningBinding"]["aggregateThresholdCommitmentRoot"],
        setup_package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"]
    );
    let expected_active_credential_binding_root = derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionAggregateOpeningCredentialBindingSet",
        "activeCredentialBindings": statement["aggregateOpeningBinding"]["activeCredentialBindings"],
    }))
    .expect("active credential binding root");
    assert_eq!(
        statement["aggregateOpeningBinding"]["activeCredentialBindingRoot"],
        json!(expected_active_credential_binding_root)
    );
    assert_eq!(
        statement["aggregateOpeningBinding"]["activeCredentialBindings"]
            .as_array()
            .expect("active credential bindings")
            .len(),
        CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1
    );

    let mut root_input = statement.clone();
    root_input
        .as_object_mut()
        .expect("statement object")
        .remove("proofStatementRoot");
    assert_eq!(
        statement["proofStatementRoot"],
        json!(derive_canonical_object_hash(&root_input).expect("statement root"))
    );
}

#[test]
fn target_share_proof_statement_binding_rejects_recomputed_root_with_wrong_setup_epoch() {
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
    statement["setupEpoch"] = json!("rebound-setup-epoch");
    rebind_share_proof_statement_root(&mut statement);

    let error = verify_share_proof_statement_binding(TargetShareProofStatementBindingInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        target_decryption_share: &local_share,
        proof_statement: &statement,
    })
    .expect_err("a rebound setup epoch must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("setup epoch"), "{}", error.message);
}

#[test]
fn target_share_proof_relation_rejects_rebound_wrong_partial_decryption() {
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
    rebind_target_decryption_share_hashes(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &mut local_share,
        "trustee-1",
    );

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
fn target_share_proof_statement_binding_accepts_bound_statement() {
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

    let verification =
        verify_share_proof_statement_binding(TargetShareProofStatementBindingInput {
            setup_package: &setup_package,
            accepted_record: &accepted_record,
            target_ciphertext_binding: &target_ciphertext_binding,
            target_ciphertexts: &target_ciphertexts,
            target_share_profile: &target_share_profile,
            target_decryption_share: &local_share,
            proof_statement: &statement,
        })
        .expect("target share proof statement binding");

    assert_eq!(
        verification["operation"],
        json!("verifyBgvTargetDecryptionShareProofStatementBinding")
    );
    // The command validates the statement binding and returns the recomputed
    // statement root; a well-formed bound statement round-trips to its own root.
    assert_eq!(
        verification["proofStatementRoot"],
        statement["proofStatementRoot"]
    );
    assert!(
        verification["proofStatementRoot"]
            .as_str()
            .is_some_and(|root| root.len() == 128)
    );
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_wrong_aggregate_commitment_body() {
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
    let first_material_root =
        statement["aggregateOpeningBinding"]["activeCredentialBindings"][0]["aggregateCommitment"]
            ["commitmentFields"][0]["materialRootHex"]
            .as_str()
            .expect("first aggregate commitment material root")
            .to_string();
    let mut tampered_material_root_bytes = crate::transcript_core::decode_hex(&first_material_root)
        .expect("aggregate material root bytes");
    tampered_material_root_bytes[0] ^= 0x01;
    statement["aggregateOpeningBinding"]["activeCredentialBindings"][0]["aggregateCommitment"]["commitmentFields"]
        [0]["materialRootHex"] = json!(crate::transcript_core::encode_hex(
        &tampered_material_root_bytes
    ));
    rebind_active_credential_binding_root(&mut statement);
    rebind_share_proof_statement_root(&mut statement);

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
fn target_result_release_rejects_wrong_target_context_before_proof_bytes() {
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
    wrong_target_record["targetContextHash"] = json!("8".repeat(128));
    rebind_target_accepted_record_hash(&mut wrong_target_record);

    let error = staged_target_result_release(
        &setup_package,
        &wrong_target_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        vec![first_share_proof, second_share_proof],
        "rust-target-release-wrong-context",
    )
    .expect_err("target result release must reject shares bound to another target context");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(
        error.message.contains("proof statement"),
        "{}",
        error.message
    );
}

#[test]
fn malformed_setup_evicts_stream_authenticated_target_proof_material() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-1",
    );
    let target_decryption_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        &local_target_share_witness_value,
        "trustee-1",
    );
    let proof_statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile_value,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &target_decryption_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");
    let mut malformed_setup_package = setup_package.clone();
    malformed_setup_package["objectType"] = json!("MalformedSetupPackage");

    let proof_bytes = vec![0x53, 0x4c, 0x54, 0x44];
    let proof_record = json!({
        "objectType": "BgvTargetDecryptionShareProofRecord",
        "proofBytesEncoding": "binary-chunked-proof-bytes",
        "proofBytesHash": hash512_hex(
            "sealed-lattice/target-decryption/share-proof/proof-bytes",
            &[&proof_bytes],
        ),
    });
    let mut proof_material = json!({
        "objectType": "BgvTargetDecryptionShareProofMaterial",
        "proofRecords": [proof_record],
    });
    let proof_material_root =
        derive_canonical_object_hash(&proof_material).expect("target proof material root");
    proof_material["proofMaterialRoot"] = json!(&proof_material_root);
    crate::bgv::setup::retain_generated_canonical_proof_material(
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        proof_material_root.clone(),
        proof_bytes,
    )
    .expect("stream-authenticated target proof material fixture");

    let error = verify_bgv_target_decryption_share_proof_material_from_request(&json!({
        "setupPackage": malformed_setup_package,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile_value,
        "targetDecryptionShare": target_decryption_share,
        "proofStatement": proof_statement,
        "proofMaterial": proof_material,
    }))
    .expect_err("malformed setup package must be refused");

    assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
    assert!(
        crate::bgv::setup::take_verified_canonical_proof_material_bytes(
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
            &proof_material_root,
        )
        .expect("target proof material store lookup")
        .is_none(),
        "failed target proof verification must evict authenticated material"
    );
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

    json!({
        "targetDecryptionShare": target_decryption_share,
        "proofStatement": proof_statement,
        "proofMaterial": {
            "objectType": "BgvTargetDecryptionShareProofMaterial",
            "proofRecords": [
                {
                    "objectType": "BgvTargetDecryptionShareProofRecord",
                    "proofBytesBase64": "AQIDBAU=",
                },
            ],
        },
    })
}

#[test]
fn target_decryption_share_generation_refuses_passive_setup_package() {
    // The passive development package carries the collective secret but is not the
    // accepted, verifier-gated SetupPackage. read_setup_binding must refuse it at
    // the trust boundary (objectType BgvPassiveSetupPackage, not SetupPackage) so
    // shares can never be certified against a package the accepted-setup verifier
    // never blessed. This fires before any witness material is read.
    let (_accepted_setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&_accepted_setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &_accepted_setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": passive_crypto_package(),
        "localTargetShareWitness": local_target_share_witness_value,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("target decryption must refuse the passive setup package");

    assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
}
