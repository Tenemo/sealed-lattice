use super::*;

pub(super) fn derive_target_decryption_share_proof_statement(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    local_target_share_witness: &Value,
    target_decryption_share: &Value,
) -> CanonicalResult<Value> {
    read_partial_decryption_share(
        target_decryption_share,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
    )?;
    let local_witness = read_local_target_decryption_share_witness(
        local_target_share_witness,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
    )?;
    let expected_share = generate_target_decryption_share_from_secret_share(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &local_witness.secret_share_by_limb,
        &local_witness.smudging_seed_hex,
    )?;
    let expected_share_root = hash_at_path(&expected_share, &["shareRoot"])?;
    compare_hash_field(
        target_decryption_share,
        "shareRoot",
        expected_share_root,
        "target decryption share root restored from local witness",
    )?;
    let expected_share_hash = hash_at_path(&expected_share, &["targetDecryptionShareHash"])?;
    compare_hash_field(
        target_decryption_share,
        "targetDecryptionShareHash",
        expected_share_hash,
        "target decryption share hash restored from local witness",
    )?;

    let statement_value = target_decryption_share_proof_statement_value(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &local_witness,
        target_decryption_share,
    )?;
    let proof_statement_root = derive_protocol_hash(
        "BgvTargetDecryptionShareProofStatementRoot",
        &statement_value,
    )?;
    let mut statement = statement_value;
    statement["proofStatementRoot"] = json!(proof_statement_root);

    Ok(statement)
}

pub(super) fn verify_target_decryption_share_proof_statement(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    target_decryption_share: &Value,
    proof_statement: &Value,
) -> CanonicalResult<Value> {
    read_partial_decryption_share(
        target_decryption_share,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
    )?;
    validate_target_decryption_share_proof_statement_shape(
        proof_statement,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        target_decryption_share,
    )?;
    let proof_statement_root = hash_at_path(proof_statement, &["proofStatementRoot"])?;

    Ok(json!({
        "ok": true,
        "operation": "verifyBgvTargetDecryptionShareProofStatement",
        "proofStatementRoot": proof_statement_root,
        "targetDecryptionShareHash": hash_at_path(target_decryption_share, &["targetDecryptionShareHash"])?,
        "shareRoot": hash_at_path(target_decryption_share, &["shareRoot"])?,
        "smudgingInputReportHash": hash_at_path(target_decryption_share, &["sharePayload", "smudgingInputReportHash"])?,
        "targetBasisHash": target_accepted.target_basis_hash,
        "oneShotTargetContextRule": TARGET_DECRYPTION_ONE_SHOT_CONTEXT_RULE,
        "restoredWitnessOwnershipRule": TARGET_DECRYPTION_RESTORED_WITNESS_RULE,
        "targetBasisRule": TARGET_DECRYPTION_TARGET_BASIS_RULE,
        "smudgingRequirement": TARGET_DECRYPTION_SMUDGING_REQUIREMENT,
        "recombinationRequirement": TARGET_DECRYPTION_RECOMBINATION_REQUIREMENT,
        "proofBoundary": TARGET_DECRYPTION_SHARE_PROOF_BOUNDARY,
    }))
}

fn target_decryption_share_proof_statement_value(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    local_witness: &LocalTargetDecryptionShareWitness,
    target_decryption_share: &Value,
) -> CanonicalResult<Value> {
    let smudging_input_report_hash = hash_at_path(
        target_decryption_share,
        &["sharePayload", "smudgingInputReportHash"],
    )?;
    let credential_bindings = local_witness
        .compact_opening
        .active_credential_bindings
        .iter()
        .map(|binding| {
            json!({
                "objectType": "TargetDecryptionCompactAggregateOpeningCredentialBinding",
                "objectVersion": 1,
                "rnsLimbIndex": binding.limb_index,
                "rnsPrime": binding.rns_prime,
                "aggregateCommitmentRoot": binding.aggregate_commitment_root,
                "aggregateOpeningRoot": binding.aggregate_opening_root,
            })
        })
        .collect::<Vec<_>>();
    let active_credential_binding_root =
        compact_aggregate_opening_credential_binding_root(&credential_bindings)?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShareProofStatement",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "electionManifestHash": setup_binding.election_manifest_hash,
        "thresholdProfileHash": setup_binding.threshold_profile_hash,
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "decryptionThreshold": target_share_profile.decryption_threshold,
        "minimumSharesForInterpolation": target_share_profile.minimum_shares_for_interpolation,
        "decryptionShareQuorum": target_share_profile.decryption_share_quorum,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "interpolationPoint": participant.interpolation_point,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetProposalHash": target_accepted.target_proposal_hash,
        "targetPreimageHash": target_accepted.target_preimage_hash,
        "targetFinalityRecordHash": target_accepted.target_finality_record_hash,
        "targetFinalityCheckpointHash": target_accepted.target_finality_checkpoint_hash,
        "evaluatorReplayRecordHash": target_accepted.evaluator_replay_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetCiphertextBindingHash": target_ciphertexts.target_ciphertext_binding_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "targetBasisHash": target_accepted.target_basis_hash,
        "targetCiphertextLevel": target_ciphertexts.target_id.level,
        "ringDegree": POLYNOMIAL_DEGREE,
        "oneShotTargetContextRule": TARGET_DECRYPTION_ONE_SHOT_CONTEXT_RULE,
        "restoredWitnessOwnershipRule": TARGET_DECRYPTION_RESTORED_WITNESS_RULE,
        "targetBasisRule": TARGET_DECRYPTION_TARGET_BASIS_RULE,
        "smudgingRequirement": TARGET_DECRYPTION_SMUDGING_REQUIREMENT,
        "recombinationRequirement": TARGET_DECRYPTION_RECOMBINATION_REQUIREMENT,
        "proofBoundary": TARGET_DECRYPTION_SHARE_PROOF_BOUNDARY,
        "thresholdShareVerificationKeyRoot": setup_binding.threshold_verification.threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": setup_binding.threshold_verification.threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHash": participant.trustee_threshold_verification_key_hash,
        "targetDecryptionShareHash": hash_at_path(target_decryption_share, &["targetDecryptionShareHash"])?,
        "shareRoot": hash_at_path(target_decryption_share, &["shareRoot"])?,
        "smudgingInputReportHash": smudging_input_report_hash,
        "compactAggregateOpeningBinding": {
            "objectType": "TargetDecryptionCompactAggregateOpeningBinding",
            "objectVersion": 1,
            "witnessOwnership": TARGET_DECRYPTION_RESTORED_WITNESS_OWNERSHIP,
            "publicMatrixSeedHash": local_witness.compact_opening.public_matrix_seed_hash,
            "shareLinkageStatementRoot": local_witness.compact_opening.share_linkage_statement_root,
            "aggregateThresholdCommitmentRoot": local_witness.compact_opening.aggregate_threshold_commitment_root,
            "activeCredentialBindingRoot": active_credential_binding_root,
            "activeCredentialBindings": credential_bindings,
        },
        "relation": "the target-decryption share payload is computed from the restored recipient aggregate threshold share that opens the compact aggregate commitment roots for the active target basis",
    }))
}

fn compact_aggregate_opening_credential_binding_root(
    credential_bindings: &[Value],
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "TargetDecryptionCompactAggregateOpeningCredentialBindingRoot",
        &json!({
            "objectType": "TargetDecryptionCompactAggregateOpeningCredentialBindingSet",
            "objectVersion": 1,
            "activeCredentialBindings": credential_bindings,
        }),
    )
}

fn validate_target_decryption_share_proof_statement_shape(
    proof_statement: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    target_decryption_share: &Value,
) -> CanonicalResult<()> {
    if string_at_path(proof_statement, &["objectType"])? != "BgvTargetDecryptionShareProofStatement"
        || unsigned_at_path(proof_statement, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption share proof statement must be BgvTargetDecryptionShareProofStatement version 1",
        ));
    }

    let mut statement_without_root = proof_statement.clone();
    statement_without_root
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption share proof statement must be an object",
            )
        })?
        .remove("proofStatementRoot")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption share proof statement must include proofStatementRoot",
            )
        })?;
    let expected_statement_root = derive_protocol_hash(
        "BgvTargetDecryptionShareProofStatementRoot",
        &statement_without_root,
    )?;
    compare_hash_field(
        proof_statement,
        "proofStatementRoot",
        &expected_statement_root,
        "target decryption share proof statement root",
    )?;

    compare_string_field(
        proof_statement,
        "setupProfileId",
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "target decryption share proof statement setup profile",
    )?;
    compare_string_field(
        proof_statement,
        "targetDecryptionProfileId",
        TARGET_DECRYPTION_PROFILE_ID,
        "target decryption share proof statement profile id",
    )?;
    for (field_name, expected) in [
        (
            "setupPackageHash",
            setup_binding.setup_package_hash.as_str(),
        ),
        ("ceremonyId", setup_binding.ceremony_id.as_str()),
        (
            "electionManifestHash",
            setup_binding.election_manifest_hash.as_str(),
        ),
        (
            "thresholdProfileHash",
            setup_binding.threshold_profile_hash.as_str(),
        ),
        (
            "targetDecryptionProfileHash",
            target_accepted.target_decryption_profile_hash.as_str(),
        ),
        (
            "targetDecryptionProfileBindingHash",
            setup_binding
                .target_decryption_profile_binding_hash
                .as_str(),
        ),
        ("targetShareProfileHash", target_share_profile.hash.as_str()),
        ("trusteeIdentity", participant.trustee_identity.as_str()),
        (
            "targetAcceptedRecordHash",
            target_accepted.target_accepted_record_hash.as_str(),
        ),
        (
            "targetProposalHash",
            target_accepted.target_proposal_hash.as_str(),
        ),
        (
            "targetPreimageHash",
            target_accepted.target_preimage_hash.as_str(),
        ),
        (
            "targetFinalityRecordHash",
            target_accepted.target_finality_record_hash.as_str(),
        ),
        (
            "targetFinalityCheckpointHash",
            target_accepted.target_finality_checkpoint_hash.as_str(),
        ),
        (
            "evaluatorReplayRecordHash",
            target_accepted.evaluator_replay_record_hash.as_str(),
        ),
        (
            "targetContextHash",
            target_accepted.target_context_hash.as_str(),
        ),
        (
            "targetCiphertextHash",
            target_accepted.target_ciphertext_hash.as_str(),
        ),
        (
            "targetDecryptionCiphertextHash",
            target_ciphertexts.target_ciphertext_hash.as_str(),
        ),
        (
            "targetCiphertextBindingHash",
            target_ciphertexts.target_ciphertext_binding_hash.as_str(),
        ),
        ("targetIdRoot", target_ciphertexts.target_id_root.as_str()),
        (
            "targetOrderRoot",
            target_ciphertexts.target_order_root.as_str(),
        ),
        (
            "targetBasisHash",
            target_accepted.target_basis_hash.as_str(),
        ),
        (
            "thresholdShareVerificationKeyRoot",
            setup_binding
                .threshold_verification
                .threshold_share_verification_key_root
                .as_str(),
        ),
        (
            "thresholdShareVerificationKeyHash",
            setup_binding
                .threshold_verification
                .threshold_share_verification_key_hash
                .as_str(),
        ),
        (
            "trusteeThresholdVerificationKeyHash",
            participant.trustee_threshold_verification_key_hash.as_str(),
        ),
        (
            "targetDecryptionShareHash",
            hash_at_path(target_decryption_share, &["targetDecryptionShareHash"])?,
        ),
        (
            "shareRoot",
            hash_at_path(target_decryption_share, &["shareRoot"])?,
        ),
        (
            "smudgingInputReportHash",
            hash_at_path(
                target_decryption_share,
                &["sharePayload", "smudgingInputReportHash"],
            )?,
        ),
    ] {
        if field_name == "ceremonyId" || field_name == "trusteeIdentity" {
            compare_string_field(
                proof_statement,
                field_name,
                expected,
                "target decryption share proof statement",
            )?;
        } else {
            compare_hash_field(
                proof_statement,
                field_name,
                expected,
                "target decryption share proof statement",
            )?;
        }
    }
    for (field_name, expected) in [
        (
            "decryptionThreshold",
            target_share_profile.decryption_threshold as u64,
        ),
        (
            "minimumSharesForInterpolation",
            target_share_profile.minimum_shares_for_interpolation as u64,
        ),
        (
            "decryptionShareQuorum",
            target_share_profile.decryption_share_quorum as u64,
        ),
        ("rosterPosition", participant.roster_position as u64),
        ("boardPosition", participant.board_position as u64),
        ("interpolationPoint", participant.interpolation_point),
        ("recoveryEpoch", participant.recovery_epoch),
        ("deviceEpoch", participant.device_epoch),
        (
            "targetCiphertextLevel",
            target_ciphertexts.target_id.level as u64,
        ),
        ("ringDegree", POLYNOMIAL_DEGREE as u64),
    ] {
        compare_unsigned_field(
            proof_statement,
            field_name,
            expected,
            "target decryption share proof statement",
        )?;
    }
    for (field_name, expected) in [
        (
            "oneShotTargetContextRule",
            TARGET_DECRYPTION_ONE_SHOT_CONTEXT_RULE,
        ),
        (
            "restoredWitnessOwnershipRule",
            TARGET_DECRYPTION_RESTORED_WITNESS_RULE,
        ),
        ("targetBasisRule", TARGET_DECRYPTION_TARGET_BASIS_RULE),
        (
            "smudgingRequirement",
            TARGET_DECRYPTION_SMUDGING_REQUIREMENT,
        ),
        (
            "recombinationRequirement",
            TARGET_DECRYPTION_RECOMBINATION_REQUIREMENT,
        ),
        ("proofBoundary", TARGET_DECRYPTION_SHARE_PROOF_BOUNDARY),
    ] {
        compare_string_field(
            proof_statement,
            field_name,
            expected,
            "target decryption share proof statement obligation",
        )?;
    }

    validate_compact_aggregate_opening_statement_binding(
        value_at_path(proof_statement, &["compactAggregateOpeningBinding"])?,
        target_ciphertexts.target_id.level + 1,
    )?;

    Ok(())
}

fn validate_compact_aggregate_opening_statement_binding(
    binding: &Value,
    active_limb_count: usize,
) -> CanonicalResult<()> {
    if string_at_path(binding, &["objectType"])? != "TargetDecryptionCompactAggregateOpeningBinding"
        || unsigned_at_path(binding, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption compact aggregate opening binding must be TargetDecryptionCompactAggregateOpeningBinding version 1",
        ));
    }
    compare_string_field(
        binding,
        "witnessOwnership",
        TARGET_DECRYPTION_RESTORED_WITNESS_OWNERSHIP,
        "target decryption compact aggregate opening binding witness ownership",
    )?;
    hash_at_path(binding, &["publicMatrixSeedHash"])?;
    hash_at_path(binding, &["shareLinkageStatementRoot"])?;
    hash_at_path(binding, &["aggregateThresholdCommitmentRoot"])?;
    let credential_bindings = array_at_path(binding, &["activeCredentialBindings"])?;
    if credential_bindings.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption compact aggregate opening binding must include one active credential binding per target limb",
        ));
    }
    for (limb_index, credential_binding) in credential_bindings.iter().enumerate() {
        if string_at_path(credential_binding, &["objectType"])?
            != "TargetDecryptionCompactAggregateOpeningCredentialBinding"
            || unsigned_at_path(credential_binding, &["objectVersion"])? != 1
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption compact aggregate credential binding must be TargetDecryptionCompactAggregateOpeningCredentialBinding version 1",
            ));
        }
        compare_unsigned_field(
            credential_binding,
            "rnsLimbIndex",
            limb_index as u64,
            "target decryption compact aggregate credential binding limb",
        )?;
        let Some(expected_prime) = DATA_PRIMES.get(limb_index).copied() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target decryption compact aggregate credential binding limb is outside the selected BGV basis",
            ));
        };
        compare_unsigned_field(
            credential_binding,
            "rnsPrime",
            expected_prime,
            "target decryption compact aggregate credential binding prime",
        )?;
        hash_at_path(credential_binding, &["aggregateCommitmentRoot"])?;
        hash_at_path(credential_binding, &["aggregateOpeningRoot"])?;
    }
    let expected_active_credential_binding_root =
        compact_aggregate_opening_credential_binding_root(credential_bindings)?;
    compare_hash_field(
        binding,
        "activeCredentialBindingRoot",
        &expected_active_credential_binding_root,
        "target decryption compact aggregate active credential binding root",
    )?;

    Ok(())
}
