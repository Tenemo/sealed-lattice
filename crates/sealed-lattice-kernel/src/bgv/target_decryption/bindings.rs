use super::*;

pub(super) fn read_setup_binding(setup_package: &Value) -> CanonicalResult<SetupBinding> {
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    let setup_package_hash = hash_at_path(setup_package, &["setupPackageHash"])?.to_string();
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?.to_string();
    let election_manifest_hash =
        hash_at_path(setup_package, &["setupInputs", "manifestHash"])?.to_string();
    let threshold_parameters_hash =
        hash_at_path(setup_package, &["setupInputs", "thresholdParametersHash"])?.to_string();
    let target_decryption_parameters_hash = hash_at_path(
        setup_package,
        &["targetDecryptionStatus", "targetDecryptionParametersHash"],
    )?
    .to_string();
    let target_decryption_parameters_binding_hash = hash_at_path(
        setup_package,
        &[
            "targetDecryptionStatus",
            "targetDecryptionParametersBindingHash",
        ],
    )?
    .to_string();
    let threshold_share_verification_key_root = hash_at_path(
        setup_package,
        &[
            "thresholdVerificationMaterial",
            "thresholdShareVerificationKeyRoot",
        ],
    )?
    .to_string();
    let threshold_share_verification_key_hash = hash_at_path(
        setup_package,
        &[
            "thresholdVerificationMaterial",
            "thresholdShareVerificationKeyHash",
        ],
    )?
    .to_string();
    let participants = array_at_path(setup_package, &["participants"])?
        .iter()
        .map(|participant| {
            let roster_position = usize_at_path(participant, &["rosterPosition"])?;
            let board_position = usize_at_path(participant, &["boardPosition"])?;
            Ok(ParticipantBinding {
                trustee_identity: string_at_path(participant, &["trusteeIdentity"])?.to_string(),
                roster_position,
                board_position,
                // Shamir abscissa = roster_position + 1 so 0-based roster positions never produce the forbidden x = 0 point; share generation and recombination must use the identical mapping.
                interpolation_point: u64::try_from(roster_position + 1).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target decryption interpolation point does not fit u64",
                    )
                })?,
                recovery_epoch: unsigned_at_path(participant, &["recoveryEpoch"])?,
                device_epoch: unsigned_at_path(participant, &["deviceEpoch"])?,
                trustee_threshold_verification_key_hash: hash_at_path(
                    participant,
                    &["trusteeThresholdVerificationKeyHash"],
                )?
                .to_string(),
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(SetupBinding {
        setup_package_hash,
        ceremony_id,
        election_manifest_hash,
        threshold_parameters_hash,
        target_decryption_parameters_hash,
        target_decryption_parameters_binding_hash,
        participants,
        threshold_verification: ThresholdVerificationBinding {
            threshold_share_verification_key_root,
            threshold_share_verification_key_hash,
        },
    })
}

pub(super) fn read_target_accepted_binding(
    record: &Value,
    setup_binding: &SetupBinding,
) -> CanonicalResult<TargetAcceptedBinding> {
    if string_at_path(record, &["objectType"])? != "TargetAcceptedRecord"
        || unsigned_at_path(record, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "targetAcceptedRecord must be a canonical TargetAcceptedRecord",
        ));
    }
    compare_string_field(
        record,
        "ceremonyId",
        &setup_binding.ceremony_id,
        "target accepted ceremony",
    )?;
    compare_hash_field(
        record,
        "electionManifestHash",
        &setup_binding.election_manifest_hash,
        "target accepted manifest hash",
    )?;
    compare_hash_field(
        record,
        "targetDecryptionParametersHash",
        &setup_binding.target_decryption_parameters_hash,
        "target decryption parameters hash",
    )?;
    let expected_record_hash = derive_canonical_object_hash(&json!({
        "boardPosition": unsigned_at_path(record, &["boardPosition"])?,
        "boardSequence": unsigned_at_path(record, &["boardSequence"])?,
        "ceremonyId": string_at_path(record, &["ceremonyId"])?,
        "electionManifestHash": hash_at_path(record, &["electionManifestHash"])?,
        "bgvParametersHash": hash_at_path(record, &["bgvParametersHash"])?,
        "evaluatorReplayRecordHash": hash_at_path(record, &["evaluatorReplayRecordHash"])?,
        "objectType": string_at_path(record, &["objectType"])?,
        "objectVersion": unsigned_at_path(record, &["objectVersion"])?,
        "organizerIdentity": string_at_path(record, &["organizerIdentity"])?,
        "targetBasisHash": hash_at_path(record, &["targetBasisHash"])?,
        "targetCiphertextHash": hash_at_path(record, &["targetCiphertextHash"])?,
        "targetContextHash": hash_at_path(record, &["targetContextHash"])?,
        "targetDecryptionParametersHash": hash_at_path(record, &["targetDecryptionParametersHash"])?,
        "targetFinalityCheckpointHash": hash_at_path(record, &["targetFinalityCheckpointHash"])?,
        "targetFinalityRecordHash": hash_at_path(record, &["targetFinalityRecordHash"])?,
        "targetLayoutHash": hash_at_path(record, &["targetLayoutHash"])?,
        "targetPreimageHash": hash_at_path(record, &["targetPreimageHash"])?,
        "targetProposalHash": hash_at_path(record, &["targetProposalHash"])?,
    }))?;
    compare_hash_field(
        record,
        "targetAcceptedRecordHash",
        &expected_record_hash,
        "target accepted record hash",
    )?;

    Ok(TargetAcceptedBinding {
        target_accepted_record_hash: expected_record_hash,
        target_proposal_hash: hash_at_path(record, &["targetProposalHash"])?.to_string(),
        target_preimage_hash: hash_at_path(record, &["targetPreimageHash"])?.to_string(),
        target_finality_record_hash: hash_at_path(record, &["targetFinalityRecordHash"])?
            .to_string(),
        target_finality_checkpoint_hash: hash_at_path(record, &["targetFinalityCheckpointHash"])?
            .to_string(),
        evaluator_replay_record_hash: hash_at_path(record, &["evaluatorReplayRecordHash"])?
            .to_string(),
        target_context_hash: hash_at_path(record, &["targetContextHash"])?.to_string(),
        target_ciphertext_hash: hash_at_path(record, &["targetCiphertextHash"])?.to_string(),
        target_layout_hash: hash_at_path(record, &["targetLayoutHash"])?.to_string(),
        target_decryption_parameters_hash: hash_at_path(
            record,
            &["targetDecryptionParametersHash"],
        )?
        .to_string(),
        target_basis_hash: hash_at_path(record, &["targetBasisHash"])?.to_string(),
    })
}

pub(super) fn read_target_share_parameters(
    value: &Value,
    setup_binding: &SetupBinding,
) -> CanonicalResult<TargetShareParameters> {
    if string_at_path(value, &["objectType"])? != "TargetDecryptionShareParameters"
        || unsigned_at_path(value, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "targetShareParameters must be a TargetDecryptionShareParameters version 1 object",
        ));
    }
    compare_hash_field(
        value,
        "thresholdParametersHash",
        &setup_binding.threshold_parameters_hash,
        "target share threshold parameters hash",
    )?;
    compare_hash_field(
        value,
        "targetDecryptionParametersHash",
        &setup_binding.target_decryption_parameters_hash,
        "target decryption parameters hash",
    )?;
    compare_hash_field(
        value,
        "targetDecryptionParametersBindingHash",
        &setup_binding.target_decryption_parameters_binding_hash,
        "target decryption parameters binding hash",
    )?;
    let decryption_threshold = usize_field(value, "decryptionThreshold")?;
    let minimum_shares_for_interpolation = usize_field(value, "minimumSharesForInterpolation")?;
    let decryption_share_quorum = usize_field(value, "decryptionShareQuorum")?;
    let participant_count = setup_binding.participants.len();
    let expected_decryption_threshold = participant_count / 3 + 1;
    if decryption_threshold != expected_decryption_threshold {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "targetShareParameters.decryptionThreshold must match the setup roster-derived threshold",
        ));
    }
    if decryption_threshold == 0
        || decryption_threshold > participant_count
        || minimum_shares_for_interpolation < decryption_threshold
        || minimum_shares_for_interpolation > decryption_share_quorum
        || decryption_share_quorum > participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "targetShareParameters quorum values are inconsistent with the setup roster",
        ));
    }

    let hash_input = json!({
        "objectType": "TargetDecryptionShareParameters",
        "objectVersion": 1,
        "thresholdParametersHash": setup_binding.threshold_parameters_hash,
        "targetDecryptionParametersHash": setup_binding.target_decryption_parameters_hash,
        "targetDecryptionParametersBindingHash": setup_binding.target_decryption_parameters_binding_hash,
        "decryptionThreshold": decryption_threshold,
        "minimumSharesForInterpolation": minimum_shares_for_interpolation,
        "decryptionShareQuorum": decryption_share_quorum,
    });
    let hash = derive_canonical_object_hash(&hash_input)?;
    compare_hash_field(
        value,
        "targetShareParametersHash",
        &hash,
        "target share parameters hash",
    )?;

    Ok(TargetShareParameters {
        decryption_threshold,
        minimum_shares_for_interpolation,
        decryption_share_quorum,
        hash,
    })
}
