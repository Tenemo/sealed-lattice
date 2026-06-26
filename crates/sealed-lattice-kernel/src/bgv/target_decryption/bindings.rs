use super::*;

const COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "compactVssAggregateThresholdCommitmentSet";
const COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "compactVssShareLinkageStatement";

pub(super) fn read_setup_binding(setup_package: &Value) -> CanonicalResult<SetupBinding> {
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    let setup_context_hashes = collective_bgv_setup_context_hashes_from_package(setup_package)?;
    let setup_package_hash = hash_at_path(setup_package, &["setupPackageHash"])?.to_string();
    let ceremony_id = string_at_path(setup_package, &["setupInputs", "ceremonyId"])?.to_string();
    let election_manifest_hash =
        hash_at_path(setup_package, &["setupInputs", "manifestHash"])?.to_string();
    let threshold_profile_hash =
        hash_at_path(setup_package, &["setupInputs", "thresholdProfileHash"])?.to_string();
    let public_matrix_seed_hash =
        hash_at_path(setup_package, &["commonRandomness", "publicMatrixSeedHash"])?.to_string();
    let target_decryption_profile_hash = hash_at_path(
        setup_package,
        &[
            "targetDecryptionProfileBinding",
            "targetDecryptionProfileHash",
        ],
    )?
    .to_string();
    let target_decryption_profile_binding_hash = hash_at_path(
        setup_package,
        &[
            "targetDecryptionProfileBinding",
            "targetDecryptionProfileBindingHash",
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
    let compact_aggregate_threshold_commitment_set = setup_package
        .get(COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD)
        .map(|aggregate_set| {
            read_compact_aggregate_threshold_commitment_set_binding(
                aggregate_set,
                &public_matrix_seed_hash,
                &participants,
            )
        })
        .transpose()?;
    let compact_share_linkage_statement_root = setup_package
        .get(COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD)
        .map(|statement| {
            hash_at_path(statement, &["statementRoot"]).map(std::borrow::ToOwned::to_owned)
        })
        .transpose()?;

    Ok(SetupBinding {
        setup_package_hash,
        ceremony_id,
        election_manifest_hash,
        roster_hash: setup_context_hashes.roster_hash,
        setup_profile_hash: setup_context_hashes.setup_profile_hash,
        q_share_hash: setup_context_hashes.q_share_hash,
        carry_aware_vss_share_relation_profile_hash: setup_context_hashes
            .carry_aware_vss_share_relation_profile_hash,
        commitment_profile_hash: setup_context_hashes.commitment_profile_hash,
        threshold_profile_hash,
        target_decryption_profile_hash,
        target_decryption_profile_binding_hash,
        public_matrix_seed_hash,
        compact_share_linkage_statement_root,
        participants,
        threshold_verification: ThresholdVerificationBinding {
            threshold_share_verification_key_root,
            threshold_share_verification_key_hash,
        },
        compact_aggregate_threshold_commitment_set,
    })
}

fn read_compact_aggregate_threshold_commitment_set_binding(
    aggregate_set: &Value,
    setup_public_matrix_seed_hash: &str,
    participants: &[ParticipantBinding],
) -> CanonicalResult<CompactAggregateThresholdCommitmentSetBinding> {
    verify_compact_vss_aggregate_threshold_commitment_set_request(&json!({
        "aggregateThresholdCommitmentSet": aggregate_set,
    }))?;
    let aggregate_threshold_commitment_root =
        hash_at_path(aggregate_set, &["aggregateThresholdCommitmentRoot"])?.to_string();
    compare_hash_field(
        aggregate_set,
        "publicMatrixSeedHash",
        setup_public_matrix_seed_hash,
        "compact aggregate threshold commitment set public matrix seed hash",
    )?;
    let participant_count = usize_at_path(aggregate_set, &["participantCount"])?;
    if participant_count != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact aggregate threshold commitment set participant count does not match the setup participants",
        ));
    }
    let rns_limb_count = usize_at_path(aggregate_set, &["rnsLimbCount"])?;
    if rns_limb_count > DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact aggregate threshold commitment set has more limbs than the canonical data basis",
        ));
    }
    let ring_degree = usize_at_path(aggregate_set, &["ringDegree"])?;
    if ring_degree != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact aggregate threshold commitment set ring degree does not match the setup profile",
        ));
    }

    let records = array_at_path(aggregate_set, &["recipientRecords"])?;
    let mut recipient_records = Vec::with_capacity(participants.len());
    for (recipient_position, participant) in participants.iter().enumerate() {
        let mut limb_records = Vec::with_capacity(rns_limb_count);
        for (rns_limb_index, expected_rns_prime) in
            DATA_PRIMES.iter().copied().enumerate().take(rns_limb_count)
        {
            let record_index = recipient_position
                .checked_mul(rns_limb_count)
                .and_then(|base| base.checked_add(rns_limb_index))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact aggregate threshold commitment record index overflowed",
                    )
                })?;
            let record = records.get(record_index).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact aggregate threshold commitment set is missing a recipient limb record",
                )
            })?;
            compare_string_field(
                record,
                "recipientIdentity",
                &participant.trustee_identity,
                "compact aggregate threshold commitment recipient identity",
            )?;
            compare_unsigned_field(
                record,
                "recipientRosterPosition",
                participant.roster_position as u64,
                "compact aggregate threshold commitment recipient roster position",
            )?;
            compare_unsigned_field(
                record,
                "recipientTrusteePoint",
                participant.interpolation_point,
                "compact aggregate threshold commitment recipient trustee point",
            )?;
            compare_unsigned_field(
                record,
                "rnsLimbIndex",
                rns_limb_index as u64,
                "compact aggregate threshold commitment RNS limb index",
            )?;
            let rns_prime = unsigned_at_path(record, &["rnsPrime"])?;
            if rns_prime != expected_rns_prime {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "compact aggregate threshold commitment RNS prime does not match the canonical data basis",
                ));
            }
            limb_records.push(CompactAggregateThresholdCommitmentRecordBinding {
                rns_prime,
                aggregate_commitment_root: hash_at_path(record, &["aggregateCommitmentRoot"])?
                    .to_string(),
                aggregate_commitment: value_at_path(record, &["commitment"])?.clone(),
            });
        }
        recipient_records.push(limb_records);
    }

    Ok(CompactAggregateThresholdCommitmentSetBinding {
        aggregate_threshold_commitment_root,
        rns_limb_count,
        recipient_records,
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
    if string_at_path(record, &["targetDecryptionProfileId"])? != TARGET_DECRYPTION_PROFILE_ID {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target accepted record uses an unsupported target decryption profile",
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
        "targetDecryptionProfileHash",
        &setup_binding.target_decryption_profile_hash,
        "target decryption profile hash",
    )?;
    compare_hash_field(
        record,
        "targetBasisHash",
        &canonical_target_basis_hash()?,
        "target basis hash",
    )?;
    let expected_record_hash = derive_protocol_hash(
        "TargetAcceptedRecordHash",
        &json!({
            "boardPosition": unsigned_at_path(record, &["boardPosition"])?,
            "boardSequence": unsigned_at_path(record, &["boardSequence"])?,
            "ceremonyId": string_at_path(record, &["ceremonyId"])?,
            "electionManifestHash": hash_at_path(record, &["electionManifestHash"])?,
            "evaluatorReplayProfileHash": hash_at_path(record, &["evaluatorReplayProfileHash"])?,
            "evaluatorReplayRecordHash": hash_at_path(record, &["evaluatorReplayRecordHash"])?,
            "objectType": string_at_path(record, &["objectType"])?,
            "objectVersion": unsigned_at_path(record, &["objectVersion"])?,
            "organizerIdentity": string_at_path(record, &["organizerIdentity"])?,
            "targetBasisHash": hash_at_path(record, &["targetBasisHash"])?,
            "targetCiphertextHash": hash_at_path(record, &["targetCiphertextHash"])?,
            "targetContextHash": hash_at_path(record, &["targetContextHash"])?,
            "targetDecryptionProfileHash": hash_at_path(record, &["targetDecryptionProfileHash"])?,
            "targetDecryptionProfileId": string_at_path(record, &["targetDecryptionProfileId"])?,
            "targetFinalityCheckpointHash": hash_at_path(record, &["targetFinalityCheckpointHash"])?,
            "targetFinalityRecordHash": hash_at_path(record, &["targetFinalityRecordHash"])?,
            "targetLayoutHash": hash_at_path(record, &["targetLayoutHash"])?,
            "targetPreimageHash": hash_at_path(record, &["targetPreimageHash"])?,
            "targetProposalHash": hash_at_path(record, &["targetProposalHash"])?,
        }),
    )?;
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
        target_decryption_profile_hash: hash_at_path(record, &["targetDecryptionProfileHash"])?
            .to_string(),
        target_basis_hash: hash_at_path(record, &["targetBasisHash"])?.to_string(),
    })
}

pub(super) fn read_target_share_profile(
    value: &Value,
    setup_binding: &SetupBinding,
) -> CanonicalResult<TargetShareProfile> {
    if string_at_path(value, &["objectType"])? != "TargetDecryptionShareProfile"
        || unsigned_at_path(value, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "targetShareProfile must be a TargetDecryptionShareProfile version 1 object",
        ));
    }
    compare_hash_field(
        value,
        "thresholdProfileHash",
        &setup_binding.threshold_profile_hash,
        "target share threshold profile hash",
    )?;
    compare_string_field(
        value,
        "targetDecryptionProfileId",
        TARGET_DECRYPTION_PROFILE_ID,
        "target decryption profile id",
    )?;
    compare_hash_field(
        value,
        "targetDecryptionProfileHash",
        &setup_binding.target_decryption_profile_hash,
        "target decryption profile hash",
    )?;
    compare_hash_field(
        value,
        "targetDecryptionProfileBindingHash",
        &setup_binding.target_decryption_profile_binding_hash,
        "target decryption profile binding hash",
    )?;
    let decryption_threshold = usize_field(value, "decryptionThreshold")?;
    let minimum_shares_for_interpolation = usize_field(value, "minimumSharesForInterpolation")?;
    let decryption_share_quorum = usize_field(value, "decryptionShareQuorum")?;
    let participant_count = setup_binding.participants.len();
    let expected_decryption_threshold = participant_count / 3 + 1;
    if decryption_threshold != expected_decryption_threshold {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "targetShareProfile.decryptionThreshold must match the setup roster-derived threshold",
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
            "targetShareProfile quorum values are inconsistent with the setup roster",
        ));
    }

    let hash_input = json!({
        "objectType": "TargetDecryptionShareProfile",
        "objectVersion": 1,
        "thresholdProfileHash": setup_binding.threshold_profile_hash,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetDecryptionProfileHash": setup_binding.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "decryptionThreshold": decryption_threshold,
        "minimumSharesForInterpolation": minimum_shares_for_interpolation,
        "decryptionShareQuorum": decryption_share_quorum,
    });
    let hash = derive_protocol_hash("TargetDecryptionShareProfileHash", &hash_input)?;
    compare_hash_field(
        value,
        "targetShareProfileHash",
        &hash,
        "target share profile hash",
    )?;

    Ok(TargetShareProfile {
        decryption_threshold,
        minimum_shares_for_interpolation,
        decryption_share_quorum,
        hash,
    })
}
