use super::*;

const VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "vssPublicAggregateThresholdCommitmentSet";
const VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "vssShareLinkageStatement";
const TARGET_RESULT_RELEASE_SETUP_CONTEXT_HASH_FIELD: &str = "releaseSetupContextHash";

// Target decryption binds the accepted, verifier-gated SetupPackage that every
// other proof family binds - never the passive development package, which is
// documented development evidence and must not enter the trust boundary.
fn require_accepted_setup_package(setup_package: &Value) -> CanonicalResult<()> {
    if string_at_path(setup_package, &["objectType"])? != "SetupPackage" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target decryption requires the accepted SetupPackage; passive or unknown setup packages are refused",
        ));
    }
    Ok(())
}

pub(super) fn read_setup_binding(setup_package: &Value) -> CanonicalResult<SetupBinding> {
    require_accepted_setup_package(setup_package)?;
    let setup_context_hashes = collective_bgv_setup_context_hashes_from_package(setup_package)?;
    // The accepted package carries no setupPackageHash field; recompute the
    // canonical hash of the whole package. It is the single subsuming anchor -
    // every package-derived binding the share statement and release context
    // commit to (participants, public-key-share roots, the VSS graph,
    // the roster-derived threshold parameters) is committed through this hash,
    // which is why the passive-dialect per-component setup and threshold-key
    // hashes are dropped from the statement rather than re-derived.
    let setup_package_hash = derive_canonical_object_hash(setup_package)?;
    let ceremony_id = string_at_path(setup_package, &["setupContext", "ceremonyId"])?.to_string();
    let election_manifest_hash =
        hash_at_path(setup_package, &["setupContext", "manifestHash"])?.to_string();
    // Kernel-canonical target-decryption parameters (level 6, K_top = 20 scope),
    // recomputed from the bound BGV parameters rather than read from a package
    // field. The accepted target record's targetDecryptionParametersHash is
    // cross-checked against this value in read_target_accepted_binding.
    let (target_decryption_profile_hash, target_decryption_profile_binding_hash) =
        canonical_target_decryption_parameter_hashes()?;
    let public_matrix_seed_hash =
        hash_at_path(setup_package, &["commonRandomness", "publicMatrixSeedHash"])?.to_string();
    // The accepted package carries no top-level participants array; identities
    // and roster positions come from the verified setupIntent registrations.
    // Board position equals the roster index and epochs are 0 in a fresh
    // accepted setup, matching the canonical participant construction.
    let participants = accepted_setup_participant_roster_from_package(setup_package)?
        .into_iter()
        .map(|(roster_position, trustee_identity)| {
            // Shamir abscissa = roster_position + 1 so 0-based roster positions never produce the forbidden x = 0 point; share generation and recombination must use the identical mapping.
            let interpolation_point = u64::try_from(roster_position + 1).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target decryption interpolation point does not fit u64",
                )
            })?;
            Ok(ParticipantBinding {
                trustee_identity,
                roster_position,
                board_position: roster_position,
                interpolation_point,
                recovery_epoch: 0,
                device_epoch: 0,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let aggregate_threshold_commitment_set = setup_package
        .get(VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD)
        .map(|aggregate_set| {
            read_aggregate_threshold_commitment_set_binding(
                aggregate_set,
                &public_matrix_seed_hash,
                &participants,
            )
        })
        .transpose()?;
    let share_linkage_statement_root = setup_package
        .get(VSS_SHARE_LINKAGE_STATEMENT_FIELD)
        .map(|statement| {
            hash_at_path(statement, &["statementRoot"]).map(std::borrow::ToOwned::to_owned)
        })
        .transpose()?;

    Ok(SetupBinding {
        setup_package_hash,
        ceremony_id,
        election_manifest_hash,
        roster_hash: setup_context_hashes.roster_hash,
        setup_parameters_hash: setup_context_hashes.setup_parameters_hash,
        target_decryption_profile_hash,
        target_decryption_profile_binding_hash,
        public_matrix_seed_hash,
        share_linkage_statement_root,
        participants,
        aggregate_threshold_commitment_set,
    })
}

pub(super) fn target_result_release_setup_context_from_setup_package(
    setup_package: &Value,
) -> CanonicalResult<Value> {
    let setup_binding = read_setup_binding(setup_package)?;
    target_result_release_setup_context_from_binding(&setup_binding)
}

pub(super) fn read_target_result_release_setup_context(
    context: &Value,
) -> CanonicalResult<SetupBinding> {
    if string_at_path(context, &["objectType"])? != "BgvTargetDecryptionReleaseSetupContext"
        || unsigned_at_path(context, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "release setup context must be a BgvTargetDecryptionReleaseSetupContext version 1 object",
        ));
    }
    let expected_context_hash = target_result_release_setup_context_hash(context)?;
    compare_hash_field(
        context,
        TARGET_RESULT_RELEASE_SETUP_CONTEXT_HASH_FIELD,
        &expected_context_hash,
        "target result release setup context hash",
    )?;

    let public_matrix_seed_hash = hash_at_path(context, &["publicMatrixSeedHash"])?.to_string();
    let participants = array_at_path(context, &["participants"])?
        .iter()
        .map(|participant| {
            Ok(ParticipantBinding {
                trustee_identity: string_at_path(participant, &["trusteeIdentity"])?.to_string(),
                roster_position: usize_at_path(participant, &["rosterPosition"])?,
                board_position: usize_at_path(participant, &["boardPosition"])?,
                interpolation_point: unsigned_at_path(participant, &["interpolationPoint"])?,
                recovery_epoch: unsigned_at_path(participant, &["recoveryEpoch"])?,
                device_epoch: unsigned_at_path(participant, &["deviceEpoch"])?,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    for participant in &participants {
        let expected_interpolation_point =
            u64::try_from(participant.roster_position + 1).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target decryption interpolation point does not fit u64",
                )
            })?;
        if participant.interpolation_point != expected_interpolation_point {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "release setup context interpolation point does not match the roster position",
            ));
        }
    }
    let aggregate_threshold_commitment_set = context
        .get(VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD)
        .filter(|value| !value.is_null())
        .map(|aggregate_set| {
            read_aggregate_threshold_commitment_set_binding(
                aggregate_set,
                &public_matrix_seed_hash,
                &participants,
            )
        })
        .transpose()?;
    let share_linkage_statement_root = context
        .get("shareLinkageStatementRoot")
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "shareLinkageStatementRoot must be a hash string",
                )
            })
        })
        .transpose()?
        .map(str::to_string);

    Ok(SetupBinding {
        setup_package_hash: hash_at_path(context, &["setupPackageHash"])?.to_string(),
        ceremony_id: string_at_path(context, &["ceremonyId"])?.to_string(),
        election_manifest_hash: hash_at_path(context, &["electionManifestHash"])?.to_string(),
        roster_hash: hash_at_path(context, &["rosterHash"])?.to_string(),
        setup_parameters_hash: hash_at_path(context, &["setupParametersHash"])?.to_string(),
        target_decryption_profile_hash: hash_at_path(context, &["targetDecryptionParametersHash"])?
            .to_string(),
        target_decryption_profile_binding_hash: hash_at_path(
            context,
            &["targetDecryptionParametersBindingHash"],
        )?
        .to_string(),
        public_matrix_seed_hash,
        share_linkage_statement_root,
        participants,
        aggregate_threshold_commitment_set,
    })
}

fn target_result_release_setup_context_from_binding(
    setup_binding: &SetupBinding,
) -> CanonicalResult<Value> {
    let mut context = json!({
        "objectType": "BgvTargetDecryptionReleaseSetupContext",
        "objectVersion": 1,
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "electionManifestHash": setup_binding.election_manifest_hash,
        "rosterHash": setup_binding.roster_hash,
        "setupParametersHash": setup_binding.setup_parameters_hash,
        "targetDecryptionParametersHash": setup_binding.target_decryption_profile_hash,
        "targetDecryptionParametersBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "publicMatrixSeedHash": setup_binding.public_matrix_seed_hash,
        "shareLinkageStatementRoot": setup_binding.share_linkage_statement_root,
        "participants": setup_binding.participants.iter().map(|participant| json!({
            "trusteeIdentity": participant.trustee_identity,
            "rosterPosition": participant.roster_position,
            "boardPosition": participant.board_position,
            "interpolationPoint": participant.interpolation_point,
            "recoveryEpoch": participant.recovery_epoch,
            "deviceEpoch": participant.device_epoch,
        })).collect::<Vec<_>>(),
        VSS_PUBLIC_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: aggregate_threshold_commitment_set_value(setup_binding)?,
    });
    let context_hash = target_result_release_setup_context_hash(&context)?;
    context
        .as_object_mut()
        .expect("target result release setup context is a JSON object")
        .insert(
            TARGET_RESULT_RELEASE_SETUP_CONTEXT_HASH_FIELD.to_string(),
            json!(context_hash),
        );

    Ok(context)
}

fn aggregate_threshold_commitment_set_value(
    setup_binding: &SetupBinding,
) -> CanonicalResult<Value> {
    let Some(aggregate_set) = &setup_binding.aggregate_threshold_commitment_set else {
        return Ok(Value::Null);
    };
    let mut records = Vec::new();
    for (recipient_index, limb_records) in aggregate_set.recipient_records.iter().enumerate() {
        let participant = setup_binding
            .participants
            .get(recipient_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "aggregate threshold commitment recipient has no setup participant",
                )
            })?;
        for (rns_limb_index, record) in limb_records.iter().enumerate() {
            records.push(json!({
                "objectType": "VssPublicAggregateThresholdCommitment",
                "objectVersion": 1,
                "recipientIdentity": participant.trustee_identity,
                "recipientRosterPosition": participant.roster_position,
                "recipientTrusteePoint": participant.interpolation_point,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": record.rns_prime,
                "aggregateCommitmentRoot": record.aggregate_commitment_root,
                "aggregateOpeningRoot": record.aggregate_opening_root,
                "commitment": record.aggregate_commitment,
                "sourceShareCommitmentRoots": record.source_share_commitment_roots,
                "sourceShareOpeningRoots": record.source_share_opening_roots,
            }));
        }
    }

    Ok(json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "objectVersion": 1,
        "publicMatrixSeedHash": setup_binding.public_matrix_seed_hash,
        "participantCount": setup_binding.participants.len(),
        "rnsLimbCount": aggregate_set.rns_limb_count,
        "ringDegree": POLYNOMIAL_DEGREE,
        "aggregateThresholdCommitmentRoot": aggregate_set.aggregate_threshold_commitment_root,
        "recipientRecords": records,
    }))
}

fn target_result_release_setup_context_hash(context: &Value) -> CanonicalResult<String> {
    let mut hash_input = context.clone();
    if let Some(object) = hash_input.as_object_mut() {
        object.remove(TARGET_RESULT_RELEASE_SETUP_CONTEXT_HASH_FIELD);
    }
    derive_canonical_object_hash(&hash_input)
}

fn read_aggregate_threshold_commitment_set_binding(
    aggregate_set: &Value,
    setup_public_matrix_seed_hash: &str,
    participants: &[ParticipantBinding],
) -> CanonicalResult<AggregateThresholdCommitmentSetBinding> {
    verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
        "aggregateThresholdCommitmentSet": aggregate_set,
    }))?;
    let aggregate_threshold_commitment_root =
        hash_at_path(aggregate_set, &["aggregateThresholdCommitmentRoot"])?.to_string();
    compare_hash_field(
        aggregate_set,
        "publicMatrixSeedHash",
        setup_public_matrix_seed_hash,
        "aggregate threshold commitment set public matrix seed hash",
    )?;
    let participant_count = usize_at_path(aggregate_set, &["participantCount"])?;
    if participant_count != participants.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "aggregate threshold commitment set participant count does not match the setup participants",
        ));
    }
    let rns_limb_count = usize_at_path(aggregate_set, &["rnsLimbCount"])?;
    if rns_limb_count > DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "aggregate threshold commitment set has more limbs than the canonical data basis",
        ));
    }
    let ring_degree = usize_at_path(aggregate_set, &["ringDegree"])?;
    if ring_degree != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "aggregate threshold commitment set ring degree does not match the setup profile",
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
                        "aggregate threshold commitment record index overflowed",
                    )
                })?;
            let record = records.get(record_index).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "aggregate threshold commitment set is missing a recipient limb record",
                )
            })?;
            compare_string_field(
                record,
                "recipientIdentity",
                &participant.trustee_identity,
                "aggregate threshold commitment recipient identity",
            )?;
            compare_unsigned_field(
                record,
                "recipientRosterPosition",
                participant.roster_position as u64,
                "aggregate threshold commitment recipient roster position",
            )?;
            compare_unsigned_field(
                record,
                "recipientTrusteePoint",
                participant.interpolation_point,
                "aggregate threshold commitment recipient trustee point",
            )?;
            compare_unsigned_field(
                record,
                "rnsLimbIndex",
                rns_limb_index as u64,
                "aggregate threshold commitment RNS limb index",
            )?;
            let rns_prime = unsigned_at_path(record, &["rnsPrime"])?;
            if rns_prime != expected_rns_prime {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "aggregate threshold commitment RNS prime does not match the canonical data basis",
                ));
            }
            limb_records.push(AggregateThresholdCommitmentRecordBinding {
                rns_prime,
                aggregate_commitment_root: hash_at_path(record, &["aggregateCommitmentRoot"])?
                    .to_string(),
                aggregate_opening_root: hash_at_path(record, &["aggregateOpeningRoot"])?
                    .to_string(),
                aggregate_commitment: value_at_path(record, &["commitment"])?.clone(),
                source_share_commitment_roots: string_array_at_path(
                    record,
                    "sourceShareCommitmentRoots",
                )?,
                source_share_opening_roots: string_array_at_path(
                    record,
                    "sourceShareOpeningRoots",
                )?,
            });
        }
        recipient_records.push(limb_records);
    }

    Ok(AggregateThresholdCommitmentSetBinding {
        aggregate_threshold_commitment_root,
        rns_limb_count,
        recipient_records,
    })
}

fn string_array_at_path(value: &Value, field_name: &str) -> CanonicalResult<Vec<String>> {
    array_at_path(value, &[field_name])?
        .iter()
        .enumerate()
        .map(|(value_index, entry)| {
            entry.as_str().map(str::to_string).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{field_name}.{value_index} must be a string"),
                )
            })
        })
        .collect()
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
        &setup_binding.target_decryption_profile_hash,
        "target decryption parameters hash",
    )?;
    compare_hash_field(
        record,
        "targetBasisHash",
        &canonical_target_basis_hash()?,
        "target basis hash",
    )?;
    let expected_record_hash = derive_canonical_object_hash(&json!({
        "objectType": string_at_path(record, &["objectType"])?,
        "objectVersion": unsigned_at_path(record, &["objectVersion"])?,
        "boardPosition": unsigned_at_path(record, &["boardPosition"])?,
        "boardSequence": unsigned_at_path(record, &["boardSequence"])?,
        "ceremonyId": string_at_path(record, &["ceremonyId"])?,
        "electionManifestHash": hash_at_path(record, &["electionManifestHash"])?,
        "evaluatorReplayRecordHash": hash_at_path(record, &["evaluatorReplayRecordHash"])?,
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
        target_decryption_profile_hash: hash_at_path(record, &["targetDecryptionParametersHash"])?
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
            CanonicalErrorCode::ComponentMismatch,
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
        "targetDecryptionProfileHash": setup_binding.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "decryptionThreshold": decryption_threshold,
        "minimumSharesForInterpolation": minimum_shares_for_interpolation,
        "decryptionShareQuorum": decryption_share_quorum,
    });
    let hash = derive_canonical_object_hash(&hash_input)?;
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
