use super::*;

pub(super) fn read_partial_decryption_share(
    share: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_parameters: &TargetShareParameters,
) -> CanonicalResult<PartialDecryptionShare> {
    if string_at_path(share, &["objectType"])? != "BgvTargetDecryptionShare"
        || unsigned_at_path(share, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target recombination accepts only BgvTargetDecryptionShare records",
        ));
    }
    let trustee_identity = string_at_path(share, &["trusteeIdentity"])?;
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption share trustee is not in the setup roster",
            )
        })?;
    compare_share_record_fields(
        share,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_parameters,
        participant,
    )?;
    let payload = value_at_path(share, &["sharePayload"])?;
    let share_root = derive_protocol_hash("BgvTargetDecryptionShareRoot", payload)?;
    compare_hash_field(share, "shareRoot", &share_root, "target share root")?;
    let expected_hash = derive_protocol_hash(
        "BgvTargetDecryptionShareHash",
        &share_record_hash_input(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_parameters,
            participant,
            &share_root,
        ),
    )?;
    compare_hash_field(
        share,
        "targetDecryptionShareHash",
        &expected_hash,
        "target decryption share hash",
    )?;

    Ok(PartialDecryptionShare {
        record: share.clone(),
        target_id_partials: read_partial_limb_set(
            payload,
            "targetId",
            target_ciphertexts.target_id.level,
        )?,
        target_order_partials: read_partial_limb_set(
            payload,
            "targetOrder",
            target_ciphertexts.target_order.level,
        )?,
        roster_position: participant.roster_position,
        board_position: participant.board_position,
        interpolation_point: participant.interpolation_point,
    })
}

pub(super) fn compare_share_record_fields(
    share: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_parameters: &TargetShareParameters,
    participant: &ParticipantBinding,
) -> CanonicalResult<()> {
    compare_hash_field(
        share,
        "setupPackageHash",
        &setup_binding.setup_package_hash,
        "target share setup package hash",
    )?;
    compare_string_field(
        share,
        "ceremonyId",
        &setup_binding.ceremony_id,
        "target share ceremony",
    )?;
    compare_hash_field(
        share,
        "electionManifestHash",
        &setup_binding.election_manifest_hash,
        "target share manifest hash",
    )?;
    compare_string_field(
        share,
        "trusteeIdentity",
        &participant.trustee_identity,
        "target share trustee identity",
    )?;
    compare_unsigned_field(
        share,
        "rosterPosition",
        participant.roster_position as u64,
        "target share roster position",
    )?;
    compare_unsigned_field(
        share,
        "boardPosition",
        participant.board_position as u64,
        "target share board position",
    )?;
    compare_unsigned_field(
        share,
        "interpolationPoint",
        participant.interpolation_point,
        "target share interpolation point",
    )?;
    compare_unsigned_field(
        share,
        "recoveryEpoch",
        participant.recovery_epoch,
        "target share recovery epoch",
    )?;
    compare_unsigned_field(
        share,
        "deviceEpoch",
        participant.device_epoch,
        "target share device epoch",
    )?;
    for (field_name, expected) in [
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
            "targetDecryptionParametersHash",
            target_accepted.target_decryption_parameters_hash.as_str(),
        ),
        (
            "targetDecryptionParametersBindingHash",
            setup_binding
                .target_decryption_parameters_binding_hash
                .as_str(),
        ),
        (
            "targetShareParametersHash",
            target_share_parameters.hash.as_str(),
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
    ] {
        compare_hash_field(share, field_name, expected, field_name)?;
    }

    Ok(())
}

pub(super) fn share_payload(
    level: usize,
    target_id_partials: &[Vec<u64>],
    target_order_partials: &[Vec<u64>],
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvTargetDecryptionSharePayload",
        "objectVersion": 1,
        "encoding": TARGET_SHARE_PAYLOAD_ENCODING,
        "level": level,
        "targetId": partial_limb_records(target_id_partials)?,
        "targetOrder": partial_limb_records(target_order_partials)?,
    }))
}

pub(super) fn partial_limb_records(partials: &[Vec<u64>]) -> CanonicalResult<Vec<Value>> {
    partials
        .iter()
        .enumerate()
        .map(|(limb_index, coefficients)| {
            if coefficients.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target partial-decryption limb has the wrong coefficient count",
                ));
            }
            let encoded = coefficient_vector_le_hex(coefficients);
            Ok(json!({
                "limbIndex": limb_index,
                "modulus": DATA_PRIMES[limb_index],
                "partialDecryptionLeHex": encoded,
                "partialDecryptionHash512": coefficient_vector_hash512(
                    coefficients,
                    TARGET_PARTIAL_DECRYPTION_LIMB_HASH_DOMAIN,
                ),
            }))
        })
        .collect()
}

pub(super) fn read_partial_limb_set(
    payload: &Value,
    role: &str,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if string_at_path(payload, &["objectType"])? != "BgvTargetDecryptionSharePayload"
        || unsigned_at_path(payload, &["objectVersion"])? != 1
        || string_at_path(payload, &["encoding"])? != TARGET_SHARE_PAYLOAD_ENCODING
        || usize_at_path(payload, &["level"])? != level
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target share payload header is not canonical for the target ciphertext level",
        ));
    }
    let records = array_at_path(payload, &[role])?;
    if records.len() != level + 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target share payload must include one partial-decryption limb per active prime",
        ));
    }
    records
        .iter()
        .enumerate()
        .map(|(limb_index, record)| {
            if usize_at_path(record, &["limbIndex"])? != limb_index
                || unsigned_at_path(record, &["modulus"])? != DATA_PRIMES[limb_index]
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target share payload limb order or modulus does not match the selected BGV basis",
                ));
            }
            let coefficients = coefficient_vector_from_le_hex(
                string_at_path(record, &["partialDecryptionLeHex"])?,
                POLYNOMIAL_DEGREE,
                "target partial-decryption coefficient vector byte length does not match the selected BGV parameters",
            )?;
            let expected_hash = coefficient_vector_hash512(
                &coefficients,
                TARGET_PARTIAL_DECRYPTION_LIMB_HASH_DOMAIN,
            );
            compare_hash_field(
                record,
                "partialDecryptionHash512",
                &expected_hash,
                "target partial-decryption limb hash",
            )?;
            let modulus = DATA_PRIMES[limb_index];
            if coefficients.iter().any(|coefficient| *coefficient >= modulus) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "target partial-decryption limb contains a non-canonical residue",
                ));
            }

            Ok(coefficients)
        })
        .collect()
}

pub(super) fn share_record_hash_input(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_parameters: &TargetShareParameters,
    participant: &ParticipantBinding,
    share_root: &str,
) -> Value {
    json!({
        "objectType": "BgvTargetDecryptionShare",
        "objectVersion": 1,
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "electionManifestHash": setup_binding.election_manifest_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
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
        "targetDecryptionParametersHash": target_accepted.target_decryption_parameters_hash,
        "targetDecryptionParametersBindingHash": setup_binding.target_decryption_parameters_binding_hash,
        "targetShareParametersHash": target_share_parameters.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "thresholdShareVerificationKeyRoot": setup_binding.threshold_verification.threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": setup_binding.threshold_verification.threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHash": participant.trustee_threshold_verification_key_hash,
        "shareRoot": share_root,
    })
}
