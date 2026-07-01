use super::*;

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn read_partial_decryption_share(
    share: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
) -> CanonicalResult<()> {
    if string_at_path(share, &["objectType"])? != "BgvTargetDecryptionShare"
        || unsigned_at_path(share, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption accepts only BgvTargetDecryptionShare records",
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
        target_share_profile,
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
            target_share_profile,
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
    let smudging_input_report = value_at_path(payload, &["smudgingInputReport"])?;
    validate_target_decryption_smudging_input_report(
        smudging_input_report,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
    )?;
    let smudging_input_report_hash = derive_protocol_hash(
        "TargetDecryptionSmudgingInputReportHash",
        smudging_input_report,
    )?;
    compare_hash_field(
        payload,
        "smudgingInputReportHash",
        &smudging_input_report_hash,
        "target decryption smudging input report hash",
    )?;

    read_partial_limb_set(payload, "targetId", target_ciphertexts.target_id.level)?;
    read_partial_limb_set(
        payload,
        "targetOrder",
        target_ciphertexts.target_order.level,
    )?;

    Ok(())
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn compare_share_record_fields(
    share: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
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

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn share_payload(
    level: usize,
    target_id_partials: &[Vec<u64>],
    target_order_partials: &[Vec<u64>],
    smudging_input_report: &Value,
    smudging_input_report_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BgvTargetDecryptionSharePayload",
        "objectVersion": 1,
        "encoding": TARGET_SHARE_PAYLOAD_ENCODING,
        "level": level,
        "smudgingInputReport": smudging_input_report,
        "smudgingInputReportHash": smudging_input_report_hash,
        "targetId": partial_limb_records(target_id_partials)?,
        "targetOrder": partial_limb_records(target_order_partials)?,
    }))
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
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
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target share payload limb order or modulus does not match the selected BGV basis",
                ));
            }
            let coefficients = coefficient_vector_from_le_hex(
                string_at_path(record, &["partialDecryptionLeHex"])?,
                POLYNOMIAL_DEGREE,
                "target partial-decryption coefficient vector byte length does not match the selected BGV profile",
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

#[cfg(any(feature = "target-decryption-development-commands", test))]
fn validate_target_decryption_smudging_input_report(
    report: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
) -> CanonicalResult<()> {
    if string_at_path(report, &["objectType"])? != "TargetDecryptionSmudgingInputReport"
        || unsigned_at_path(report, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption smudging input report must be TargetDecryptionSmudgingInputReport version 1",
        ));
    }
    compare_string_field(
        report,
        "setupProfileId",
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "target decryption smudging input report setup profile",
    )?;
    compare_string_field(
        report,
        "targetDecryptionProfileId",
        TARGET_DECRYPTION_PROFILE_ID,
        "target decryption smudging input report profile",
    )?;
    compare_string_field(
        report,
        "smudgingProfileId",
        TARGET_DECRYPTION_SMUDGING_PROFILE_ID,
        "target decryption smudging input report profile",
    )?;
    for (field_name, expected) in [
        (
            "setupPackageHash",
            setup_binding.setup_package_hash.as_str(),
        ),
        (
            "targetAcceptedRecordHash",
            target_accepted.target_accepted_record_hash.as_str(),
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
        ("targetShareProfileHash", target_share_profile.hash.as_str()),
        (
            "targetBasisHash",
            target_accepted.target_basis_hash.as_str(),
        ),
        ("targetIdRoot", target_ciphertexts.target_id_root.as_str()),
        (
            "targetOrderRoot",
            target_ciphertexts.target_order_root.as_str(),
        ),
    ] {
        compare_hash_field(
            report,
            field_name,
            expected,
            "target decryption smudging input report binding",
        )?;
    }
    compare_string_field(
        report,
        "trusteeIdentity",
        &participant.trustee_identity,
        "target decryption smudging input report trustee identity",
    )?;
    for (field_name, expected) in [
        ("rosterPosition", participant.roster_position as u64),
        ("boardPosition", participant.board_position as u64),
        ("interpolationPoint", participant.interpolation_point),
        ("recoveryEpoch", participant.recovery_epoch),
        ("deviceEpoch", participant.device_epoch),
        (
            "minimumSharesForInterpolation",
            target_share_profile.minimum_shares_for_interpolation as u64,
        ),
        (
            "decryptionThreshold",
            target_share_profile.decryption_threshold as u64,
        ),
        (
            "activeRnsLimbCount",
            (target_ciphertexts.target_id.level + 1) as u64,
        ),
        ("ringDegree", POLYNOMIAL_DEGREE as u64),
        (
            "smudgingPolynomialDegree",
            target_share_profile
                .minimum_shares_for_interpolation
                .saturating_sub(1) as u64,
        ),
        ("plaintextMultiple", PLAINTEXT_MODULUS),
    ] {
        compare_unsigned_field(
            report,
            field_name,
            expected,
            "target decryption smudging input report",
        )?;
    }
    if integer_at_path(report, &["smudgingCoefficientBound"])?
        != TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target decryption smudging input report coefficient bound does not match its target decryption binding",
        ));
    }
    let role_reports = array_at_path(report, &["roleReports"])?;
    if role_reports.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption smudging input report must include targetId and targetOrder role reports",
        ));
    }
    validate_target_decryption_smudging_role_report(
        &role_reports[0],
        "targetId",
        target_ciphertexts.target_id.level,
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
    )?;
    validate_target_decryption_smudging_role_report(
        &role_reports[1],
        "targetOrder",
        target_ciphertexts.target_order.level,
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
    )
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
fn validate_target_decryption_smudging_role_report(
    role_report: &Value,
    expected_role: &str,
    level: usize,
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
) -> CanonicalResult<()> {
    compare_string_field(
        role_report,
        "role",
        expected_role,
        "target decryption smudging role report role",
    )?;
    let limb_reports = array_at_path(role_report, &["limbReports"])?;
    if limb_reports.len() != level + 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption smudging role report must include one limb report per active prime",
        ));
    }
    let maximum_reported_noise_share =
        smudging_noise_share_bound(interpolation_point, minimum_shares_for_interpolation)?;
    for (rns_limb_index, limb_report) in limb_reports.iter().enumerate() {
        compare_unsigned_field(
            limb_report,
            "rnsLimbIndex",
            rns_limb_index as u64,
            "target decryption smudging limb report index",
        )?;
        compare_unsigned_field(
            limb_report,
            "rnsPrime",
            DATA_PRIMES[rns_limb_index],
            "target decryption smudging limb report prime",
        )?;
        let maximum_absolute_noise_share =
            unsigned_at_path(limb_report, &["maximumAbsoluteNoiseShare"])?;
        if maximum_absolute_noise_share > maximum_reported_noise_share {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target decryption smudging limb report exceeds its zero-share coefficient bound",
            ));
        }
    }

    Ok(())
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn share_record_hash_input(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
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
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "thresholdShareVerificationKeyRoot": setup_binding.threshold_verification.threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": setup_binding.threshold_verification.threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHash": participant.trustee_threshold_verification_key_hash,
        "shareRoot": share_root,
    })
}
