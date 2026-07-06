use super::*;

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn derive_target_decryption_share_proof_statement(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    local_target_share_witness: &Value,
    target_decryption_share: &Value,
) -> CanonicalResult<Value> {
    let local_witness = verify_target_decryption_relation_from_local_witness(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        local_target_share_witness,
        target_decryption_share,
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
    let proof_statement_root = derive_canonical_object_hash(&statement_value)?;
    let mut statement = statement_value;
    statement["proofStatementRoot"] = json!(proof_statement_root);

    Ok(statement)
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn verify_target_decryption_share_proof_statement_binding(
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

    // This development introspection command validates only the statement
    // binding (it errors above on any mismatch); it does not verify the succinct
    // proof itself, which is the job of the result-release absorb path via
    // `verify_target_decryption_share_proof_material`. It returns the recomputed
    // statement root as evidence of the binding it checked, and carries no
    // self-attested status/verdict/refusal field.
    Ok(json!({
        "operation": "verifyBgvTargetDecryptionShareProofStatementBinding",
        "proofStatementRoot": hash_at_path(proof_statement, &["proofStatementRoot"])?,
    }))
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
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
    let accepted_aggregate_set = setup_binding
        .aggregate_threshold_commitment_set
        .as_ref()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption aggregate opening statement requires the accepted aggregate threshold commitment set",
            )
        })?;
    let credential_bindings = local_witness
        .opening
        .active_credential_bindings
        .iter()
        .map(|binding| {
            let accepted_record = accepted_aggregate_set
                .recipient_records
                .get(participant.roster_position)
                .and_then(|limb_records| limb_records.get(binding.limb_index))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "accepted aggregate threshold commitment set is missing the active recipient limb",
                    )
                })?;
            if accepted_record.rns_prime != binding.rns_prime
                || accepted_record.aggregate_commitment_root != binding.aggregate_commitment_root
                || accepted_record.aggregate_opening_root != binding.aggregate_opening_root
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target decryption aggregate credential binding does not match the accepted aggregate commitment record",
                ));
            }
            Ok(json!({
                "objectType": "TargetDecryptionAggregateOpeningCredentialBinding",
                "rnsLimbIndex": binding.limb_index,
                "rnsPrime": binding.rns_prime,
                "aggregateCommitmentRoot": binding.aggregate_commitment_root,
                "aggregateOpeningRoot": binding.aggregate_opening_root,
                "aggregateCommitment": accepted_record.aggregate_commitment.clone(),
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let active_credential_binding_root =
        aggregate_opening_credential_binding_root(&credential_bindings)?;
    let smudging_commitment_set =
        target_decryption_smudging_commitment_set_from_polynomial_openings(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            &local_witness.smudging_seed_hex,
            &local_witness.smudging_polynomial_openings,
        )?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShareProofStatement",
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "setupEpoch": local_witness.setup_epoch,
        "electionManifestHash": setup_binding.election_manifest_hash,
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
        "targetDecryptionShareHash": hash_at_path(target_decryption_share, &["targetDecryptionShareHash"])?,
        "shareRoot": hash_at_path(target_decryption_share, &["shareRoot"])?,
        "smudgingInputReportHash": smudging_input_report_hash,
        "smudgingCommitmentBinding": {
            "objectType": "TargetDecryptionSmudgingCommitmentBinding",
            "smudgingCommitmentSetRoot": smudging_commitment_set.root,
            "smudgingCommitmentSet": smudging_commitment_set.value,
        },
        "aggregateOpeningBinding": {
            "objectType": "TargetDecryptionAggregateOpeningBinding",
            "publicMatrixSeedHash": local_witness.opening.public_matrix_seed_hash,
            "shareLinkageStatementRoot": local_witness.opening.share_linkage_statement_root,
            "aggregateThresholdCommitmentRoot": local_witness.opening.aggregate_threshold_commitment_root,
            "activeCredentialBindingRoot": active_credential_binding_root,
            "activeCredentialBindings": credential_bindings,
        },
    }))
}

fn aggregate_opening_credential_binding_root(
    credential_bindings: &[Value],
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionAggregateOpeningCredentialBindingSet",
        "activeCredentialBindings": credential_bindings,
    }))
}

pub(super) fn validate_target_decryption_share_proof_statement_shape(
    proof_statement: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    target_decryption_share: &Value,
) -> CanonicalResult<()> {
    if string_at_path(proof_statement, &["objectType"])? != "BgvTargetDecryptionShareProofStatement"
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
    let expected_statement_root = derive_canonical_object_hash(&statement_without_root)?;
    compare_hash_field(
        proof_statement,
        "proofStatementRoot",
        &expected_statement_root,
        "target decryption share proof statement root",
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
    string_at_path(proof_statement, &["setupEpoch"])?;
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
    validate_aggregate_opening_statement_binding(
        value_at_path(proof_statement, &["aggregateOpeningBinding"])?,
        setup_binding,
        participant,
        target_ciphertexts.target_id.level + 1,
    )?;
    validate_smudging_commitment_statement_binding(
        value_at_path(proof_statement, &["smudgingCommitmentBinding"])?,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
    )?;

    Ok(())
}

fn validate_smudging_commitment_statement_binding(
    binding: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
) -> CanonicalResult<()> {
    if string_at_path(binding, &["objectType"])? != "TargetDecryptionSmudgingCommitmentBinding"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption smudging commitment binding must be TargetDecryptionSmudgingCommitmentBinding version 1",
        ));
    }
    let smudging_commitment_set = value_at_path(binding, &["smudgingCommitmentSet"])?;
    validate_target_decryption_smudging_commitment_set(
        smudging_commitment_set,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
    )?;
    let set_root = hash_at_path(smudging_commitment_set, &["smudgingCommitmentSetRoot"])?;
    compare_hash_field(
        binding,
        "smudgingCommitmentSetRoot",
        set_root,
        "target decryption smudging commitment binding root",
    )
}

fn validate_target_decryption_smudging_commitment_set(
    commitment_set: &Value,
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
) -> CanonicalResult<()> {
    if string_at_path(commitment_set, &["objectType"])? != "TargetDecryptionSmudgingCommitmentSet"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption smudging commitment set must be TargetDecryptionSmudgingCommitmentSet version 1",
        ));
    }
    compare_string_field(
        commitment_set,
        "commitmentRole",
        TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
        "target decryption smudging commitment set role",
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
        (
            "publicMatrixSeedHash",
            setup_binding.public_matrix_seed_hash.as_str(),
        ),
    ] {
        compare_hash_field(
            commitment_set,
            field_name,
            expected,
            "target decryption smudging commitment set",
        )?;
    }
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    for (field_name, expected) in [
        ("activeRnsLimbCount", active_limb_count as u64),
        ("ringDegree", POLYNOMIAL_DEGREE as u64),
        (
            "smudgingPolynomialDegree",
            target_share_profile
                .minimum_shares_for_interpolation
                .saturating_sub(1) as u64,
        ),
        (
            "messageCoefficientBound",
            (TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND as u64) * 2 + 1,
        ),
    ] {
        compare_unsigned_field(
            commitment_set,
            field_name,
            expected,
            "target decryption smudging commitment set",
        )?;
    }
    if integer_at_path(commitment_set, &["smudgingCoefficientBound"])?
        != TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND
        || integer_at_path(commitment_set, &["signedCoefficientOffset"])?
            != TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target decryption smudging commitment set coefficient encoding does not match the smudging profile",
        ));
    }
    let records = array_at_path(commitment_set, &["commitmentRecords"])?;
    let polynomial_degree = target_share_profile
        .minimum_shares_for_interpolation
        .saturating_sub(1);
    let expected_record_count = TARGET_DECRYPTION_SMUDGING_ROLES
        .len()
        .checked_mul(active_limb_count)
        .and_then(|count| count.checked_mul(polynomial_degree))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target decryption smudging commitment record count overflowed",
            )
        })?;
    if records.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption smudging commitment set does not contain the expected role, limb, and polynomial-degree records",
        ));
    }
    let mut record_index = 0_usize;
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            for polynomial_degree_index in 1..=polynomial_degree {
                validate_smudging_commitment_record(
                    &records[record_index],
                    setup_binding,
                    role,
                    rns_limb_index,
                    rns_prime,
                    polynomial_degree_index,
                )?;
                record_index += 1;
            }
        }
    }

    let mut without_root = commitment_set.clone();
    without_root
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption smudging commitment set must be an object",
            )
        })?
        .remove("smudgingCommitmentSetRoot")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption smudging commitment set must include its root",
            )
        })?;
    let expected_root = derive_canonical_object_hash(&without_root)?;
    compare_hash_field(
        commitment_set,
        "smudgingCommitmentSetRoot",
        &expected_root,
        "target decryption smudging commitment set root",
    )
}

fn validate_smudging_commitment_record(
    record: &Value,
    setup_binding: &SetupBinding,
    expected_role: &str,
    expected_limb_index: usize,
    expected_rns_prime: u64,
    expected_polynomial_degree: usize,
) -> CanonicalResult<()> {
    if string_at_path(record, &["objectType"])? != "TargetDecryptionSmudgingCommitment"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption smudging commitment record must be TargetDecryptionSmudgingCommitment version 1",
        ));
    }
    compare_string_field(
        record,
        "role",
        expected_role,
        "target decryption smudging commitment role",
    )?;
    compare_unsigned_field(
        record,
        "rnsLimbIndex",
        expected_limb_index as u64,
        "target decryption smudging commitment limb",
    )?;
    compare_unsigned_field(
        record,
        "rnsPrime",
        expected_rns_prime,
        "target decryption smudging commitment prime",
    )?;
    compare_unsigned_field(
        record,
        "polynomialDegree",
        expected_polynomial_degree as u64,
        "target decryption smudging commitment polynomial degree",
    )?;
    let commitment = value_at_path(record, &["commitment"])?;
    validate_smudging_commitment_shape(
        commitment,
        setup_binding,
        expected_limb_index,
        expected_rns_prime,
    )?;
    let commitment_root = derive_canonical_object_hash(commitment)?;
    compare_hash_field(
        record,
        "commitmentRoot",
        &commitment_root,
        "target decryption smudging commitment root",
    )
}

fn validate_smudging_commitment_shape(
    commitment: &Value,
    setup_binding: &SetupBinding,
    expected_limb_index: usize,
    expected_rns_prime: u64,
) -> CanonicalResult<()> {
    if string_at_path(commitment, &["objectType"])? != "VssPublicCommitment"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption smudging commitment must be VssPublicCommitment version 1",
        ));
    }
    compare_string_field(
        commitment,
        "commitmentRole",
        TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
        "target decryption smudging commitment role",
    )?;
    compare_hash_field(
        commitment,
        "publicMatrixSeedHash",
        &setup_binding.public_matrix_seed_hash,
        "target decryption smudging commitment matrix seed",
    )?;
    compare_unsigned_field(
        commitment,
        "rnsLimbIndex",
        expected_limb_index as u64,
        "target decryption smudging commitment limb",
    )?;
    compare_unsigned_field(
        commitment,
        "rnsPrime",
        expected_rns_prime,
        "target decryption smudging commitment prime",
    )?;
    compare_unsigned_field(
        commitment,
        "ringDegree",
        POLYNOMIAL_DEGREE as u64,
        "target decryption smudging commitment ring degree",
    )?;
    compare_unsigned_field(
        commitment,
        "outputCoordinateCount",
        VSS_PUBLIC_OUTPUT_COORDINATE_COUNT as u64,
        "target decryption smudging commitment output coordinate count",
    )?;
    compare_unsigned_field(
        commitment,
        "randomnessColumnCount",
        VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT as u64,
        "target decryption smudging commitment randomness column count",
    )?;
    hash_at_path(commitment, &["commitmentContextHash"])?;
    let commitment_limbs = array_at_path(commitment, &["commitmentLimbs"])?;
    if commitment_limbs.len() != 3 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption smudging commitment must include every commitment field",
        ));
    }
    for (commitment_modulus_index, limb) in commitment_limbs.iter().enumerate() {
        compare_unsigned_field(
            limb,
            "commitmentModulusIndex",
            commitment_modulus_index as u64,
            "target decryption smudging commitment modulus index",
        )?;
        compare_unsigned_field(
            limb,
            "modulus",
            DATA_PRIMES[commitment_modulus_index],
            "target decryption smudging commitment modulus",
        )?;
        let coordinates = array_at_path(limb, &["coordinates"])?;
        if coordinates.len() != VSS_PUBLIC_OUTPUT_COORDINATE_COUNT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target decryption smudging commitment coordinate count does not match the profile",
            ));
        }
        let modulus = DATA_PRIMES[commitment_modulus_index];
        for coordinate in coordinates {
            let coordinate_value = unsigned_at_path(coordinate, &[])?;
            if coordinate_value >= modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "target decryption smudging commitment coordinate is outside its commitment field",
                ));
            }
        }
    }

    Ok(())
}

fn validate_aggregate_opening_statement_binding(
    binding: &Value,
    setup_binding: &SetupBinding,
    participant: &ParticipantBinding,
    active_limb_count: usize,
) -> CanonicalResult<()> {
    if string_at_path(binding, &["objectType"])? != "TargetDecryptionAggregateOpeningBinding"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption aggregate opening binding must be TargetDecryptionAggregateOpeningBinding version 1",
        ));
    }
    compare_hash_field(
        binding,
        "publicMatrixSeedHash",
        &setup_binding.public_matrix_seed_hash,
        "target decryption aggregate opening binding public matrix seed hash",
    )?;
    let accepted_share_linkage_statement_root = setup_binding
        .share_linkage_statement_root
        .as_ref()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption aggregate opening binding requires the accepted share-linkage statement",
            )
        })?;
    compare_hash_field(
        binding,
        "shareLinkageStatementRoot",
        accepted_share_linkage_statement_root,
        "target decryption aggregate opening binding share-linkage statement root",
    )?;
    let accepted_aggregate_set = setup_binding
        .aggregate_threshold_commitment_set
        .as_ref()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption aggregate opening binding requires the accepted aggregate threshold commitment set",
            )
        })?;
    compare_hash_field(
        binding,
        "aggregateThresholdCommitmentRoot",
        &accepted_aggregate_set.aggregate_threshold_commitment_root,
        "target decryption aggregate opening binding aggregate threshold commitment root",
    )?;
    if active_limb_count > accepted_aggregate_set.rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted aggregate threshold commitment set does not cover every active target limb",
        ));
    }
    let credential_bindings = array_at_path(binding, &["activeCredentialBindings"])?;
    if credential_bindings.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption aggregate opening binding must include one active credential binding per target limb",
        ));
    }
    for (limb_index, credential_binding) in credential_bindings.iter().enumerate() {
        if string_at_path(credential_binding, &["objectType"])?
            != "TargetDecryptionAggregateOpeningCredentialBinding"
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption aggregate credential binding must be TargetDecryptionAggregateOpeningCredentialBinding version 1",
            ));
        }
        compare_unsigned_field(
            credential_binding,
            "rnsLimbIndex",
            limb_index as u64,
            "target decryption aggregate credential binding limb",
        )?;
        let Some(expected_prime) = DATA_PRIMES.get(limb_index).copied() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target decryption aggregate credential binding limb is outside the selected BGV basis",
            ));
        };
        compare_unsigned_field(
            credential_binding,
            "rnsPrime",
            expected_prime,
            "target decryption aggregate credential binding prime",
        )?;
        let accepted_record = accepted_aggregate_set
            .recipient_records
            .get(participant.roster_position)
            .and_then(|limb_records| limb_records.get(limb_index))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "accepted aggregate threshold commitment set is missing the active recipient limb",
                )
            })?;
        if accepted_record.rns_prime != expected_prime {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "accepted aggregate threshold commitment RNS prime does not match the active target limb",
            ));
        }
        compare_hash_field(
            credential_binding,
            "aggregateCommitmentRoot",
            &accepted_record.aggregate_commitment_root,
            "target decryption aggregate credential binding accepted aggregate commitment record",
        )?;
        compare_hash_field(
            credential_binding,
            "aggregateOpeningRoot",
            &accepted_record.aggregate_opening_root,
            "target decryption aggregate credential binding accepted aggregate opening record",
        )?;
        let aggregate_commitment = value_at_path(credential_binding, &["aggregateCommitment"])?;
        crate::bgv::setup::validate_standalone_vss_public_commitment_body(
            aggregate_commitment,
            "public VSS commitment",
        )?;
        compare_string_field(
            aggregate_commitment,
            "commitmentRole",
            "aggregate-threshold-share",
            "target decryption aggregate credential binding commitment role",
        )?;
        compare_hash_field(
            aggregate_commitment,
            "publicMatrixSeedHash",
            &setup_binding.public_matrix_seed_hash,
            "target decryption aggregate credential binding commitment public matrix seed hash",
        )?;
        compare_unsigned_field(
            aggregate_commitment,
            "rnsLimbIndex",
            limb_index as u64,
            "target decryption aggregate credential binding commitment limb",
        )?;
        compare_unsigned_field(
            aggregate_commitment,
            "rnsPrime",
            expected_prime,
            "target decryption aggregate credential binding commitment prime",
        )?;
        let aggregate_commitment_root = derive_canonical_object_hash(aggregate_commitment)?;
        if aggregate_commitment_root != accepted_record.aggregate_commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target decryption aggregate credential binding commitment body does not match the accepted aggregate commitment record",
            ));
        }
    }
    let expected_active_credential_binding_root =
        aggregate_opening_credential_binding_root(credential_bindings)?;
    compare_hash_field(
        binding,
        "activeCredentialBindingRoot",
        &expected_active_credential_binding_root,
        "target decryption aggregate active credential binding root",
    )?;

    Ok(())
}
