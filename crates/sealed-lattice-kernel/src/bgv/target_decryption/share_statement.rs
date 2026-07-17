use super::*;

pub(super) fn derive_target_decryption_share_proof_statement(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    local_target_share_witness: &Value,
    target_decryption_share: &Value,
) -> CanonicalResult<Value> {
    let local_witness = verify_target_decryption_relation_from_local_witness(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        participant,
        local_target_share_witness,
        target_decryption_share,
    )?;

    derive_target_decryption_share_proof_statement_from_verified_local_witness(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        participant,
        &local_witness,
        target_decryption_share,
    )
}

pub(super) fn derive_target_decryption_share_proof_statement_from_verified_local_witness(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    local_witness: &LocalTargetDecryptionShareWitness,
    target_decryption_share: &Value,
) -> CanonicalResult<Value> {
    target_decryption_share_proof_statement_value(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        participant,
        local_witness,
        target_decryption_share,
    )
}

pub(super) fn verify_target_decryption_share_proof_statement_binding(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    target_decryption_share: &Value,
    proof_statement: &Value,
) -> CanonicalResult<Value> {
    validate_target_decryption_share_proof_statement_shape(
        proof_statement,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        participant,
        target_decryption_share,
    )?;

    Ok(json!({
        "proofStatementRoot": target_decryption_share_proof_statement_root(proof_statement)?,
    }))
}

fn target_decryption_share_proof_statement_value(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    local_witness: &LocalTargetDecryptionShareWitness,
    target_decryption_share: &Value,
) -> CanonicalResult<Value> {
    let accepted_aggregate_set = &setup_binding.aggregate_threshold_commitment_set;
    let credential_bindings = local_witness
        .active_credential_bindings
        .iter()
        .enumerate()
        .map(|(limb_index, binding)| {
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
            if accepted_record.aggregate_commitment_root != binding.aggregate_commitment_root
                || accepted_record.aggregate_opening_root != binding.aggregate_opening_root
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target decryption aggregate credential binding does not match the accepted aggregate commitment record",
                ));
            }
            Ok(json!({
                "aggregateOpeningRoot": binding.aggregate_opening_root,
                "aggregateCommitment": accepted_record.aggregate_commitment.clone(),
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let smudging_commitment_set =
        target_decryption_smudging_commitment_set_from_flooding_noise_openings(
            target_accepted,
            target_ciphertexts,
            participant,
            &local_witness.private_flooding_seed_hex,
            &local_witness.flooding_noise_openings,
        )?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShareProofStatement",
        "trusteeRosterPosition": participant.roster_position,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetDecryptionShareHash": target_decryption_share_hash(target_decryption_share)?,
        "smudgingCommitmentSet": smudging_commitment_set,
        "aggregateOpeningCredentials": credential_bindings,
    }))
}

pub(super) fn target_decryption_share_proof_statement_root_preimage(
    proof_statement: &Value,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": string_at_path(proof_statement, &["objectType"])?,
        "trusteeRosterPosition": unsigned_at_path(proof_statement, &["trusteeRosterPosition"])?,
        "targetAcceptedRecordHash": hash_at_path(proof_statement, &["targetAcceptedRecordHash"])?,
        "targetDecryptionShareHash": hash_at_path(proof_statement, &["targetDecryptionShareHash"])?,
        "smudgingCommitmentSet": value_at_path(proof_statement, &["smudgingCommitmentSet"])?,
        "aggregateOpeningCredentials": array_at_path(proof_statement, &["aggregateOpeningCredentials"])?,
    }))
}

pub(super) fn target_decryption_share_proof_statement_root(
    proof_statement: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&target_decryption_share_proof_statement_root_preimage(
        proof_statement,
    )?)
}

pub(super) fn aggregate_opening_credential_binding_root(
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
    participant: &ParticipantBinding,
    target_decryption_share: &Value,
) -> CanonicalResult<()> {
    read_partial_decryption_share(
        target_decryption_share,
        setup_binding,
        target_accepted,
        target_ciphertexts,
    )?;
    if string_at_path(proof_statement, &["objectType"])? != "BgvTargetDecryptionShareProofStatement"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target decryption share proof statement must be BgvTargetDecryptionShareProofStatement version 1",
        ));
    }

    let target_decryption_share_hash = target_decryption_share_hash(target_decryption_share)?;
    for (field_name, expected) in [
        (
            "targetAcceptedRecordHash",
            target_accepted.target_accepted_record_hash.as_str(),
        ),
        (
            "targetDecryptionShareHash",
            target_decryption_share_hash.as_str(),
        ),
    ] {
        compare_hash_field(
            proof_statement,
            field_name,
            expected,
            "target decryption share proof statement",
        )?;
    }
    compare_unsigned_field(
        proof_statement,
        "trusteeRosterPosition",
        participant.roster_position as u64,
        "target decryption share proof statement roster position",
    )?;
    validate_aggregate_opening_statement_binding(
        proof_statement,
        setup_binding,
        participant,
        target_ciphertexts.target_id.level + 1,
    )?;
    validate_target_decryption_smudging_commitment_set(
        value_at_path(proof_statement, &["smudgingCommitmentSet"])?,
        target_accepted,
        target_ciphertexts,
        participant,
    )
}

fn validate_target_decryption_smudging_commitment_set(
    commitment_set: &Value,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
) -> CanonicalResult<()> {
    if string_at_path(commitment_set, &["objectType"])? != "TargetDecryptionSmudgingCommitmentSet" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target decryption smudging commitment set must be TargetDecryptionSmudgingCommitmentSet",
        ));
    }
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let records = array_at_path(commitment_set, &["commitmentRecords"])?;
    let expected_record_count = TARGET_DECRYPTION_SMUDGING_ROLES
        .len()
        .checked_mul(active_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target decryption smudging commitment record count overflowed",
            )
        })?;
    if records.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption smudging commitment set must contain one record per active role and limb",
        ));
    }
    let mut record_index = 0_usize;
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for rns_limb_index in 0..active_limb_count {
            validate_smudging_commitment_record(
                &records[record_index],
                target_accepted,
                participant,
                role,
                rns_limb_index,
            )?;
            record_index += 1;
        }
    }

    Ok(())
}

pub(super) fn target_decryption_smudging_commitment_set_root(
    commitment_set: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": string_at_path(commitment_set, &["objectType"])?,
        "commitmentRecords": array_at_path(commitment_set, &["commitmentRecords"])?,
    }))
}

fn validate_smudging_commitment_record(
    record: &Value,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    role: &str,
    expected_limb_index: usize,
) -> CanonicalResult<()> {
    if string_at_path(record, &["objectType"])? != "TargetDecryptionSmudgingCommitment" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target decryption smudging commitment record must be TargetDecryptionSmudgingCommitment",
        ));
    }
    let commitment = value_at_path(record, &["commitment"])?;
    validate_smudging_commitment_shape(
        commitment,
        target_accepted,
        participant,
        role,
        expected_limb_index,
    )?;
    Ok(())
}

fn validate_smudging_commitment_shape(
    commitment: &Value,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    role: &str,
    expected_limb_index: usize,
) -> CanonicalResult<()> {
    crate::bgv::setup::validate_standalone_vss_committed_material_commitment(
        commitment,
        "target decryption smudging commitment",
    )?;
    compare_hash_field(
        commitment,
        "commitmentContextHash",
        &target_decryption_flooding_noise_commitment_context_hash(
            target_accepted,
            participant,
            role,
            expected_limb_index,
        )?,
        "target decryption flooding-noise commitment context",
    )?;

    Ok(())
}

fn validate_aggregate_opening_statement_binding(
    proof_statement: &Value,
    setup_binding: &SetupBinding,
    participant: &ParticipantBinding,
    active_limb_count: usize,
) -> CanonicalResult<()> {
    let accepted_aggregate_set = &setup_binding.aggregate_threshold_commitment_set;
    if active_limb_count > accepted_aggregate_set.rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "accepted aggregate threshold commitment set does not cover every active target limb",
        ));
    }
    let credential_bindings = array_at_path(proof_statement, &["aggregateOpeningCredentials"])?;
    if credential_bindings.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target decryption aggregate opening binding must include one active credential binding per target limb",
        ));
    }
    for (limb_index, credential_binding) in credential_bindings.iter().enumerate() {
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
        compare_hash_field(
            credential_binding,
            "aggregateOpeningRoot",
            &accepted_record.aggregate_opening_root,
            "target decryption aggregate credential binding accepted aggregate opening record",
        )?;
        let aggregate_commitment = value_at_path(credential_binding, &["aggregateCommitment"])?;
        crate::bgv::setup::validate_standalone_vss_committed_material_commitment(
            aggregate_commitment,
            "public VSS commitment",
        )?;
        let aggregate_commitment_root = derive_canonical_object_hash(aggregate_commitment)?;
        if aggregate_commitment_root != accepted_record.aggregate_commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target decryption aggregate credential binding commitment body does not match the accepted aggregate commitment record",
            ));
        }
    }
    Ok(())
}
