use super::*;

#[cfg(test)]
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
    let proof_statement_root = derive_canonical_object_hash(
        &target_decryption_share_proof_statement_root_preimage(&statement_value)?,
    )?;
    let mut statement = statement_value;
    statement["proofStatementRoot"] = json!(proof_statement_root);

    Ok(statement)
}

#[cfg(test)]
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

    Ok(json!({
        "proofStatementRoot": hash_at_path(proof_statement, &["proofStatementRoot"])?,
    }))
}

#[cfg(test)]
fn target_decryption_share_proof_statement_value(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    local_witness: &LocalTargetDecryptionShareWitness,
    target_decryption_share: &Value,
) -> CanonicalResult<Value> {
    let accepted_aggregate_set = &setup_binding.aggregate_threshold_commitment_set;
    let credential_bindings = local_witness
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
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "targetCiphertextLevel": target_ciphertexts.target_id.level,
        "targetDecryptionShareHash": hash_at_path(target_decryption_share, &["targetDecryptionShareHash"])?,
        "smudgingCommitmentSet": smudging_commitment_set,
        "aggregateOpeningCredentials": credential_bindings,
    }))
}

pub(super) fn target_decryption_share_proof_statement_root_preimage(
    proof_statement: &Value,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": string_at_path(proof_statement, &["objectType"])?,
        "setupPackageHash": hash_at_path(proof_statement, &["setupPackageHash"])?,
        "trusteeIdentity": string_at_path(proof_statement, &["trusteeIdentity"])?,
        "rosterPosition": unsigned_at_path(proof_statement, &["rosterPosition"])?,
        "targetAcceptedRecordHash": hash_at_path(proof_statement, &["targetAcceptedRecordHash"])?,
        "targetCiphertextHash": hash_at_path(proof_statement, &["targetCiphertextHash"])?,
        "targetIdRoot": hash_at_path(proof_statement, &["targetIdRoot"])?,
        "targetOrderRoot": hash_at_path(proof_statement, &["targetOrderRoot"])?,
        "targetCiphertextLevel": unsigned_at_path(proof_statement, &["targetCiphertextLevel"])?,
        "targetDecryptionShareHash": hash_at_path(proof_statement, &["targetDecryptionShareHash"])?,
        "smudgingCommitmentSet": value_at_path(proof_statement, &["smudgingCommitmentSet"])?,
        "aggregateOpeningCredentials": array_at_path(proof_statement, &["aggregateOpeningCredentials"])?,
    }))
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

    let expected_statement_root = derive_canonical_object_hash(
        &target_decryption_share_proof_statement_root_preimage(proof_statement)?,
    )?;
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
        (
            "targetAcceptedRecordHash",
            target_accepted.target_accepted_record_hash.as_str(),
        ),
        (
            "targetCiphertextHash",
            target_ciphertexts.target_ciphertext_hash.as_str(),
        ),
        ("targetIdRoot", target_ciphertexts.target_id_root.as_str()),
        (
            "targetOrderRoot",
            target_ciphertexts.target_order_root.as_str(),
        ),
        (
            "targetDecryptionShareHash",
            hash_at_path(target_decryption_share, &["targetDecryptionShareHash"])?,
        ),
    ] {
        compare_hash_field(
            proof_statement,
            field_name,
            expected,
            "target decryption share proof statement",
        )?;
    }
    compare_string_field(
        proof_statement,
        "trusteeIdentity",
        &participant.trustee_identity,
        "target decryption share proof statement trustee",
    )?;
    compare_unsigned_field(
        proof_statement,
        "rosterPosition",
        participant.roster_position as u64,
        "target decryption share proof statement roster position",
    )?;
    compare_unsigned_field(
        proof_statement,
        "targetCiphertextLevel",
        target_ciphertexts.target_id.level as u64,
        "target decryption share proof statement ciphertext level",
    )?;
    validate_aggregate_opening_statement_binding(
        proof_statement,
        setup_binding,
        participant,
        target_ciphertexts.target_id.level + 1,
    )?;
    validate_target_decryption_smudging_commitment_set(
        value_at_path(proof_statement, &["smudgingCommitmentSet"])?,
        target_ciphertexts,
        target_share_profile,
    )
}

fn validate_target_decryption_smudging_commitment_set(
    commitment_set: &Value,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
) -> CanonicalResult<()> {
    if string_at_path(commitment_set, &["objectType"])? != "TargetDecryptionSmudgingCommitmentSet" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption smudging commitment set must be TargetDecryptionSmudgingCommitmentSet",
        ));
    }
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let polynomial_degree = target_share_profile
        .minimum_shares_for_interpolation
        .checked_sub(1)
        .filter(|degree| *degree > 0)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target decryption smudging polynomial degree must be positive",
            )
        })?;
    let records = array_at_path(commitment_set, &["commitmentRecords"])?;
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
    for _ in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            for _ in 0..polynomial_degree {
                validate_smudging_commitment_record(
                    &records[record_index],
                    rns_limb_index,
                    rns_prime,
                )?;
                record_index += 1;
            }
        }
    }

    let expected_root = derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "commitmentRecords": records,
    }))?;
    compare_hash_field(
        commitment_set,
        "smudgingCommitmentSetRoot",
        &expected_root,
        "target decryption smudging commitment set root",
    )
}

fn validate_smudging_commitment_record(
    record: &Value,
    expected_limb_index: usize,
    expected_rns_prime: u64,
) -> CanonicalResult<()> {
    if string_at_path(record, &["objectType"])? != "TargetDecryptionSmudgingCommitment" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target decryption smudging commitment record must be TargetDecryptionSmudgingCommitment",
        ));
    }
    let commitment = value_at_path(record, &["commitment"])?;
    validate_smudging_commitment_shape(commitment, expected_limb_index, expected_rns_prime)?;
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
    expected_limb_index: usize,
    expected_rns_prime: u64,
) -> CanonicalResult<()> {
    crate::bgv::setup::validate_standalone_vss_committed_material_commitment(
        commitment,
        "target decryption smudging commitment",
    )?;
    compare_string_field(
        commitment,
        "commitmentRole",
        TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
        "target decryption smudging commitment role",
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
        crate::bgv::setup::validate_standalone_vss_committed_material_commitment(
            aggregate_commitment,
            "public VSS commitment",
        )?;
        compare_string_field(
            aggregate_commitment,
            "commitmentRole",
            "aggregate-threshold-share",
            "target decryption aggregate credential binding commitment role",
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
    Ok(())
}
