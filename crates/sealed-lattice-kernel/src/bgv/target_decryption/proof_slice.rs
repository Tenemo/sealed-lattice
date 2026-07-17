use super::*;

pub(super) struct TargetDecryptionShareAllActiveLimbsProofStatementInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
}

pub(super) fn target_decryption_share_all_active_limbs_proof_statement_from_public_inputs(
    input: TargetDecryptionShareAllActiveLimbsProofStatementInput<'_>,
) -> CanonicalResult<Value> {
    let active_limb_count = input.target_ciphertexts.target_id.level + 1;
    for target_role in TARGET_DECRYPTION_SMUDGING_ROLES {
        let selected_ciphertext =
            target_ciphertext_for_role(input.target_ciphertexts, target_role)?;
        if selected_ciphertext.level + 1 != active_limb_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target proof material requires equal active limb counts for every target role",
            ));
        }
    }
    let statement_aggregate_bindings =
        array_at_path(input.proof_statement, &["aggregateOpeningCredentials"])?;
    if statement_aggregate_bindings.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target proof statement aggregate bindings must cover every active target limb",
        ));
    }
    let active_credential_binding_root =
        aggregate_opening_credential_binding_root(statement_aggregate_bindings)?;
    let proof_statement_root = target_decryption_share_proof_statement_root(input.proof_statement)?;
    let smudging_commitment_set =
        value_at_path(input.proof_statement, &["smudgingCommitmentSet"])?.clone();

    let mut limb_statements = Vec::with_capacity(active_limb_count);
    for target_rns_limb_index in 0..active_limb_count {
        if DATA_PRIMES.get(target_rns_limb_index).is_none() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target proof slice limb is outside the selected BGV basis",
            ));
        };
        let preliminary_aggregate_binding = statement_aggregate_bindings
            .get(target_rns_limb_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target proof statement is missing the requested aggregate binding",
                )
            })?;
        let aggregate_opening_root =
            hash_at_path(preliminary_aggregate_binding, &["aggregateOpeningRoot"])?.to_string();
        let aggregate_commitment =
            value_at_path(preliminary_aggregate_binding, &["aggregateCommitment"])?.clone();
        let aggregate_commitment_root = derive_canonical_object_hash(&aggregate_commitment)?;
        target_statement_aggregate_binding(
            input.proof_statement,
            target_rns_limb_index,
            &aggregate_commitment_root,
            &aggregate_opening_root,
        )?;
        let mut role_statements = Vec::with_capacity(TARGET_DECRYPTION_SMUDGING_ROLES.len());
        for target_role in TARGET_DECRYPTION_SMUDGING_ROLES {
            let selected_ciphertext =
                target_ciphertext_for_role(input.target_ciphertexts, target_role)?;
            let released_partials = read_partial_limb_set(
                value_at_path(input.target_decryption_share, &["sharePayload"])?,
                target_role,
                selected_ciphertext.level,
            )?;
            let target_ciphertext_component_one = selected_ciphertext
                .components
                .get(1)
                .and_then(|component| component.get(target_rns_limb_index))
                .cloned()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target proof slice ciphertext component is missing the selected limb",
                    )
                })?;
            role_statements.push(json!({
                "targetCiphertextComponentOne": target_ciphertext_component_one,
                "releasedPartialDecryption": released_partials[target_rns_limb_index],
            }));
        }
        limb_statements.push(json!({
            "aggregateOpeningRoot": aggregate_opening_root,
            "aggregateCommitment": aggregate_commitment,
            "targetRoleStatements": role_statements,
        }));
    }

    Ok(json!({
        "context": {
            "setupContextHash": input.setup_binding.setup_context_hash,
            "trusteeRosterPosition": input.participant.roster_position,
            "targetShareProofStatementRoot": proof_statement_root,
        },
        "targetDecryptionShare": {
            "targetShareProofStatementRoot": proof_statement_root,
            "publicMatrixSeedHash": input.setup_binding.public_matrix_seed_hash,
            "participantCount": input.setup_binding.participants.len(),
            "trusteeRosterPosition": input.participant.roster_position,
            "activeCredentialBindingRoot": active_credential_binding_root,
            "targetRnsLimbStatements": limb_statements,
            "smudgingCommitmentSet": smudging_commitment_set,
        },
    }))
}

fn target_ciphertext_for_role<'a>(
    target_ciphertexts: &'a TargetCiphertextPair,
    target_role: &str,
) -> CanonicalResult<&'a Ciphertext> {
    match target_role {
        "targetId" => Ok(&target_ciphertexts.target_id),
        "targetOrder" => Ok(&target_ciphertexts.target_order),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target proof slice role must be targetId or targetOrder",
        )),
    }
}

fn target_statement_aggregate_binding<'a>(
    proof_statement: &'a Value,
    target_rns_limb_index: usize,
    aggregate_commitment_root: &str,
    aggregate_opening_root: &str,
) -> CanonicalResult<&'a Value> {
    let bindings = array_at_path(proof_statement, &["aggregateOpeningCredentials"])?;
    let binding = bindings.get(target_rns_limb_index).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target proof statement is missing the requested aggregate binding",
        )
    })?;
    let bound_commitment_root =
        derive_canonical_object_hash(value_at_path(binding, &["aggregateCommitment"])?)?;
    if bound_commitment_root != aggregate_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target proof slice aggregate commitment does not match the selected opening",
        ));
    }
    compare_hash_field(
        binding,
        "aggregateOpeningRoot",
        aggregate_opening_root,
        "target proof slice aggregate opening root",
    )?;

    Ok(binding)
}
