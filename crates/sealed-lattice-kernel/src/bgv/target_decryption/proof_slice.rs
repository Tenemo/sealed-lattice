use super::*;

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) struct TargetDecryptionShareAllActiveLimbsProofRequestInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) local_target_share_witness: &'a Value,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_randomness_seed_hex: &'a str,
    pub(super) proof_randomness_nonce_hex: &'a str,
}

pub(super) struct TargetDecryptionShareAllActiveLimbsProofStatementInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn target_decryption_share_all_active_limbs_proof_request_from_local_witness(
    input: TargetDecryptionShareAllActiveLimbsProofRequestInput<'_>,
) -> CanonicalResult<Value> {
    validate_target_decryption_share_proof_statement_shape(
        input.proof_statement,
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
        input.participant,
        input.target_decryption_share,
    )?;
    let local_witness = verify_target_decryption_relation_from_local_witness(
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
        input.participant,
        input.local_target_share_witness,
        input.target_decryption_share,
    )?;
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

    let mut message_vectors = Vec::with_capacity(
        active_limb_count * (1 + TARGET_DECRYPTION_SMUDGING_ROLES.len() * POLYNOMIAL_DEGREE),
    );
    let mut opening_randomness = Vec::with_capacity(
        active_limb_count * (1 + TARGET_DECRYPTION_SMUDGING_ROLES.len() * POLYNOMIAL_DEGREE),
    );
    for target_rns_limb_index in 0..active_limb_count {
        let Some(target_rns_prime) = DATA_PRIMES.get(target_rns_limb_index).copied() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target proof slice limb is outside the selected BGV basis",
            ));
        };
        let aggregate_opening = local_witness
            .compact_opening
            .active_credential_bindings
            .get(target_rns_limb_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "local target-decryption witness is missing the requested aggregate opening",
                )
            })?;
        if aggregate_opening.limb_index != target_rns_limb_index
            || aggregate_opening.rns_prime != target_rns_prime
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target proof slice aggregate opening does not match the selected limb",
            ));
        }
        target_statement_aggregate_binding(
            input.proof_statement,
            target_rns_limb_index,
            &aggregate_opening.aggregate_commitment_root,
            &aggregate_opening.aggregate_opening_root,
        )?;

        message_vectors.push(u64_coefficients_to_i64(
            &aggregate_opening.aggregate_commitment_message_values,
            "target proof slice aggregate message",
        )?);
        opening_randomness.push(aggregate_opening.aggregate_randomness_by_column.clone());
        for target_role in TARGET_DECRYPTION_SMUDGING_ROLES {
            let smudging_openings = target_decryption_smudging_proof_openings_for_slice(
                input.setup_binding,
                input.target_accepted,
                input.target_ciphertexts,
                input.target_share_profile,
                &local_witness.smudging_seed_hex,
                &local_witness.smudging_polynomial_openings,
                target_role,
                target_rns_limb_index,
                target_rns_prime,
            )?;
            message_vectors.extend(
                smudging_openings
                    .iter()
                    .map(|opening| {
                        u64_coefficients_to_i64(
                            &opening.message_coefficients,
                            "target proof slice smudging message",
                        )
                    })
                    .collect::<CanonicalResult<Vec<_>>>()?,
            );
            opening_randomness.extend(
                smudging_openings
                    .into_iter()
                    .map(|opening| opening.randomness_by_column),
            );
        }
    }

    let mut proof_request =
        target_decryption_share_all_active_limbs_proof_statement_from_public_inputs(
            TargetDecryptionShareAllActiveLimbsProofStatementInput {
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                participant: input.participant,
                target_decryption_share: input.target_decryption_share,
                proof_statement: input.proof_statement,
            },
        )?;
    proof_request["targetDecryptionMessageVectors"] = json!(message_vectors);
    proof_request["targetDecryptionOpeningRandomnessByCommitment"] = json!(opening_randomness);
    proof_request["proofRandomnessSeedHex"] = json!(input.proof_randomness_seed_hex);
    proof_request["proofRandomnessNonceHex"] = json!(input.proof_randomness_nonce_hex);

    Ok(proof_request)
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
    let statement_aggregate_bindings = array_at_path(
        value_at_path(input.proof_statement, &["compactAggregateOpeningBinding"])?,
        &["activeCredentialBindings"],
    )?;
    if statement_aggregate_bindings.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target proof statement aggregate bindings must cover every active target limb",
        ));
    }
    let active_credential_binding_root = hash_at_path(
        input.proof_statement,
        &[
            "compactAggregateOpeningBinding",
            "activeCredentialBindingRoot",
        ],
    )?
    .to_string();
    let proof_statement_root =
        hash_at_path(input.proof_statement, &["proofStatementRoot"])?.to_string();
    let smudging_commitment_set = value_at_path(
        input.proof_statement,
        &["smudgingCommitmentBinding", "smudgingCommitmentSet"],
    )?
    .clone();
    let smudging_commitment_set_root = hash_at_path(
        input.proof_statement,
        &["smudgingCommitmentBinding", "smudgingCommitmentSetRoot"],
    )?;
    let aggregate_message_coefficient_bound = (0..active_limb_count)
        .map(|target_rns_limb_index| {
            compact_aggregate_message_coefficient_bound(
                DATA_PRIMES[target_rns_limb_index],
                input.setup_binding.participants.len(),
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target proof material must include at least one active limb",
            )
        })?;

    let mut limb_statements = Vec::with_capacity(active_limb_count);
    for target_rns_limb_index in 0..active_limb_count {
        let Some(target_rns_prime) = DATA_PRIMES.get(target_rns_limb_index).copied() else {
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
        let aggregate_commitment_root =
            hash_at_path(preliminary_aggregate_binding, &["aggregateCommitmentRoot"])?.to_string();
        let aggregate_opening_root =
            hash_at_path(preliminary_aggregate_binding, &["aggregateOpeningRoot"])?.to_string();
        let statement_aggregate_binding = target_statement_aggregate_binding(
            input.proof_statement,
            target_rns_limb_index,
            &aggregate_commitment_root,
            &aggregate_opening_root,
        )?;
        let aggregate_commitment =
            value_at_path(statement_aggregate_binding, &["aggregateCommitment"])?.clone();
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
                "targetRole": target_role,
                "targetCiphertextComponentOne": target_ciphertext_component_one,
                "releasedPartialDecryption": released_partials[target_rns_limb_index],
            }));
        }
        limb_statements.push(json!({
            "targetRnsLimbIndex": target_rns_limb_index,
            "targetRnsPrime": target_rns_prime,
            "aggregateCommitmentRoot": aggregate_commitment_root,
            "aggregateOpeningRoot": aggregate_opening_root,
            "aggregateCommitment": aggregate_commitment,
            "targetRoleStatements": role_statements,
        }));
    }

    Ok(json!({
        "context": {
            "ceremonyId": input.setup_binding.ceremony_id,
            "manifestHash": input.setup_binding.election_manifest_hash,
            "rosterHash": input.setup_binding.roster_hash,
            "trusteeIdentity": input.participant.trustee_identity,
            "trusteeRosterPosition": input.participant.roster_position,
            "setupEpoch": string_at_path(input.proof_statement, &["setupEpoch"])?,
            "targetShareProofStatementRoot": proof_statement_root,
            "activeCredentialBindingRoot": active_credential_binding_root,
            "smudgingCommitmentSetRoot": smudging_commitment_set_root,
        },
        "ringDegree": POLYNOMIAL_DEGREE,
        "targetDecryptionShare": {
            "targetShareProofStatementRoot": proof_statement_root,
            "publicMatrixSeedHash": input.setup_binding.public_matrix_seed_hash,
            "targetBasisHash": input.target_accepted.target_basis_hash,
            "trusteeIdentity": input.participant.trustee_identity,
            "trusteeRosterPosition": input.participant.roster_position,
            "activeCredentialBindingRoot": active_credential_binding_root,
            "interpolationPoint": input.participant.interpolation_point,
            "targetRnsLimbStatements": limb_statements,
            "aggregateMessageCoefficientBound": aggregate_message_coefficient_bound,
            "smudgingCommitmentSet": smudging_commitment_set,
            "plaintextMultiple": PLAINTEXT_MODULUS,
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
    let bindings = array_at_path(
        value_at_path(proof_statement, &["compactAggregateOpeningBinding"])?,
        &["activeCredentialBindings"],
    )?;
    let binding = bindings.get(target_rns_limb_index).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target proof statement is missing the requested aggregate binding",
        )
    })?;
    compare_unsigned_field(
        binding,
        "rnsLimbIndex",
        target_rns_limb_index as u64,
        "target proof slice aggregate binding limb",
    )?;
    compare_hash_field(
        binding,
        "aggregateCommitmentRoot",
        aggregate_commitment_root,
        "target proof slice aggregate binding root",
    )?;
    compare_hash_field(
        binding,
        "aggregateOpeningRoot",
        aggregate_opening_root,
        "target proof slice aggregate opening root",
    )?;

    Ok(binding)
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
fn u64_coefficients_to_i64(coefficients: &[u64], field_name: &str) -> CanonicalResult<Vec<i64>> {
    coefficients
        .iter()
        .map(|coefficient| {
            i64::try_from(*coefficient).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    format!("{field_name} coefficient does not fit a signed integer"),
                )
            })
        })
        .collect()
}
