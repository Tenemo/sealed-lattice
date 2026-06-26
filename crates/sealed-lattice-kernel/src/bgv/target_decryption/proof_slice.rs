use super::*;

pub(super) struct TargetDecryptionShareProofSliceRequestInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) local_target_share_witness: &'a Value,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) target_role: &'a str,
    pub(super) target_rns_limb_index: usize,
    pub(super) proof_randomness_source: &'a str,
    pub(super) proof_randomness_seed_hex: &'a str,
    pub(super) proof_randomness_nonce_hex: &'a str,
}

pub(super) fn target_decryption_share_proof_slice_request_from_local_witness(
    input: TargetDecryptionShareProofSliceRequestInput<'_>,
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
    let selected_ciphertext = match input.target_role {
        "targetId" => &input.target_ciphertexts.target_id,
        "targetOrder" => &input.target_ciphertexts.target_order,
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target proof slice role must be targetId or targetOrder",
            ));
        }
    };
    if input.target_rns_limb_index > selected_ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target proof slice limb must be active for the selected ciphertext",
        ));
    }
    let Some(target_rns_prime) = DATA_PRIMES.get(input.target_rns_limb_index).copied() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target proof slice limb is outside the selected BGV basis",
        ));
    };
    let aggregate_opening = local_witness
        .compact_opening
        .active_credential_bindings
        .get(input.target_rns_limb_index)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "local target-decryption witness is missing the requested aggregate opening",
            )
        })?;
    if aggregate_opening.rns_prime != target_rns_prime {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target proof slice aggregate opening prime does not match the selected limb",
        ));
    }

    let statement_aggregate_binding = target_statement_aggregate_binding(
        input.proof_statement,
        input.target_rns_limb_index,
        &aggregate_opening.aggregate_commitment_root,
    )?;
    let aggregate_commitment =
        value_at_path(statement_aggregate_binding, &["aggregateCommitment"])?.clone();
    let released_partials = read_partial_limb_set(
        value_at_path(input.target_decryption_share, &["sharePayload"])?,
        input.target_role,
        selected_ciphertext.level,
    )?;
    let target_ciphertext_component_one = selected_ciphertext
        .components
        .get(1)
        .and_then(|component| component.get(input.target_rns_limb_index))
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target proof slice ciphertext component is missing the selected limb",
            )
        })?;
    let smudging_openings = target_decryption_smudging_proof_openings_for_slice(
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
        &local_witness.smudging_seed_hex,
        &local_witness.smudging_polynomial_openings,
        input.target_role,
        input.target_rns_limb_index,
        target_rns_prime,
    )?;

    let mut message_vectors = Vec::with_capacity(1 + smudging_openings.len());
    message_vectors.push(u64_coefficients_to_i64(
        &aggregate_opening.aggregate_commitment_message_values,
        "target proof slice aggregate message",
    )?);
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

    let mut opening_randomness = Vec::with_capacity(1 + smudging_openings.len());
    opening_randomness.push(aggregate_opening.aggregate_randomness_by_column.clone());
    opening_randomness.extend(
        smudging_openings
            .into_iter()
            .map(|opening| opening.randomness_by_column),
    );

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

    Ok(json!({
        "context": {
            "ceremonyId": input.setup_binding.ceremony_id,
            "manifestHash": input.setup_binding.election_manifest_hash,
            "rosterHash": input.setup_binding.roster_hash,
            "trusteeIdentity": input.participant.trustee_identity,
            "trusteeRosterPosition": input.participant.roster_position,
            "setupEpoch": local_witness.setup_epoch,
            "targetShareProofStatementRoot": proof_statement_root,
            "aggregateCommitmentRoot": aggregate_opening.aggregate_commitment_root,
            "smudgingCommitmentSetRoot": smudging_commitment_set_root,
        },
        "ringDegree": POLYNOMIAL_DEGREE,
        "targetDecryptionShare": {
            "targetShareProofStatementRoot": proof_statement_root,
            "publicMatrixSeedHash": input.setup_binding.public_matrix_seed_hash,
            "targetBasisHash": input.target_accepted.target_basis_hash,
            "trusteeIdentity": input.participant.trustee_identity,
            "trusteeRosterPosition": input.participant.roster_position,
            "targetRole": input.target_role,
            "targetRnsLimbIndex": input.target_rns_limb_index,
            "targetRnsPrime": target_rns_prime,
            "interpolationPoint": input.participant.interpolation_point,
            "targetCiphertextComponentOne": target_ciphertext_component_one,
            "releasedPartialDecryption": released_partials[input.target_rns_limb_index],
            "aggregateCommitmentRoot": aggregate_opening.aggregate_commitment_root,
            "aggregateCommitment": aggregate_commitment,
            "aggregateMessageCoefficientBound": aggregate_opening.aggregate_message_coefficient_bound,
            "smudgingCommitmentSet": smudging_commitment_set,
            "plaintextMultiple": PLAINTEXT_MODULUS,
        },
        "targetDecryptionMessageVectors": message_vectors,
        "targetDecryptionOpeningRandomnessByCommitment": opening_randomness,
        "proofRandomnessSource": input.proof_randomness_source,
        "proofRandomnessSeedHex": input.proof_randomness_seed_hex,
        "proofRandomnessNonceHex": input.proof_randomness_nonce_hex,
    }))
}

fn target_statement_aggregate_binding<'a>(
    proof_statement: &'a Value,
    target_rns_limb_index: usize,
    aggregate_commitment_root: &str,
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

    Ok(binding)
}

fn u64_coefficients_to_i64(coefficients: &[u64], field_name: &str) -> CanonicalResult<Vec<i64>> {
    coefficients
        .iter()
        .map(|coefficient| {
            i64::try_from(*coefficient).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!("{field_name} coefficient does not fit a signed integer"),
                )
            })
        })
        .collect()
}

pub(super) fn proof_slice_statement_from_request(proof_request: &Value) -> CanonicalResult<Value> {
    let mut proof_slice_statement = proof_request.clone();
    let object = proof_slice_statement.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target proof slice request must be an object",
        )
    })?;
    object.remove("targetDecryptionMessageVectors");
    object.remove("targetDecryptionOpeningRandomnessByCommitment");
    object.remove("proofRandomnessSource");
    object.remove("proofRandomnessSeedHex");
    object.remove("proofRandomnessNonceHex");

    Ok(proof_slice_statement)
}
