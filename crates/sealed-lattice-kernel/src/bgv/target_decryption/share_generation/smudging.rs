#[cfg(test)]
use super::super::*;
use super::*;

pub(in super::super) fn apply_plaintext_multiple_flooding_noise(
    flooding_noise_openings: &[TargetDecryptionFloodingNoiseOpening],
    role: &str,
    partials_by_limb: &[Vec<u64>],
    denominator_clearing_factor: u64,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut flooded_partials = partials_by_limb.to_vec();
    let noise = target_decryption_flooding_noise_for_role(flooding_noise_openings, role)?;
    for (rns_limb_index, limb_partials) in flooded_partials.iter_mut().enumerate() {
        let rns_prime = DATA_PRIMES[rns_limb_index];
        let plaintext_multiple = mul_mod_fast(
            PLAINTEXT_MODULUS % rns_prime,
            denominator_clearing_factor % rns_prime,
            rns_prime,
        );
        for (partial_coefficient, noise_coefficient) in
            limb_partials.iter_mut().zip(noise.coefficients.iter())
        {
            let flooding_term = mul_mod_fast(
                signed_residue(*noise_coefficient, rns_prime),
                plaintext_multiple,
                rns_prime,
            );
            *partial_coefficient = add_mod_fast(*partial_coefficient, flooding_term, rns_prime);
        }
    }

    Ok(flooded_partials)
}

fn target_decryption_flooding_noise_for_role<'a>(
    flooding_noise_openings: &'a [TargetDecryptionFloodingNoiseOpening],
    role: &str,
) -> CanonicalResult<&'a TargetDecryptionFloodingNoiseOpening> {
    let role_index = TARGET_DECRYPTION_SMUDGING_ROLES
        .iter()
        .position(|candidate| *candidate == role)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target-decryption flooding-noise role is not supported",
            )
        })?;
    if flooding_noise_openings.len() != TARGET_DECRYPTION_SMUDGING_ROLES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption flooding noise must contain one ring vector per target role",
        ));
    }
    let opening = flooding_noise_openings.get(role_index).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption flooding noise is missing a target role",
        )
    })?;
    if opening.coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption flooding noise ring vector has the wrong coefficient count",
        ));
    }

    Ok(opening)
}

pub(in super::super) fn target_decryption_flooding_noise_coefficients(
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    role: &str,
) -> CanonicalResult<Vec<i64>> {
    let private_flooding_seed = decode_private_flooding_seed(private_flooding_seed_hex)?;
    if !TARGET_DECRYPTION_SMUDGING_ROLES.contains(&role) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target-decryption flooding-noise role is not supported",
        ));
    }
    let coefficient_span = u64::try_from(
        TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND * 2 + 1,
    )
    .map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target-decryption flooding-noise coefficient bound is invalid",
        )
    })?;
    let roster_position = (participant.roster_position as u64).to_le_bytes();
    let mut sampler = DeterministicSampler::new(
        TARGET_DECRYPTION_FLOODING_NOISE_DOMAIN,
        &[
            &private_flooding_seed,
            target_accepted.target_accepted_record_hash.as_bytes(),
            &roster_position,
            role.as_bytes(),
        ],
    );

    sampler
        .uniform_residues(coefficient_span, POLYNOMIAL_DEGREE)
        .into_iter()
        .map(|sampled_coefficient| {
            i64::try_from(sampled_coefficient)
                .map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "target-decryption flooding-noise coefficient does not fit a signed integer",
                    )
                })
                .map(|value| value - TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND)
        })
        .collect()
}

pub(in super::super) fn target_decryption_flooding_noise_openings(
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
) -> CanonicalResult<Vec<TargetDecryptionFloodingNoiseOpening>> {
    let mut openings = Vec::with_capacity(TARGET_DECRYPTION_SMUDGING_ROLES.len());
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        let coefficients = target_decryption_flooding_noise_coefficients(
            target_accepted,
            participant,
            private_flooding_seed_hex,
            role,
        )?;
        openings.push(TargetDecryptionFloodingNoiseOpening { coefficients });
    }

    Ok(openings)
}

pub(in super::super) fn target_decryption_smudging_commitment_set_from_flooding_noise_openings(
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    flooding_noise_openings: &[TargetDecryptionFloodingNoiseOpening],
) -> CanonicalResult<Value> {
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    if flooding_noise_openings.len() != TARGET_DECRYPTION_SMUDGING_ROLES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption flooding noise does not cover the active target statement",
        ));
    }
    let expected_record_count = TARGET_DECRYPTION_SMUDGING_ROLES.len() * active_limb_count;
    let mut records = Vec::with_capacity(expected_record_count);
    for (role_index, role) in TARGET_DECRYPTION_SMUDGING_ROLES.iter().enumerate() {
        let opening = &flooding_noise_openings[role_index];
        if opening.coefficients.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption flooding-noise opening has the wrong coefficient count",
            ));
        }
        for rns_limb_index in 0..active_limb_count {
            let commitment_opening = target_decryption_flooding_noise_commitment_opening(
                target_accepted,
                participant,
                private_flooding_seed_hex,
                opening,
                role,
                rns_limb_index,
            )?;
            records.push(target_decryption_smudging_commitment_record(
                &commitment_opening,
                rns_limb_index,
            )?);
        }
    }

    Ok(json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "commitmentRecords": records,
    }))
}

fn target_decryption_flooding_noise_commitment_opening(
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    opening: &TargetDecryptionFloodingNoiseOpening,
    role: &str,
    rns_limb_index: usize,
) -> CanonicalResult<TargetDecryptionSmudgingCommitmentOpening> {
    let message_coefficients = opening
        .coefficients
        .iter()
        .map(|coefficient| {
            let shifted = coefficient
                .checked_add(TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "target-decryption flooding-noise coefficient encoding overflowed",
                    )
                })?;
            u64::try_from(shifted).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption flooding-noise coefficient is outside the commitment encoding range",
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let material_seed_hex = target_decryption_flooding_noise_commitment_material_seed_hex(
        target_accepted,
        participant,
        private_flooding_seed_hex,
        role,
        rns_limb_index,
    )?;
    let commitment_context = target_decryption_flooding_noise_commitment_context(
        target_accepted,
        participant,
        role,
        rns_limb_index,
    );

    Ok(TargetDecryptionSmudgingCommitmentOpening {
        message_coefficients,
        material_seed_hex,
        commitment_context,
    })
}

fn target_decryption_smudging_commitment_record(
    opening: &TargetDecryptionSmudgingCommitmentOpening,
    rns_limb_index: usize,
) -> CanonicalResult<Value> {
    let computation = crate::bgv::setup::compute_vss_committed_material_commitment(
        crate::bgv::setup::VssCommittedMaterialCommitmentInput {
            commitment_role: TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_ROLE,
            commitment_context: &opening.commitment_context,
            rns_limb_index,
            message_coefficients: &opening.message_coefficients,
            material_seed_hex: &opening.material_seed_hex,
        },
    )?;

    Ok(json!({
        "objectType": "TargetDecryptionSmudgingCommitment",
        "commitment": computation.commitment,
    }))
}

fn target_decryption_flooding_noise_commitment_material_seed_hex(
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
) -> CanonicalResult<String> {
    let private_flooding_seed = decode_private_flooding_seed(private_flooding_seed_hex)?;
    let roster_position = (participant.roster_position as u64).to_le_bytes();
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();

    Ok(hash512_hex(
        TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_MATERIAL_SEED_DOMAIN,
        &[
            &private_flooding_seed,
            target_accepted.target_accepted_record_hash.as_bytes(),
            &roster_position,
            role.as_bytes(),
            &rns_limb_index_bytes,
        ],
    ))
}

pub(in super::super) fn target_decryption_flooding_noise_commitment_context_hash(
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    role: &str,
    rns_limb_index: usize,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "VssCommittedMaterialCommitmentContext",
        "commitmentRole": TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_ROLE,
        "commitmentContext": target_decryption_flooding_noise_commitment_context(
            target_accepted,
            participant,
            role,
            rns_limb_index,
        ),
    }))
}

fn target_decryption_flooding_noise_commitment_context(
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    role: &str,
    rns_limb_index: usize,
) -> Value {
    json!({
        "objectType": "TargetDecryptionFloodingNoiseCommitmentContext",
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "trusteeRosterPosition": participant.roster_position,
        "role": role,
        "rnsLimbIndex": rns_limb_index,
    })
}

fn decode_private_flooding_seed(private_flooding_seed_hex: &str) -> CanonicalResult<Vec<u8>> {
    if private_flooding_seed_hex.len() != 128
        || !private_flooding_seed_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "private target-decryption flooding seed must be 64 lowercase-hexadecimal bytes",
        ));
    }
    decode_hex(private_flooding_seed_hex)
}
