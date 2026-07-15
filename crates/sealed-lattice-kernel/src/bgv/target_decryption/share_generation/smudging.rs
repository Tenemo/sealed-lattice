#[cfg(test)]
use super::super::*;
use super::*;

pub(in super::super) fn apply_plaintext_multiple_flooding_noise(
    flooding_noise_openings: &[TargetDecryptionFloodingNoiseOpening],
    role: &str,
    partials_by_limb: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut flooded_partials = partials_by_limb.to_vec();
    for (rns_limb_index, limb_partials) in flooded_partials.iter_mut().enumerate() {
        let rns_prime = DATA_PRIMES[rns_limb_index];
        let noise = target_decryption_flooding_noise_for_limb(
            flooding_noise_openings,
            role,
            rns_limb_index,
            rns_prime,
        )?;
        let plaintext_multiple = PLAINTEXT_MODULUS % rns_prime;
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

fn target_decryption_flooding_noise_for_limb<'a>(
    flooding_noise_openings: &'a [TargetDecryptionFloodingNoiseOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<&'a TargetDecryptionFloodingNoiseOpening> {
    let mut matches = flooding_noise_openings.iter().filter(|opening| {
        opening.role == role
            && opening.rns_limb_index == rns_limb_index
            && opening.rns_prime == rns_prime
    });
    let opening = matches.next().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption flooding noise is missing an active role and limb",
        )
    })?;
    if matches.next().is_some() || opening.coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption flooding noise must contain one ring vector per active role and limb",
        ));
    }

    Ok(opening)
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn target_decryption_flooding_noise_coefficients(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
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
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();
    let rns_prime_bytes = rns_prime.to_le_bytes();
    let mut sampler = DeterministicSampler::new(
        TARGET_DECRYPTION_FLOODING_NOISE_DOMAIN,
        &[
            &private_flooding_seed,
            setup_binding.setup_package_hash.as_bytes(),
            target_accepted.target_accepted_record_hash.as_bytes(),
            target_ciphertexts.target_ciphertext_hash.as_bytes(),
            participant.trustee_identity.as_bytes(),
            &roster_position,
            role.as_bytes(),
            &rns_limb_index_bytes,
            &rns_prime_bytes,
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
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
) -> CanonicalResult<Vec<TargetDecryptionFloodingNoiseOpening>> {
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let mut openings =
        Vec::with_capacity(TARGET_DECRYPTION_SMUDGING_ROLES.len() * active_limb_count);
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            openings.push(TargetDecryptionFloodingNoiseOpening {
                role: role.to_string(),
                rns_limb_index,
                rns_prime,
                coefficients: target_decryption_flooding_noise_coefficients(
                    setup_binding,
                    target_accepted,
                    target_ciphertexts,
                    participant,
                    private_flooding_seed_hex,
                    role,
                    rns_limb_index,
                    rns_prime,
                )?,
            });
        }
    }

    Ok(openings)
}

pub(in super::super) fn target_decryption_smudging_commitment_set_from_flooding_noise_openings(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    flooding_noise_openings: &[TargetDecryptionFloodingNoiseOpening],
) -> CanonicalResult<Value> {
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let expected_record_count = TARGET_DECRYPTION_SMUDGING_ROLES.len() * active_limb_count;
    if flooding_noise_openings.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption flooding noise does not cover the active target statement",
        ));
    }
    let mut records = Vec::with_capacity(expected_record_count);
    let mut opening_index = 0;
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            let opening = &flooding_noise_openings[opening_index];
            if opening.role != role
                || opening.rns_limb_index != rns_limb_index
                || opening.rns_prime != rns_prime
                || opening.coefficients.len() != POLYNOMIAL_DEGREE
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption flooding-noise openings are not in canonical statement order",
                ));
            }
            let commitment_opening = target_decryption_flooding_noise_commitment_opening(
                setup_binding,
                target_accepted,
                participant,
                private_flooding_seed_hex,
                opening,
            )?;
            records.push(target_decryption_smudging_commitment_record(
                &commitment_opening,
            )?);
            opening_index += 1;
        }
    }

    Ok(json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "commitmentRecords": records,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn target_decryption_flooding_noise_proof_opening_for_slice(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    flooding_noise_openings: &[TargetDecryptionFloodingNoiseOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<TargetDecryptionFloodingNoiseProofOpening> {
    let opening = target_decryption_flooding_noise_for_limb(
        flooding_noise_openings,
        role,
        rns_limb_index,
        rns_prime,
    )?;
    let commitment_opening = target_decryption_flooding_noise_commitment_opening(
        setup_binding,
        target_accepted,
        participant,
        private_flooding_seed_hex,
        opening,
    )?;
    Ok(TargetDecryptionFloodingNoiseProofOpening {
        message_coefficients: commitment_opening.message_coefficients,
        material_seed_hex: commitment_opening.material_seed_hex,
    })
}

fn target_decryption_flooding_noise_commitment_opening(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    opening: &TargetDecryptionFloodingNoiseOpening,
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
        setup_binding,
        target_accepted,
        participant,
        private_flooding_seed_hex,
        &opening.role,
        opening.rns_limb_index,
        opening.rns_prime,
    )?;
    let commitment_context = target_decryption_flooding_noise_commitment_context(
        setup_binding,
        target_accepted,
        participant,
        &opening.role,
        opening.rns_limb_index,
        opening.rns_prime,
    );

    Ok(TargetDecryptionSmudgingCommitmentOpening {
        rns_limb_index: opening.rns_limb_index,
        rns_prime: opening.rns_prime,
        message_coefficients,
        material_seed_hex,
        commitment_context,
    })
}

fn target_decryption_smudging_commitment_record(
    opening: &TargetDecryptionSmudgingCommitmentOpening,
) -> CanonicalResult<Value> {
    let computation = crate::bgv::setup::compute_vss_committed_material_commitment(
        crate::bgv::setup::VssCommittedMaterialCommitmentInput {
            commitment_role: TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_ROLE,
            commitment_context: &opening.commitment_context,
            rns_limb_index: opening.rns_limb_index,
            rns_prime: opening.rns_prime,
            ring_degree: POLYNOMIAL_DEGREE,
            message_coefficients: &opening.message_coefficients,
            message_coefficient_bound: (TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND as u64)
                * 2
                + 1,
            material_seed_hex: &opening.material_seed_hex,
        },
    )?;

    Ok(json!({
        "objectType": "TargetDecryptionSmudgingCommitment",
        "commitment": computation.commitment,
    }))
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_flooding_noise_commitment_material_seed_hex(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    private_flooding_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<String> {
    let private_flooding_seed = decode_private_flooding_seed(private_flooding_seed_hex)?;
    let roster_position = (participant.roster_position as u64).to_le_bytes();
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();
    let rns_prime_bytes = rns_prime.to_le_bytes();

    Ok(hash512_hex(
        TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_MATERIAL_SEED_DOMAIN,
        &[
            &private_flooding_seed,
            setup_binding.setup_package_hash.as_bytes(),
            target_accepted.target_accepted_record_hash.as_bytes(),
            participant.trustee_identity.as_bytes(),
            &roster_position,
            role.as_bytes(),
            &rns_limb_index_bytes,
            &rns_prime_bytes,
        ],
    ))
}

pub(in super::super) fn target_decryption_flooding_noise_commitment_context_hash(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "VssCommittedMaterialCommitmentContext",
        "commitmentRole": TARGET_DECRYPTION_FLOODING_NOISE_COMMITMENT_ROLE,
        "commitmentContext": target_decryption_flooding_noise_commitment_context(
            setup_binding,
            target_accepted,
            participant,
            role,
            rns_limb_index,
            rns_prime,
        ),
    }))
}

fn target_decryption_flooding_noise_commitment_context(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    participant: &ParticipantBinding,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> Value {
    json!({
        "objectType": "TargetDecryptionFloodingNoiseCommitmentContext",
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "trusteeIdentity": participant.trustee_identity,
        "trusteeRosterPosition": participant.roster_position,
        "role": role,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
    })
}

fn decode_private_flooding_seed(private_flooding_seed_hex: &str) -> CanonicalResult<Vec<u8>> {
    if private_flooding_seed_hex.len() != 128
        || !private_flooding_seed_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "private target-decryption flooding seed must be 64 lowercase-hexadecimal bytes",
        ));
    }
    decode_hex(private_flooding_seed_hex)
}
