#[cfg(test)]
use super::super::*;
use super::*;

pub(in super::super) fn target_decryption_smudging_seed_hex(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_share_profile: &TargetShareProfile,
) -> String {
    hash512_hex(
        TARGET_DECRYPTION_SMUDGING_SEED_HASH_DOMAIN,
        &[
            setup_binding.setup_package_hash.as_bytes(),
            target_accepted.target_accepted_record_hash.as_bytes(),
            target_accepted.target_context_hash.as_bytes(),
            target_accepted.target_ciphertext_hash.as_bytes(),
            target_share_profile.hash.as_bytes(),
            target_accepted.target_basis_hash.as_bytes(),
        ],
    )
}

pub(in super::super) fn apply_plaintext_multiple_zero_share_smudging(
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    partials_by_limb: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut smudged_partials = partials_by_limb.to_vec();
    for (rns_limb_index, limb_partials) in smudged_partials.iter_mut().enumerate() {
        let rns_prime = DATA_PRIMES[rns_limb_index];
        let noise_share = target_decryption_smudging_noise_share_from_openings(
            target_share_profile,
            participant,
            smudging_polynomial_openings,
            role,
            rns_limb_index,
            rns_prime,
        )?;
        let plaintext_multiple = PLAINTEXT_MODULUS % rns_prime;
        for (partial_coefficient, noise_residue) in limb_partials.iter_mut().zip(noise_share.iter())
        {
            let smudging_term = mul_mod_fast(*noise_residue, plaintext_multiple, rns_prime);
            *partial_coefficient = add_mod_fast(*partial_coefficient, smudging_term, rns_prime);
        }
    }

    Ok(smudged_partials)
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_noise_share_from_openings(
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut residues = vec![0_u64; POLYNOMIAL_DEGREE];
    let evaluation_point = participant.interpolation_point()? % rns_prime;
    let mut evaluation_point_power_mod = evaluation_point;
    let polynomial_openings = target_decryption_smudging_polynomial_openings_for_limb(
        target_share_profile,
        smudging_polynomial_openings,
        role,
        rns_limb_index,
        rns_prime,
    )?;
    for polynomial_opening in polynomial_openings {
        for (residue, sampled_coefficient) in residues
            .iter_mut()
            .zip(polynomial_opening.polynomial_coefficients.iter())
        {
            let residue_term = mul_mod_fast(
                signed_residue(*sampled_coefficient, rns_prime),
                evaluation_point_power_mod,
                rns_prime,
            );
            *residue = add_mod_fast(*residue, residue_term, rns_prime);
        }
        evaluation_point_power_mod =
            mul_mod(evaluation_point_power_mod, evaluation_point, rns_prime)?;
    }

    Ok(residues)
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn target_decryption_smudging_polynomial_coefficients(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let smudging_seed_bytes = decode_hex(smudging_seed_hex)?;
    if smudging_seed_bytes.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption smudging seed must be a 64-byte lowercase hexadecimal value",
        ));
    }
    if !TARGET_DECRYPTION_SMUDGING_ROLES.contains(&role) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target-decryption smudging role is not supported",
        ));
    }
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();
    let rns_prime_bytes = rns_prime.to_le_bytes();
    let minimum_shares_bytes =
        (target_share_profile.minimum_shares_for_interpolation as u64).to_le_bytes();
    let coefficient_span = u64::try_from(TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND * 2 + 1)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target-decryption smudging coefficient bound is invalid",
            )
        })?;

    (1..target_share_profile.minimum_shares_for_interpolation)
        .map(|polynomial_degree| {
            let polynomial_degree_bytes = (polynomial_degree as u64).to_le_bytes();
            let mut sampler = DeterministicSampler::new(
                TARGET_DECRYPTION_SMUDGING_ZERO_SHARE_DOMAIN,
                &[
                    &smudging_seed_bytes,
                    setup_binding.setup_package_hash.as_bytes(),
                    target_accepted.target_accepted_record_hash.as_bytes(),
                    target_accepted.target_context_hash.as_bytes(),
                    target_accepted.target_ciphertext_hash.as_bytes(),
                    target_ciphertexts.target_ciphertext_hash.as_bytes(),
                    target_share_profile.hash.as_bytes(),
                    role.as_bytes(),
                    &rns_limb_index_bytes,
                    &rns_prime_bytes,
                    &minimum_shares_bytes,
                    &polynomial_degree_bytes,
                ],
            );

            sampler
                .uniform_residues(coefficient_span, POLYNOMIAL_DEGREE)
                .into_iter()
                .map(|sampled_coefficient| {
                    i64::try_from(sampled_coefficient).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "target-decryption smudging coefficient does not fit a signed integer",
                        )
                    }).map(|value| value - TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect()
}

pub(in super::super) fn target_decryption_smudging_polynomial_openings(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
) -> CanonicalResult<Vec<TargetDecryptionSmudgingPolynomialOpening>> {
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let mut openings = Vec::with_capacity(
        TARGET_DECRYPTION_SMUDGING_ROLES.len()
            * active_limb_count
            * target_share_profile
                .minimum_shares_for_interpolation
                .saturating_sub(1),
    );
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            let coefficients_by_degree = target_decryption_smudging_polynomial_coefficients(
                setup_binding,
                target_accepted,
                target_ciphertexts,
                target_share_profile,
                smudging_seed_hex,
                role,
                rns_limb_index,
                rns_prime,
            )?;
            for (degree_offset, polynomial_coefficients) in
                coefficients_by_degree.into_iter().enumerate()
            {
                openings.push(TargetDecryptionSmudgingPolynomialOpening {
                    role: role.to_string(),
                    rns_limb_index,
                    rns_prime,
                    polynomial_degree: degree_offset + 1,
                    polynomial_coefficients,
                });
            }
        }
    }

    Ok(openings)
}

fn target_decryption_smudging_polynomial_openings_for_limb<'a>(
    target_share_profile: &TargetShareProfile,
    smudging_polynomial_openings: &'a [TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<Vec<&'a TargetDecryptionSmudgingPolynomialOpening>> {
    let smudging_polynomial_degree = target_share_profile
        .minimum_shares_for_interpolation
        .checked_sub(1)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "target-decryption smudging polynomial degree is invalid",
            )
        })?;
    let mut openings_by_degree = vec![None; smudging_polynomial_degree + 1];
    for opening in smudging_polynomial_openings.iter().filter(|opening| {
        opening.role == role
            && opening.rns_limb_index == rns_limb_index
            && opening.rns_prime == rns_prime
    }) {
        if opening.polynomial_degree == 0
            || opening.polynomial_degree > smudging_polynomial_degree
            || opening.polynomial_coefficients.len() != POLYNOMIAL_DEGREE
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption smudging polynomial opening has an invalid degree or coefficient count",
            ));
        }
        if openings_by_degree[opening.polynomial_degree].is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption smudging polynomial openings contain a duplicate degree",
            ));
        }
        openings_by_degree[opening.polynomial_degree] = Some(opening);
    }

    (1..=smudging_polynomial_degree)
        .map(|polynomial_degree| {
            openings_by_degree[polynomial_degree].ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption smudging polynomial openings are missing an active degree",
                )
            })
        })
        .collect()
}

#[cfg(test)]
pub(in super::super) fn target_decryption_smudging_commitment_set_from_polynomial_openings(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
) -> CanonicalResult<TargetDecryptionSmudgingCommitmentSet> {
    let active_limb_count = target_ciphertexts.target_id.level + 1;
    let smudging_polynomial_degree = target_share_profile
        .minimum_shares_for_interpolation
        .saturating_sub(1);
    let expected_record_count =
        TARGET_DECRYPTION_SMUDGING_ROLES.len() * active_limb_count * smudging_polynomial_degree;
    if smudging_polynomial_openings.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption smudging polynomial openings do not cover the active target statement",
        ));
    }
    let mut records = Vec::with_capacity(expected_record_count);
    let mut opening_index = 0;
    for role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for (rns_limb_index, &rns_prime) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
            for polynomial_degree in 1..=smudging_polynomial_degree {
                let opening = &smudging_polynomial_openings[opening_index];
                if opening.role != role
                    || opening.rns_limb_index != rns_limb_index
                    || opening.rns_prime != rns_prime
                    || opening.polynomial_degree != polynomial_degree
                    || opening.polynomial_coefficients.len() != POLYNOMIAL_DEGREE
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target-decryption smudging polynomial openings are not in canonical statement order",
                    ));
                }
                let commitment_opening = target_decryption_smudging_commitment_opening(
                    setup_binding,
                    target_accepted,
                    target_share_profile,
                    smudging_seed_hex,
                    opening,
                )?;
                records.push(target_decryption_smudging_commitment_record(
                    &commitment_opening,
                )?);
                opening_index += 1;
            }
        }
    }

    let mut value = json!({
        "objectType": "TargetDecryptionSmudgingCommitmentSet",
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "publicMatrixSeedHash": setup_binding.public_matrix_seed_hash,
        "activeRnsLimbCount": active_limb_count,
        "ringDegree": POLYNOMIAL_DEGREE,
        "smudgingCoefficientBound": TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
        "signedCoefficientOffset": TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
        "messageCoefficientBound": (TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND as u64) * 2 + 1,
        "smudgingPolynomialDegree": smudging_polynomial_degree,
        "commitmentRole": TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
        "commitmentRecords": records,
    });
    let root = derive_canonical_object_hash(&value)?;
    value["smudgingCommitmentSetRoot"] = json!(root);

    Ok(TargetDecryptionSmudgingCommitmentSet { value, root })
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn target_decryption_smudging_proof_openings_for_slice(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> CanonicalResult<Vec<TargetDecryptionSmudgingProofOpening>> {
    target_decryption_smudging_polynomial_openings_for_limb(
        target_share_profile,
        smudging_polynomial_openings,
        role,
        rns_limb_index,
        rns_prime,
    )?
    .into_iter()
    .map(|polynomial_opening| {
        let commitment_opening = target_decryption_smudging_commitment_opening(
            setup_binding,
            target_accepted,
            target_share_profile,
            smudging_seed_hex,
            polynomial_opening,
        )?;
        let commitment_context_hash = derive_canonical_object_hash(&json!({
            "objectType": "VssCommittedMaterialCommitmentContext",
            "commitmentRole": TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
            "commitmentContext": commitment_opening.commitment_context,
        }))?;
        Ok(TargetDecryptionSmudgingProofOpening {
            message_coefficients: commitment_opening.message_coefficients,
            material_seed_hex: commitment_opening.material_seed_hex,
            commitment_context_hash,
        })
    })
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_commitment_opening(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    polynomial_opening: &TargetDecryptionSmudgingPolynomialOpening,
) -> CanonicalResult<TargetDecryptionSmudgingCommitmentOpening> {
    let coefficient_offset = TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND;
    let message_coefficients = polynomial_opening
        .polynomial_coefficients
        .iter()
        .map(|coefficient| {
            let shifted = coefficient.checked_add(coefficient_offset).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption smudging coefficient encoding overflowed",
                )
            })?;
            u64::try_from(shifted).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "target-decryption smudging coefficient is outside the commitment encoding range",
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let material_seed_hex = target_decryption_smudging_commitment_material_seed_hex(
        setup_binding,
        target_accepted,
        target_share_profile,
        smudging_seed_hex,
        &polynomial_opening.role,
        polynomial_opening.rns_limb_index,
        polynomial_opening.rns_prime,
        polynomial_opening.polynomial_degree,
    )?;
    let commitment_context = target_decryption_smudging_commitment_context(
        setup_binding,
        target_accepted,
        target_share_profile,
        &polynomial_opening.role,
        polynomial_opening.rns_limb_index,
        polynomial_opening.rns_prime,
        polynomial_opening.polynomial_degree,
    );

    Ok(TargetDecryptionSmudgingCommitmentOpening {
        #[cfg(test)]
        role: polynomial_opening.role.clone(),
        #[cfg(test)]
        rns_limb_index: polynomial_opening.rns_limb_index,
        #[cfg(test)]
        rns_prime: polynomial_opening.rns_prime,
        #[cfg(test)]
        polynomial_degree: polynomial_opening.polynomial_degree,
        message_coefficients,
        material_seed_hex,
        commitment_context,
    })
}

#[cfg(test)]
fn target_decryption_smudging_commitment_record(
    opening: &TargetDecryptionSmudgingCommitmentOpening,
) -> CanonicalResult<Value> {
    let computation = crate::bgv::setup::compute_vss_committed_material_commitment(
        crate::bgv::setup::VssCommittedMaterialCommitmentInput {
            commitment_role: TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE,
            commitment_context: &opening.commitment_context,
            rns_limb_index: opening.rns_limb_index,
            rns_prime: opening.rns_prime,
            ring_degree: POLYNOMIAL_DEGREE,
            message_coefficients: &opening.message_coefficients,
            message_coefficient_bound: (TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND as u64) * 2
                + 1,
            material_seed_hex: &opening.material_seed_hex,
        },
    )?;

    Ok(json!({
        "objectType": "TargetDecryptionSmudgingCommitment",
        "role": opening.role.as_str(),
        "rnsLimbIndex": opening.rns_limb_index,
        "rnsPrime": opening.rns_prime,
        "polynomialDegree": opening.polynomial_degree,
        "commitmentRoot": computation.commitment_root,
        "commitment": computation.commitment,
    }))
}

// The private deterministic material seed for one smudging committed-material
// commitment, derived from the trustee's private smudging seed and the full
// target context so distinct roles, limbs, and degrees hide with distinct mask
// and salt streams while the same inputs regenerate byte-identical trees at
// proof time.
#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_commitment_material_seed_hex(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_share_profile: &TargetShareProfile,
    smudging_seed_hex: &str,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    polynomial_degree: usize,
) -> CanonicalResult<String> {
    let smudging_seed_bytes = decode_hex(smudging_seed_hex)?;
    if smudging_seed_bytes.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption smudging seed must be a 64-byte lowercase hexadecimal value",
        ));
    }
    let rns_limb_index_bytes = (rns_limb_index as u64).to_le_bytes();
    let rns_prime_bytes = rns_prime.to_le_bytes();
    let polynomial_degree_bytes = (polynomial_degree as u64).to_le_bytes();

    Ok(hash512_hex(
        TARGET_DECRYPTION_SMUDGING_COMMITMENT_MATERIAL_SEED_DOMAIN,
        &[
            &smudging_seed_bytes,
            setup_binding.setup_package_hash.as_bytes(),
            target_accepted.target_accepted_record_hash.as_bytes(),
            target_accepted.target_context_hash.as_bytes(),
            target_accepted.target_ciphertext_hash.as_bytes(),
            target_share_profile.hash.as_bytes(),
            role.as_bytes(),
            &rns_limb_index_bytes,
            &rns_prime_bytes,
            &polynomial_degree_bytes,
        ],
    ))
}

#[allow(clippy::too_many_arguments)]
fn target_decryption_smudging_commitment_context(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_share_profile: &TargetShareProfile,
    role: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    polynomial_degree: usize,
) -> Value {
    json!({
        "objectType": "TargetDecryptionSmudgingPolynomialCoefficientCommitmentContext",
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "role": role,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "polynomialDegree": polynomial_degree,
        "signedCoefficientOffset": TARGET_DECRYPTION_SMUDGING_COEFFICIENT_BOUND,
    })
}
