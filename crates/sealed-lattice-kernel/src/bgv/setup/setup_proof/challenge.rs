use super::*;

pub(in crate::bgv::setup) fn sample_setup_proof_lnp_tbox_uniform_residue_bytes(
    domain: &str,
    proof_randomness_seed_hex: &str,
    field_index: u64,
    coefficient_index: usize,
    bit_count: usize,
    modulus: Option<&BigUint>,
) -> CanonicalResult<Vec<u8>> {
    if bit_count == 0 {
        return Err(setup_proof_error(
            "setup proof LNP tbox uniform residue bit count must be positive",
        ));
    }
    if let Some(modulus) = modulus {
        if modulus.is_zero() {
            return Err(setup_proof_error(
                "setup proof LNP tbox uniform residue modulus must be positive",
            ));
        }
        if modulus.bits() > bit_count as u64 {
            return Err(setup_proof_error(
                "setup proof LNP tbox uniform residue modulus does not fit the declared bit count",
            ));
        }
    }

    let byte_count = bit_count
        .checked_add(7)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox bit count overflowed"))?
        / 8;
    let field_index_bytes = field_index.to_le_bytes();
    let coefficient_index_bytes = u64::try_from(coefficient_index)
        .map_err(|_| setup_proof_error("setup proof LNP tbox coefficient index overflowed"))?
        .to_le_bytes();
    let kept_high_bits = bit_count % 8;
    let mut rejection_counter = 0_u64;

    loop {
        let rejection_counter_bytes = rejection_counter.to_le_bytes();
        let mut candidate_bytes = Vec::with_capacity(byte_count);
        let mut block_index = 0_u64;
        while candidate_bytes.len() < byte_count {
            let block_index_bytes = block_index.to_le_bytes();
            let block = hash512(
                domain,
                &[
                    proof_randomness_seed_hex.as_bytes(),
                    &field_index_bytes,
                    &coefficient_index_bytes,
                    &rejection_counter_bytes,
                    &block_index_bytes,
                ],
            );
            candidate_bytes.extend_from_slice(&block);
            block_index = block_index.checked_add(1).ok_or_else(|| {
                setup_proof_error("setup proof LNP tbox sampler block index overflowed")
            })?;
        }
        candidate_bytes.truncate(byte_count);
        if kept_high_bits != 0 {
            let high_byte_mask = (1_u8 << kept_high_bits) - 1;
            let last_byte = candidate_bytes
                .last_mut()
                .expect("positive bit count produces at least one byte");
            *last_byte &= high_byte_mask;
        }

        if modulus.is_none_or(|modulus| BigUint::from_bytes_le(&candidate_bytes) < *modulus) {
            return Ok(candidate_bytes);
        }

        rejection_counter = rejection_counter.checked_add(1).ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox sampler rejection counter overflowed")
        })?;
    }
}

pub(in crate::bgv::setup) fn derive_setup_proof_scalar_challenge(
    proof_family: &str,
    scalar_challenge_domain: &str,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    challenge_bits: usize,
) -> CanonicalResult<u64> {
    validate_hash_string(
        statement_hash_hex,
        "setupProofScalarChallenge.statementHash",
    )?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofScalarChallenge.relationCommitmentHash",
    )?;
    if challenge_bits == 0 || challenge_bits > u64::BITS as usize {
        return Err(setup_proof_error(
            "setup proof scalar challenge bit count must be in 1..=64",
        ));
    }

    let challenge_coefficients = derive_setup_proof_challenge_coefficients(
        proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
        SETUP_PROOF_LNP_PROOF_RING_DEGREE,
    )?;
    let mut encoded_challenge = Vec::with_capacity(challenge_coefficients.len() * 8);
    for coefficient in challenge_coefficients {
        encoded_challenge.extend_from_slice(&coefficient.to_le_bytes());
    }

    let byte_count = challenge_bits.div_ceil(8);
    let unused_high_bits = byte_count * 8 - challenge_bits;
    let mut block_index = 0_u64;
    loop {
        let block_index_bytes = block_index.to_le_bytes();
        let block = hash512(
            scalar_challenge_domain,
            &[
                statement_hash_hex.as_bytes(),
                relation_commitment_hash_hex.as_bytes(),
                &encoded_challenge,
                &block_index_bytes,
            ],
        );
        let mut challenge_bytes = [0_u8; 8];
        challenge_bytes[..byte_count].copy_from_slice(&block[..byte_count]);
        if unused_high_bits > 0 {
            let kept_high_mask = 0xff_u8 >> unused_high_bits;
            challenge_bytes[byte_count - 1] &= kept_high_mask;
        }
        let challenge = u64::from_le_bytes(challenge_bytes);
        if challenge != 0 {
            return Ok(challenge);
        }

        block_index = block_index.checked_add(1).ok_or_else(|| {
            setup_proof_error("setup proof scalar challenge block index overflowed")
        })?;
    }
}

pub(crate) struct SetupProofLnpTboxChallengeMaterial {
    pub(crate) challenge_coefficients: Vec<i64>,
    pub(crate) lower_protocol_challenge_hash: String,
}

pub(in crate::bgv::setup) fn setup_proof_challenge_domain_hash(
    setup_profile_id: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "ChallengeDomainHash",
        &setup_proof_challenge_domain_value(setup_profile_id),
    )
}

pub(super) fn setup_proof_challenge_domain_value(setup_profile_id: &str) -> Value {
    json!({
        "objectType": "SetupProofChallengeDomain",
        "objectVersion": 1,
        "purpose": SETUP_PROOF_CHALLENGE_DOMAIN_PURPOSE,
        "setupProfileId": setup_profile_id,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "challengeDomain": SETUP_PROOF_CHALLENGE_DOMAIN,
        "challengeBits": SETUP_PROOF_CHALLENGE_BITS,
        "challengeCount": SETUP_PROOF_CHALLENGE_COUNT,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "lnpTboxChallengeEncodedBits": SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS,
        "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeSeedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        "challengeStreamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
        "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        "challengeDifferenceInvertibilityAccounting": challenge_difference_invertibility_accounting_value().expect("fixed setup proof challenge accounting is valid"),
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "randomOracleModel": "repo-owned Fiat-Shamir/QROM accounting is accepted by the setup proof accounting certificate",
    })
}

pub(in crate::bgv::setup) fn challenge_difference_invertibility_accounting_value()
-> CanonicalResult<Value> {
    let proof_modulus = setup_proof_lnp_tbox_proof_modulus();
    let challenge_coefficient_bound = BigUint::from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND);
    let difference_coefficient_bound = &challenge_coefficient_bound * BigUint::from(2_u32);
    let lnp_bound_left =
        BigUint::from(4_u32) * &challenge_coefficient_bound * &challenge_coefficient_bound;
    if lnp_bound_left >= proof_modulus {
        return Err(setup_proof_error(
            "setup proof challenge coefficient bound does not satisfy the LNP22 invertibility condition",
        ));
    }

    Ok(json!({
        "objectType": "SetupProofChallengeDifferenceInvertibilityAccounting",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofRing": "Z_qproof[X]/(X^d+1)",
        "proofRingDegree": SETUP_PROOF_LNP_PROOF_RING_DEGREE,
        "proofModulusDecimal": proof_modulus.to_string(),
        "proofModulusBitCount": proof_modulus.bits(),
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "challengeDifferenceCoefficientBound": difference_coefficient_bound.to_string(),
        "condition": "4 * challengeCoefficientBound^2 < proofModulus",
        "conditionLeftDecimal": lnp_bound_left.to_string(),
        "conditionRightDecimal": proof_modulus.to_string(),
        "conditionSatisfied": true,
        "referenceRows": [
            {
                "document": "LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General",
                "localReferencePath": "reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt",
                "sections": [
                    "Section 2.7 Challenge Space",
                    "Appendix A, Theorem A.2 knowledge soundness"
                ],
            }
        ],
        "status": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
    }))
}

fn challenge_audit_statement_hash(proof_family: &str) -> String {
    hash512_hex(
        "sealed-lattice/collective-bgv-setup/challenge-audit-statement-v1",
        &[proof_family.as_bytes()],
    )
}

fn challenge_audit_relation_commitment_hash(proof_family: &str) -> String {
    hash512_hex(
        "sealed-lattice/collective-bgv-setup/challenge-audit-relation-commitment-v1",
        &[proof_family.as_bytes()],
    )
}

fn sampled_challenge_coefficients(coefficients: &[i64], sample_positions: &[usize]) -> Vec<Value> {
    sample_positions
        .iter()
        .map(|coefficient_position| {
            json!({
                "coefficientPosition": coefficient_position,
                "coefficientValue": coefficients[*coefficient_position],
            })
        })
        .collect()
}

fn subtract_centered_coefficients(left: &[i64], right: &[i64]) -> CanonicalResult<Vec<i64>> {
    if left.len() != right.len() {
        return Err(setup_proof_error(
            "setup proof challenge difference requires equal-length coefficient vectors",
        ));
    }

    left.iter()
        .zip(right)
        .map(|(left_coefficient, right_coefficient)| {
            left_coefficient
                .checked_sub(*right_coefficient)
                .ok_or_else(|| setup_proof_error("setup proof challenge difference overflowed"))
        })
        .collect()
}

fn centered_coefficient_infinity_norm(coefficients: &[i64]) -> u64 {
    coefficients
        .iter()
        .map(|coefficient| coefficient.unsigned_abs())
        .max()
        .unwrap_or(0)
}

fn centered_polynomial_is_invertible_mod_negacyclic(
    coefficients: &[i64],
    ring_degree: usize,
    modulus: &BigUint,
) -> CanonicalResult<bool> {
    if coefficients.len() != ring_degree {
        return Err(setup_proof_error(
            "setup proof challenge polynomial length does not match the proof ring degree",
        ));
    }
    let polynomial = centered_coefficients_to_modular_polynomial(coefficients, modulus);
    if polynomial.is_empty() {
        return Ok(false);
    }

    let ring_polynomial = negacyclic_modulus_polynomial(ring_degree);
    let greatest_common_divisor =
        modular_polynomial_greatest_common_divisor(polynomial, ring_polynomial, modulus)?;
    Ok(greatest_common_divisor.len() == 1 && greatest_common_divisor[0].is_one())
}

fn centered_coefficients_to_modular_polynomial(
    coefficients: &[i64],
    modulus: &BigUint,
) -> Vec<BigUint> {
    let mut polynomial = coefficients
        .iter()
        .map(|coefficient| {
            if *coefficient >= 0 {
                BigUint::from(*coefficient as u64) % modulus
            } else {
                let magnitude = BigUint::from(coefficient.unsigned_abs()) % modulus;
                if magnitude.is_zero() {
                    BigUint::zero()
                } else {
                    modulus.clone() - magnitude
                }
            }
        })
        .collect::<Vec<_>>();
    trim_modular_polynomial(&mut polynomial);

    polynomial
}

fn negacyclic_modulus_polynomial(ring_degree: usize) -> Vec<BigUint> {
    let mut polynomial = vec![BigUint::zero(); ring_degree + 1];
    polynomial[0] = BigUint::one();
    polynomial[ring_degree] = BigUint::one();
    polynomial
}

fn modular_polynomial_greatest_common_divisor(
    mut left: Vec<BigUint>,
    mut right: Vec<BigUint>,
    modulus: &BigUint,
) -> CanonicalResult<Vec<BigUint>> {
    trim_modular_polynomial(&mut left);
    trim_modular_polynomial(&mut right);

    while !right.is_empty() {
        let remainder = modular_polynomial_remainder(left, &right, modulus)?;
        left = right;
        right = remainder;
    }

    if left.is_empty() {
        return Ok(left);
    }
    let leading_inverse = modular_inverse(
        left.last()
            .expect("non-empty modular polynomial has a leading coefficient"),
        modulus,
    )?;
    for coefficient in &mut left {
        *coefficient = (coefficient.clone() * &leading_inverse) % modulus;
    }
    trim_modular_polynomial(&mut left);

    Ok(left)
}

fn modular_polynomial_remainder(
    mut numerator: Vec<BigUint>,
    denominator: &[BigUint],
    modulus: &BigUint,
) -> CanonicalResult<Vec<BigUint>> {
    let mut denominator = denominator.to_vec();
    trim_modular_polynomial(&mut denominator);
    if denominator.is_empty() {
        return Err(setup_proof_error(
            "setup proof modular polynomial division by zero",
        ));
    }

    let denominator_degree = denominator.len() - 1;
    let denominator_leading_inverse = modular_inverse(
        denominator
            .last()
            .expect("non-empty denominator has a leading coefficient"),
        modulus,
    )?;

    trim_modular_polynomial(&mut numerator);
    while !numerator.is_empty() && numerator.len() >= denominator.len() {
        let numerator_degree = numerator.len() - 1;
        let shift = numerator_degree - denominator_degree;
        let scale = (numerator[numerator_degree].clone() * &denominator_leading_inverse) % modulus;
        if !scale.is_zero() {
            for (denominator_index, denominator_coefficient) in denominator.iter().enumerate() {
                let target_index = shift + denominator_index;
                let product = (&scale * denominator_coefficient) % modulus;
                let current = numerator[target_index].clone();
                numerator[target_index] = if current >= product {
                    current - product
                } else {
                    (current + modulus.clone()) - product
                };
                numerator[target_index] = numerator[target_index].clone() % modulus;
            }
        }
        trim_modular_polynomial(&mut numerator);
    }

    Ok(numerator)
}

fn modular_inverse(value: &BigUint, modulus: &BigUint) -> CanonicalResult<BigUint> {
    if value.is_zero() {
        return Err(setup_proof_error(
            "setup proof modular inverse of zero is undefined",
        ));
    }
    let exponent = modulus - BigUint::from(2_u32);

    Ok(value.modpow(&exponent, modulus))
}

fn trim_modular_polynomial(polynomial: &mut Vec<BigUint>) {
    while polynomial.last().is_some_and(BigUint::is_zero) {
        polynomial.pop();
    }
}

pub(in crate::bgv::setup) fn setup_proof_challenge_space_audit_value(
    ring_degree: usize,
) -> CanonicalResult<Value> {
    let sample_positions = challenge_sample_positions(ring_degree)?;
    let proof_modulus = setup_proof_lnp_tbox_proof_modulus();
    let mut family_challenges = Vec::new();
    for proof_family in SETUP_PROOF_FAMILIES {
        let statement_hash = challenge_audit_statement_hash(proof_family);
        let relation_commitment_hash = challenge_audit_relation_commitment_hash(proof_family);
        let challenge_coefficients = derive_setup_proof_challenge_coefficients(
            proof_family,
            &statement_hash,
            &relation_commitment_hash,
            ring_degree,
        )?;
        let samples = sampled_challenge_coefficients(&challenge_coefficients, &sample_positions);
        family_challenges.push((
            *proof_family,
            statement_hash,
            relation_commitment_hash,
            challenge_coefficients,
            samples,
        ));
    }

    let mut sampled_difference_checks = Vec::new();
    for left_index in 0..family_challenges.len() {
        for right_index in (left_index + 1)..family_challenges.len() {
            let left = &family_challenges[left_index];
            let right = &family_challenges[right_index];
            let difference_coefficients = subtract_centered_coefficients(&left.3, &right.3)?;
            let coefficient_infinity_norm =
                centered_coefficient_infinity_norm(&difference_coefficients);
            let difference_samples =
                sampled_challenge_coefficients(&difference_coefficients, &sample_positions);
            sampled_difference_checks.push(json!({
                "leftProofFamily": left.0,
                "rightProofFamily": right.0,
                "coefficientInfinityNorm": coefficient_infinity_norm,
                "differenceCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND * 2,
                "sampledDifferenceCoefficients": difference_samples,
                "invertibleOverProofRing": centered_polynomial_is_invertible_mod_negacyclic(
                    &difference_coefficients,
                    ring_degree,
                    &proof_modulus,
                )?,
            }));
        }
    }

    let family_samples = family_challenges
        .iter()
        .map(
            |(
                proof_family,
                statement_hash,
                relation_commitment_hash,
                _challenge_coefficients,
                samples,
            )| {
                json!({
                    "proofFamily": proof_family,
                    "statementHash": statement_hash,
                    "relationCommitmentHash": relation_commitment_hash,
                    "sampledCoefficients": samples,
                })
            },
        )
        .collect::<Vec<_>>();

    Ok(json!({
        "objectType": "SetupProofChallengeSpaceAudit",
        "objectVersion": 1,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamilies": SETUP_PROOF_FAMILIES,
        "applicationRingDegree": POLYNOMIAL_DEGREE,
        "lnpTboxProofRingDegree": ring_degree,
        "challengeCoefficientBound": SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND,
        "lnpTboxChallengeLog2Range": SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE,
        "lnpTboxChallengeEncodedBits": u64::try_from(ring_degree)
            .map_err(|_| setup_proof_error("setup proof challenge audit ring degree does not fit u64"))?
            .checked_mul(SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE as u64)
            .ok_or_else(|| setup_proof_error("setup proof challenge encoded bit count overflowed"))?,
        "lnpTboxChallengeSpaceBits": SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS,
        "challengeSpace": SETUP_PROOF_CHALLENGE_SPACE,
        "challengeSampler": SETUP_PROOF_CHALLENGE_SAMPLER,
        "challengeSeedDomain": SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
        "challengeStreamDomain": SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
        "challengeDifferenceInvertibilityStatus": SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS,
        "challengeDifferenceInvertibilityAccounting": challenge_difference_invertibility_accounting_value()?,
        "familySamples": family_samples,
        "sampledDifferenceChecks": sampled_difference_checks,
    }))
}

pub(in crate::bgv::setup) fn setup_proof_challenge_space_audit_hash(
    namespace: &str,
    ring_degree: usize,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        namespace,
        &setup_proof_challenge_space_audit_value(ring_degree)?,
    )
}

pub(in crate::bgv::setup) fn derive_setup_proof_challenge_coefficients(
    proof_family: &str,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    ring_degree: usize,
) -> CanonicalResult<Vec<i64>> {
    if !SETUP_PROOF_FAMILIES.contains(&proof_family) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge proof family is not in the fixed setup-proof profile",
        ));
    }
    validate_hash_string(statement_hash_hex, "setupProofChallenge.statementHash")?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofChallenge.relationCommitmentHash",
    )?;
    let sampler = SetupProofChallengeSampler::new(
        proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
    );
    derive_setup_proof_challenge_coefficients_from_sampler(proof_family, ring_degree, sampler)
}

#[cfg(test)]
pub(crate) fn derive_setup_proof_lnp_tbox_challenge_from_prefix(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
) -> CanonicalResult<SetupProofLnpTboxChallengeMaterial> {
    let (_, challenge_material) = setup_proof_lnp_tbox_z34_seed_and_challenge_from_prefix(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        prefix_bytes,
    )?;

    Ok(challenge_material)
}

pub(super) fn setup_proof_lnp_tbox_z34_seed_and_challenge_from_prefix(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    prefix_bytes: &[u8],
) -> CanonicalResult<(
    SetupProofLnpTboxZ34SeedMaterial,
    SetupProofLnpTboxChallengeMaterial,
)> {
    validate_lnp_tbox_layout(layout)?;
    validate_hash_string(
        statement_hash_hex,
        "setupProofLnpTboxChallenge.statementHash",
    )?;
    validate_hash_string(
        relation_commitment_hash_hex,
        "setupProofLnpTboxChallenge.relationCommitmentHash",
    )?;
    let mut reader = LnpBitReader::new(prefix_bytes);
    let t_b_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.t_b_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "tB",
    )?;
    let z34_seed_material = setup_proof_lnp_tbox_z34_seed_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &t_b_coefficients,
    )?;
    let h_coefficients = decode_uniform_polyvec(
        &mut reader,
        layout.h_polynomial_count,
        layout.proof_ring_degree,
        &layout.proof_modulus,
        layout.proof_modulus_bit_count,
        "h",
    )?;
    verify_lnp_tbox_h_forced_zero_coefficients(&h_coefficients, layout.proof_ring_degree)?;
    let compressed_bit_count = layout
        .proof_modulus_bit_count
        .checked_sub(layout.compression_dropped_bits)
        .ok_or_else(|| setup_proof_error("setup proof compressed tA1 bit count underflowed"))?;
    let compressed_modulus = BigUint::one() << compressed_bit_count;
    decode_uniform_polyvec(
        &mut reader,
        layout.t_a1_polynomial_count,
        layout.proof_ring_degree,
        &compressed_modulus,
        compressed_bit_count,
        "tA1",
    )?;
    reader.finish_exact_end("setup proof LNP tbox prefix")?;

    let challenge_material = setup_proof_lnp_tbox_challenge_material(
        layout,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &z34_seed_material,
    )?;

    Ok((z34_seed_material, challenge_material))
}

pub(super) fn setup_proof_lnp_tbox_challenge_material(
    layout: &SetupProofLnpTboxLayout,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
    z34_seed_material: &SetupProofLnpTboxZ34SeedMaterial,
) -> CanonicalResult<SetupProofLnpTboxChallengeMaterial> {
    let lower_protocol_challenge_hash = hash512_hex(
        SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_DOMAIN,
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            statement_hash_hex.as_bytes(),
            relation_commitment_hash_hex.as_bytes(),
            z34_seed_material.seed_material_hash.as_bytes(),
            z34_seed_material.challenge_seed_hash.as_bytes(),
            z34_seed_material.challenge_tail_hash.as_bytes(),
            z34_seed_material.challenge_row_domain_hash.as_bytes(),
            z34_seed_material.challenge_z3_row_set_hash.as_bytes(),
            z34_seed_material.challenge_z4_row_set_hash.as_bytes(),
        ],
    );
    let sampler = SetupProofChallengeSampler::new_lnp_tbox_lower_protocol(
        layout.proof_family,
        statement_hash_hex,
        relation_commitment_hash_hex,
        &lower_protocol_challenge_hash,
    );
    let challenge_coefficients = derive_setup_proof_challenge_coefficients_from_sampler(
        layout.proof_family,
        layout.proof_ring_degree,
        sampler,
    )?;

    Ok(SetupProofLnpTboxChallengeMaterial {
        challenge_coefficients,
        lower_protocol_challenge_hash,
    })
}

fn derive_setup_proof_challenge_coefficients_from_sampler(
    proof_family: &str,
    ring_degree: usize,
    mut sampler: SetupProofChallengeSampler,
) -> CanonicalResult<Vec<i64>> {
    if !SETUP_PROOF_FAMILIES.contains(&proof_family) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge proof family is not in the fixed setup-proof profile",
        ));
    }
    if ring_degree < 2 || !ring_degree.is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge ring degree must be even and at least two",
        ));
    }

    let half_degree = ring_degree / 2;
    let mut coefficients = vec![0_i64; ring_degree];
    for coefficient in coefficients.iter_mut().take(half_degree) {
        let sample = sampler.next_bounded_sample(
            SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .expect("fixed challenge modulus fits u64"),
            3,
        )?;
        *coefficient = i64::try_from(sample).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge sample does not fit i64",
            )
        })? - i64::try_from(SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND)
            .expect("fixed challenge coefficient bound fits i64");
    }
    coefficients[half_degree] = 0;
    for coefficient_position in (half_degree + 1)..ring_degree {
        coefficients[coefficient_position] = -coefficients[ring_degree - coefficient_position];
    }

    Ok(coefficients)
}

struct SetupProofChallengeSampler {
    seed: [u8; 64],
    block_index: u64,
    block: [u8; 64],
    bit_offset: usize,
}

impl SetupProofChallengeSampler {
    fn new(
        proof_family: &str,
        statement_hash_hex: &str,
        relation_commitment_hash_hex: &str,
    ) -> Self {
        Self {
            seed: hash512(
                SETUP_PROOF_CHALLENGE_SEED_DOMAIN,
                &[
                    proof_family.as_bytes(),
                    statement_hash_hex.as_bytes(),
                    relation_commitment_hash_hex.as_bytes(),
                ],
            ),
            block_index: 0,
            block: [0_u8; 64],
            bit_offset: 512,
        }
    }

    fn new_lnp_tbox_lower_protocol(
        proof_family: &str,
        statement_hash_hex: &str,
        relation_commitment_hash_hex: &str,
        lower_protocol_challenge_hash: &str,
    ) -> Self {
        Self {
            seed: hash512(
                SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_SEED_DOMAIN,
                &[
                    proof_family.as_bytes(),
                    statement_hash_hex.as_bytes(),
                    relation_commitment_hash_hex.as_bytes(),
                    lower_protocol_challenge_hash.as_bytes(),
                ],
            ),
            block_index: 0,
            block: [0_u8; 64],
            bit_offset: 512,
        }
    }

    fn next_bounded_sample(&mut self, modulus: u64, bit_count: usize) -> CanonicalResult<u64> {
        if bit_count == 0 || bit_count > 63 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge sample bit count is outside the supported range",
            ));
        }
        if modulus < (1_u64 << (bit_count - 1)) || modulus >= (1_u64 << bit_count) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "setup proof challenge modulus does not match the rejection bit count",
            ));
        }

        loop {
            let candidate = self.next_bits(bit_count)?;
            if candidate < modulus {
                return Ok(candidate);
            }
        }
    }

    fn next_bits(&mut self, bit_count: usize) -> CanonicalResult<u64> {
        if self.bit_offset + bit_count > 512 {
            let block_index_bytes = self.block_index.to_le_bytes();
            self.block = hash512(
                SETUP_PROOF_CHALLENGE_STREAM_DOMAIN,
                &[&self.seed, &block_index_bytes],
            );
            self.block_index = self.block_index.checked_add(1).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "setup proof challenge stream block index overflowed",
                )
            })?;
            self.bit_offset = 0;
        }

        let mut value = 0_u64;
        for bit_index in 0..bit_count {
            let absolute_bit_index = self.bit_offset + bit_index;
            let byte = self.block[absolute_bit_index / 8];
            let bit = (byte >> (absolute_bit_index % 8)) & 1;
            value |= u64::from(bit) << bit_index;
        }
        self.bit_offset += bit_count;

        Ok(value)
    }
}

pub(super) fn challenge_sample_positions(ring_degree: usize) -> CanonicalResult<Vec<usize>> {
    if ring_degree < 2 || !ring_degree.is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup proof challenge sample positions require an even ring degree",
        ));
    }

    let half_degree = ring_degree / 2;
    let last_position = ring_degree - 1;
    let mut positions = vec![0, 1.min(last_position), half_degree - 1, half_degree];
    if half_degree + 1 < ring_degree {
        positions.push(half_degree + 1);
    }
    positions.push(last_position);
    positions.sort_unstable();
    positions.dedup();

    Ok(positions)
}
