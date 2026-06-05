use super::*;

pub(super) fn sampled_evaluation_key_relation_checks(
    private_setup_seed_hash: &str,
    setup_seed_hash: &str,
    participant_identities: &[String],
    relinearization_levels: &[usize],
    rotation_schedule: &[RotationScheduleEntry],
) -> CanonicalResult<Vec<Value>> {
    let (collective_secret_coefficients, _) = collective_signed_secret_and_error_coefficients(
        private_setup_seed_hash,
        participant_identities,
    );
    let mut checks = Vec::new();
    let mut sampled_relinearization_levels = BTreeSet::new();
    if let Some(first_level) = relinearization_levels.first() {
        sampled_relinearization_levels.insert(*first_level);
    }
    sampled_relinearization_levels.insert(DIRECT_COMPARISON_OUTPUT_LEVEL);
    if let Some(last_level) = relinearization_levels.last() {
        sampled_relinearization_levels.insert(*last_level);
    }
    for level in sampled_relinearization_levels {
        let seed = evaluation_key_stream_seed(setup_seed_hash, "relinearization", level, None);
        checks.push(sampled_key_switch_relation_check(
            setup_seed_hash,
            &collective_secret_coefficients,
            "relinearization",
            "secret-square",
            level,
            None,
            &seed,
        )?);
    }
    let mut sampled_rotation_indexes = BTreeSet::new();
    if !rotation_schedule.is_empty() {
        sampled_rotation_indexes.insert(0_usize);
        sampled_rotation_indexes.insert(1_usize);
        sampled_rotation_indexes.insert(rotation_schedule.len() - 2);
        sampled_rotation_indexes.insert(rotation_schedule.len() - 1);
    }
    for required_purpose in [
        "direct-score-packing-generator-basis",
        "generator-ordered-packed-rank-forward-basis",
        "generator-ordered-packed-rank-return-basis",
    ] {
        if let Some((rotation_index, _)) = rotation_schedule
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.purpose == required_purpose)
        {
            sampled_rotation_indexes.insert(rotation_index);
        }
    }
    for rotation_index in sampled_rotation_indexes {
        let entry = &rotation_schedule[rotation_index];
        let seed = evaluation_key_stream_seed(
            setup_seed_hash,
            "rotation",
            entry.level,
            Some(entry.rotation),
        );
        checks.push(sampled_key_switch_relation_check(
            setup_seed_hash,
            &collective_secret_coefficients,
            "rotation",
            entry.purpose,
            entry.level,
            Some(entry.rotation),
            &seed,
        )?);
    }

    Ok(checks)
}

pub(super) fn sampled_key_switch_relation_check(
    setup_seed_hash: &str,
    collective_secret_coefficients: &[i64],
    key_kind: &str,
    purpose: &str,
    level: usize,
    rotation: Option<usize>,
    seed: &str,
) -> CanonicalResult<Value> {
    let source_limbs =
        key_switch_source_limbs(collective_secret_coefficients, key_kind, rotation, level)?;
    let secret_residues = DATA_PRIMES[..=level]
        .iter()
        .map(|modulus| {
            collective_secret_coefficients
                .iter()
                .map(|coefficient| signed_to_modulus_residue(*coefficient, *modulus))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let domain = match rotation {
        Some(galois_element) => format!("galois-{galois_element}"),
        None => "relinearization".to_string(),
    };
    let mut digit_indexes = BTreeSet::new();
    digit_indexes.insert(0_usize);
    digit_indexes.insert(level);
    let mut limb_indexes = BTreeSet::new();
    limb_indexes.insert(0_usize);
    limb_indexes.insert(level);
    let mut samples = Vec::new();
    for digit_index in digit_indexes {
        let digit_bytes = (digit_index as u64).to_le_bytes();
        let error = DeterministicSampler::new(
            KEY_SWITCH_ERROR_DOMAIN,
            &[domain.as_bytes(), seed.as_bytes(), &digit_bytes],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);
        for limb_index in limb_indexes.iter().copied() {
            let modulus = DATA_PRIMES[limb_index];
            let modulus_bytes = modulus.to_le_bytes();
            let public_sample = DeterministicSampler::new(
                KEY_SWITCH_SAMPLE_DOMAIN,
                &[
                    domain.as_bytes(),
                    seed.as_bytes(),
                    &digit_bytes,
                    &modulus_bytes,
                ],
            )
            .uniform_residues(modulus, POLYNOMIAL_DEGREE);
            let public_sample_secret_product =
                negacyclic_product_mod(&public_sample, &secret_residues[limb_index], modulus)?;
            for position in sample_positions() {
                let scaled_error = signed_to_plaintext_scaled_residue(error[position], modulus)?;
                let expected = if limb_index == digit_index {
                    add_mod(
                        scaled_error,
                        source_limbs[digit_index][position] % modulus,
                        modulus,
                    )?
                } else {
                    scaled_error
                };
                let component_zero = if limb_index == digit_index {
                    add_mod(
                        sub_mod(
                            scaled_error,
                            public_sample_secret_product[position],
                            modulus,
                        )?,
                        source_limbs[digit_index][position] % modulus,
                        modulus,
                    )?
                } else {
                    sub_mod(
                        scaled_error,
                        public_sample_secret_product[position],
                        modulus,
                    )?
                };
                let decrypted_key_limb = add_mod(
                    component_zero,
                    public_sample_secret_product[position],
                    modulus,
                )?;
                samples.push(json!({
                    "digitIndex": digit_index,
                    "limbIndex": limb_index,
                    "position": position,
                    "modulus": modulus,
                    "componentZeroCoefficient": component_zero,
                    "componentOneCoefficient": public_sample[position],
                    "decryptedKeyLimbCoefficient": decrypted_key_limb,
                    "expectedKeyLimbCoefficient": expected,
                    "relationMatches": decrypted_key_limb == expected,
                }));
            }
        }
    }

    Ok(json!({
        "keyKind": key_kind,
        "purpose": purpose,
        "level": level,
        "rotation": rotation,
        "keyStreamSeed": seed,
        "setupSeedHash": setup_seed_hash,
        "samples": samples,
    }))
}

pub(super) fn key_switch_source_limbs(
    collective_secret_coefficients: &[i64],
    key_kind: &str,
    rotation: Option<usize>,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let secret_residues = DATA_PRIMES[..=level]
        .iter()
        .map(|modulus| {
            collective_secret_coefficients
                .iter()
                .map(|coefficient| signed_to_modulus_residue(*coefficient, *modulus))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    match key_kind {
        "relinearization" => {
            #[cfg(not(target_arch = "wasm32"))]
            {
                secret_residues
                    .par_iter()
                    .enumerate()
                    .map(|(limb_index, limb)| {
                        negacyclic_product_mod(limb, limb, DATA_PRIMES[limb_index])
                    })
                    .collect()
            }
            #[cfg(target_arch = "wasm32")]
            {
                secret_residues
                    .iter()
                    .enumerate()
                    .map(|(limb_index, limb)| {
                        negacyclic_product_mod(limb, limb, DATA_PRIMES[limb_index])
                    })
                    .collect()
            }
        }
        "rotation" => {
            let galois_element = rotation.ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "rotation key material requires a Galois element",
                )
            })?;
            let rotated_secret =
                automorphism_signed(collective_secret_coefficients, galois_element);
            Ok(DATA_PRIMES[..=level]
                .iter()
                .map(|modulus| {
                    rotated_secret
                        .iter()
                        .map(|coefficient| signed_to_modulus_residue(*coefficient, *modulus))
                        .collect::<Vec<_>>()
                })
                .collect())
        }
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "unknown evaluation key material source kind",
        )),
    }
}

pub(super) fn automorphism_signed(input: &[i64], galois_element: usize) -> Vec<i64> {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_i64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % ring_order;
        if exponent < POLYNOMIAL_DEGREE {
            output[exponent] += value;
        } else {
            output[exponent - POLYNOMIAL_DEGREE] -= value;
        }
    }

    output
}
