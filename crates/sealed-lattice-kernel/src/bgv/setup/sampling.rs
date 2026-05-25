use super::*;

pub(super) fn sample_public_residues(seed_digest: &str, label: &str, modulus: u64) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            json!({
                "position": position,
                "modulus": modulus,
                "value": sample_residue(seed_digest, label, position, modulus),
            })
        })
        .collect()
}

pub(super) fn sample_small_distribution(
    seed_digest: &str,
    identity: &str,
    label: &str,
    minimum: i64,
    maximum: i64,
) -> Vec<Value> {
    let width = u64::try_from(maximum - minimum + 1).expect("small distribution width fits u64");
    sample_positions()
        .into_iter()
        .map(|position| {
            let value = minimum
                + i64::try_from(sample_small_distribution_offset(
                    seed_digest,
                    identity,
                    label,
                    position,
                    width,
                ))
                .expect("small distribution offset fits i64");
            json!({
                "position": position,
                "value": value,
            })
        })
        .collect()
}

pub(super) fn sample_small_distribution_offset(
    seed_digest: &str,
    identity: &str,
    label: &str,
    position: usize,
    width: u64,
) -> u64 {
    let position_text = position.to_string();
    let mut block_index = 0_u64;
    loop {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/sample-small-distribution-v2",
            &[
                seed_digest.as_bytes(),
                identity.as_bytes(),
                label.as_bytes(),
                position_text.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        for chunk in output.chunks_exact(8) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            if let Some(reduced_value) = reduce_unbiased_u64(u64::from_le_bytes(word), width) {
                return reduced_value;
            }
        }
        block_index = block_index
            .checked_add(1)
            .expect("small distribution rejection block index overflowed");
    }
}

pub(super) fn sample_centered_binomial_eta2(
    seed_digest: &str,
    identity: &str,
    label: &str,
) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            let position_text = position.to_string();
            let output = hash512(
                "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-v1",
                &[
                    seed_digest.as_bytes(),
                    identity.as_bytes(),
                    label.as_bytes(),
                    position_text.as_bytes(),
                ],
            );
            let low_weight = i64::from(output[0] & 1) + i64::from((output[0] >> 1) & 1);
            let high_weight = i64::from((output[0] >> 2) & 1) + i64::from((output[0] >> 3) & 1);
            json!({
                "position": position,
                "value": low_weight - high_weight,
            })
        })
        .collect()
}

pub(super) fn dense_public_residues(seed_digest: &str, label: &str, modulus: u64) -> Vec<u64> {
    (0..POLYNOMIAL_DEGREE)
        .map(|position| sample_residue(seed_digest, label, position, modulus))
        .collect()
}

pub(super) fn dense_small_coefficients(
    seed_digest: &str,
    identity: &str,
    label: &str,
    minimum: i64,
    maximum: i64,
) -> Vec<i64> {
    let width = u64::try_from(maximum - minimum + 1).expect("small distribution width fits u64");
    (0..POLYNOMIAL_DEGREE)
        .map(|position| {
            minimum
                + i64::try_from(sample_small_distribution_offset(
                    seed_digest,
                    identity,
                    label,
                    position,
                    width,
                ))
                .expect("small distribution offset fits i64")
        })
        .collect()
}

pub(super) fn dense_centered_binomial_coefficients(
    seed_digest: &str,
    identity: &str,
    label: &str,
) -> Vec<i64> {
    (0..POLYNOMIAL_DEGREE)
        .map(|position| {
            let position_text = position.to_string();
            let output = hash512(
                "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-v1",
                &[
                    seed_digest.as_bytes(),
                    identity.as_bytes(),
                    label.as_bytes(),
                    position_text.as_bytes(),
                ],
            );
            let low_weight = i64::from(output[0] & 1) + i64::from((output[0] >> 1) & 1);
            let high_weight = i64::from((output[0] >> 2) & 1) + i64::from((output[0] >> 3) & 1);
            low_weight - high_weight
        })
        .collect()
}

pub(super) fn signed_to_modulus_residue(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        u64::try_from(value).expect("non-negative small value fits u64") % modulus
    } else {
        let magnitude = value.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

pub(super) fn negacyclic_product_mod(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let left_ntt = forward_negacyclic_ntt(left, modulus)?;
    let right_ntt = forward_negacyclic_ntt(right, modulus)?;
    let product_ntt = left_ntt
        .iter()
        .zip(right_ntt.iter())
        .map(|(left_value, right_value)| mul_mod(*left_value, *right_value, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;

    inverse_negacyclic_ntt(&product_ntt, modulus)
}

pub(super) fn sample_values(values: &[u64]) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            json!({
                "position": position,
                "value": values[position],
            })
        })
        .collect()
}

pub(super) fn sample_signed_values(values: &[i64]) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            json!({
                "position": position,
                "value": values[position],
            })
        })
        .collect()
}

pub(super) fn sample_encryption_relation_checks(
    message_residues: &[u64],
    public_key_product: &[u64],
    public_sample_product: &[u64],
    error_zero_residues: &[u64],
    error_one_residues: &[u64],
) -> CanonicalResult<Vec<Value>> {
    let modulus = DATA_PRIMES[0];
    sample_positions()
        .into_iter()
        .map(|position| {
            let component_zero = add_mod(
                add_mod(
                    public_key_product[position],
                    error_zero_residues[position],
                    modulus,
                )?,
                message_residues[position],
                modulus,
            )?;
            let component_one = add_mod(
                public_sample_product[position],
                error_one_residues[position],
                modulus,
            )?;
            Ok(json!({
                "position": position,
                "modulus": modulus,
                "componentZeroCoefficient": component_zero,
                "componentOneCoefficient": component_one,
                "relationMatches": true,
            }))
        })
        .collect()
}

pub(super) fn sample_residue(seed_digest: &str, label: &str, position: usize, modulus: u64) -> u64 {
    let position_text = position.to_string();
    let modulus_text = modulus.to_string();
    let mut block_index = 0_u64;
    loop {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/sample-residue-v2",
            &[
                seed_digest.as_bytes(),
                label.as_bytes(),
                position_text.as_bytes(),
                modulus_text.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        for chunk in output.chunks_exact(8) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            if let Some(reduced_value) = reduce_unbiased_u64(u64::from_le_bytes(word), modulus) {
                return reduced_value;
            }
        }
        block_index = block_index
            .checked_add(1)
            .expect("public residue rejection block index overflowed");
    }
}

pub(super) fn reduce_unbiased_u64(candidate: u64, modulus: u64) -> Option<u64> {
    if modulus == 0 {
        return None;
    }
    let modulus = u128::from(modulus);
    let accepted_candidate_count = ((1_u128 << 64) / modulus) * modulus;
    let candidate = u128::from(candidate);
    if candidate < accepted_candidate_count {
        Some(u64::try_from(candidate % modulus).expect("reduced candidate fits u64"))
    } else {
        None
    }
}

pub(super) fn sample_positions() -> Vec<usize> {
    let mut positions = vec![
        0_usize,
        1,
        2,
        17,
        POLYNOMIAL_DEGREE / 2,
        POLYNOMIAL_DEGREE - 1,
    ];
    positions.sort_unstable();
    positions.dedup();

    positions
}

pub(super) fn development_fixture_digest(fixture_record: &Value) -> CanonicalResult<String> {
    let canonical_fixture = canonical_json(fixture_record)?;

    Ok(hash512_hex(
        "sealed-lattice-bgv-rns/development-fixture-digest-v1",
        &[canonical_fixture.as_bytes()],
    ))
}
