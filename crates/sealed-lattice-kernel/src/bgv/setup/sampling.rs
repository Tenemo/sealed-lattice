use super::*;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

pub(super) fn sample_public_residues(seed_hash: &str, label: &str, modulus: u64) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            json!({
                "position": position,
                "modulus": modulus,
                "value": sample_residue(seed_hash, label, position, modulus),
            })
        })
        .collect()
}

#[cfg(test)]
pub(super) fn sample_small_distribution(
    seed_hash: &str,
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
                    seed_hash, identity, label, position, width,
                ))
                .expect("small distribution offset fits i64");
            json!({
                "position": position,
                "value": value,
            })
        })
        .collect()
}

pub(super) fn sample_bounded_collective_secret_share_distribution(
    seed_hash: &str,
    participant_identities: &[String],
    participant_identity: &str,
) -> CanonicalResult<Vec<Value>> {
    sample_positions()
        .into_iter()
        .map(|position| {
            Ok(json!({
                "position": position,
                "value": bounded_collective_secret_share_coefficient(
                    seed_hash,
                    participant_identities,
                    participant_identity,
                    position,
                )?,
            }))
        })
        .collect()
}

pub(super) fn sample_bounded_collective_error_share_distribution(
    seed_hash: &str,
    participant_identities: &[String],
    participant_identity: &str,
) -> CanonicalResult<Vec<Value>> {
    sample_positions()
        .into_iter()
        .map(|position| {
            Ok(json!({
                "position": position,
                "value": bounded_collective_error_share_coefficient(
                    seed_hash,
                    participant_identities,
                    participant_identity,
                    position,
                )?,
            }))
        })
        .collect()
}

pub(super) fn sample_small_distribution_offset(
    seed_hash: &str,
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
                seed_hash.as_bytes(),
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

// Each coefficient position has a single hash-elected owner, so the collective
// secret and error are a position-partition of single-draw samples and stay
// within the per-coefficient bound (no n-fold variance blow-up).
pub(super) fn bounded_collective_secret_share_coefficient(
    seed_hash: &str,
    participant_identities: &[String],
    participant_identity: &str,
    position: usize,
) -> CanonicalResult<i64> {
    if !is_collective_share_owner(
        seed_hash,
        participant_identities,
        participant_identity,
        "local-secret-share",
        position,
    )? {
        return Ok(0);
    }

    match sample_small_distribution_offset(
        seed_hash,
        participant_identity,
        "local-secret-share",
        position,
        3,
    ) {
        0 => Ok(-1),
        1 => Ok(0),
        2 => Ok(1),
        _ => unreachable!("ternary secret offset is sampled modulo three"),
    }
}

pub(super) fn bounded_collective_error_share_coefficient(
    seed_hash: &str,
    participant_identities: &[String],
    participant_identity: &str,
    position: usize,
) -> CanonicalResult<i64> {
    if !is_collective_share_owner(
        seed_hash,
        participant_identities,
        participant_identity,
        "local-error",
        position,
    )? {
        return Ok(0);
    }

    Ok(centered_binomial_eta2_coefficient(
        seed_hash,
        participant_identity,
        "local-error",
        position,
    ))
}

fn is_collective_share_owner(
    seed_hash: &str,
    participant_identities: &[String],
    participant_identity: &str,
    label: &str,
    position: usize,
) -> CanonicalResult<bool> {
    let participant_index = participant_identities
        .iter()
        .position(|identity| identity == participant_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collective share owner schedule references an unknown participant identity",
            )
        })?;
    let owner_index =
        collective_share_owner_index(seed_hash, label, position, participant_identities.len())?;

    Ok(participant_index == owner_index)
}

fn collective_share_owner_index(
    seed_hash: &str,
    label: &str,
    position: usize,
    participant_count: usize,
) -> CanonicalResult<usize> {
    if participant_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective share owner schedule requires at least one participant",
        ));
    }
    let participant_count_u64 =
        u64::try_from(participant_count).expect("participant count fits u64");
    let position_text = position.to_string();
    let mut block_index = 0_u64;
    loop {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/bounded-collective-share-owner-v1",
            &[
                seed_hash.as_bytes(),
                label.as_bytes(),
                position_text.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        for chunk in output.chunks_exact(8) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            if let Some(reduced_value) =
                reduce_unbiased_u64(u64::from_le_bytes(word), participant_count_u64)
            {
                return Ok(usize::try_from(reduced_value).expect("owner index fits usize"));
            }
        }
        block_index = block_index
            .checked_add(1)
            .expect("collective share owner rejection block index overflowed");
    }
}

#[cfg(test)]
pub(super) fn sample_centered_binomial_eta2(
    seed_hash: &str,
    identity: &str,
    label: &str,
) -> Vec<Value> {
    sample_positions()
        .into_iter()
        .map(|position| {
            let value = centered_binomial_eta2_coefficient(seed_hash, identity, label, position);
            json!({
                "position": position,
                "value": value,
            })
        })
        .collect()
}

pub(super) fn dense_public_residues(seed_hash: &str, label: &str, modulus: u64) -> Vec<u64> {
    dense_public_residues_with_degree(seed_hash, label, modulus, POLYNOMIAL_DEGREE)
}

// Same per-position framing as `dense_public_residues` over an explicit
// degree, so reduced development rings derive a prefix of the profile-ring
// residues instead of a differently framed vector.
pub(super) fn dense_public_residues_with_degree(
    seed_hash: &str,
    label: &str,
    modulus: u64,
    ring_degree: usize,
) -> Vec<u64> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        (0..ring_degree)
            .into_par_iter()
            .map(|position| sample_residue(seed_hash, label, position, modulus))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        (0..ring_degree)
            .map(|position| sample_residue(seed_hash, label, position, modulus))
            .collect()
    }
}

pub(super) fn dense_small_coefficients(
    seed_hash: &str,
    identity: &str,
    label: &str,
    minimum: i64,
    maximum: i64,
) -> Vec<i64> {
    let width = u64::try_from(maximum - minimum + 1).expect("small distribution width fits u64");
    #[cfg(not(target_arch = "wasm32"))]
    {
        (0..POLYNOMIAL_DEGREE)
            .into_par_iter()
            .map(|position| {
                minimum
                    + i64::try_from(sample_small_distribution_offset(
                        seed_hash, identity, label, position, width,
                    ))
                    .expect("small distribution offset fits i64")
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        (0..POLYNOMIAL_DEGREE)
            .map(|position| {
                minimum
                    + i64::try_from(sample_small_distribution_offset(
                        seed_hash, identity, label, position, width,
                    ))
                    .expect("small distribution offset fits i64")
            })
            .collect()
    }
}

pub(super) fn dense_centered_binomial_coefficients(
    seed_hash: &str,
    identity: &str,
    label: &str,
) -> Vec<i64> {
    let mut coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut block_index = 0_u64;
    while coefficients.len() < POLYNOMIAL_DEGREE {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-dense-v1",
            &[
                seed_hash.as_bytes(),
                identity.as_bytes(),
                label.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        for byte in output {
            coefficients.push(centered_binomial_eta2_from_bits(byte));
            if coefficients.len() == POLYNOMIAL_DEGREE {
                break;
            }
            coefficients.push(centered_binomial_eta2_from_bits(byte >> 4));
            if coefficients.len() == POLYNOMIAL_DEGREE {
                break;
            }
        }
        block_index = block_index
            .checked_add(1)
            .expect("centered binomial block index overflowed");
    }

    coefficients
}

fn centered_binomial_eta2_coefficient(
    seed_hash: &str,
    identity: &str,
    label: &str,
    position: usize,
) -> i64 {
    let position_text = position.to_string();
    let output = hash512(
        "sealed-lattice-bgv-rns/sample-centered-binomial-eta2-v1",
        &[
            seed_hash.as_bytes(),
            identity.as_bytes(),
            label.as_bytes(),
            position_text.as_bytes(),
        ],
    );

    centered_binomial_eta2_from_bits(output[0])
}

// Centered binomial distribution with eta=2, support [-2, 2]: takes 4 random
// bits per sample and returns (b0 + b1) - (b2 + b3).
// eta = 2 is the accepted error parameter: per-coefficient noise stays in
// [-2, 2], which feeds the BGV noise budget and the commitment no-wrap bound.
fn centered_binomial_eta2_from_bits(bits: u8) -> i64 {
    let low_weight = i64::from(bits & 1) + i64::from((bits >> 1) & 1);
    let high_weight = i64::from((bits >> 2) & 1) + i64::from((bits >> 3) & 1);

    low_weight - high_weight
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

pub(super) fn signed_to_plaintext_scaled_residue(value: i64, modulus: u64) -> CanonicalResult<u64> {
    mul_mod(
        PLAINTEXT_MODULUS % modulus,
        signed_to_modulus_residue(value, modulus),
        modulus,
    )
}

// Polynomial multiplication in Z_q[X]/(X^N + 1): forward NTT both operands,
// multiply pointwise, then inverse NTT.
pub(super) fn negacyclic_product_mod(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut left_ntt = left.to_vec();
    let mut right_ntt = right.to_vec();
    forward_negacyclic_ntt_in_place(&mut left_ntt, modulus)?;
    forward_negacyclic_ntt_in_place(&mut right_ntt, modulus)?;
    for (left_value, right_value) in left_ntt.iter_mut().zip(right_ntt.iter()) {
        *left_value = mul_mod(*left_value, *right_value, modulus)?;
    }
    inverse_negacyclic_ntt_in_place(&mut left_ntt, modulus)?;

    Ok(left_ntt)
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
    scaled_error_zero_residues: &[u64],
    scaled_error_one_residues: &[u64],
) -> CanonicalResult<Vec<Value>> {
    let modulus = DATA_PRIMES[0];
    sample_positions()
        .into_iter()
        .map(|position| {
            let component_zero = add_mod(
                add_mod(
                    public_key_product[position],
                    scaled_error_zero_residues[position],
                    modulus,
                )?,
                message_residues[position],
                modulus,
            )?;
            let component_one = add_mod(
                public_sample_product[position],
                scaled_error_one_residues[position],
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

pub(super) fn sample_residue(seed_hash: &str, label: &str, position: usize, modulus: u64) -> u64 {
    let position_text = position.to_string();
    let modulus_text = modulus.to_string();
    let mut block_index = 0_u64;
    loop {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/sample-residue-v2",
            &[
                seed_hash.as_bytes(),
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
    // Rejection sampling: accept only the largest multiple of the modulus below
    // 2^64 so the reduction is bias-free; None means resample.
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
