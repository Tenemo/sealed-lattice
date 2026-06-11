use super::*;

pub(super) struct EvaluationKeyShareMasks {
    pub(super) secret_masks: Vec<i128>,
    pub(super) negative_indicator_masks: Vec<i128>,
    pub(super) randomness_masks_by_limb: Vec<Vec<Vec<i128>>>,
    pub(super) error_masks_by_digit: Vec<Vec<i128>>,
    pub(super) relinearization_source_masks_by_digit: Vec<Vec<i128>>,
    pub(super) carry_masks_by_digit_by_limb: Vec<Vec<Vec<i128>>>,
}

pub(super) fn sample_evaluation_key_share_masks(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<EvaluationKeyShareMasks> {
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let digit_count = input.component_b_by_digit.len();
    let limb_count = input
        .component_b_by_digit
        .first()
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no digits"))?;
    let secret_masks = (0..ring_degree)
        .map(|coefficient_index| {
            sample_signed_mask_i128(
                EVALUATION_KEY_SHARE_SECRET_MASK_DOMAIN,
                input.proof_randomness_seed_hex,
                &[0, coefficient_index as u64],
                EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_masks = (0..ring_degree)
        .map(|coefficient_index| {
            sample_signed_mask_i128(
                EVALUATION_KEY_SHARE_NEGATIVE_INDICATOR_MASK_DOMAIN,
                input.proof_randomness_seed_hex,
                &[0, coefficient_index as u64],
                EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_masks_by_limb = (0..DATA_PRIMES.len())
        .map(|rns_limb_index| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column_index| {
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            sample_signed_mask_i128(
                                EVALUATION_KEY_SHARE_RANDOMNESS_MASK_DOMAIN,
                                input.proof_randomness_seed_hex,
                                &[
                                    rns_limb_index as u64,
                                    randomness_column_index as u64,
                                    coefficient_index as u64,
                                ],
                                EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS,
                            )
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_masks_by_digit = (0..digit_count)
        .map(|digit_index| {
            (0..ring_degree)
                .map(|coefficient_index| {
                    sample_signed_mask_i128(
                        EVALUATION_KEY_SHARE_ERROR_MASK_DOMAIN,
                        input.proof_randomness_seed_hex,
                        &[digit_index as u64, coefficient_index as u64],
                        EVALUATION_KEY_SHARE_ERROR_MASK_BITS,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let relinearization_source_masks_by_digit =
        if input.proof_family == EvaluationKeyShareProofFamily::Relinearization {
            if relinearization_record_uses_same_secret_source(input.proof_record) {
                vec![secret_masks.clone(); digit_count]
            } else {
                (0..digit_count)
                    .map(|digit_index| {
                        (0..ring_degree)
                            .map(|coefficient_index| {
                                sample_signed_mask_i128(
                                    EVALUATION_KEY_SHARE_SOURCE_MASK_DOMAIN,
                                    input.proof_randomness_seed_hex,
                                    &[digit_index as u64, coefficient_index as u64],
                                    EVALUATION_KEY_SHARE_SOURCE_MASK_BITS,
                                )
                            })
                            .collect::<CanonicalResult<Vec<_>>>()
                    })
                    .collect::<CanonicalResult<Vec<_>>>()?
            }
        } else {
            Vec::new()
        };
    let carry_masks_by_digit_by_limb = (0..digit_count)
        .map(|digit_index| {
            (0..limb_count)
                .map(|rns_limb_index| {
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            sample_signed_mask_i128(
                                EVALUATION_KEY_SHARE_CARRY_MASK_DOMAIN,
                                input.proof_randomness_seed_hex,
                                &[
                                    digit_index as u64,
                                    rns_limb_index as u64,
                                    coefficient_index as u64,
                                ],
                                EVALUATION_KEY_SHARE_CARRY_MASK_BITS,
                            )
                        })
                        .collect::<CanonicalResult<Vec<_>>>()
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(EvaluationKeyShareMasks {
        secret_masks,
        negative_indicator_masks,
        randomness_masks_by_limb,
        error_masks_by_digit,
        relinearization_source_masks_by_digit,
        carry_masks_by_digit_by_limb,
    })
}

fn sample_signed_mask_i128(
    domain: &str,
    proof_randomness_seed_hex: &str,
    coordinates: &[u64],
    bit_count: usize,
) -> CanonicalResult<i128> {
    let magnitude =
        sample_unsigned_i128(domain, proof_randomness_seed_hex, coordinates, bit_count)?;
    let sign_block = hash512(
        domain,
        &[
            proof_randomness_seed_hex.as_bytes(),
            b"sign",
            &coordinates
                .iter()
                .flat_map(|coordinate| coordinate.to_le_bytes())
                .collect::<Vec<_>>(),
        ],
    );
    if sign_block[0] & 1 == 0 {
        Ok(magnitude)
    } else {
        magnitude
            .checked_neg()
            .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key mask overflowed"))
    }
}

fn sample_unsigned_i128(
    domain: &str,
    proof_randomness_seed_hex: &str,
    coordinates: &[u64],
    bit_count: usize,
) -> CanonicalResult<i128> {
    if bit_count > 120 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key mask sampler supports at most 120 bits",
        ));
    }
    let coordinate_bytes = coordinates
        .iter()
        .flat_map(|coordinate| coordinate.to_le_bytes())
        .collect::<Vec<_>>();
    let block = hash512(
        domain,
        &[proof_randomness_seed_hex.as_bytes(), &coordinate_bytes],
    );
    let mut value = 0_i128;
    let byte_count = bit_count.div_ceil(8);
    for (byte_index, byte) in block[..byte_count].iter().enumerate() {
        value |= i128::from(*byte) << (byte_index * 8);
    }
    if !bit_count.is_multiple_of(8) {
        let mask = (1_i128 << bit_count) - 1;
        value &= mask;
    }

    Ok(value)
}
