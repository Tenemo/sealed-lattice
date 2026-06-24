use super::*;

pub(super) fn centered_integer_to_residue(value: i128, modulus: u64) -> CanonicalResult<u64> {
    let modulus_wide = i128::from(modulus);
    let residue = value.rem_euclid(modulus_wide);
    u64::try_from(residue)
        .map_err(|_| invalid_commitment_input("centered residue does not fit u64"))
}

#[cfg(test)]
pub(super) fn centered_big_integer_to_residue(
    value: &BigInt,
    modulus: u64,
) -> CanonicalResult<u64> {
    let modulus_big = BigInt::from(modulus);
    let residue = ((value % &modulus_big) + &modulus_big) % &modulus_big;
    residue
        .to_u64()
        .ok_or_else(|| invalid_commitment_input("centered residue does not fit u64"))
}

pub(super) fn validate_message_coefficients(
    message_coefficients: &[u128],
    exclusive_bound: Option<u128>,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment message coefficient count must match the ring degree",
        ));
    }
    if let Some(exclusive_bound) = exclusive_bound
        && message_coefficients
            .iter()
            .any(|coefficient| *coefficient >= exclusive_bound)
    {
        return Err(invalid_commitment_input(
            "commitment message coefficient is outside the declared integer range",
        ));
    }
    if !setup_coefficients_fit_commitment_modulus_product(message_coefficients) {
        return Err(invalid_commitment_input(
            "commitment message coefficient would wrap in the CRT commitment modulus",
        ));
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn validate_signed_message_coefficients(
    message_coefficients: &[i128],
    ring_degree: usize,
) -> CanonicalResult<()> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "signed commitment message coefficient count must match the ring degree",
        ));
    }
    if !message_coefficients.iter().all(|coefficient| {
        setup_signed_coefficient_fits_centered_commitment_modulus_product(*coefficient)
    }) {
        return Err(invalid_commitment_input(
            "signed commitment message coefficient would wrap in the centered CRT commitment modulus",
        ));
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn validate_big_signed_message_coefficients(
    message_coefficients: &[BigInt],
    ring_degree: usize,
) -> CanonicalResult<()> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "signed commitment message coefficient count must match the ring degree",
        ));
    }
    if !message_coefficients
        .iter()
        .all(setup_big_signed_coefficient_fits_centered_commitment_modulus_product)
    {
        return Err(invalid_commitment_input(
            "signed commitment message coefficient would wrap in the centered CRT commitment modulus",
        ));
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn signed_message_coefficient_magnitude_bound(
    message_coefficients: &[i128],
) -> CanonicalResult<u128> {
    message_coefficients
        .iter()
        .map(|coefficient| {
            let magnitude = coefficient.checked_abs().ok_or_else(|| {
                invalid_commitment_input(
                    "signed commitment message coefficient absolute value overflowed",
                )
            })?;
            u128::try_from(magnitude).map_err(|_| {
                invalid_commitment_input(
                    "signed commitment message coefficient magnitude does not fit u128",
                )
            })
        })
        .try_fold(0_u128, |bound, magnitude| {
            magnitude.map(|magnitude| bound.max(magnitude))
        })
}

// ceil(log2(value)) via bit_length(value - 1); the minus one makes exact powers
// of two report b instead of b + 1.
pub(super) fn ceil_log2_big_uint(value: &BigUint) -> u32 {
    if value <= &BigUint::from(1_u8) {
        return 0;
    }
    let previous = value - BigUint::from(1_u8);
    u32::try_from(previous.bits()).expect("setup commitment modulus bit length fits u32")
}

#[cfg(test)]
pub(super) fn validate_randomness_by_column(
    randomness_by_column: &[Vec<i128>],
    infinity_bound: i128,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if infinity_bound < 0 {
        return Err(invalid_commitment_input(
            "commitment randomness bound must be non-negative",
        ));
    }
    validate_randomness_shape(randomness_by_column, ring_degree)?;
    for randomness_column in randomness_by_column {
        if randomness_column
            .iter()
            .any(|coefficient| coefficient.abs() > infinity_bound)
        {
            return Err(invalid_commitment_input(
                "commitment randomness coefficient exceeds the opening bound",
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_randomness_shape(
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
) -> CanonicalResult<()> {
    if randomness_by_column.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment opening must contain the selected randomness width",
        ));
    }
    for randomness_column in randomness_by_column {
        if randomness_column.len() != ring_degree {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment randomness column coefficient count must match the ring degree",
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_source_rns_limb(
    source_rns_limb_index: usize,
    source_message_modulus: u64,
) -> CanonicalResult<()> {
    if DATA_PRIMES.get(source_rns_limb_index) != Some(&source_message_modulus) {
        return Err(invalid_commitment_input(
            "commitment source RNS limb does not match the selected Q_share prime list",
        ));
    }

    Ok(())
}

pub(super) fn validate_ring_degree(ring_degree: usize) -> CanonicalResult<()> {
    if ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE
        || !ring_degree.is_power_of_two()
        || !POLYNOMIAL_DEGREE.is_multiple_of(ring_degree)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment ring degree must be a power-of-two divisor of the selected BGV ring degree",
        ));
    }

    Ok(())
}

pub(super) fn validate_matrix_coordinate(
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_coefficient_position: usize,
) -> CanonicalResult<()> {
    if source_rns_limb_index >= DATA_PRIMES.len() {
        return Err(invalid_commitment_input(
            "commitment matrix source RNS limb is outside Q_share",
        ));
    }
    if !SETUP_COMMITMENT_MODULUS_LIMB_INDICES.contains(&commitment_modulus_index) {
        return Err(invalid_commitment_input(
            "commitment matrix modulus limb is outside the commitment parameters",
        ));
    }
    if matrix_row_index >= SETUP_COMMITMENT_ROW_COUNT {
        return Err(invalid_commitment_input(
            "commitment matrix row is outside the selected BDLOP shape",
        ));
    }
    if randomness_column_index >= SETUP_COMMITMENT_RANDOMNESS_WIDTH {
        return Err(invalid_commitment_input(
            "commitment matrix column is outside the selected BDLOP shape",
        ));
    }
    if ring_coefficient_position >= POLYNOMIAL_DEGREE {
        return Err(invalid_commitment_input(
            "commitment matrix ring coefficient is outside the selected ring degree",
        ));
    }

    Ok(())
}

pub(super) fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() != 128 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a lowercase Hash512 hex string"),
        ));
    }
    if !hash
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be lowercase hexadecimal"),
        ));
    }

    Ok(())
}
