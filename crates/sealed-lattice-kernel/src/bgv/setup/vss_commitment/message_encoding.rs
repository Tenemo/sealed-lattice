use super::*;

pub(in crate::bgv::setup) fn vss_public_message_digits(
    coefficient: u64,
) -> CanonicalResult<[u64; VSS_PUBLIC_MESSAGE_DIGIT_COUNT]> {
    let maximum_coefficient = u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)
        .checked_pow(VSS_PUBLIC_MESSAGE_DIGIT_COUNT as u32)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS message digit range overflowed",
            )
        })?;
    if u128::from(coefficient) >= maximum_coefficient {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "VSS message coefficient exceeds the full-message coordinate range",
        ));
    }

    let mut remaining = coefficient;
    let mut digits = [0_u64; VSS_PUBLIC_MESSAGE_DIGIT_COUNT];
    for digit in &mut digits {
        *digit = remaining % VSS_PUBLIC_MESSAGE_DIGIT_BASE;
        remaining /= VSS_PUBLIC_MESSAGE_DIGIT_BASE;
    }
    if remaining != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "VSS message coefficient did not fit the selected digit range",
        ));
    }

    Ok(digits)
}

pub(crate) fn vss_public_canonical_message_digit_columns(
    message_coefficients: &[u64],
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS message coefficient count must match ringDegree",
        ));
    }
    let mut columns = vec![vec![0_u64; ring_degree]; VSS_PUBLIC_MESSAGE_DIGIT_COUNT];
    for (coefficient_index, coefficient) in message_coefficients.iter().enumerate() {
        for (digit_index, digit) in vss_public_message_digits(*coefficient)?
            .into_iter()
            .enumerate()
        {
            columns[digit_index][coefficient_index] = digit;
        }
    }

    Ok(columns)
}
