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

pub(in crate::bgv::setup) fn vss_public_message_digit_only_encoding_layout()
-> VssPublicMessageEncodingLayout {
    VssPublicMessageEncodingLayout {
        low_digit_trit_count: 0,
        high_digit_trit_count: 0,
    }
}

pub(in crate::bgv::setup) fn vss_public_message_encoding_layout(
    message_bound_exclusive: u64,
) -> CanonicalResult<VssPublicMessageEncodingLayout> {
    if message_bound_exclusive == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "VSS message coefficient bound must be positive",
        ));
    }
    let maximum_coefficient = u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE)
        .checked_pow(VSS_PUBLIC_MESSAGE_DIGIT_COUNT as u32)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS message digit range overflowed",
            )
        })?;
    if u128::from(message_bound_exclusive) > maximum_coefficient {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "VSS message coefficient bound exceeds the two-digit message range",
        ));
    }
    let low_digit_bound =
        u128::from(message_bound_exclusive).min(u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE));
    let high_digit_bound =
        u128::from(message_bound_exclusive).div_ceil(u128::from(VSS_PUBLIC_MESSAGE_DIGIT_BASE));
    let low_digit_trit_count = vss_public_trit_count_for_bound(low_digit_bound)?;
    let high_digit_trit_count = vss_public_trit_count_for_bound(high_digit_bound)?;
    Ok(VssPublicMessageEncodingLayout {
        low_digit_trit_count,
        high_digit_trit_count,
    })
}

/// Selects the source-message layout for a VSS share-linkage proof. A threshold
/// aggregate reopens recipient-share digits whose range was already established
/// by the source proofs, while an ordinary linkage proof must range-prove them.
pub(in crate::bgv::setup) fn vss_public_share_linkage_source_message_encoding_layout(
    is_threshold_aggregate: bool,
    message_bound_exclusive: u64,
) -> CanonicalResult<VssPublicMessageEncodingLayout> {
    if is_threshold_aggregate {
        Ok(vss_public_message_digit_only_encoding_layout())
    } else {
        vss_public_message_encoding_layout(message_bound_exclusive)
    }
}

/// Selects the layout for one packed VSS share-linkage message. Source columns
/// precede recipient-item columns in the packed relation.
pub(in crate::bgv::setup) fn vss_public_share_linkage_packed_message_encoding_layout(
    is_threshold_aggregate: bool,
    message_position: usize,
    source_message_count: usize,
    message_bound_exclusive: u64,
) -> CanonicalResult<VssPublicMessageEncodingLayout> {
    if message_position < source_message_count {
        vss_public_share_linkage_source_message_encoding_layout(
            is_threshold_aggregate,
            message_bound_exclusive,
        )
    } else {
        vss_public_message_encoding_layout(message_bound_exclusive)
    }
}

pub(super) fn vss_public_trit_count_for_bound(bound_exclusive: u128) -> CanonicalResult<usize> {
    if bound_exclusive == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "VSS trit bound must be positive",
        ));
    }
    let mut represented_bound = 1_u128;
    let mut trit_count = 0_usize;
    while represented_bound < bound_exclusive {
        represented_bound = represented_bound.checked_mul(3).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS trit bound overflowed",
            )
        })?;
        trit_count = trit_count.checked_add(1).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS trit count overflowed",
            )
        })?;
    }

    Ok(trit_count)
}
