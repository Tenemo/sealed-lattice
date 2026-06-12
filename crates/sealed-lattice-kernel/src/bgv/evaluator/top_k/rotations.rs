use super::*;

pub(crate) fn galois_power(exponent: usize) -> usize {
    let modulus = 2 * POLYNOMIAL_DEGREE;
    let mut value = 1_usize;
    for _ in 0..(exponent % GENERATOR_SUBGROUP_ORDER) {
        value = (value * PACKED_SCORE_GALOIS_GENERATOR) % modulus;
    }

    value
}

pub(crate) fn inverse_galois_element(galois_element: usize) -> CanonicalResult<usize> {
    let modulus = i128::try_from(2 * POLYNOMIAL_DEGREE).expect("ring order fits i128");
    let mut previous_remainder = modulus;
    let mut remainder = i128::try_from(galois_element).expect("Galois element fits i128");
    let mut previous_coefficient = 0_i128;
    let mut coefficient = 1_i128;
    while remainder != 0 {
        let quotient = previous_remainder / remainder;
        let next_remainder = previous_remainder - quotient * remainder;
        previous_remainder = remainder;
        remainder = next_remainder;
        let next_coefficient = previous_coefficient - quotient * coefficient;
        previous_coefficient = coefficient;
        coefficient = next_coefficient;
    }
    if previous_remainder != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois element is not invertible modulo the ring order",
        ));
    }
    let inverse = ((previous_coefficient % modulus) + modulus) % modulus;

    Ok(usize::try_from(inverse).expect("inverse below ring order fits usize"))
}

#[cfg(test)]
pub(crate) fn packed_rank_galois_elements(option_count: usize) -> CanonicalResult<Vec<usize>> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "packed rank rotation set requires 2 <= option count and a valid slot window",
        ));
    }
    let mut elements = Vec::with_capacity(2 * (option_count - 1));
    for shift in 1..option_count {
        let galois_element = galois_power(shift);
        elements.push(galois_element);
        elements.push(inverse_galois_element(galois_element)?);
    }

    Ok(elements)
}

pub(crate) fn generator_exponent_or_conjugated(
    galois_element: usize,
) -> CanonicalResult<(bool, usize)> {
    if galois_element.is_multiple_of(2) || galois_element >= 2 * POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois element must be an odd element modulo the ring order",
        ));
    }
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let mut current = 1_usize;
    for exponent in 0..GENERATOR_SUBGROUP_ORDER {
        if current == galois_element {
            return Ok((false, exponent));
        }
        if (ring_order - current) % ring_order == galois_element {
            return Ok((true, exponent));
        }
        current = (current * PACKED_SCORE_GALOIS_GENERATOR) % ring_order;
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        "Galois element is outside the selected compact generator basis",
    ))
}

pub(crate) fn generator_power_basis_for_exponent(exponent: usize) -> Vec<usize> {
    let mut basis = Vec::new();
    let mut remaining = exponent % GENERATOR_SUBGROUP_ORDER;
    let mut bit = 0_usize;
    while remaining > 0 {
        if remaining & 1 == 1 {
            basis.push(galois_power(1_usize << bit));
        }
        remaining >>= 1;
        bit += 1;
    }

    basis
}

pub(crate) fn compact_positive_generator_basis_for_rotations(
    rotations: impl IntoIterator<Item = usize>,
) -> CanonicalResult<Vec<usize>> {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let mut basis = BTreeSet::new();
    for rotation in rotations {
        if rotation == 1 {
            continue;
        }
        let (requires_conjugation, exponent) = generator_exponent_or_conjugated(rotation)?;
        if requires_conjugation {
            basis.insert(ring_order - 1);
        }
        for basis_rotation in generator_power_basis_for_exponent(exponent) {
            basis.insert(basis_rotation);
        }
    }

    Ok(basis.into_iter().collect())
}

pub(crate) fn packed_rank_shift_basis_exponents(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "packed rank compact rotation basis requires 2 <= option count and a valid slot window",
        ));
    }
    // The batched-pair evaluation rotates by score shifts (below the option
    // count) and by pair-window offsets (below the unordered pair count), so
    // the power-of-two basis must cover the largest window offset.
    let largest_shift = option_count * (option_count - 1) / 2 - 1;
    let mut exponents = Vec::new();
    let mut bit = 0_usize;
    while (1_usize << bit) <= largest_shift {
        exponents.push(1_usize << bit);
        bit += 1;
    }

    Ok(exponents)
}

pub(crate) fn direct_score_packing_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    compact_positive_generator_basis_for_rotations(direct_score_packing_galois_elements(
        option_count,
    )?)
}

pub(crate) fn packed_rank_forward_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    Ok(packed_rank_shift_basis_exponents(option_count)?
        .into_iter()
        .map(galois_power)
        .collect())
}

pub(crate) fn packed_rank_return_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    packed_rank_shift_basis_exponents(option_count)?
        .into_iter()
        .map(|exponent| inverse_galois_element(galois_power(exponent)))
        .collect()
}

pub(crate) fn rotate_with_compact_positive_generator_basis(
    context: &EvaluatorContext,
    ciphertext: &Ciphertext,
    galois_element: usize,
    level: usize,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    if galois_element == 1 {
        return Ok(ciphertext.clone());
    }
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let (requires_conjugation, exponent) = generator_exponent_or_conjugated(galois_element)?;
    let mut rotated = ciphertext.clone();
    if requires_conjugation {
        rotated = context.rotate_ciphertext(
            &rotated,
            ring_order - 1,
            level,
            &format!("{seed_hex}-conjugation"),
        )?;
    }
    for basis_rotation in generator_power_basis_for_exponent(exponent) {
        rotated = context.rotate_ciphertext(
            &rotated,
            basis_rotation,
            level,
            &format!("{seed_hex}-generator-basis-{basis_rotation}"),
        )?;
    }

    Ok(rotated)
}

pub(crate) fn rotate_with_compact_inverse_generator_basis(
    context: &EvaluatorContext,
    ciphertext: &Ciphertext,
    shift: usize,
    level: usize,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    let mut rotated = ciphertext.clone();
    let mut remaining = shift;
    let mut bit = 0_usize;
    while remaining > 0 {
        if remaining & 1 == 1 {
            let basis_rotation = inverse_galois_element(galois_power(1_usize << bit))?;
            rotated = context.rotate_ciphertext(
                &rotated,
                basis_rotation,
                level,
                &format!("{seed_hex}-inverse-generator-basis-{basis_rotation}"),
            )?;
        }
        remaining >>= 1;
        bit += 1;
    }

    Ok(rotated)
}

// The frozen rotation key schedule: score-packing and packed-rank-forward
// rotations at the selected evaluator working level (the replay mod-switches
// the aggregate there before packing), and packed-rank-return rotations at
// the comparison output level. Lower-level consumers use the same keys
// through truncation.
pub(crate) fn selected_evaluator_rotation_key_schedule(
    option_count: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    if SELECTED_EVALUATOR_WORKING_LEVEL >= DATA_PRIMES.len()
        || DIRECT_COMPARISON_OUTPUT_LEVEL > SELECTED_EVALUATOR_WORKING_LEVEL
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "selected evaluator rotation schedule levels must fit the data basis",
        ));
    }
    let mut required = BTreeSet::new();
    for galois_element in direct_score_packing_basis_galois_elements(option_count)? {
        required.insert((galois_element, SELECTED_EVALUATOR_WORKING_LEVEL));
    }
    for galois_element in packed_rank_forward_basis_galois_elements(option_count)? {
        required.insert((galois_element, SELECTED_EVALUATOR_WORKING_LEVEL));
    }
    // Inverse-basis rotations run at the working level (pair-window
    // realignment) and at the comparison output level (rank return); one key
    // at the working level serves both through truncation.
    for galois_element in packed_rank_return_basis_galois_elements(option_count)? {
        required.insert((galois_element, SELECTED_EVALUATOR_WORKING_LEVEL));
    }

    Ok(required.into_iter().collect())
}
