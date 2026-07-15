use super::*;
use crate::bgv::parameters::LOGICAL_SLOT_GENERATOR;
use std::sync::OnceLock;

static GALOIS_ELEMENT_POSITIONS: OnceLock<Vec<Option<(bool, usize)>>> = OnceLock::new();

fn logical_slot_generator() -> usize {
    LOGICAL_SLOT_GENERATOR
}

pub(crate) fn galois_power(exponent: usize) -> CanonicalResult<usize> {
    Ok(modular_power(
        logical_slot_generator(),
        exponent % GENERATOR_SUBGROUP_ORDER,
        2 * POLYNOMIAL_DEGREE,
    ))
}

pub(crate) fn logical_slot_galois_element(logical_slot_index: usize) -> CanonicalResult<usize> {
    if logical_slot_index >= POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "logical slot index is outside the selected ring",
        ));
    }
    let positive_element = modular_power(
        logical_slot_generator(),
        logical_slot_index % GENERATOR_SUBGROUP_ORDER,
        2 * POLYNOMIAL_DEGREE,
    );
    if logical_slot_index < GENERATOR_SUBGROUP_ORDER {
        Ok(positive_element)
    } else {
        Ok(2 * POLYNOMIAL_DEGREE - positive_element)
    }
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

pub(crate) fn generator_exponent_or_conjugated(
    galois_element: usize,
) -> CanonicalResult<(bool, usize)> {
    // Only odd residues are units mod 2N, so only odd Galois elements induce
    // slot permutations; an even element would not be invertible and would
    // merge slots.
    if galois_element.is_multiple_of(2) || galois_element >= 2 * POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois element must be an odd element modulo the ring order",
        ));
    }
    galois_element_positions()[galois_element].ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois element is outside the selected compact generator basis",
        )
    })
}

fn galois_element_positions() -> &'static [Option<(bool, usize)>] {
    GALOIS_ELEMENT_POSITIONS.get_or_init(|| {
        let ring_order = 2 * POLYNOMIAL_DEGREE;
        let mut positions = vec![None; ring_order];
        let mut positive_element = 1_usize;
        for exponent in 0..GENERATOR_SUBGROUP_ORDER {
            positions[positive_element] = Some((false, exponent));
            positions[ring_order - positive_element] = Some((true, exponent));
            positive_element = positive_element * logical_slot_generator() % ring_order;
        }
        positions
    })
}

fn modular_power(mut base: usize, mut exponent: usize, modulus: usize) -> usize {
    let mut result = 1_usize;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

// Decompose each rotation into power-of-two generator steps (and one
// conjugation X -> X^-1 when needed) so the scheduled rotation-key set is
// O(log N) keys instead of one per rotation.
pub(crate) fn generator_power_basis_for_exponent(exponent: usize) -> CanonicalResult<Vec<usize>> {
    let mut basis = Vec::new();
    let mut remaining = exponent % GENERATOR_SUBGROUP_ORDER;
    let mut bit = 0_usize;
    while remaining > 0 {
        if remaining & 1 == 1 {
            basis.push(galois_power(1_usize << bit)?);
        }
        remaining >>= 1;
        bit += 1;
    }

    Ok(basis)
}

pub(crate) fn generator_inverse_power_basis_for_exponent(
    exponent: usize,
) -> CanonicalResult<Vec<usize>> {
    generator_power_basis_for_exponent(exponent)?
        .into_iter()
        .map(inverse_galois_element)
        .collect()
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
    let exact_rotations = direct_score_packing_galois_elements(option_count)?;
    let inverse_basis = generator_inverse_power_basis_for_exponent(option_count)?;
    let composed_rotation = inverse_basis.iter().fold(1_usize, |accumulated, rotation| {
        (accumulated * rotation) % (2 * POLYNOMIAL_DEGREE)
    });
    if exact_rotations.as_slice() != [composed_rotation] {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct score-packing rotation does not match the canonical logical-slot basis",
        ));
    }

    Ok(inverse_basis)
}

pub(crate) fn packed_rank_forward_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    packed_rank_shift_basis_exponents(option_count)?
        .into_iter()
        .map(galois_power)
        .collect()
}

pub(crate) fn packed_rank_return_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    packed_rank_shift_basis_exponents(option_count)?
        .into_iter()
        .map(|exponent| inverse_galois_element(galois_power(exponent)?))
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
    for basis_rotation in generator_power_basis_for_exponent(exponent)? {
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
    for basis_rotation in generator_inverse_power_basis_for_exponent(shift)? {
        rotated = context.rotate_ciphertext(
            &rotated,
            basis_rotation,
            level,
            &format!("{seed_hex}-inverse-generator-basis-{basis_rotation}"),
        )?;
    }

    Ok(rotated)
}

// The frozen rotation key schedule: score-packing and packed-rank-forward
// rotations at the selected evaluator working level (the replay mod-switches
// the aggregate there before packing), and packed-rank-return rotations at
// the comparison output level. Lower-level consumers use the same keys
// through truncation.
#[cfg(test)]
pub(crate) fn selected_evaluator_rotation_key_schedule(
    option_count: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    if SELECTED_EVALUATOR_WORKING_LEVEL >= crate::bgv::parameters::DATA_PRIMES.len()
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
