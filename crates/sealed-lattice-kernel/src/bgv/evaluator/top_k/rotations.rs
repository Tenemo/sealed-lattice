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
            CanonicalErrorCode::InvalidProtocolObject,
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
            CanonicalErrorCode::InvalidProtocolObject,
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
            CanonicalErrorCode::InvalidProtocolObject,
            "Galois element must be an odd element modulo the ring order",
        ));
    }
    galois_element_positions()[galois_element].ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
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

const SIGNED_GENERATOR_LARGE_STEP: usize = 17;

// Decompose a logical rotation into the shortest canonical signed path over
// generator exponents one and seventeen. The two signs produce exactly four
// suite keys while still covering the complete selected evaluator schedule.
pub(crate) fn generator_power_basis_for_exponent(exponent: usize) -> CanonicalResult<Vec<usize>> {
    let subgroup_order = i64::try_from(GENERATOR_SUBGROUP_ORDER).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "logical generator subgroup order does not fit the signed path search",
        )
    })?;
    let reduced_exponent = i64::try_from(exponent % GENERATOR_SUBGROUP_ORDER).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "logical generator exponent does not fit the signed path search",
        )
    })?;
    let large_step = i64::try_from(SIGNED_GENERATOR_LARGE_STEP)
        .expect("selected signed generator step fits i64");
    let mut selected: Option<(i64, i64, i64)> = None;
    for wrapped_exponent in [
        reduced_exponent - subgroup_order,
        reduced_exponent,
        reduced_exponent + subgroup_order,
    ] {
        let approximate_large_step_count = wrapped_exponent.div_euclid(large_step);
        for large_step_count in
            approximate_large_step_count.saturating_sub(1)..=approximate_large_step_count + 1
        {
            let unit_step_count = wrapped_exponent - large_step_count * large_step;
            let hop_count = unit_step_count.abs() + large_step_count.abs();
            let candidate = (hop_count, unit_step_count, large_step_count);
            if selected.is_none_or(|current| {
                (
                    candidate.0,
                    candidate.1.abs(),
                    candidate.2.abs(),
                    candidate.1,
                    candidate.2,
                ) < (
                    current.0,
                    current.1.abs(),
                    current.2.abs(),
                    current.1,
                    current.2,
                )
            }) {
                selected = Some(candidate);
            }
        }
    }

    let (_, unit_step_count, large_step_count) = selected.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "logical generator signed path search produced no candidate",
        )
    })?;
    let positive_unit = galois_power(1)?;
    let negative_unit = inverse_galois_element(positive_unit)?;
    let positive_large = galois_power(SIGNED_GENERATOR_LARGE_STEP)?;
    let negative_large = inverse_galois_element(positive_large)?;
    let mut basis = Vec::with_capacity(
        usize::try_from(unit_step_count.abs() + large_step_count.abs())
            .expect("selected signed path length fits usize"),
    );
    basis.extend(std::iter::repeat_n(
        if large_step_count < 0 {
            negative_large
        } else {
            positive_large
        },
        usize::try_from(large_step_count.abs()).expect("large-step count fits usize"),
    ));
    basis.extend(std::iter::repeat_n(
        if unit_step_count < 0 {
            negative_unit
        } else {
            positive_unit
        },
        usize::try_from(unit_step_count.abs()).expect("unit-step count fits usize"),
    ));

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

fn largest_packed_rank_shift(option_count: usize) -> CanonicalResult<usize> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "packed rank compact rotation basis requires 2 <= option count and a valid slot window",
        ));
    }
    Ok(option_count * (option_count - 1) / 2 - 1)
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
            CanonicalErrorCode::InvalidProtocolObject,
            "direct score-packing rotation does not match the canonical logical-slot basis",
        ));
    }

    Ok(inverse_basis)
}

pub(crate) fn packed_rank_forward_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    let largest_shift = largest_packed_rank_shift(option_count)?;
    let mut basis = BTreeSet::new();
    for exponent in 1..=largest_shift {
        basis.extend(generator_power_basis_for_exponent(exponent)?);
    }
    Ok(basis.into_iter().collect())
}

pub(crate) fn packed_rank_return_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    let largest_shift = largest_packed_rank_shift(option_count)?;
    let mut basis = BTreeSet::new();
    for exponent in 1..=largest_shift {
        basis.extend(generator_inverse_power_basis_for_exponent(exponent)?);
    }
    Ok(basis.into_iter().collect())
}

// The frozen four-key signed rotation schedule sits at the evaluator working
// level. Lower-level consumers use the same keys through truncation.
pub(crate) fn selected_evaluator_rotation_key_schedule(
    option_count: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    if SELECTED_EVALUATOR_WORKING_LEVEL >= crate::bgv::parameters::DATA_PRIMES.len()
        || DIRECT_COMPARISON_OUTPUT_LEVEL > SELECTED_EVALUATOR_WORKING_LEVEL
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
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
