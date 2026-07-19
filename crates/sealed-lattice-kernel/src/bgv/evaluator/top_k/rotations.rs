use super::*;
use crate::bgv::parameters::LOGICAL_SLOT_GENERATOR;
use crate::foundation::FOUNDATION_PROFILE;
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

const SELECTED_OPTION_COUNT: usize = FOUNDATION_PROFILE.option_count as usize;
const SELECTED_PAIR_COUNT: usize = SELECTED_OPTION_COUNT * (SELECTED_OPTION_COUNT - 1) / 2;
const FORWARD_PAIR_WINDOW_LARGE_STEP: usize = 38;
const INVERSE_PAIR_SHIFT_LARGE_STEP: usize = 7;
pub(crate) const NEGATIVE_SEVEN_GALOIS_ELEMENT: usize = 7_971;
pub(crate) const NEGATIVE_ONE_GALOIS_ELEMENT: usize = 43_691;
pub(crate) const POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT: usize = 130_393;

fn validate_selected_directed_rotation_basis() -> CanonicalResult<()> {
    let expected_negative_one = inverse_galois_element(galois_power(1)?)?;
    let expected_negative_seven = inverse_galois_element(galois_power(7)?)?;
    let expected_positive_thirty_eight = galois_power(FORWARD_PAIR_WINDOW_LARGE_STEP)?;
    if expected_negative_one != NEGATIVE_ONE_GALOIS_ELEMENT
        || expected_negative_seven != NEGATIVE_SEVEN_GALOIS_ELEMENT
        || expected_positive_thirty_eight != POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "selected directed Galois basis disagrees with the ring parameters",
        ));
    }
    Ok(())
}

/// Returns the selected directed path that moves a comparison window at the
/// given shift-major offset back to the first logical slot. The path advances
/// by thirty-eight until it reaches or passes the offset, then removes the
/// exact overshoot with negative-seven and negative-one steps.
pub(crate) fn forward_pair_window_rotation_path(
    window_offset: usize,
) -> CanonicalResult<Vec<usize>> {
    if window_offset >= SELECTED_PAIR_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "pair-window offset is outside the selected shift-major layout",
        ));
    }
    validate_selected_directed_rotation_basis()?;
    if window_offset == 0 {
        return Ok(Vec::new());
    }

    let positive_step_count = window_offset.div_ceil(FORWARD_PAIR_WINDOW_LARGE_STEP);
    let overshoot = positive_step_count
        .checked_mul(FORWARD_PAIR_WINDOW_LARGE_STEP)
        .and_then(|reached_offset| reached_offset.checked_sub(window_offset))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "pair-window rotation path arithmetic overflowed",
            )
        })?;
    let negative_seven_step_count = overshoot / INVERSE_PAIR_SHIFT_LARGE_STEP;
    let negative_one_step_count = overshoot % INVERSE_PAIR_SHIFT_LARGE_STEP;
    let mut path = Vec::with_capacity(
        positive_step_count + negative_seven_step_count + negative_one_step_count,
    );
    path.extend(std::iter::repeat_n(
        POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT,
        positive_step_count,
    ));
    path.extend(std::iter::repeat_n(
        NEGATIVE_SEVEN_GALOIS_ELEMENT,
        negative_seven_step_count,
    ));
    path.extend(std::iter::repeat_n(
        NEGATIVE_ONE_GALOIS_ELEMENT,
        negative_one_step_count,
    ));
    Ok(path)
}

/// Returns the selected negative-seven then negative-one path that moves a
/// pairwise comparison result from the lower option slot to the higher option
/// slot for the given option shift.
pub(crate) fn inverse_pair_shift_rotation_path(shift: usize) -> CanonicalResult<Vec<usize>> {
    if shift >= SELECTED_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "pair shift is outside the selected option geometry",
        ));
    }
    validate_selected_directed_rotation_basis()?;
    let negative_seven_step_count = shift / INVERSE_PAIR_SHIFT_LARGE_STEP;
    let negative_one_step_count = shift % INVERSE_PAIR_SHIFT_LARGE_STEP;
    let mut path = Vec::with_capacity(negative_seven_step_count + negative_one_step_count);
    path.extend(std::iter::repeat_n(
        NEGATIVE_SEVEN_GALOIS_ELEMENT,
        negative_seven_step_count,
    ));
    path.extend(std::iter::repeat_n(
        NEGATIVE_ONE_GALOIS_ELEMENT,
        negative_one_step_count,
    ));
    Ok(path)
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

// The three selected directed rotations are first used after comparison, so
// their suite-fixed catalog entries are generated at that exact level.
pub(crate) fn selected_evaluator_rotation_key_schedule(
    option_count: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    if option_count != SELECTED_OPTION_COUNT
        || DIRECT_COMPARISON_OUTPUT_LEVEL >= crate::bgv::parameters::DATA_PRIMES.len()
        || DIRECT_COMPARISON_OUTPUT_LEVEL > SELECTED_EVALUATOR_WORKING_LEVEL
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "selected evaluator rotation schedule disagrees with the exact suite geometry",
        ));
    }
    validate_selected_directed_rotation_basis()?;
    Ok(vec![
        (
            NEGATIVE_SEVEN_GALOIS_ELEMENT,
            DIRECT_COMPARISON_OUTPUT_LEVEL,
        ),
        (NEGATIVE_ONE_GALOIS_ELEMENT, DIRECT_COMPARISON_OUTPUT_LEVEL),
        (
            POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT,
            DIRECT_COMPARISON_OUTPUT_LEVEL,
        ),
    ])
}
