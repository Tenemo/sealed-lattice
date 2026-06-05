use std::collections::BTreeSet;

use crate::{
    bgv::{
        evaluator::{
            circuit::{
                EvaluatorContext, evaluate_polynomial,
                evaluate_polynomial_with_fixed_baby_step_count_and_deferred_terminal_switch,
                modulus_switch_to, multiply, multiply_without_immediate_modulus_switch,
                normalize_scaling,
            },
            engine::{
                Ciphertext, add_plaintext_coefficients, ciphertext_add, ciphertext_negate,
                ciphertext_sub, encode_slots_to_coefficients, plaintext_mul, scalar_mul,
                signed_residue,
            },
        },
        modular_arithmetic::{add_mod, inverse_mod, mul_mod, sub_mod},
        profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

// The deterministic tie policy: a higher aggregate score ranks first, and equal
// scores are broken by the lower option index.
pub(crate) const TIE_POLICY: &str = "higher-sum-first-then-lower-option-index";
pub(crate) const AGGREGATE_SCORE_COORDINATES_PER_OPTION: usize = 11;
pub(crate) const DIRECT_COMPARISON_BABY_STEP_COUNT: usize = 31;
pub(crate) const DIRECT_COMPARISON_OUTPUT_LEVEL: usize = 6;
pub(crate) const RANK_LOOKUP_BABY_STEP_COUNT: usize = 5;
const PACKED_SCORE_GALOIS_GENERATOR: usize = 3;
const GENERATOR_SUBGROUP_ORDER: usize = POLYNOMIAL_DEGREE / 2;

pub(crate) struct PackedRankEvaluation {
    pub(crate) packed_ranks: Ciphertext,
    exact_rank_indicators: Vec<Ciphertext>,
}

// Number of score bits for the certified score domain [0, score_domain_max].
pub(crate) fn score_bit_count(score_domain_max: u64) -> usize {
    let mut bits = 0_usize;
    let mut bound = score_domain_max;
    while bound > 0 {
        bits += 1;
        bound >>= 1;
    }
    bits.max(1)
}

// Lagrange interpolation over the plaintext field: given f(0), f(1), ...,
// f(n-1), return the coefficients (lowest degree first) of the unique degree
// (n-1) interpolating polynomial.
pub(crate) fn interpolate_coefficients(values: &[u64]) -> CanonicalResult<Vec<u64>> {
    let point_count = values.len();
    let mut coefficients = vec![0_u64; point_count];
    for (point, value) in values.iter().enumerate() {
        // Build the Lagrange basis numerator polynomial and its denominator.
        let mut numerator = vec![1_u64];
        let mut denominator = 1_u64;
        for other in 0..point_count {
            if other == point {
                continue;
            }
            numerator = multiply_by_linear_root(&numerator, other as u64)?;
            let difference = signed_residue(point as i64 - other as i64, PLAINTEXT_MODULUS);
            denominator = mul_mod(denominator, difference, PLAINTEXT_MODULUS)?;
        }
        let scale = mul_mod(
            *value,
            inverse_mod(denominator, PLAINTEXT_MODULUS)?,
            PLAINTEXT_MODULUS,
        )?;
        for (degree, numerator_coefficient) in numerator.iter().enumerate() {
            coefficients[degree] = add_mod(
                coefficients[degree],
                mul_mod(*numerator_coefficient, scale, PLAINTEXT_MODULUS)?,
                PLAINTEXT_MODULUS,
            )?;
        }
    }

    Ok(coefficients)
}

// Multiply a polynomial by (x - root) over the plaintext field.
fn multiply_by_linear_root(polynomial: &[u64], root: u64) -> CanonicalResult<Vec<u64>> {
    let mut product = vec![0_u64; polynomial.len() + 1];
    for (degree, coefficient) in polynomial.iter().enumerate() {
        product[degree + 1] = add_mod(product[degree + 1], *coefficient, PLAINTEXT_MODULUS)?;
        let scaled_root = mul_mod(*coefficient, root, PLAINTEXT_MODULUS)?;
        product[degree] = sub_mod(product[degree], scaled_root, PLAINTEXT_MODULUS)?;
    }

    Ok(product)
}

// The bit-extraction polynomials for the certified score domain: one polynomial
// per bit, interpolating the function x -> (x >> bit) & 1 over [0, domain_max].
pub(crate) fn bit_extraction_polynomials(score_domain_max: u64) -> CanonicalResult<Vec<Vec<u64>>> {
    let bit_count = score_bit_count(score_domain_max);
    let point_count = usize::try_from(score_domain_max).expect("domain fits usize") + 1;
    (0..bit_count)
        .map(|bit| {
            let values = (0..point_count)
                .map(|value| ((value as u64) >> bit) & 1)
                .collect::<Vec<_>>();
            interpolate_coefficients(&values)
        })
        .collect()
}

// A plaintext polynomial whose every slot holds the same constant value.
fn broadcast_constant(value: u64) -> Vec<u64> {
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    coefficients[0] = value % PLAINTEXT_MODULUS;

    coefficients
}

// Add the slot-wise constant `value` to a scaling-one ciphertext.
fn add_constant(ciphertext: &Ciphertext, value: u64) -> CanonicalResult<Ciphertext> {
    let normalized = normalize_scaling(ciphertext)?;

    add_plaintext_coefficients(&normalized, &broadcast_constant(value))
}

// Logical NOT of an encrypted boolean (1 - bit), valid for scaling-one inputs.
fn boolean_not(ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
    let negated = ciphertext_negate(&normalize_scaling(ciphertext)?)?;

    add_plaintext_coefficients(&negated, &broadcast_constant(1))
}

// Bring several ciphertexts to a common level and scaling, then add them.
pub(crate) fn sum_aligned(ciphertexts: &[Ciphertext]) -> CanonicalResult<Ciphertext> {
    if ciphertexts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "cannot sum an empty ciphertext set",
        ));
    }
    let target_level = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.level)
        .min()
        .expect("non-empty set has a minimum level");
    let mut accumulator = normalize_scaling(&modulus_switch_to(&ciphertexts[0], target_level)?)?;
    for ciphertext in &ciphertexts[1..] {
        let aligned = normalize_scaling(&modulus_switch_to(ciphertext, target_level)?)?;
        accumulator = ciphertext_add(&accumulator, &aligned)?;
    }

    Ok(accumulator)
}

fn add_to_aligned_sum(
    accumulator: &mut Option<Ciphertext>,
    term: Ciphertext,
) -> CanonicalResult<()> {
    *accumulator = Some(match accumulator.take() {
        Some(current) => sum_aligned(&[current, term])?,
        None => term,
    });

    Ok(())
}

fn require_aligned_sum(
    accumulator: Option<Ciphertext>,
    empty_message: &'static str,
) -> CanonicalResult<Ciphertext> {
    accumulator
        .ok_or_else(|| CanonicalError::new(CanonicalErrorCode::InvalidFixture, empty_message))
}

// Derive the encrypted score bits of a broadcast score ciphertext.
pub(crate) fn derive_score_bits(
    context: &EvaluatorContext,
    score: &Ciphertext,
    bit_polynomials: &[Vec<u64>],
) -> CanonicalResult<Vec<Ciphertext>> {
    bit_polynomials
        .iter()
        .map(|polynomial| evaluate_polynomial(context, score, polynomial))
        .collect()
}

// Bit-sliced greater-than and equality of two encrypted bit decompositions
// (least-significant bit first). Returns (greater_than, equal) encrypted
// booleans.
pub(crate) fn bit_sliced_greater_than_and_equal(
    context: &EvaluatorContext,
    left_bits: &[Ciphertext],
    right_bits: &[Ciphertext],
) -> CanonicalResult<(Ciphertext, Ciphertext)> {
    let bit_count = left_bits.len();
    if bit_count == 0 || right_bits.len() != bit_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "bit-sliced comparison requires matching non-empty bit decompositions",
        ));
    }
    // Per-bit equality: eq_k = 1 - (a_k - b_k)^2.
    let mut bit_equal = Vec::with_capacity(bit_count);
    for bit in 0..bit_count {
        let difference = ciphertext_sub(&left_bits[bit], &right_bits[bit])?;
        let squared = multiply(context, &difference, &difference)?;
        bit_equal.push(boolean_not(&squared)?);
    }
    // Suffix equality above each bit: prefix_above[bit] = product of eq_k for
    // k > bit. Computed from the most-significant bit downward.
    let mut suffix_equal = vec![None; bit_count];
    for bit in (0..bit_count).rev() {
        if bit == bit_count - 1 {
            // Empty product is the encrypted constant one; represent it as
            // eq over no bits by reusing the top equality's all-ones structure.
            suffix_equal[bit] = Some(encrypted_one_like(&bit_equal[bit])?);
        } else {
            let higher = suffix_equal[bit + 1]
                .clone()
                .expect("higher suffix present");
            suffix_equal[bit] = Some(multiply(context, &higher, &bit_equal[bit + 1])?);
        }
    }
    // greater_than = sum_bit a_bit * (1 - b_bit) * suffix_equal[bit].
    let mut terms = Vec::with_capacity(bit_count);
    for bit in 0..bit_count {
        let not_right = boolean_not(&right_bits[bit])?;
        let strictly_greater = multiply(context, &left_bits[bit], &not_right)?;
        let suffix = suffix_equal[bit].clone().expect("suffix present");
        terms.push(multiply(context, &strictly_greater, &suffix)?);
    }
    let greater_than = sum_aligned(&terms)?;
    // equal = product of all per-bit equalities = suffix below the lowest bit.
    let lowest_suffix = suffix_equal[0].clone().expect("lowest suffix present");
    let equal = multiply(context, &lowest_suffix, &bit_equal[0])?;

    Ok((greater_than, equal))
}

// An encrypted constant one at the same level and scaling as a reference
// ciphertext: zero the reference, then add the plaintext constant one.
fn encrypted_one_like(reference: &Ciphertext) -> CanonicalResult<Ciphertext> {
    add_constant(&scalar_mul(reference, 0)?, 1)
}

// Encrypted ahead indicator for the ordered pair (challenger, option):
// ahead = GT(challenger, option) + tie * EQ(challenger, option), where tie is
// the public bit that the challenger's index is lower than the option's.
pub(crate) fn ahead_indicator(
    greater_than: &Ciphertext,
    equal: &Ciphertext,
    challenger_index: usize,
    option_index: usize,
) -> CanonicalResult<Ciphertext> {
    let greater_aligned = normalize_scaling(greater_than)?;
    let equal_aligned = normalize_scaling(&modulus_switch_to(
        equal,
        greater_than.level.min(equal.level),
    )?)?;
    let greater_at_level = normalize_scaling(&modulus_switch_to(
        &greater_aligned,
        greater_than.level.min(equal.level),
    )?)?;
    if challenger_index < option_index {
        ciphertext_add(&greater_at_level, &equal_aligned)
    } else {
        Ok(greater_at_level)
    }
}

// The encrypted rank of an option: the number of other options that are ahead
// of it under the tie policy.
pub(crate) fn accumulate_rank(ahead_indicators: &[Ciphertext]) -> CanonicalResult<Ciphertext> {
    sum_aligned(ahead_indicators)
}

// The encrypted top-k indicator [rank < top_count] over the rank domain
// [0, option_count - 1].
pub(crate) fn top_k_indicator(
    context: &EvaluatorContext,
    rank: &Ciphertext,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<Ciphertext> {
    let (indicator, _) = top_k_indicator_and_order_value(context, rank, option_count, top_count)?;

    Ok(indicator)
}

// The encrypted target-order value: rank + 1 when rank is inside the selected
// top-k prefix, and zero otherwise. Evaluating this directly avoids the extra
// ciphertext multiplication `(rank + 1) * indicator` during sparse projection.
pub(crate) fn top_k_order_value(
    context: &EvaluatorContext,
    rank: &Ciphertext,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<Ciphertext> {
    let (_, order_value) = top_k_indicator_and_order_value(context, rank, option_count, top_count)?;

    Ok(order_value)
}

pub(crate) fn top_k_indicator_and_order_value(
    context: &EvaluatorContext,
    rank: &Ciphertext,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<(Ciphertext, Ciphertext)> {
    if top_count == 0 || top_count > option_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "top-k prefix evaluation requires 1 <= top_count <= option_count",
        ));
    }
    let normalized_rank = normalize_scaling(&modulus_switch_to(rank, context.working_level())?)?;
    if top_count == option_count {
        let selected_every_slot =
            add_plaintext_coefficients(&scalar_mul(&normalized_rank, 0)?, &broadcast_constant(1))?;
        let rank_plus_one = add_plaintext_coefficients(&normalized_rank, &broadcast_constant(1))?;

        return Ok((selected_every_slot, rank_plus_one));
    }

    let indicator_values = (0..option_count)
        .map(|rank_value| u64::from(rank_value < top_count))
        .collect::<Vec<_>>();
    let order_values = (0..option_count)
        .map(|rank_value| {
            if rank_value < top_count {
                u64::try_from(rank_value + 1).expect("rank value fits u64")
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let indicator = evaluate_rank_lookup(context, &normalized_rank, &indicator_values)?;
    let order_value = evaluate_rank_lookup(context, &normalized_rank, &order_values)?;

    Ok((indicator, order_value))
}

fn evaluate_rank_lookup(
    context: &EvaluatorContext,
    normalized_rank: &Ciphertext,
    values: &[u64],
) -> CanonicalResult<Ciphertext> {
    if values.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "rank lookup values must contain at least one value",
        ));
    }
    let polynomial = interpolate_coefficients(values)?;
    evaluate_polynomial_with_fixed_baby_step_count_and_deferred_terminal_switch(
        context,
        normalized_rank,
        &polynomial,
        RANK_LOOKUP_BABY_STEP_COUNT,
    )
}

// The plaintext selector polynomial placing a broadcast value into a single
// target slot.
fn slot_selector(slot: usize) -> CanonicalResult<Vec<u64>> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    slots[slot] = 1;

    encode_slots_to_coefficients(&slots)
}

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
fn packed_rank_galois_elements(option_count: usize) -> CanonicalResult<Vec<usize>> {
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

fn generator_exponent_or_conjugated(galois_element: usize) -> CanonicalResult<(bool, usize)> {
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

fn generator_power_basis_for_exponent(exponent: usize) -> Vec<usize> {
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

fn compact_positive_generator_basis_for_rotations(
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

fn packed_rank_shift_basis_exponents(option_count: usize) -> CanonicalResult<Vec<usize>> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "packed rank compact rotation basis requires 2 <= option count and a valid slot window",
        ));
    }
    let largest_shift = option_count - 1;
    let mut exponents = Vec::new();
    let mut bit = 0_usize;
    while (1_usize << bit) <= largest_shift {
        exponents.push(1_usize << bit);
        bit += 1;
    }

    Ok(exponents)
}

pub(crate) fn aggregate_score_packing_basis_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    compact_positive_generator_basis_for_rotations(aggregate_score_packing_galois_elements(
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

fn rotate_with_compact_positive_generator_basis(
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

fn rotate_with_compact_inverse_generator_basis(
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

pub(crate) fn packed_score_slot(logical_index: usize) -> usize {
    (galois_power(logical_index) - 1) / 2
}

pub(crate) fn aggregate_score_slot(option_index: usize) -> usize {
    option_index * AGGREGATE_SCORE_COORDINATES_PER_OPTION
}

fn galois_element_moving_slot_to_target(
    source_slot: usize,
    target_slot: usize,
) -> CanonicalResult<usize> {
    if source_slot >= POLYNOMIAL_DEGREE || target_slot >= POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "slot move requires source and target slots inside the selected ring",
        ));
    }
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let source_odd = 2 * source_slot + 1;
    let target_odd = 2 * target_slot + 1;
    let inverse_target_odd = inverse_galois_element(target_odd)?;

    Ok((source_odd * inverse_target_odd) % ring_order)
}

pub(crate) fn aggregate_score_packing_galois_elements(
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    if option_count < 2
        || option_count * AGGREGATE_SCORE_COORDINATES_PER_OPTION > POLYNOMIAL_DEGREE
        || option_count * 2 > POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregate score packing requires at least two options and a valid aggregate layout window",
        ));
    }
    let mut elements = BTreeSet::new();
    for option_index in 0..option_count {
        let source_slot = aggregate_score_slot(option_index);
        for target_logical_index in [option_index, option_index + option_count] {
            let target_slot = packed_score_slot(target_logical_index);
            let galois_element = galois_element_moving_slot_to_target(source_slot, target_slot)?;
            if galois_element != 1 {
                elements.insert(galois_element);
            }
        }
    }

    Ok(elements.into_iter().collect())
}

pub(crate) fn selected_evaluator_rotation_key_schedule(
    option_count: usize,
    working_level: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    if working_level >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "selected evaluator rotation schedule requires a working level inside the data basis",
        ));
    }
    let full_level = DATA_PRIMES.len() - 1;
    let mut required = BTreeSet::new();
    if full_level <= working_level {
        for galois_element in aggregate_score_packing_basis_galois_elements(option_count)? {
            required.insert((galois_element, full_level));
        }
        for galois_element in packed_rank_forward_basis_galois_elements(option_count)? {
            required.insert((galois_element, full_level));
        }
    }
    if DIRECT_COMPARISON_OUTPUT_LEVEL <= working_level {
        for galois_element in packed_rank_return_basis_galois_elements(option_count)? {
            required.insert((galois_element, DIRECT_COMPARISON_OUTPUT_LEVEL));
        }
    }

    Ok(required.into_iter().collect())
}

pub(crate) fn pack_reconstructed_aggregate_scores(
    context: &EvaluatorContext,
    reconstructed_aggregate: &Ciphertext,
    option_count: usize,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    if option_count < 2
        || option_count * AGGREGATE_SCORE_COORDINATES_PER_OPTION > POLYNOMIAL_DEGREE
        || option_count * 2 > POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregate score packing requires at least two options and a valid aggregate layout window",
        ));
    }
    let normalized_aggregate = normalize_scaling(reconstructed_aggregate)?;
    let mut packed_terms = Vec::with_capacity(option_count);
    for option_index in 0..option_count {
        let source_slot = aggregate_score_slot(option_index);
        let selected_score = plaintext_mul(&normalized_aggregate, &slot_selector(source_slot)?)?;
        for target_logical_index in [option_index, option_index + option_count] {
            let target_slot = packed_score_slot(target_logical_index);
            let packed_score = if source_slot == target_slot {
                selected_score.clone()
            } else {
                let galois_element =
                    galois_element_moving_slot_to_target(source_slot, target_slot)?;
                rotate_with_compact_positive_generator_basis(
                    context,
                    &selected_score,
                    galois_element,
                    selected_score.level,
                    &format!("{seed_hex}-aggregate-score-pack-{option_index}"),
                )?
            };
            packed_terms.push(packed_score);
        }
    }

    sum_aligned(&packed_terms)
}

pub(crate) fn pack_direct_score_slots(
    context: &EvaluatorContext,
    direct_scores: &Ciphertext,
    option_count: usize,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "direct score-slot packing requires at least two options and a valid packed window",
        ));
    }
    let normalized_scores = normalize_scaling(direct_scores)?;
    let mut packed_terms = Vec::with_capacity(option_count * 2);
    let rotation_seed = format!("{seed_hex}-direct-score-pack-rotation");
    for option in 0..option_count {
        for logical_index in [option, option + option_count] {
            packed_terms.push(move_single_slot_value(
                context,
                &normalized_scores,
                option,
                packed_score_slot(logical_index),
                &rotation_seed,
            )?);
        }
    }

    sum_aligned(&packed_terms)
}

fn packed_score_slot_selector(logical_indices: &[usize]) -> CanonicalResult<Vec<u64>> {
    let weights = logical_indices
        .iter()
        .map(|logical_index| (*logical_index, 1_u64))
        .collect::<Vec<_>>();

    packed_score_weighted_selector(&weights)
}

fn packed_score_weighted_selector(weights: &[(usize, u64)]) -> CanonicalResult<Vec<u64>> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    for (logical_index, weight) in weights {
        slots[packed_score_slot(*logical_index)] = weight % PLAINTEXT_MODULUS;
    }

    encode_slots_to_coefficients(&slots)
}

fn pack_broadcast_scores(scores: &[Ciphertext]) -> CanonicalResult<Ciphertext> {
    let option_count = scores.len();
    let mut packed_terms = Vec::with_capacity(option_count);
    for (option_index, score) in scores.iter().enumerate() {
        let duplicate_index = option_index + option_count;
        let mut logical_indices = vec![option_index];
        if duplicate_index < POLYNOMIAL_DEGREE {
            logical_indices.push(duplicate_index);
        }
        let selector = packed_score_slot_selector(&logical_indices)?;
        packed_terms.push(plaintext_mul(&normalize_scaling(score)?, &selector)?);
    }

    sum_aligned(&packed_terms)
}

fn packed_pair_lower_mask(option_count: usize, shift: usize) -> CanonicalResult<Vec<u64>> {
    let logical_indices = (0..(option_count - shift)).collect::<Vec<_>>();

    packed_score_slot_selector(&logical_indices)
}

pub(crate) fn evaluate_packed_ranks_via_difference(
    context: &EvaluatorContext,
    scores: &[Ciphertext],
    score_domain_max: u64,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    let option_count = scores.len();
    let packed_scores = pack_broadcast_scores(scores)?;

    evaluate_packed_ranks_from_packed_scores(
        context,
        &packed_scores,
        option_count,
        score_domain_max,
        seed_hex,
    )
}

pub(crate) fn evaluate_packed_ranks_from_packed_scores(
    context: &EvaluatorContext,
    packed_scores: &Ciphertext,
    option_count: usize,
    score_domain_max: u64,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    Ok(evaluate_packed_rank_evaluation_from_packed_scores(
        context,
        packed_scores,
        option_count,
        score_domain_max,
        seed_hex,
        0,
    )?
    .packed_ranks)
}

pub(crate) fn evaluate_packed_rank_evaluation_from_packed_scores(
    context: &EvaluatorContext,
    packed_scores: &Ciphertext,
    option_count: usize,
    score_domain_max: u64,
    seed_hex: &str,
    exact_rank_count: usize,
) -> CanonicalResult<PackedRankEvaluation> {
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "packed top-k rank evaluation requires at least two options",
        ));
    }
    if option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "packed top-k rank evaluation exceeds the generator-ordered slot window",
        ));
    }
    if exact_rank_count > option_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "exact rank derivation cannot request more ranks than options",
        ));
    }
    let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_max)?;
    let shift_constant = broadcast_constant(score_domain_max);
    let mut rank_terms = Vec::with_capacity(2 * (option_count - 1));
    let mut ahead_terms_by_option = vec![Vec::with_capacity(option_count - 1); option_count];
    for shift in 1..option_count {
        let galois_element = galois_power(shift);
        let shifted_scores = rotate_with_compact_positive_generator_basis(
            context,
            packed_scores,
            galois_element,
            packed_scores.level,
            &format!("{seed_hex}-packed-rank-galois-{shift}"),
        )?;
        let difference = ciphertext_sub(packed_scores, &shifted_scores)?;
        let shifted_difference =
            add_plaintext_coefficients(&normalize_scaling(&difference)?, &shift_constant)?;
        let refreshed_shifted_difference = modulus_switch_to(
            &shifted_difference,
            shifted_difference.level.saturating_sub(1),
        )?;
        let greater_or_equal = evaluate_direct_comparison_polynomial(
            context,
            &refreshed_shifted_difference,
            &greater_or_equal_polynomial,
        )?;
        let lower_pair_mask = packed_pair_lower_mask(option_count, shift)?;
        let lower_beats_higher =
            plaintext_mul(&normalize_scaling(&greater_or_equal)?, &lower_pair_mask)?;
        let negated_lower_beats_higher =
            ciphertext_negate(&normalize_scaling(&lower_beats_higher)?)?;
        let higher_beats_lower =
            add_plaintext_coefficients(&negated_lower_beats_higher, &lower_pair_mask)?;
        let lower_beats_higher_for_return =
            modulus_switch_to(&lower_beats_higher, DIRECT_COMPARISON_OUTPUT_LEVEL)?;
        let lower_beats_higher_at_higher_slot = rotate_with_compact_inverse_generator_basis(
            context,
            &lower_beats_higher_for_return,
            shift,
            lower_beats_higher_for_return.level,
            &format!("{seed_hex}-packed-rank-inverse-galois-{shift}"),
        )?;
        for lower_option in 0..(option_count - shift) {
            let higher_option = lower_option + shift;
            ahead_terms_by_option[lower_option].push(higher_beats_lower.clone());
            ahead_terms_by_option[higher_option].push(lower_beats_higher_at_higher_slot.clone());
        }
        rank_terms.push(higher_beats_lower);
        rank_terms.push(lower_beats_higher_at_higher_slot);
    }

    let packed_ranks = sum_aligned(&rank_terms)?;
    let exact_rank_indicators = if exact_rank_count == 0 {
        Vec::new()
    } else {
        exact_rank_indicators_from_ahead_terms(
            context,
            &ahead_terms_by_option,
            option_count,
            exact_rank_count,
        )?
    };

    Ok(PackedRankEvaluation {
        packed_ranks,
        exact_rank_indicators,
    })
}

pub(crate) fn evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
    context: &EvaluatorContext,
    packed_scores: &Ciphertext,
    option_count: usize,
    score_domain_max: u64,
    seed_hex: &str,
) -> CanonicalResult<PackedRankEvaluation> {
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "batched packed-rank evaluation requires at least two options",
        ));
    }
    if option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "batched packed-rank evaluation exceeds the generator-ordered slot window",
        ));
    }
    let pair_count = option_count * option_count.saturating_sub(1) / 2;
    if pair_count > GENERATOR_SUBGROUP_ORDER {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "batched packed-rank evaluation exceeds the generator subgroup slot window",
        ));
    }
    let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_max)?;
    let shift_constant = broadcast_constant(score_domain_max);
    let mut comparison_input_sum = None;
    let mut pair_windows = Vec::with_capacity(option_count - 1);
    let mut next_window_offset = 0_usize;
    for shift in 1..option_count {
        let pair_window_size = option_count - shift;
        pair_windows.push((shift, next_window_offset, pair_window_size));
        let shifted_scores = rotate_with_compact_positive_generator_basis(
            context,
            packed_scores,
            galois_power(shift),
            packed_scores.level,
            &format!("{seed_hex}-batched-pair-score-shift-{shift}"),
        )?;
        let difference = ciphertext_sub(packed_scores, &shifted_scores)?;
        let shifted_difference =
            add_plaintext_coefficients(&normalize_scaling(&difference)?, &shift_constant)?;
        let lower_pair_inputs = plaintext_mul(
            &normalize_scaling(&shifted_difference)?,
            &packed_pair_lower_mask(option_count, shift)?,
        )?;
        let windowed_inputs = if next_window_offset == 0 {
            lower_pair_inputs
        } else {
            rotate_with_compact_inverse_generator_basis(
                context,
                &lower_pair_inputs,
                next_window_offset,
                lower_pair_inputs.level,
                &format!("{seed_hex}-batched-pair-window-{shift}"),
            )?
        };
        add_to_aligned_sum(&mut comparison_input_sum, windowed_inputs)?;
        next_window_offset += pair_window_size;
    }
    let comparison_inputs = require_aligned_sum(
        comparison_input_sum,
        "batched packed-rank evaluation did not produce comparison inputs",
    )?;
    let refreshed_comparison_inputs = modulus_switch_to(
        &comparison_inputs,
        comparison_inputs.level.saturating_sub(1),
    )?;
    drop(comparison_inputs);
    let comparison_baby_step_count = direct_comparison_baby_step_count(score_domain_max)?;
    let comparison_outputs = evaluate_direct_comparison_polynomial_with_baby_step_count(
        context,
        &refreshed_comparison_inputs,
        &greater_or_equal_polynomial,
        comparison_baby_step_count,
    )?;
    drop(refreshed_comparison_inputs);
    drop(greater_or_equal_polynomial);

    let mut rank_sum = None;
    for (shift, window_offset, pair_window_size) in pair_windows {
        let window_logical_indices =
            (window_offset..(window_offset + pair_window_size)).collect::<Vec<_>>();
        let windowed_lower_beats_higher = plaintext_mul(
            &normalize_scaling(&comparison_outputs)?,
            &packed_score_slot_selector(&window_logical_indices)?,
        )?;
        let lower_beats_higher = if window_offset == 0 {
            windowed_lower_beats_higher
        } else {
            rotate_with_compact_positive_generator_basis(
                context,
                &windowed_lower_beats_higher,
                galois_power(window_offset),
                windowed_lower_beats_higher.level,
                &format!("{seed_hex}-batched-pair-window-return-{shift}"),
            )?
        };
        let lower_pair_mask = packed_pair_lower_mask(option_count, shift)?;
        let lower_beats_higher_for_lower_slots =
            plaintext_mul(&normalize_scaling(&lower_beats_higher)?, &lower_pair_mask)?;
        let higher_beats_lower_for_lower_slots = add_plaintext_coefficients(
            &ciphertext_negate(&normalize_scaling(&lower_beats_higher_for_lower_slots)?)?,
            &lower_pair_mask,
        )?;
        let lower_beats_higher_for_return = modulus_switch_to(
            &lower_beats_higher_for_lower_slots,
            DIRECT_COMPARISON_OUTPUT_LEVEL,
        )?;
        let lower_beats_higher_at_higher_slot = rotate_with_compact_inverse_generator_basis(
            context,
            &lower_beats_higher_for_return,
            shift,
            lower_beats_higher_for_return.level,
            &format!("{seed_hex}-batched-pair-rank-return-{shift}"),
        )?;
        add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }
    drop(comparison_outputs);

    let packed_ranks = require_aligned_sum(
        rank_sum,
        "batched packed-rank evaluation did not produce rank terms",
    )?;

    Ok(PackedRankEvaluation {
        packed_ranks,
        exact_rank_indicators: Vec::new(),
    })
}

fn exact_rank_indicators_from_ahead_terms(
    context: &EvaluatorContext,
    ahead_terms_by_option: &[Vec<Ciphertext>],
    option_count: usize,
    exact_rank_count: usize,
) -> CanonicalResult<Vec<Ciphertext>> {
    let mut masked_terms_by_rank = vec![Vec::with_capacity(option_count); exact_rank_count];
    for (option_index, ahead_terms) in ahead_terms_by_option.iter().enumerate() {
        if ahead_terms.len() != option_count - 1 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "exact rank derivation requires one ahead indicator for every other option",
            ));
        }
        let option_rank_indicators =
            exact_rank_indicators_for_option(context, ahead_terms, exact_rank_count)?;
        let option_selector = packed_score_slot_selector(&[option_index])?;
        for (rank_value, indicator) in option_rank_indicators.iter().enumerate() {
            masked_terms_by_rank[rank_value].push(plaintext_mul(
                &normalize_scaling(indicator)?,
                &option_selector,
            )?);
        }
    }

    masked_terms_by_rank
        .into_iter()
        .map(|rank_terms| sum_aligned(&rank_terms))
        .collect()
}

fn exact_rank_indicators_for_option(
    context: &EvaluatorContext,
    ahead_terms: &[Ciphertext],
    exact_rank_count: usize,
) -> CanonicalResult<Vec<Ciphertext>> {
    if exact_rank_count == 0 {
        return Ok(Vec::new());
    }
    let factors = ahead_terms
        .iter()
        .map(|ahead| {
            let bit = normalize_scaling(ahead)?;
            let one = encrypted_one_like(&bit)?;
            let not_bit = ciphertext_sub(&one, &bit)?;

            Ok(vec![not_bit, bit])
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    multiply_ciphertext_polynomials_balanced(context, factors, exact_rank_count - 1)
}

fn multiply_ciphertext_polynomials_balanced(
    context: &EvaluatorContext,
    factors: Vec<Vec<Ciphertext>>,
    max_degree: usize,
) -> CanonicalResult<Vec<Ciphertext>> {
    if factors.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "exact rank derivation requires at least one factor",
        ));
    }
    let mut current = factors;
    while current.len() > 1 {
        let defer_terminal_switch = current.len() == 2;
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0].clone());
            } else {
                next.push(multiply_ciphertext_polynomials(
                    context,
                    &pair[0],
                    &pair[1],
                    max_degree,
                    defer_terminal_switch,
                )?);
            }
        }
        current = next;
    }

    let mut coefficients = current.pop().expect("non-empty product has one result");
    while coefficients.len() <= max_degree {
        coefficients.push(scalar_mul(&coefficients[0], 0)?);
    }

    Ok(coefficients)
}

fn multiply_ciphertext_polynomials(
    context: &EvaluatorContext,
    left: &[Ciphertext],
    right: &[Ciphertext],
    max_degree: usize,
    defer_modulus_switch: bool,
) -> CanonicalResult<Vec<Ciphertext>> {
    let mut accumulated_products_by_degree = (0..=max_degree)
        .map(|_| None)
        .collect::<Vec<Option<Ciphertext>>>();
    for (left_degree, left_coefficient) in left.iter().enumerate() {
        for (right_degree, right_coefficient) in right.iter().enumerate() {
            let degree = left_degree + right_degree;
            if degree > max_degree {
                continue;
            }
            let product = if defer_modulus_switch {
                multiply_without_immediate_modulus_switch(
                    context,
                    left_coefficient,
                    right_coefficient,
                )?
            } else {
                multiply(context, left_coefficient, right_coefficient)?
            };
            accumulated_products_by_degree[degree] =
                if let Some(accumulated_product) = accumulated_products_by_degree[degree].take() {
                    let terms = [accumulated_product, product];
                    Some(sum_aligned(&terms)?)
                } else {
                    Some(product)
                };
        }
    }

    accumulated_products_by_degree
        .into_iter()
        .map(|product| product.map_or_else(|| scalar_mul(&left[0], 0), Ok))
        .collect()
}

// Encrypted sparse target projection result.
pub(crate) struct EncryptedSparseTarget {
    pub(crate) target_id: Ciphertext,
    pub(crate) target_order: Ciphertext,
}

pub(crate) fn project_packed_sparse_target(
    context: &EvaluatorContext,
    packed_ranks: &Ciphertext,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<EncryptedSparseTarget> {
    let rank_evaluation = PackedRankEvaluation {
        packed_ranks: packed_ranks.clone(),
        exact_rank_indicators: Vec::new(),
    };
    project_packed_sparse_target_from_rank_evaluation(
        context,
        &rank_evaluation,
        option_count,
        top_count,
    )
}

pub(crate) fn project_packed_sparse_target_from_rank_evaluation(
    context: &EvaluatorContext,
    rank_evaluation: &PackedRankEvaluation,
    option_count: usize,
    top_count: usize,
) -> CanonicalResult<EncryptedSparseTarget> {
    let id_weights = (0..option_count)
        .map(|option| {
            (
                option,
                u64::try_from(option + 1).expect("option identifier fits u64"),
            )
        })
        .collect::<Vec<_>>();
    let option_indices = (0..option_count).collect::<Vec<_>>();
    let id_selector = packed_score_weighted_selector(&id_weights)?;
    let option_slot_mask = packed_score_slot_selector(&option_indices)?;

    if top_count == option_count {
        let normalized_ranks = normalize_scaling(&rank_evaluation.packed_ranks)?;
        let encrypted_zero = scalar_mul(&normalized_ranks, 0)?;

        return Ok(EncryptedSparseTarget {
            target_id: add_plaintext_coefficients(&encrypted_zero, &id_selector)?,
            target_order: add_plaintext_coefficients(&normalized_ranks, &option_slot_mask)?,
        });
    }

    let (indicators, order_values) = if top_count == option_count {
        top_k_indicator_and_order_value(
            context,
            &rank_evaluation.packed_ranks,
            option_count,
            top_count,
        )?
    } else if rank_evaluation.exact_rank_indicators.len() >= top_count {
        let indicator_terms = rank_evaluation.exact_rank_indicators[..top_count].to_vec();
        let indicators = sum_aligned(&indicator_terms)?;
        let order_terms = rank_evaluation.exact_rank_indicators[..top_count]
            .iter()
            .enumerate()
            .map(|(rank_value, indicator)| {
                scalar_mul(
                    &normalize_scaling(indicator)?,
                    i64::try_from(rank_value + 1).expect("rank value fits i64"),
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let order_values = sum_aligned(&order_terms)?;

        (indicators, order_values)
    } else {
        top_k_indicator_and_order_value(
            context,
            &rank_evaluation.packed_ranks,
            option_count,
            top_count,
        )?
    };

    Ok(EncryptedSparseTarget {
        target_id: plaintext_mul(&normalize_scaling(&indicators)?, &id_selector)?,
        target_order: plaintext_mul(&normalize_scaling(&order_values)?, &option_slot_mask)?,
    })
}

// Project encrypted ranks and indicators into the sparse WinnerRankTopK-v1
// target layout: TargetIdSlot[a] = (a+1)*indicator, TargetOrderSlot[a] =
// (rank+1)*indicator, packed into per-option slots with all other slots zero.
pub(crate) fn project_sparse_target(
    context: &EvaluatorContext,
    ranks: &[Ciphertext],
    indicators: &[Ciphertext],
    top_count: usize,
) -> CanonicalResult<EncryptedSparseTarget> {
    let option_count = ranks.len();
    if indicators.len() != option_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sparse target projection requires one indicator per option",
        ));
    }
    let mut id_slots = Vec::with_capacity(option_count);
    let mut order_slots = Vec::with_capacity(option_count);
    for option in 0..option_count {
        let indicator = &indicators[option];
        // TargetIdSlot[a] = (a + 1) * indicator (public scalar times indicator).
        let id_value = scalar_mul(
            indicator,
            i64::try_from(option + 1).expect("option fits i64"),
        )?;
        // TargetOrderSlot[a] is evaluated directly as rank + 1 inside the
        // selected prefix and zero outside it, avoiding an extra depth level.
        let order_value = top_k_order_value(context, &ranks[option], option_count, top_count)?;
        // Place each broadcast value into its option slot with a plaintext mask.
        id_slots.push(plaintext_mul(
            &normalize_scaling(&id_value)?,
            &slot_selector(option)?,
        )?);
        order_slots.push(plaintext_mul(
            &normalize_scaling(&order_value)?,
            &slot_selector(option)?,
        )?);
    }

    Ok(EncryptedSparseTarget {
        target_id: sum_aligned(&id_slots)?,
        target_order: sum_aligned(&order_slots)?,
    })
}

fn move_single_slot_value(
    context: &EvaluatorContext,
    ciphertext: &Ciphertext,
    source_slot: usize,
    target_slot: usize,
    seed_hex: &str,
) -> CanonicalResult<Ciphertext> {
    if source_slot >= POLYNOMIAL_DEGREE || target_slot >= POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "single-slot move requires source and target slots inside the ring",
        ));
    }
    let selected = plaintext_mul(
        &normalize_scaling(ciphertext)?,
        &slot_selector(source_slot)?,
    )?;
    if source_slot == target_slot {
        return Ok(selected);
    }
    let galois_element = galois_element_moving_slot_to_target(source_slot, target_slot)?;

    context.rotate_ciphertext(&selected, galois_element, selected.level, seed_hex)
}

// The encrypted outputs of one top-k evaluation: the per-option ranks, the
// sparse target ciphertexts, and one representative comparator/bit ciphertext
// for binding the public encrypted evaluator output bundle.
pub(crate) struct TopKEvaluationOutputs {
    pub(crate) ranks: Vec<Ciphertext>,
    pub(crate) score_bit_sample: Ciphertext,
    pub(crate) greater_than_sample: Ciphertext,
    pub(crate) equal_sample: Ciphertext,
    pub(crate) ahead_sample: Ciphertext,
    pub(crate) target: EncryptedSparseTarget,
}

// Run the full encrypted top-k evaluation over the per-option broadcast score
// ciphertexts: score-bit derivation, bit-sliced comparison of every ordered
// pair, ahead indicators under the tie policy, rank accumulation, the top-k
// indicator, and the sparse target projection.
pub(crate) fn evaluate_top_k(
    context: &EvaluatorContext,
    scores: &[Ciphertext],
    top_count: usize,
    score_domain_max: u64,
) -> CanonicalResult<TopKEvaluationOutputs> {
    let option_count = scores.len();
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "top-k evaluation requires at least two options",
        ));
    }
    let bit_polynomials = bit_extraction_polynomials(score_domain_max)?;
    let bits = scores
        .iter()
        .map(|score| derive_score_bits(context, score, &bit_polynomials))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let score_bit_sample = bits[0][0].clone();

    let mut ranks = Vec::with_capacity(option_count);
    let mut greater_than_sample = None;
    let mut equal_sample = None;
    let mut ahead_sample = None;
    for option in 0..option_count {
        let mut ahead = Vec::with_capacity(option_count - 1);
        for challenger in 0..option_count {
            if challenger == option {
                continue;
            }
            let (greater_than, equal) =
                bit_sliced_greater_than_and_equal(context, &bits[challenger], &bits[option])?;
            let indicator = ahead_indicator(&greater_than, &equal, challenger, option)?;
            if greater_than_sample.is_none() {
                greater_than_sample = Some(greater_than);
                equal_sample = Some(equal);
                ahead_sample = Some(indicator.clone());
            }
            ahead.push(indicator);
        }
        ranks.push(accumulate_rank(&ahead)?);
    }

    let indicators = ranks
        .iter()
        .map(|rank| top_k_indicator(context, rank, option_count, top_count))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let target = project_sparse_target(context, &ranks, &indicators, top_count)?;

    Ok(TopKEvaluationOutputs {
        ranks,
        score_bit_sample,
        greater_than_sample: greater_than_sample.expect("at least one ordered pair"),
        equal_sample: equal_sample.expect("at least one ordered pair"),
        ahead_sample: ahead_sample.expect("at least one ordered pair"),
        target,
    })
}

// Depth-efficient comparison polynomials over the shifted score-difference
// domain [0, 2*score_domain_max]: `greater` is 1 exactly when the shifted value
// exceeds score_domain_max (i.e. challenger score > option score) and
// `greater_or_equal` is 1 when it is at least score_domain_max. Evaluating one of
// these on (Score_challenger - Score_option + score_domain_max) compares at
// multiplicative depth close to ceil(log2(2*score_domain_max + 1)) with no
// per-bit extraction. Per Iliashenko-Zucca this depth is the floor for
// comparison; their digit method reduces the multiplication count, not the
// depth. The active implementation uses a fixed baby-step
// Paterson-Stockmeyer split to reduce multiplication count while preserving
// enough level for rank-prefix projection.
pub(crate) fn comparison_polynomials(
    score_domain_max: u64,
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    let shift = score_domain_max;
    let point_count = usize::try_from(2 * shift).expect("comparison domain fits usize") + 1;
    let greater = (0..point_count)
        .map(|value| u64::from(value as u64 > shift))
        .collect::<Vec<_>>();
    let greater_or_equal = (0..point_count)
        .map(|value| u64::from(value as u64 >= shift))
        .collect::<Vec<_>>();

    Ok((
        interpolate_coefficients(&greater)?,
        interpolate_coefficients(&greater_or_equal)?,
    ))
}

pub(crate) fn evaluate_direct_comparison_polynomial(
    context: &EvaluatorContext,
    comparison_input: &Ciphertext,
    polynomial: &[u64],
) -> CanonicalResult<Ciphertext> {
    evaluate_polynomial_with_fixed_baby_step_count_and_deferred_terminal_switch(
        context,
        comparison_input,
        polynomial,
        DIRECT_COMPARISON_BABY_STEP_COUNT,
    )
}

fn evaluate_direct_comparison_polynomial_with_baby_step_count(
    context: &EvaluatorContext,
    comparison_input: &Ciphertext,
    polynomial: &[u64],
    baby_step_count: usize,
) -> CanonicalResult<Ciphertext> {
    evaluate_polynomial_with_fixed_baby_step_count_and_deferred_terminal_switch(
        context,
        comparison_input,
        polynomial,
        baby_step_count,
    )
}

fn direct_comparison_baby_step_count(score_domain_max: u64) -> CanonicalResult<usize> {
    let point_count = usize::try_from(
        score_domain_max
            .checked_mul(2)
            .and_then(|maximum| maximum.checked_add(1))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "direct comparison domain overflowed",
                )
            })?,
    )
    .map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct comparison domain does not fit usize",
        )
    })?;

    Ok(integer_square_root_ceil(point_count).max(2))
}

fn integer_square_root_ceil(value: usize) -> usize {
    let mut root = 1_usize;
    while root.saturating_mul(root) < value {
        root += 1;
    }

    root
}

// Run the encrypted top-k evaluation using the depth-efficient difference
// comparator (the reserved comparison-input derivation path) instead of per-bit
// extraction plus a bit-sliced comparator. The ahead indicator for an ordered
// pair is computed directly: greater-or-equal when the challenger has the lower
// index (tie goes to the lower index) and strictly-greater otherwise.
pub(crate) fn evaluate_top_k_via_difference(
    context: &EvaluatorContext,
    scores: &[Ciphertext],
    top_count: usize,
    score_domain_max: u64,
) -> CanonicalResult<TopKEvaluationOutputs> {
    let option_count = scores.len();
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "top-k evaluation requires at least two options",
        ));
    }
    let (greater_polynomial, greater_or_equal_polynomial) =
        comparison_polynomials(score_domain_max)?;
    let shift_constant = broadcast_constant(score_domain_max);

    let mut ranks = Vec::with_capacity(option_count);
    let mut ahead_sample = None;
    for option in 0..option_count {
        let mut ahead = Vec::with_capacity(option_count - 1);
        for challenger in 0..option_count {
            if challenger == option {
                continue;
            }
            let difference = ciphertext_sub(&scores[challenger], &scores[option])?;
            let shifted =
                add_plaintext_coefficients(&normalize_scaling(&difference)?, &shift_constant)?;
            let polynomial = if challenger < option {
                &greater_or_equal_polynomial
            } else {
                &greater_polynomial
            };
            let indicator = evaluate_direct_comparison_polynomial(context, &shifted, polynomial)?;
            if ahead_sample.is_none() {
                ahead_sample = Some(indicator.clone());
            }
            ahead.push(indicator);
        }
        ranks.push(accumulate_rank(&ahead)?);
    }

    let indicators = ranks
        .iter()
        .map(|rank| top_k_indicator(context, rank, option_count, top_count))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let target = project_sparse_target(context, &ranks, &indicators, top_count)?;
    let ahead_sample = ahead_sample.expect("at least one ordered pair");

    Ok(TopKEvaluationOutputs {
        score_bit_sample: ahead_sample.clone(),
        greater_than_sample: ahead_sample.clone(),
        equal_sample: ahead_sample.clone(),
        ahead_sample,
        ranks,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DIRECT_COMPARISON_OUTPUT_LEVEL, accumulate_rank,
        aggregate_score_packing_basis_galois_elements, aggregate_score_packing_galois_elements,
        aggregate_score_slot, ahead_indicator, bit_extraction_polynomials,
        bit_sliced_greater_than_and_equal, broadcast_constant, comparison_polynomials,
        derive_score_bits, evaluate_direct_comparison_polynomial,
        evaluate_packed_rank_evaluation_from_packed_scores,
        evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs,
        evaluate_packed_ranks_via_difference, evaluate_top_k_via_difference,
        exact_rank_indicators_for_option, galois_element_moving_slot_to_target, galois_power,
        generator_exponent_or_conjugated, generator_power_basis_for_exponent,
        interpolate_coefficients, pack_broadcast_scores, packed_rank_forward_basis_galois_elements,
        packed_rank_return_basis_galois_elements, packed_score_slot,
        project_packed_sparse_target_from_rank_evaluation, project_sparse_target, score_bit_count,
        selected_evaluator_rotation_key_schedule, top_k_indicator, top_k_order_value,
    };
    use crate::bgv::evaluator::{
        circuit::{EvaluatorContext, modulus_switch_to, normalize_scaling},
        engine::{Ciphertext, add_plaintext_coefficients, ciphertext_sub},
    };
    use crate::bgv::modular_arithmetic::{add_mod, mul_mod, pow_mod};
    use crate::bgv::profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE};

    fn evaluate_plaintext(coefficients: &[u64], point: u64) -> u64 {
        let mut accumulator = 0_u64;
        for (degree, coefficient) in coefficients.iter().enumerate() {
            let power = pow_mod(point, degree as u64, PLAINTEXT_MODULUS).expect("power");
            accumulator = add_mod(
                accumulator,
                mul_mod(*coefficient, power, PLAINTEXT_MODULUS).expect("mul"),
                PLAINTEXT_MODULUS,
            )
            .expect("add");
        }
        accumulator
    }

    #[test]
    fn score_bit_count_matches_domain() {
        assert_eq!(score_bit_count(0), 1);
        assert_eq!(score_bit_count(1), 1);
        assert_eq!(score_bit_count(10), 4);
        assert_eq!(score_bit_count(200), 8);
        assert_eq!(score_bit_count(500), 9);
    }

    #[test]
    fn interpolation_reproduces_sampled_values() {
        let values = [5_u64, 9, 2, 7, 65_000];
        let coefficients = interpolate_coefficients(&values).expect("interpolate");
        for (point, value) in values.iter().enumerate() {
            assert_eq!(evaluate_plaintext(&coefficients, point as u64), *value);
        }
    }

    // Encrypt a value broadcast into every slot (the constant polynomial).
    fn encrypt_broadcast(context: &EvaluatorContext, value: u64, seed: &str) -> Ciphertext {
        let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        coefficients[0] = value;
        context
            .key()
            .encrypt_coefficients(&coefficients, seed)
            .expect("encrypt broadcast")
    }

    #[test]
    #[ignore = "heavy full-ring top-k pipeline; run with --ignored"]
    fn encrypted_top_k_matches_plaintext_oracle() {
        let context = EvaluatorContext::new("top-k-e2e-v1", 9).expect("evaluator context");
        let key = context.key();
        let score_domain_max = 3_u64;
        let scores = [3_u64, 1_u64];
        let option_count = scores.len();
        let top_count = 1_usize;
        let bit_polynomials =
            bit_extraction_polynomials(score_domain_max).expect("bit polynomials");

        let score_ciphertexts = scores
            .iter()
            .enumerate()
            .map(|(option, value)| encrypt_broadcast(&context, *value, &format!("score-{option}")))
            .collect::<Vec<_>>();
        let bits = score_ciphertexts
            .iter()
            .map(|score| derive_score_bits(&context, score, &bit_polynomials).expect("bits"))
            .collect::<Vec<_>>();

        let mut ranks = Vec::with_capacity(option_count);
        for option in 0..option_count {
            let mut ahead = Vec::new();
            for challenger in 0..option_count {
                if challenger == option {
                    continue;
                }
                let (greater_than, equal) =
                    bit_sliced_greater_than_and_equal(&context, &bits[challenger], &bits[option])
                        .expect("compare");
                ahead.push(
                    ahead_indicator(&greater_than, &equal, challenger, option).expect("ahead"),
                );
            }
            ranks.push(accumulate_rank(&ahead).expect("rank"));
        }

        assert_eq!(
            key.decrypt_to_slots(&ranks[0]).expect("decrypt rank 0")[0],
            0
        );
        assert_eq!(
            key.decrypt_to_slots(&ranks[1]).expect("decrypt rank 1")[0],
            1
        );

        let indicators = ranks
            .iter()
            .map(|rank| {
                top_k_indicator(&context, rank, option_count, top_count).expect("indicator")
            })
            .collect::<Vec<_>>();
        let target =
            project_sparse_target(&context, &ranks, &indicators, top_count).expect("project");
        let id_slots = key.decrypt_to_slots(&target.target_id).expect("decrypt id");
        let order_slots = key
            .decrypt_to_slots(&target.target_order)
            .expect("decrypt order");
        assert_eq!(&id_slots[..option_count], &[1, 0]);
        assert_eq!(&order_slots[..option_count], &[1, 0]);
    }

    #[test]
    #[ignore = "heavy comparison-input top-k pipeline; run with --ignored"]
    fn comparison_input_evaluator_matches_oracle_with_tie() {
        // m = 3 with a tie between options 0 and 2 broken by the lower index,
        // K_top = 2. The comparison-input path is correct at this profile with
        // enough tail level for the rank-prefix target projection.
        let context = EvaluatorContext::new("comparison-input-tie", 9).expect("context");
        let key = context.key();
        let scores = [2_u64, 3, 2];
        let option_count = scores.len();
        let score_ciphertexts = scores
            .iter()
            .enumerate()
            .map(|(option, value)| encrypt_broadcast(&context, *value, &format!("cmp-{option}")))
            .collect::<Vec<_>>();
        let outputs =
            evaluate_top_k_via_difference(&context, &score_ciphertexts, 2, 3).expect("evaluate");
        let ranks = outputs
            .ranks
            .iter()
            .map(|rank| key.decrypt_to_slots(rank).expect("rank")[0])
            .collect::<Vec<_>>();
        assert_eq!(ranks, vec![1, 0, 2]);
        let id_slots = key.decrypt_to_slots(&outputs.target.target_id).expect("id");
        let order_slots = key
            .decrypt_to_slots(&outputs.target.target_order)
            .expect("order");
        assert_eq!(&id_slots[..option_count], &[1, 2, 0]);
        assert_eq!(&order_slots[..option_count], &[2, 1, 0]);
    }

    #[test]
    #[ignore = "heavy packed batched-pair evaluator smoke; run selectively"]
    fn packed_batched_pair_ranks_match_oracle_with_tie() {
        let context = EvaluatorContext::new("packed-batched-pair-target-tie", 7).expect("context");
        let key = context.key();
        let scores = [10_u64, 7, 10, 1];
        let option_count = scores.len();
        let score_ciphertexts = scores
            .iter()
            .enumerate()
            .map(|(option, value)| {
                encrypt_broadcast(&context, *value, &format!("packed-batched-score-{option}"))
            })
            .collect::<Vec<_>>();
        let packed_scores = pack_broadcast_scores(&score_ciphertexts).expect("packed scores");

        let rank_evaluation =
            evaluate_packed_rank_evaluation_from_packed_scores_with_batched_pairs(
                &context,
                &packed_scores,
                option_count,
                9,
                "packed-batched-pair-target",
            )
            .expect("batched rank evaluation");

        let rank_slots = key
            .decrypt_to_slots(&rank_evaluation.packed_ranks)
            .expect("decrypt ranks");
        let decoded_ranks = (0..option_count)
            .map(|option| rank_slots[packed_score_slot(option)])
            .collect::<Vec<_>>();
        assert_eq!(decoded_ranks, vec![0, 2, 1, 3]);
        let target = project_packed_sparse_target_from_rank_evaluation(
            &context,
            &rank_evaluation,
            option_count,
            option_count,
        )
        .expect("target");
        let target_id_slots = key.decrypt_to_slots(&target.target_id).expect("target ids");
        let target_order_slots = key
            .decrypt_to_slots(&target.target_order)
            .expect("target orders");
        let decoded_target_ids = (0..option_count)
            .map(|option| target_id_slots[packed_score_slot(option)])
            .collect::<Vec<_>>();
        let decoded_target_orders = (0..option_count)
            .map(|option| target_order_slots[packed_score_slot(option)])
            .collect::<Vec<_>>();
        assert_eq!(decoded_target_ids, vec![1, 2, 3, 4]);
        assert_eq!(decoded_target_orders, vec![1, 3, 2, 4]);
    }

    #[test]
    #[ignore = "heavy full-domain direct-comparison polynomial; run with --ignored"]
    fn direct_comparison_full_domain_polynomial_decrypts() {
        let context =
            EvaluatorContext::new("comparison-input-full-domain-depth", 15).expect("context");
        let key = context.key();
        let score_domain_max = 200_u64;
        let shifted_difference = key
            .encrypt_slots(&[400, 282, 200, 118, 0], "full-domain-comparison-inputs")
            .expect("comparison inputs");
        let (greater_polynomial, greater_or_equal_polynomial) =
            comparison_polynomials(score_domain_max).expect("comparison polynomial");
        let greater = evaluate_direct_comparison_polynomial(
            &context,
            &shifted_difference,
            &greater_polynomial,
        )
        .expect("greater");
        let greater_or_equal = evaluate_direct_comparison_polynomial(
            &context,
            &shifted_difference,
            &greater_or_equal_polynomial,
        )
        .expect("greater or equal");
        assert_eq!(
            &key.decrypt_to_slots(&greater).expect("greater slots")[..5],
            &[1, 1, 0, 0, 0]
        );
        assert_eq!(
            &key.decrypt_to_slots(&greater_or_equal)
                .expect("greater-or-equal slots")[..5],
            &[1, 1, 1, 0, 0]
        );
        assert_eq!(greater.level, DIRECT_COMPARISON_OUTPUT_LEVEL);
        assert_eq!(greater_or_equal.level, DIRECT_COMPARISON_OUTPUT_LEVEL);
    }

    #[test]
    fn bit_extraction_polynomials_recover_each_bit_over_domain() {
        let domain_max = 20_u64;
        let polynomials = bit_extraction_polynomials(domain_max).expect("bit polynomials");
        assert_eq!(polynomials.len(), score_bit_count(domain_max));
        for value in 0..=domain_max {
            for (bit, polynomial) in polynomials.iter().enumerate() {
                let expected = (value >> bit) & 1;
                assert_eq!(evaluate_plaintext(polynomial, value), expected);
            }
        }
    }

    #[test]
    fn top_k_order_polynomial_masks_unselected_ranks() {
        let context = EvaluatorContext::new("top-k-order-value", 4).expect("context");
        let rank_values = [0_u64, 1, 2, 3, 4];
        let encrypted_ranks = context
            .key()
            .encrypt_slots(&rank_values, "rank-order")
            .expect("rank ciphertext");
        let order_values =
            top_k_order_value(&context, &encrypted_ranks, rank_values.len(), 2).expect("order");
        let decrypted = context
            .key()
            .decrypt_to_slots(&order_values)
            .expect("decrypt order");

        assert_eq!(&decrypted[..rank_values.len()], &[1, 2, 0, 0, 0]);
    }

    #[test]
    fn packed_score_slots_follow_generator_order_without_collisions() {
        let slots = (0..40).map(packed_score_slot).collect::<Vec<_>>();
        let unique_slots = slots
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(slots[0], 0);
        assert_eq!(slots[1], 1);
        assert_eq!(slots[2], 4);
        assert_eq!(unique_slots.len(), slots.len());
        assert!(slots.iter().all(|slot| *slot < POLYNOMIAL_DEGREE));
    }

    #[test]
    fn aggregate_score_packing_rotations_move_layout_slots_to_packed_slots() {
        let rotations =
            aggregate_score_packing_galois_elements(20).expect("aggregate score rotations");

        assert_eq!(rotations.len(), 39);
        assert!(rotations.iter().all(|rotation| rotation % 2 == 1));
        for option in 0..20 {
            let source_slot = aggregate_score_slot(option);
            for target_logical_index in [option, option + 20] {
                let target_slot = packed_score_slot(target_logical_index);
                let galois_element = galois_element_moving_slot_to_target(source_slot, target_slot)
                    .expect("slot move Galois element");
                let source_for_target =
                    (galois_element * (2 * target_slot + 1)) % (2 * POLYNOMIAL_DEGREE);

                assert_eq!(source_for_target, 2 * source_slot + 1);
                if source_slot == target_slot {
                    assert_eq!(galois_element, 1);
                } else {
                    assert!(rotations.contains(&galois_element));
                }
            }
        }
    }

    #[test]
    fn compact_rotation_basis_covers_selected_logical_rotations() {
        let aggregate_basis =
            aggregate_score_packing_basis_galois_elements(20).expect("aggregate basis");
        let forward_basis =
            packed_rank_forward_basis_galois_elements(20).expect("rank forward basis");
        let return_basis = packed_rank_return_basis_galois_elements(20).expect("rank return basis");
        let schedule =
            selected_evaluator_rotation_key_schedule(20, DATA_PRIMES.len() - 1).expect("schedule");
        let full_level = DATA_PRIMES.len() - 1;
        let full_level_keys = schedule
            .iter()
            .filter(|(_, level)| *level == full_level)
            .map(|(rotation, _)| *rotation)
            .collect::<std::collections::BTreeSet<_>>();
        let return_level_keys = schedule
            .iter()
            .filter(|(_, level)| *level == DIRECT_COMPARISON_OUTPUT_LEVEL)
            .map(|(rotation, _)| *rotation)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(aggregate_basis.len(), 15);
        assert_eq!(forward_basis.len(), 5);
        assert_eq!(return_basis.len(), 5);
        assert_eq!(schedule.len(), 20);
        assert_eq!(full_level_keys.len(), 15);
        assert_eq!(return_level_keys.len(), 5);
        assert!(full_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
        for rotation in aggregate_score_packing_galois_elements(20).expect("logical packing") {
            let (requires_conjugation, exponent) =
                generator_exponent_or_conjugated(rotation).expect("covered rotation");
            if requires_conjugation {
                assert!(full_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
            }
            for basis_rotation in generator_power_basis_for_exponent(exponent) {
                assert!(full_level_keys.contains(&basis_rotation));
            }
        }
    }

    #[test]
    fn packed_rank_rotation_set_matches_unordered_pair_schedule() {
        let rotations = super::packed_rank_galois_elements(20).expect("rotations");
        let unique_rotations = rotations
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(rotations.len(), 38);
        assert_eq!(unique_rotations.len(), 38);
        assert_eq!(rotations[0], 3);
        assert_eq!(
            rotations[1],
            super::inverse_galois_element(3).expect("inverse")
        );
        assert!(rotations.iter().all(|rotation| rotation % 2 == 1));
        assert!(
            rotations
                .iter()
                .all(|rotation| *rotation < 2 * POLYNOMIAL_DEGREE)
        );
    }

    #[test]
    #[ignore = "heavy packed direct-comparison rank pipeline; run with --ignored"]
    fn packed_difference_ranks_match_oracle_with_tie() {
        let context = EvaluatorContext::new("packed-rank-seed", 7).expect("context");
        let scores = [2_u64, 4, 4, 1];
        let score_ciphertexts = scores
            .iter()
            .enumerate()
            .map(|(option, value)| {
                encrypt_broadcast(&context, *value, &format!("packed-score-{option}"))
            })
            .collect::<Vec<_>>();
        let packed_ranks = evaluate_packed_ranks_via_difference(
            &context,
            &score_ciphertexts,
            4,
            "packed-rank-test",
        )
        .expect("packed ranks");
        let decrypted = context
            .key()
            .decrypt_to_slots(&packed_ranks)
            .expect("decrypt packed ranks");
        let rank_slots = (0..scores.len())
            .map(|option| decrypted[packed_score_slot(option)])
            .collect::<Vec<_>>();

        assert_eq!(rank_slots, vec![2, 0, 1, 3]);
    }

    #[test]
    #[ignore = "heavy packed sparse-target smoke test; run with --ignored"]
    fn packed_sparse_target_matches_two_option_oracle() {
        let context = EvaluatorContext::new("packed-target-seed", 15).expect("context");
        let scores = [170_u64, 88];
        let score_ciphertexts = scores
            .iter()
            .enumerate()
            .map(|(option, value)| {
                encrypt_broadcast(&context, *value, &format!("packed-target-score-{option}"))
            })
            .collect::<Vec<_>>();
        let unpacked_outputs = evaluate_top_k_via_difference(&context, &score_ciphertexts, 1, 200)
            .expect("unpacked ranks");
        let unpacked_rank_slots = context
            .key()
            .decrypt_to_slots(&unpacked_outputs.ranks[0])
            .expect("unpacked rank slots");
        assert_eq!(unpacked_rank_slots[0], 0);

        let packed_scores = pack_broadcast_scores(&score_ciphertexts).expect("packed scores");
        let shifted_scores = context
            .rotate_ciphertext(
                &packed_scores,
                galois_power(1),
                packed_scores.level,
                "packed-target-debug-shift",
            )
            .expect("shifted scores");
        let shifted_difference = add_plaintext_coefficients(
            &normalize_scaling(
                &ciphertext_sub(&packed_scores, &shifted_scores).expect("score difference"),
            )
            .expect("normalized difference"),
            &broadcast_constant(200),
        )
        .expect("shifted difference");
        let shifted_slots = context
            .key()
            .decrypt_to_slots(&shifted_difference)
            .expect("shifted difference slots");
        assert_eq!(
            &[
                shifted_slots[packed_score_slot(0)],
                shifted_slots[packed_score_slot(1)]
            ],
            &[282, 118]
        );

        let packed_rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores(
            &context,
            &packed_scores,
            scores.len(),
            200,
            "packed-target-test",
            1,
        )
        .expect("packed rank evaluation");
        let rank_slots = context
            .key()
            .decrypt_to_slots(&packed_rank_evaluation.packed_ranks)
            .expect("packed rank slots");
        assert_eq!(
            (0..scores.len())
                .map(|option| rank_slots[packed_score_slot(option)])
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        let target = project_packed_sparse_target_from_rank_evaluation(
            &context,
            &packed_rank_evaluation,
            scores.len(),
            1,
        )
        .expect("target");
        let id_slots = context
            .key()
            .decrypt_to_slots(&target.target_id)
            .expect("decrypt packed id");
        let order_slots = context
            .key()
            .decrypt_to_slots(&target.target_order)
            .expect("decrypt packed order");
        let target_ids = (0..scores.len())
            .map(|option| id_slots[packed_score_slot(option)])
            .collect::<Vec<_>>();
        let target_orders = (0..scores.len())
            .map(|option| order_slots[packed_score_slot(option)])
            .collect::<Vec<_>>();

        assert_eq!(target_ids, vec![1, 0]);
        assert_eq!(target_orders, vec![1, 0]);
    }

    #[test]
    #[ignore = "heavy packed sparse-target tie test; run with --ignored"]
    fn packed_sparse_target_matches_four_option_oracle_with_tie() {
        let context = EvaluatorContext::new("packed-target-four-option", 10).expect("context");
        let key = context.key();
        let scores = [2_u64, 4, 4, 1];
        let score_ciphertexts = scores
            .iter()
            .enumerate()
            .map(|(option, score)| encrypt_broadcast(&context, *score, &format!("score-{option}")))
            .collect::<Vec<_>>();
        let packed_scores = pack_broadcast_scores(&score_ciphertexts).expect("packed scores");
        let packed_rank_evaluation = evaluate_packed_rank_evaluation_from_packed_scores(
            &context,
            &packed_scores,
            scores.len(),
            4,
            "packed-rank-target-four",
            2,
        )
        .expect("ranks");
        let packed_target = project_packed_sparse_target_from_rank_evaluation(
            &context,
            &packed_rank_evaluation,
            scores.len(),
            2,
        )
        .expect("target");
        let target_id_slots = key
            .decrypt_to_slots(&packed_target.target_id)
            .expect("target id");
        let target_order_slots = key
            .decrypt_to_slots(&packed_target.target_order)
            .expect("target order");
        let target_ids = (0..scores.len())
            .map(|option| target_id_slots[packed_score_slot(option)])
            .collect::<Vec<_>>();
        let target_orders = (0..scores.len())
            .map(|option| target_order_slots[packed_score_slot(option)])
            .collect::<Vec<_>>();

        assert_eq!(target_ids, vec![0, 2, 3, 0]);
        assert_eq!(target_orders, vec![0, 1, 2, 0]);
    }

    #[test]
    #[ignore = "diagnostic exact-rank noise check; run selectively"]
    fn clean_full_option_exact_rank_indicator_decrypts() {
        let context = EvaluatorContext::new("clean-full-option-exact-rank", 15).expect("context");
        let key = context.key();
        let expected_rank = 8;
        let exact_rank_count = 10;
        for input_level in [10_usize, 12] {
            let ahead_terms = (0..19)
                .map(|ahead_index| {
                    let bit = u64::from(ahead_index < expected_rank);
                    let encrypted_bit = key
                        .encrypt_slots(
                            &[bit; 4],
                            &format!("clean-ahead-bit-{input_level}-{ahead_index}"),
                        )
                        .expect("encrypted clean ahead bit");

                    modulus_switch_to(&encrypted_bit, input_level).expect("clean ahead bit level")
                })
                .collect::<Vec<_>>();
            let indicators =
                exact_rank_indicators_for_option(&context, &ahead_terms, exact_rank_count)
                    .expect("exact rank indicators");
            let decrypted = indicators
                .iter()
                .map(|indicator| key.decrypt_to_slots(indicator).expect("indicator slots")[0])
                .collect::<Vec<_>>();

            assert_eq!(
                decrypted,
                vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
                "exact rank indicators must decrypt from clean bits at level {input_level}",
            );
        }
    }

    #[test]
    #[ignore = "heavy full-rank-domain projection tail; run with --ignored"]
    fn full_rank_domain_projection_tail_decrypts_with_headroom() {
        let context = EvaluatorContext::new("full-rank-domain-tail", 6).expect("context");
        let key = context.key();
        let rank_ciphertext = modulus_switch_to(
            &key.encrypt_slots(&[0, 1, 9, 10, 19], "full-rank-domain-values")
                .expect("encrypt ranks"),
            6,
        )
        .expect("level");
        let indicator = top_k_indicator(&context, &rank_ciphertext, 20, 10).expect("indicator");
        let order_value = top_k_order_value(&context, &rank_ciphertext, 20, 10).expect("order");
        let indicator_slots = key.decrypt_to_slots(&indicator).expect("indicator slots");
        let order_slots = key.decrypt_to_slots(&order_value).expect("order slots");

        assert_eq!(&indicator_slots[..5], &[1, 1, 1, 0, 0]);
        assert_eq!(&order_slots[..5], &[1, 2, 10, 0, 0]);
        assert_eq!(indicator.level, 1);
        assert_eq!(order_value.level, 1);
    }
}
