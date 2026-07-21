use crate::{
    bgv::parameters::{
        PLAINTEXT_EXTENSION_DEGREE, PLAINTEXT_EXTENSION_LANE_COUNT,
        PLAINTEXT_LANE_IDEMPOTENT_SCALE, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE,
        plaintext_extension_lane_root,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

use super::{MAXIMUM_SCORE, MINIMUM_SCORE, OPTION_COUNT};

pub(crate) const PAIR_CHARACTER_PLAINTEXT_MODULUS: u64 = PLAINTEXT_MODULUS;
pub(crate) const PAIR_CHARACTER_RING_DEGREE: usize = POLYNOMIAL_DEGREE;
pub(crate) const PAIR_CHARACTER_LANE_COUNT: usize = PLAINTEXT_EXTENSION_LANE_COUNT;
pub(crate) const PAIR_CHARACTER_LANE_DEGREE: usize = PLAINTEXT_EXTENSION_DEGREE;
pub(crate) const PAIR_CHARACTER_CIPHERTEXT_COUNT: usize = 2;
pub(crate) const PAIR_CHARACTER_AUXILIARY_COUNT: usize = 3;
pub(crate) const SCORE_BUCKET_COUNT: usize = (MAXIMUM_SCORE - MINIMUM_SCORE + 1) as usize;

const PAIR_COUNT: usize = OPTION_COUNT * (OPTION_COUNT - 1) / 2;
const PAIR_CHARACTER_BANK_LANE_COUNT: usize = PAIR_CHARACTER_LANE_COUNT / 2;
const EXPECTED_ACTIVE_LANE_COUNTS: [usize; PAIR_CHARACTER_CIPHERTEXT_COUNT] = [93, 97];

/// One suite-fixed placement of every pair at a given option separation.
/// The start is local to one 64-lane Frobenius-orbit bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PairCharacterShiftPlacement {
    ciphertext_ordinal: u16,
    bank_ordinal: u16,
    lane_start: u16,
}

/// The topology-audited pair catalog. Entry `d - 1` places every pair
/// `(lower, lower + d)` in increasing `lower` order.
const PAIR_CHARACTER_SHIFT_PLACEMENTS: [PairCharacterShiftPlacement; OPTION_COUNT - 1] = [
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 0,
        lane_start: 7,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 0,
        lane_start: 35,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 1,
        lane_start: 15,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 1,
        lane_start: 33,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 1,
        lane_start: 12,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 1,
        lane_start: 58,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 0,
        lane_start: 38,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 0,
        lane_start: 57,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 0,
        lane_start: 21,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 1,
        lane_start: 31,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 1,
        lane_start: 49,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 1,
        lane_start: 41,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 1,
        lane_start: 6,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 0,
        lane_start: 29,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 1,
        lane_start: 58,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 0,
        lane_start: 57,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 1,
        bank_ordinal: 1,
        lane_start: 52,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 0,
        lane_start: 12,
    },
    PairCharacterShiftPlacement {
        ciphertext_ordinal: 0,
        bank_ordinal: 0,
        lane_start: 7,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterLaneAssignment {
    ciphertext_ordinal: u16,
    lane_ordinal: u16,
    lower_option_ordinal: u16,
    higher_option_ordinal: u16,
}

impl PairCharacterLaneAssignment {
    pub(crate) const fn ciphertext_ordinal(self) -> u16 {
        self.ciphertext_ordinal
    }

    pub(crate) const fn lane_ordinal(self) -> u16 {
        self.lane_ordinal
    }

    pub(crate) const fn lower_option_ordinal(self) -> u16 {
        self.lower_option_ordinal
    }

    pub(crate) const fn higher_option_ordinal(self) -> u16 {
        self.higher_option_ordinal
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterPlaintext {
    auxiliary_left_coefficients: Vec<u64>,
    auxiliary_right_coefficients: Vec<u64>,
    message_coefficients: Vec<u64>,
}

/// One nonzero row of a deterministic pair-character encoder profile.
/// Values are reduced in the plaintext field before they are exposed so a
/// proof-field embedding cannot observe unreduced sums from several lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PairCharacterEncoderProfileTerm {
    lane_block_ordinal: usize,
    trace_row_ordinal: usize,
    value: u64,
}

impl PairCharacterEncoderProfileTerm {
    pub(crate) const fn lane_block_ordinal(self) -> usize {
        self.lane_block_ordinal
    }

    pub(crate) const fn trace_row_ordinal(self) -> usize {
        self.trace_row_ordinal
    }

    pub(crate) const fn value(self) -> u64 {
        self.value
    }
}

impl PairCharacterPlaintext {
    pub(crate) fn auxiliary_left_coefficients(&self) -> &[u64] {
        &self.auxiliary_left_coefficients
    }

    pub(crate) fn auxiliary_right_coefficients(&self) -> &[u64] {
        &self.auxiliary_right_coefficients
    }

    pub(crate) fn message_coefficients(&self) -> &[u64] {
        &self.message_coefficients
    }
}

pub(crate) fn selected_pair_character_lane_assignments()
-> CanonicalResult<Vec<PairCharacterLaneAssignment>> {
    let mut assignments = Vec::with_capacity(PAIR_COUNT);
    for (shift_index, placement) in PAIR_CHARACTER_SHIFT_PLACEMENTS.iter().copied().enumerate() {
        let shift = shift_index + 1;
        for lower_option_ordinal in 0..OPTION_COUNT - shift {
            let lane_within_bank = (usize::from(placement.lane_start) + lower_option_ordinal)
                % PAIR_CHARACTER_BANK_LANE_COUNT;
            let lane_ordinal = usize::from(placement.bank_ordinal)
                .checked_mul(PAIR_CHARACTER_BANK_LANE_COUNT)
                .and_then(|bank_start| bank_start.checked_add(lane_within_bank))
                .ok_or_else(pair_character_geometry_error)?;
            assignments.push(PairCharacterLaneAssignment {
                ciphertext_ordinal: placement.ciphertext_ordinal,
                lane_ordinal: u16::try_from(lane_ordinal)
                    .map_err(|_| pair_character_geometry_error())?,
                lower_option_ordinal: u16::try_from(lower_option_ordinal)
                    .map_err(|_| pair_character_geometry_error())?,
                higher_option_ordinal: u16::try_from(lower_option_ordinal + shift)
                    .map_err(|_| pair_character_geometry_error())?,
            });
        }
    }
    validate_pair_character_lane_assignments(&assignments)?;
    Ok(assignments)
}

pub(crate) fn pair_character_plaintexts(
    scores: &[u64],
    plaintext_modulus: u64,
    ring_degree: usize,
) -> CanonicalResult<[PairCharacterPlaintext; PAIR_CHARACTER_CIPHERTEXT_COUNT]> {
    validate_pair_character_geometry(plaintext_modulus, ring_degree)?;
    if scores.len() != OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "pair-character ballot requires exactly twenty scores",
        ));
    }
    if scores
        .iter()
        .any(|score| !(MINIMUM_SCORE..=MAXIMUM_SCORE).contains(score))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "pair-character ballot score is outside the selected score domain",
        ));
    }

    let assignments = selected_pair_character_lane_assignments()?;
    let mut plaintexts = core::array::from_fn(|_| PairCharacterPlaintext {
        auxiliary_left_coefficients: vec![0_u64; ring_degree],
        auxiliary_right_coefficients: vec![0_u64; ring_degree],
        message_coefficients: vec![0_u64; ring_degree],
    });
    for assignment in assignments {
        let plaintext = plaintexts
            .get_mut(usize::from(assignment.ciphertext_ordinal))
            .ok_or_else(pair_character_geometry_error)?;
        let lower_score = scores[usize::from(assignment.lower_option_ordinal)];
        let higher_score = scores[usize::from(assignment.higher_option_ordinal)];
        let left_exponent = usize::try_from(lower_score + MAXIMUM_SCORE - MINIMUM_SCORE)
            .map_err(|_| pair_character_geometry_error())?;
        let message_exponent =
            usize::try_from(lower_score + MAXIMUM_SCORE - MINIMUM_SCORE - higher_score)
                .map_err(|_| pair_character_geometry_error())?;
        let inverse_lane_root = modular_power(
            pair_character_lane_root(usize::from(assignment.lane_ordinal))?,
            PAIR_CHARACTER_PLAINTEXT_MODULUS - 2,
            PAIR_CHARACTER_PLAINTEXT_MODULUS,
        );
        let mut idempotent_coefficient = PLAINTEXT_LANE_IDEMPOTENT_SCALE;
        for lane_coefficient_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
            let lane_block_start = lane_coefficient_ordinal
                .checked_mul(PAIR_CHARACTER_LANE_DEGREE)
                .ok_or_else(pair_character_geometry_error)?;
            add_coefficient(
                &mut plaintext.auxiliary_left_coefficients,
                lane_block_start + left_exponent,
                idempotent_coefficient,
            )?;
            let higher_score =
                usize::try_from(higher_score).map_err(|_| pair_character_geometry_error())?;
            if lane_coefficient_ordinal == 0 {
                add_coefficient(
                    &mut plaintext.auxiliary_right_coefficients,
                    ring_degree
                        .checked_sub(higher_score)
                        .ok_or_else(pair_character_geometry_error)?,
                    modular_negation(idempotent_coefficient, plaintext_modulus),
                )?;
            } else {
                add_coefficient(
                    &mut plaintext.auxiliary_right_coefficients,
                    lane_block_start
                        .checked_sub(higher_score)
                        .ok_or_else(pair_character_geometry_error)?,
                    idempotent_coefficient,
                )?;
            }
            add_coefficient(
                &mut plaintext.message_coefficients,
                lane_block_start + message_exponent,
                idempotent_coefficient,
            )?;
            idempotent_coefficient =
                modular_product(idempotent_coefficient, inverse_lane_root, plaintext_modulus);
        }
    }
    Ok(plaintexts)
}

pub(crate) fn pair_character_encoder_profile_sequence(
    ciphertext_ordinal: u16,
    auxiliary_ordinal: u16,
    option_ordinal: u16,
) -> CanonicalResult<Vec<u64>> {
    let terms = pair_character_encoder_profile_terms(
        ciphertext_ordinal,
        auxiliary_ordinal,
        option_ordinal,
    )?;
    let mut sequence = vec![0_u64; PAIR_CHARACTER_RING_DEGREE];
    for term in terms {
        let value = sequence
            .get_mut(term.trace_row_ordinal)
            .ok_or_else(pair_character_geometry_error)?;
        if *value != 0 {
            return Err(pair_character_geometry_error());
        }
        *value = term.value;
    }
    Ok(sequence)
}

pub(crate) fn pair_character_encoder_profile_terms(
    ciphertext_ordinal: u16,
    auxiliary_ordinal: u16,
    option_ordinal: u16,
) -> CanonicalResult<Vec<PairCharacterEncoderProfileTerm>> {
    if usize::from(ciphertext_ordinal) >= PAIR_CHARACTER_CIPHERTEXT_COUNT
        || usize::from(auxiliary_ordinal) >= 2
        || usize::from(option_ordinal) >= OPTION_COUNT
    {
        return Err(pair_character_geometry_error());
    }
    let mut coefficient_by_lane_block = [0_u64; PAIR_CHARACTER_LANE_COUNT];
    for (shift_index, placement) in PAIR_CHARACTER_SHIFT_PLACEMENTS.iter().copied().enumerate() {
        if placement.ciphertext_ordinal != ciphertext_ordinal {
            continue;
        }
        let shift = shift_index + 1;
        for lower_option_index in 0..OPTION_COUNT - shift {
            let higher_option_index = lower_option_index + shift;
            let contributes = match auxiliary_ordinal {
                0 => lower_option_index == usize::from(option_ordinal),
                1 => higher_option_index == usize::from(option_ordinal),
                _ => false,
            };
            if !contributes {
                continue;
            }
            let lane_within_bank = (usize::from(placement.lane_start) + lower_option_index)
                % PAIR_CHARACTER_BANK_LANE_COUNT;
            let lane_ordinal = usize::from(placement.bank_ordinal)
                .checked_mul(PAIR_CHARACTER_BANK_LANE_COUNT)
                .and_then(|bank_start| bank_start.checked_add(lane_within_bank))
                .ok_or_else(pair_character_geometry_error)?;
            let inverse_lane_root = modular_power(
                pair_character_lane_root(lane_ordinal)?,
                PAIR_CHARACTER_PLAINTEXT_MODULUS - 2,
                PAIR_CHARACTER_PLAINTEXT_MODULUS,
            );
            let mut idempotent_coefficient = PLAINTEXT_LANE_IDEMPOTENT_SCALE;
            for accumulated in &mut coefficient_by_lane_block {
                *accumulated = modular_sum(
                    *accumulated,
                    idempotent_coefficient,
                    PAIR_CHARACTER_PLAINTEXT_MODULUS,
                );
                idempotent_coefficient = modular_product(
                    idempotent_coefficient,
                    inverse_lane_root,
                    PAIR_CHARACTER_PLAINTEXT_MODULUS,
                );
            }
        }
    }
    let mut terms = Vec::with_capacity(PAIR_CHARACTER_LANE_COUNT);
    for (lane_block_ordinal, coefficient) in coefficient_by_lane_block.into_iter().enumerate() {
        let trace_row_ordinal =
            pair_character_encoder_profile_trace_row_ordinal(lane_block_ordinal)?;
        let value = if auxiliary_ordinal == 1 && lane_block_ordinal == 0 {
            modular_negation(coefficient, PAIR_CHARACTER_PLAINTEXT_MODULUS)
        } else {
            coefficient
        };
        if value != 0 {
            terms.push(PairCharacterEncoderProfileTerm {
                lane_block_ordinal,
                trace_row_ordinal,
                value,
            });
        }
    }
    Ok(terms)
}

pub(crate) fn pair_character_encoder_profile_trace_row_ordinal(
    lane_block_ordinal: usize,
) -> CanonicalResult<usize> {
    if lane_block_ordinal >= PAIR_CHARACTER_LANE_COUNT {
        return Err(pair_character_geometry_error());
    }
    lane_block_ordinal
        .checked_mul(PAIR_CHARACTER_LANE_DEGREE)
        .filter(|ordinal| *ordinal < PAIR_CHARACTER_RING_DEGREE)
        .ok_or_else(pair_character_geometry_error)
}

pub(crate) fn pair_character_lane_value(
    coefficients: &[u64],
    lane_ordinal: usize,
) -> CanonicalResult<[u64; PAIR_CHARACTER_LANE_DEGREE]> {
    validate_pair_character_geometry(PAIR_CHARACTER_PLAINTEXT_MODULUS, coefficients.len())?;
    let lane_root = pair_character_lane_root(lane_ordinal)?;
    let mut value = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
    let mut lane_root_power = 1_u64;
    for lane_coefficient_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
        let lane_block_start = lane_coefficient_ordinal * PAIR_CHARACTER_LANE_DEGREE;
        for residue_exponent in 0..PAIR_CHARACTER_LANE_DEGREE {
            value[residue_exponent] = modular_sum(
                value[residue_exponent],
                modular_product(
                    coefficients[lane_block_start + residue_exponent],
                    lane_root_power,
                    PAIR_CHARACTER_PLAINTEXT_MODULUS,
                ),
                PAIR_CHARACTER_PLAINTEXT_MODULUS,
            );
        }
        lane_root_power =
            modular_product(lane_root_power, lane_root, PAIR_CHARACTER_PLAINTEXT_MODULUS);
    }
    Ok(value)
}

/// Coefficients of the suite-fixed idempotent for one logical lane, ordered
/// by powers of `Z = X^256`. Callers place entry `j` at coefficient `256*j`
/// in the full ring.
pub(crate) fn pair_character_lane_idempotent_coefficients(
    lane_ordinal: usize,
) -> CanonicalResult<Vec<u64>> {
    let inverse_lane_root = modular_power(
        pair_character_lane_root(lane_ordinal)?,
        PAIR_CHARACTER_PLAINTEXT_MODULUS - 2,
        PAIR_CHARACTER_PLAINTEXT_MODULUS,
    );
    let mut coefficients = Vec::with_capacity(PAIR_CHARACTER_LANE_COUNT);
    let mut coefficient = PLAINTEXT_LANE_IDEMPOTENT_SCALE;
    for _ in 0..PAIR_CHARACTER_LANE_COUNT {
        coefficients.push(coefficient);
        coefficient = modular_product(
            coefficient,
            inverse_lane_root,
            PAIR_CHARACTER_PLAINTEXT_MODULUS,
        );
    }
    Ok(coefficients)
}

fn validate_pair_character_geometry(
    plaintext_modulus: u64,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if plaintext_modulus != PAIR_CHARACTER_PLAINTEXT_MODULUS
        || ring_degree != PAIR_CHARACTER_RING_DEGREE
        || PAIR_CHARACTER_LANE_COUNT * PAIR_CHARACTER_LANE_DEGREE != ring_degree
    {
        return Err(pair_character_geometry_error());
    }
    Ok(())
}

fn validate_pair_character_lane_assignments(
    assignments: &[PairCharacterLaneAssignment],
) -> CanonicalResult<()> {
    if assignments.len() != PAIR_COUNT {
        return Err(pair_character_geometry_error());
    }
    let mut occupied = [[false; PAIR_CHARACTER_LANE_COUNT]; PAIR_CHARACTER_CIPHERTEXT_COUNT];
    let mut active_counts = [0_usize; PAIR_CHARACTER_CIPHERTEXT_COUNT];
    let mut assignment_ordinal = 0_usize;
    for shift in 1..OPTION_COUNT {
        for lower_option_ordinal in 0..OPTION_COUNT - shift {
            let assignment = assignments[assignment_ordinal];
            let ciphertext_index = usize::from(assignment.ciphertext_ordinal);
            let lane_index = usize::from(assignment.lane_ordinal);
            if ciphertext_index >= PAIR_CHARACTER_CIPHERTEXT_COUNT
                || lane_index >= PAIR_CHARACTER_LANE_COUNT
                || usize::from(assignment.lower_option_ordinal) != lower_option_ordinal
                || usize::from(assignment.higher_option_ordinal) != lower_option_ordinal + shift
                || occupied[ciphertext_index][lane_index]
            {
                return Err(pair_character_geometry_error());
            }
            occupied[ciphertext_index][lane_index] = true;
            active_counts[ciphertext_index] += 1;
            assignment_ordinal += 1;
        }
    }
    if active_counts != EXPECTED_ACTIVE_LANE_COUNTS {
        return Err(pair_character_geometry_error());
    }
    Ok(())
}

fn pair_character_lane_root(lane_ordinal: usize) -> CanonicalResult<u64> {
    plaintext_extension_lane_root(lane_ordinal).ok_or_else(pair_character_geometry_error)
}

fn add_coefficient(
    coefficients: &mut [u64],
    coefficient_ordinal: usize,
    contribution: u64,
) -> CanonicalResult<()> {
    let coefficient = coefficients
        .get_mut(coefficient_ordinal)
        .ok_or_else(pair_character_geometry_error)?;
    *coefficient = modular_sum(*coefficient, contribution, PAIR_CHARACTER_PLAINTEXT_MODULUS);
    Ok(())
}

fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = modular_product(result, base, modulus);
        }
        base = modular_product(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn modular_product(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

fn modular_sum(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

fn modular_negation(value: u64, modulus: u64) -> u64 {
    if value == 0 { 0 } else { modulus - value }
}

fn pair_character_geometry_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "pair-character ballot received incompatible selected-suite geometry",
    )
}
