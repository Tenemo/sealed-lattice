//! Test-only stochastic modulus-down recurrence for the selected evaluator.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use num_bigint::{BigInt, BigUint};
use num_traits::Signed;

use super::*;
use crate::bgv::evaluator::{
    program::{
        CandidateEvaluatorRecurrenceTrace, EvaluatorInstructionStream, EvaluatorOpcode,
        EvaluatorProgramSet, compile_factor_four_candidate_recurrence_trace,
        encode_constant_coefficients, selected_evaluator_program_set,
    },
    top_k::SELECTED_EVALUATOR_WORKING_LEVEL,
};
use crate::{
    bgv::{
        key_switch_topology::{
            canonical_residue_byte_length, validate_key_switch_special_basis_dominates_data_blocks,
        },
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
        target_decryption::kllps_release::{
            ensure_factor_four_parameter_conditions_with_data_primes,
            factor_four_required_flooding_bound,
        },
    },
    foundation::MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
};

const SELECTED_PARTICIPANT_COUNT: u64 = 10;
const SELECTED_BALLOT_COUNT: usize = 10;
const SELECTED_OPTION_COUNT: usize = 20;
const SELECTED_SCORE_DOMAIN_MAXIMUM: u64 = 90;
const MINIMUM_TARGET_LEVEL: usize = 5;
const CURRENT_COMPARISON_BABY_STEP_COUNT: usize = 14;
const DITHER_DENSITY_POWER_OF_TWO: u32 = 248;
const DITHER_DENSITY_DIVISOR: u64 = 152;
const SAMPLER_DENSITY_POWER_OF_TWO: u32 = 256;

fn exact_action_correction_catalog(streams: &[EvaluatorInstructionStream]) -> Vec<(usize, usize)> {
    streams
        .iter()
        .map(|stream| {
            let mut register_levels = vec![Some(SELECTED_EVALUATOR_WORKING_LEVEL)];
            let mut correction_count = 0_usize;
            for instruction in stream.instructions() {
                let input_levels = instruction
                    .input_registers()
                    .iter()
                    .map(|register| {
                        register_levels[*register as usize]
                            .expect("compiled instruction reads a live register")
                    })
                    .collect::<Vec<_>>();
                let output_level = match instruction.opcode() {
                    EvaluatorOpcode::ModulusSwitchToLevel => {
                        let target_level = instruction.immediate0() as usize;
                        correction_count += input_levels[0] - target_level;
                        Some(target_level)
                    }
                    EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => {
                        assert_eq!(input_levels[0], input_levels[1]);
                        correction_count += 2;
                        Some(input_levels[0] - 1)
                    }
                    EvaluatorOpcode::CiphertextMultiplyAndRelinearize
                    | EvaluatorOpcode::GaloisRotate => {
                        correction_count += 1;
                        Some(input_levels[0])
                    }
                    EvaluatorOpcode::DropRegister => {
                        register_levels[instruction.input_registers()[0] as usize] = None;
                        None
                    }
                    EvaluatorOpcode::DeclareOutput => None,
                    _ => Some(input_levels[0]),
                };
                if let Some(output_level) = output_level {
                    assert_eq!(
                        instruction.output_register(),
                        Some(register_levels.len() as u32)
                    );
                    register_levels.push(Some(output_level));
                } else {
                    assert!(instruction.output_register().is_none());
                }
            }
            (usize::from(stream.top_count()), correction_count)
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct WholeActionTail {
    correction_count: usize,
    combined_row_count: u64,
    bernoulli_draw_count: u64,
    secret_squared_l2_bound: u64,
    dither_threshold: u64,
    sampler_cap_bits: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PositiveRational {
    numerator: BigUint,
    denominator: BigUint,
}

impl PositiveRational {
    fn new(numerator: BigUint, denominator: BigUint) -> Self {
        assert!(!denominator.is_zero());
        let common_divisor = greatest_common_divisor(numerator.clone(), denominator.clone());
        Self {
            numerator: numerator / &common_divisor,
            denominator: denominator / common_divisor,
        }
    }

    fn zero() -> Self {
        Self::new(BigUint::zero(), BigUint::one())
    }

    fn from_u64(value: u64) -> Self {
        Self::new(BigUint::from(value), BigUint::one())
    }

    fn add(&self, other: &Self) -> Self {
        Self::new(
            &self.numerator * &other.denominator + &other.numerator * &self.denominator,
            &self.denominator * &other.denominator,
        )
    }

    fn multiply(&self, other: &Self) -> Self {
        Self::new(
            &self.numerator * &other.numerator,
            &self.denominator * &other.denominator,
        )
    }

    fn multiply_u64(&self, multiplier: u64) -> Self {
        Self::new(
            &self.numerator * BigUint::from(multiplier),
            self.denominator.clone(),
        )
    }

    fn divide_u64(&self, divisor: u64) -> Self {
        Self::new(
            self.numerator.clone(),
            &self.denominator * BigUint::from(divisor),
        )
    }

    fn subtract(&self, other: &Self) -> Self {
        let left = &self.numerator * &other.denominator;
        let right = &other.numerator * &self.denominator;
        assert!(left >= right);
        Self::new(left - right, &self.denominator * &other.denominator)
    }

    fn greater_than_or_equal(&self, other: &Self) -> bool {
        &self.numerator * &other.denominator >= &other.numerator * &self.denominator
    }
}

fn greatest_common_divisor(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

// For 0 <= z < 1, this is the first m positive terms of 2*atanh(z)
// plus an exact geometric upper bound for the remaining positive tail.
fn natural_log_atanh_upper_bound(z: &PositiveRational, term_count: usize) -> PositiveRational {
    assert!(z.numerator < z.denominator);
    assert!(term_count > 0);
    let z_squared = z.multiply(z);
    let mut power = z.clone();
    let mut sum = PositiveRational::zero();
    for term_index in 0..term_count {
        let odd_denominator = u64::try_from(2 * term_index + 1).expect("term index fits u64");
        sum = sum.add(&power.divide_u64(odd_denominator));
        power = power.multiply(&z_squared);
    }
    let tail_odd_denominator = u64::try_from(2 * term_count + 1).expect("tail term index fits u64");
    let one_minus_z_squared = PositiveRational::from_u64(1).subtract(&z_squared);
    let tail = PositiveRational::new(
        &power.numerator * &one_minus_z_squared.denominator,
        &power.denominator * &one_minus_z_squared.numerator * BigUint::from(tail_odd_denominator),
    );
    sum.add(&tail).multiply_u64(2)
}

fn natural_log_integer_upper_bound(value: &BigUint) -> PositiveRational {
    assert!(!value.is_zero());
    let binary_exponent = value.bits() - 1;
    let lower_power_of_two = BigUint::one() << binary_exponent as usize;
    let normalized_offset =
        PositiveRational::new(value - &lower_power_of_two, value + &lower_power_of_two);
    let natural_log_two_upper_bound = natural_log_atanh_upper_bound(
        &PositiveRational::new(BigUint::one(), BigUint::from(3_u8)),
        4,
    );
    natural_log_two_upper_bound
        .multiply_u64(binary_exponent)
        .add(&natural_log_atanh_upper_bound(&normalized_offset, 4))
}

fn secret_squared_l2_bernstein_condition(
    candidate_bound: u64,
    coefficient_square_mean: &PositiveRational,
    coefficient_square_variance: &PositiveRational,
    centered_coefficient_square_upper_bound: &PositiveRational,
) -> bool {
    let mean = coefficient_square_mean.multiply_u64(POLYNOMIAL_DEGREE as u64);
    let candidate = PositiveRational::from_u64(candidate_bound);
    if !candidate.greater_than_or_equal(&mean) {
        return false;
    }
    let deviation = candidate.subtract(&mean);
    let variance = coefficient_square_variance.multiply_u64(POLYNOMIAL_DEGREE as u64);
    let logarithmic_tail_parameter = natural_log_atanh_upper_bound(
        &PositiveRational::new(BigUint::one(), BigUint::from(3_u8)),
        4,
    )
    .multiply_u64(88);
    let left = deviation.multiply(&deviation);
    let right = logarithmic_tail_parameter.multiply_u64(2).multiply(
        &variance.add(
            &centered_coefficient_square_upper_bound
                .multiply(&deviation)
                .divide_u64(3),
        ),
    );
    left.greater_than_or_equal(&right)
}

fn secret_squared_l2_bernstein_bound(
    coefficient_square_mean: PositiveRational,
    coefficient_square_variance: PositiveRational,
    centered_coefficient_square_upper_bound: PositiveRational,
) -> u64 {
    let mut upper_bound = 1_u64;
    while !secret_squared_l2_bernstein_condition(
        upper_bound,
        &coefficient_square_mean,
        &coefficient_square_variance,
        &centered_coefficient_square_upper_bound,
    ) {
        upper_bound = upper_bound
            .checked_mul(2)
            .expect("secret squared L2 search fits u64");
    }
    let mut lower_bound = 0_u64;
    while lower_bound + 1 < upper_bound {
        let midpoint = lower_bound + (upper_bound - lower_bound) / 2;
        if secret_squared_l2_bernstein_condition(
            midpoint,
            &coefficient_square_mean,
            &coefficient_square_variance,
            &centered_coefficient_square_upper_bound,
        ) {
            upper_bound = midpoint;
        } else {
            lower_bound = midpoint;
        }
    }
    upper_bound
}

fn honest_secret_squared_l2_bound() -> u64 {
    // For the sum of ten independent ternary coefficients:
    // E[S^2] = 20/3, Var(S^2) = 740/9, and S^2-E[S^2] <= 280/3.
    secret_squared_l2_bernstein_bound(
        PositiveRational::new(BigUint::from(20_u8), BigUint::from(3_u8)),
        PositiveRational::new(BigUint::from(740_u16), BigUint::from(9_u8)),
        PositiveRational::new(BigUint::from(280_u16), BigUint::from(3_u8)),
    )
}

fn bounded_malicious_shift_secret_squared_l2_bound() -> u64 {
    // Seven honest ternary coefficients plus three fixed shifts in [-1,1]
    // give one aggregate fixed shift in [-3,3]. Uniformly over that shift,
    // E[S^2] <= 41/3, Var(S^2) <= 1862/9, and the centered upper increment
    // is at most 286/3. The event failure probability is at most 2^-88.
    secret_squared_l2_bernstein_bound(
        PositiveRational::new(BigUint::from(41_u8), BigUint::from(3_u8)),
        PositiveRational::new(BigUint::from(1_862_u16), BigUint::from(9_u8)),
        PositiveRational::new(BigUint::from(286_u16), BigUint::from(3_u8)),
    )
}

fn action_tail_threshold_condition(
    candidate_threshold: u64,
    secret_squared_l2_bound: u64,
    logarithmic_tail_parameter: &PositiveRational,
) -> bool {
    let threshold = BigUint::from(candidate_threshold);
    BigUint::from(6_u8) * &logarithmic_tail_parameter.denominator * &threshold * &threshold
        >= &logarithmic_tail_parameter.numerator
            * (BigUint::from(3_u8) * BigUint::from(secret_squared_l2_bound + 1)
                + BigUint::from(40_u8) * threshold)
}

fn minimum_action_tail_threshold(
    secret_squared_l2_bound: u64,
    logarithmic_tail_parameter: &PositiveRational,
) -> u64 {
    let mut upper_bound = 1_u64;
    while !action_tail_threshold_condition(
        upper_bound,
        secret_squared_l2_bound,
        logarithmic_tail_parameter,
    ) {
        upper_bound = upper_bound
            .checked_mul(2)
            .expect("action-tail threshold search fits u64");
    }
    let mut lower_bound = 0_u64;
    while lower_bound + 1 < upper_bound {
        let midpoint = lower_bound + (upper_bound - lower_bound) / 2;
        if action_tail_threshold_condition(
            midpoint,
            secret_squared_l2_bound,
            logarithmic_tail_parameter,
        ) {
            upper_bound = midpoint;
        } else {
            lower_bound = midpoint;
        }
    }
    upper_bound
}

fn whole_action_tail(correction_count: usize, secret_squared_l2_bound: u64) -> WholeActionTail {
    let correction_count = correction_count as u64;
    let ring_degree = POLYNOMIAL_DEGREE as u64;
    let combined_row_count = correction_count * ring_degree;
    let bernoulli_draw_count = combined_row_count * 2;

    // DFMS21 Proposition 3.5 is applied once to the complete action relation.
    // At q = 2^80 - 1, 152(q+1)^2 * (2^-248 / 152) = 2^-88.
    let action_density_denominator = (BigUint::from(2_u8)
        * BigUint::from(combined_row_count)
        * BigUint::from(DITHER_DENSITY_DIVISOR))
        << DITHER_DENSITY_POWER_OF_TWO as usize;
    let logarithmic_tail_parameter = natural_log_integer_upper_bound(&action_density_denominator);
    let threshold =
        minimum_action_tail_threshold(secret_squared_l2_bound, &logarithmic_tail_parameter);
    let sampler_multiplier =
        BigUint::from(DITHER_DENSITY_DIVISOR) * BigUint::from(bernoulli_draw_count);
    let sampler_cap_bits = u64::from(SAMPLER_DENSITY_POWER_OF_TWO)
        + if sampler_multiplier <= BigUint::one() {
            0
        } else {
            (&sampler_multiplier - BigUint::one()).bits()
        };
    WholeActionTail {
        correction_count: correction_count as usize,
        combined_row_count,
        bernoulli_draw_count,
        secret_squared_l2_bound,
        dither_threshold: threshold,
        sampler_cap_bits,
    }
}

fn compiled_target_bounds(
    trace: &CandidateEvaluatorRecurrenceTrace,
    prepared_constants: &BTreeMap<Vec<u8>, ExactPlaintextPolynomialNorms>,
    data_primes_per_block: usize,
    special_primes: &[u64],
    stochastic_rounding_correction_bound: Option<u64>,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots_with_data_primes(
        SELECTED_PARTICIPANT_COUNT,
        SELECTED_BALLOT_COUNT,
        Arc::from(DATA_PRIMES.as_slice()),
        data_primes_per_block,
        Arc::new(
            special_primes
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product(),
        ),
    )?;
    let aggregate =
        if let Some(stochastic_rounding_correction_bound) = stochastic_rounding_correction_bound {
            aggregate.with_stochastic_rounding_correction_bound(BigUint::from(
                stochastic_rounding_correction_bound,
            ))
        } else {
            aggregate
        };
    trace
        .streams()
        .iter()
        .map(|stream| {
            let mut registers = vec![Some(aggregate.clone())];
            let mut target_identifier = None;
            let mut target_order = None;
            for instruction in stream.instructions() {
                let inputs = instruction
                    .input_registers()
                    .iter()
                    .map(|register| {
                        registers
                            .get(*register as usize)
                            .and_then(Option::as_ref)
                            .cloned()
                            .ok_or_else(|| {
                                invalid_recurrence(
                                    "compiled recurrence instruction reads a dropped register",
                                )
                            })
                    })
                    .collect::<CanonicalResult<Vec<_>>>()?;
                let output = match instruction.opcode() {
                    EvaluatorOpcode::ModulusSwitchToLevel => {
                        Some(inputs[0].modulus_switch_to(instruction.immediate0() as usize)?)
                    }
                    EvaluatorOpcode::NormalizeDecryptionMultiplier => {
                        if instruction.immediate0() != 1 {
                            return Err(invalid_recurrence(
                                "compiled recurrence normalizes to an unsupported multiplier",
                            ));
                        }
                        Some(inputs[0].normalize_scaling()?)
                    }
                    EvaluatorOpcode::CiphertextAdd => Some(inputs[0].add(&inputs[1])?),
                    EvaluatorOpcode::CiphertextSubtract => Some(inputs[0].subtract(&inputs[1])?),
                    EvaluatorOpcode::CiphertextNegate => Some(inputs[0].negate()),
                    EvaluatorOpcode::PlaintextAdd | EvaluatorOpcode::PlaintextMultiply => {
                        let constant_hash = instruction.constant_hash().ok_or_else(|| {
                            invalid_recurrence(
                                "compiled plaintext instruction omits its constant hash",
                            )
                        })?;
                        let plaintext_norms = prepared_constants
                            .get(constant_hash.as_bytes().as_slice())
                            .ok_or_else(|| {
                                invalid_recurrence(
                                    "compiled plaintext instruction references an unknown constant",
                                )
                            })?;
                        if instruction.opcode() == EvaluatorOpcode::PlaintextAdd {
                            Some(inputs[0].add_plaintext_with_bounds(
                                &plaintext_norms.infinity_bound,
                                &plaintext_norms.canonical_lift_offset_bound,
                            )?)
                        } else {
                            Some(inputs[0].plaintext_multiply_with_norm(&plaintext_norms.l1_norm)?)
                        }
                    }
                    EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => {
                        Some(inputs[0].multiply_and_switch(&inputs[1])?)
                    }
                    EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                        Some(inputs[0].multiply_without_terminal_switch(&inputs[1])?)
                    }
                    EvaluatorOpcode::GaloisRotate => Some(inputs[0].rotate_once()?),
                    EvaluatorOpcode::DropRegister => {
                        registers[instruction.input_registers()[0] as usize] = None;
                        None
                    }
                    EvaluatorOpcode::DeclareOutput => {
                        match instruction.immediate0() {
                            1 if target_identifier.is_none() => {
                                target_identifier = Some(inputs[0].clone())
                            }
                            2 if target_order.is_none() => target_order = Some(inputs[0].clone()),
                            _ => {
                                return Err(invalid_recurrence(
                                    "compiled recurrence declares an invalid output role",
                                ));
                            }
                        }
                        None
                    }
                };
                if let Some(output) = output {
                    if instruction.output_register() != Some(registers.len() as u32) {
                        return Err(invalid_recurrence(
                            "compiled recurrence output registers are not consecutive",
                        ));
                    }
                    registers.push(Some(output));
                } else if instruction.output_register().is_some() {
                    return Err(invalid_recurrence(
                        "compiled recurrence nonproducing instruction declares an output",
                    ));
                }
            }
            let target_identifier = target_identifier.ok_or_else(|| {
                invalid_recurrence("compiled recurrence omits the target identifier")
            })?;
            let target_order = target_order
                .ok_or_else(|| invalid_recurrence("compiled recurrence omits the target order"))?;
            if target_identifier.level != MINIMUM_TARGET_LEVEL
                || target_order.level != MINIMUM_TARGET_LEVEL
            {
                return Err(invalid_recurrence(
                    "compiled recurrence output reached the wrong data-basis prefix",
                ));
            }
            Ok(DirectBallotTargetNoiseBound {
                top_count: usize::from(stream.top_count()),
                target_identifier,
                target_order,
            })
        })
        .collect()
}

fn prepare_compiled_constants_once(
    trace: &CandidateEvaluatorRecurrenceTrace,
) -> CanonicalResult<BTreeMap<Vec<u8>, ExactPlaintextPolynomialNorms>> {
    trace
        .constants()
        .iter()
        .map(|constant| {
            let coefficients = encode_constant_coefficients(constant).map_err(|reason| {
                invalid_recurrence(format!(
                    "compiled recurrence constant encoding was refused: {reason:?}"
                ))
            })?;
            Ok((
                constant.constant_hash()?.as_bytes().to_vec(),
                ExactPlaintextPolynomialNorms::from_coefficients(&coefficients),
            ))
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
struct CandidateTopology {
    special_prime_count: usize,
    data_primes_per_block: usize,
}

#[derive(Clone, Copy, Debug)]
struct CandidateResourceCosts {
    relinearization_catalog_level: usize,
    galois_catalog_position_count: usize,
    relinearization_catalog_wire_byte_length: u64,
    galois_catalog_wire_byte_length: u64,
    participant_source_wire_byte_length: u64,
    final_store_wire_byte_length: u64,
    ceremony_wire_byte_length: u64,
    final_store_resident_byte_length: u64,
    maximum_single_key_component_resident_byte_length: u64,
    evaluator_aggregate_source_polynomial_count: u64,
}

fn compiled_key_catalog(
    trace: &CandidateEvaluatorRecurrenceTrace,
) -> CanonicalResult<(usize, Vec<(u64, usize)>)> {
    let mut relinearization_levels = BTreeSet::new();
    let mut galois_levels = BTreeMap::<u64, usize>::new();
    for stream in trace.streams() {
        let mut register_levels = vec![Some(SELECTED_EVALUATOR_WORKING_LEVEL)];
        for instruction in stream.instructions() {
            let input_levels = instruction
                .input_registers()
                .iter()
                .map(|register| {
                    register_levels
                        .get(*register as usize)
                        .copied()
                        .flatten()
                        .ok_or_else(|| {
                            invalid_recurrence(
                                "compiled key catalog reads a missing recurrence register",
                            )
                        })
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            let output_level = match instruction.opcode() {
                EvaluatorOpcode::ModulusSwitchToLevel => Some(instruction.immediate0() as usize),
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => {
                    relinearization_levels.insert(input_levels[0]);
                    Some(input_levels[0] - 1)
                }
                EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                    relinearization_levels.insert(input_levels[0]);
                    Some(input_levels[0])
                }
                EvaluatorOpcode::GaloisRotate => {
                    galois_levels
                        .entry(instruction.immediate0())
                        .and_modify(|level| *level = (*level).max(input_levels[0]))
                        .or_insert(input_levels[0]);
                    Some(input_levels[0])
                }
                EvaluatorOpcode::DropRegister => {
                    register_levels[instruction.input_registers()[0] as usize] = None;
                    None
                }
                EvaluatorOpcode::DeclareOutput => None,
                _ => Some(input_levels[0]),
            };
            if let Some(output_level) = output_level {
                register_levels.push(Some(output_level));
            }
        }
    }
    let relinearization_catalog_level = relinearization_levels
        .iter()
        .next_back()
        .copied()
        .ok_or_else(|| invalid_recurrence("compiled recurrence has no relinearization opcode"))?;
    Ok((
        relinearization_catalog_level,
        galois_levels.into_iter().collect(),
    ))
}

fn component_resource_costs(
    level: usize,
    topology: CandidateTopology,
) -> CanonicalResult<(u64, u64, u64)> {
    let data_prime_count = level + 1;
    let data_block_count = data_prime_count.div_ceil(topology.data_primes_per_block);
    let special_primes = &SPECIAL_PRIMES[..topology.special_prime_count];
    let bytes_per_coefficient = DATA_PRIMES[..data_prime_count]
        .iter()
        .chain(special_primes)
        .try_fold(0_u64, |total, modulus| {
            total
                .checked_add(
                    u64::try_from(canonical_residue_byte_length(*modulus)?).map_err(|_| {
                        invalid_recurrence("component residue byte length does not fit u64")
                    })?,
                )
                .ok_or_else(|| invalid_recurrence("component wire byte length overflowed"))
        })?;
    let coefficient_count = u64::try_from(data_block_count)
        .ok()
        .and_then(|block_count| block_count.checked_mul(POLYNOMIAL_DEGREE as u64))
        .ok_or_else(|| invalid_recurrence("component coefficient count overflowed"))?;
    let wire_byte_length = coefficient_count
        .checked_mul(bytes_per_coefficient)
        .ok_or_else(|| invalid_recurrence("component wire byte length overflowed"))?;
    let resident_byte_length = coefficient_count
        .checked_mul(
            u64::try_from(data_prime_count + topology.special_prime_count)
                .ok()
                .and_then(|limb_count| limb_count.checked_mul(8))
                .ok_or_else(|| invalid_recurrence("component resident width overflowed"))?,
        )
        .ok_or_else(|| invalid_recurrence("component resident byte length overflowed"))?;
    let source_polynomial_count = u64::try_from(data_block_count)
        .ok()
        .and_then(|block_count| {
            u64::try_from(data_prime_count + topology.special_prime_count)
                .ok()
                .and_then(|limb_count| block_count.checked_mul(limb_count))
        })
        .ok_or_else(|| invalid_recurrence("component source-polynomial count overflowed"))?;
    Ok((
        wire_byte_length,
        resident_byte_length,
        source_polynomial_count,
    ))
}

fn candidate_resource_costs(
    trace: &CandidateEvaluatorRecurrenceTrace,
    topology: CandidateTopology,
) -> CanonicalResult<CandidateResourceCosts> {
    let (relinearization_level, galois_positions) = compiled_key_catalog(trace)?;
    let (relinearization_wire, relinearization_resident, relinearization_columns) =
        component_resource_costs(relinearization_level, topology)?;
    let mut galois_wire = 0_u64;
    let mut galois_resident = 0_u64;
    let mut galois_columns = 0_u64;
    let mut maximum_galois_resident = 0_u64;
    for (_, level) in &galois_positions {
        let (wire, resident, columns) = component_resource_costs(*level, topology)?;
        galois_wire = galois_wire
            .checked_add(wire)
            .ok_or_else(|| invalid_recurrence("Galois catalog wire length overflowed"))?;
        galois_resident = galois_resident
            .checked_add(resident)
            .ok_or_else(|| invalid_recurrence("Galois catalog resident length overflowed"))?;
        galois_columns = galois_columns
            .checked_add(columns)
            .ok_or_else(|| invalid_recurrence("Galois catalog column count overflowed"))?;
        maximum_galois_resident = maximum_galois_resident.max(resident);
    }
    let participant_source_wire_byte_length = relinearization_wire
        .checked_mul(3)
        .and_then(|relinearization| relinearization.checked_add(galois_wire))
        .ok_or_else(|| invalid_recurrence("participant evaluator source length overflowed"))?;
    let final_store_wire_byte_length = relinearization_wire
        .checked_mul(2)
        .and_then(|relinearization| relinearization.checked_add(galois_wire))
        .ok_or_else(|| invalid_recurrence("final evaluator store length overflowed"))?;
    let ceremony_wire_byte_length = participant_source_wire_byte_length
        .checked_mul(SELECTED_PARTICIPANT_COUNT)
        .and_then(|sources| sources.checked_add(final_store_wire_byte_length))
        .ok_or_else(|| invalid_recurrence("ceremony evaluator material length overflowed"))?;
    let final_store_resident_byte_length = relinearization_resident
        .checked_mul(2)
        .and_then(|relinearization| relinearization.checked_add(galois_resident))
        .ok_or_else(|| invalid_recurrence("final evaluator resident length overflowed"))?;
    let participant_source_columns = relinearization_columns
        .checked_mul(3)
        .and_then(|relinearization| relinearization.checked_add(galois_columns))
        .ok_or_else(|| invalid_recurrence("participant source-column count overflowed"))?;
    let final_store_columns = relinearization_columns
        .checked_mul(2)
        .and_then(|relinearization| relinearization.checked_add(galois_columns))
        .ok_or_else(|| invalid_recurrence("final store-column count overflowed"))?;
    let evaluator_aggregate_source_polynomial_count = participant_source_columns
        .checked_mul(SELECTED_PARTICIPANT_COUNT)
        .and_then(|sources| sources.checked_add(final_store_columns))
        .ok_or_else(|| invalid_recurrence("evaluator proof source-column count overflowed"))?;
    Ok(CandidateResourceCosts {
        relinearization_catalog_level: relinearization_level,
        galois_catalog_position_count: galois_positions.len(),
        relinearization_catalog_wire_byte_length: relinearization_wire,
        galois_catalog_wire_byte_length: galois_wire,
        participant_source_wire_byte_length,
        final_store_wire_byte_length,
        ceremony_wire_byte_length,
        final_store_resident_byte_length,
        maximum_single_key_component_resident_byte_length: relinearization_resident
            .max(maximum_galois_resident),
        evaluator_aggregate_source_polynomial_count,
    })
}

#[derive(Debug)]
struct CandidateMeasurement {
    baby_step_count: usize,
    topology: CandidateTopology,
    tail: WholeActionTail,
    stochastic_target_bounds: Vec<DirectBallotTargetNoiseBound>,
    stochastic_maximum_error_bound: BigUint,
    stochastic_minimum_decryption_margin: BigInt,
    stochastic_factor_four_c2_margin: BigInt,
    stochastic_factor_four_conditions_hold: bool,
    deterministic_target_bounds: Vec<DirectBallotTargetNoiseBound>,
    deterministic_maximum_error_bound: BigUint,
    deterministic_minimum_decryption_margin: BigInt,
    deterministic_factor_four_c2_margin: BigInt,
    deterministic_factor_four_conditions_hold: bool,
    resource_costs: CandidateResourceCosts,
}

fn summarize_target_bounds(
    bounds: &[DirectBallotTargetNoiseBound],
) -> CanonicalResult<(BigUint, BigInt, BigInt, bool)> {
    let maximum_error_bound = bounds
        .iter()
        .map(DirectBallotTargetNoiseBound::maximum_error_coefficient_bound)
        .max()
        .cloned()
        .ok_or_else(|| invalid_recurrence("compiled target-bound catalog is empty"))?;
    let minimum_decryption_margin = bounds
        .iter()
        .flat_map(|bound| {
            [
                bound.target_identifier.minimum_decryption_margin.clone(),
                bound.target_order.minimum_decryption_margin.clone(),
                bound.target_identifier.final_decryption_margin(),
                bound.target_order.final_decryption_margin(),
            ]
        })
        .min()
        .ok_or_else(|| invalid_recurrence("compiled target-margin catalog is empty"))?;
    let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)?;
    let factor_four_conditions_hold = ensure_factor_four_parameter_conditions_with_data_primes(
        MINIMUM_TARGET_LEVEL,
        &maximum_error_bound,
        &flooding_bound,
        &DATA_PRIMES,
    )
    .is_ok();
    let target_modulus = DATA_PRIMES[..=MINIMUM_TARGET_LEVEL]
        .iter()
        .map(|prime| BigUint::from(*prime))
        .product::<BigUint>();
    let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
    let scaled_c2_left = &plaintext_modulus
        * ((&maximum_error_bound << 4_usize)
            + &plaintext_modulus * BigUint::from(5_u8)
            + &flooding_bound * BigUint::from(16_u64 * 44));
    let factor_four_c2_margin =
        BigInt::from(target_modulus << 1_usize) - BigInt::from(scaled_c2_left);
    Ok((
        maximum_error_bound,
        minimum_decryption_margin,
        factor_four_c2_margin,
        factor_four_conditions_hold,
    ))
}

fn measure_candidate(
    trace: &CandidateEvaluatorRecurrenceTrace,
    prepared_constants: &BTreeMap<Vec<u8>, ExactPlaintextPolynomialNorms>,
    topology: CandidateTopology,
    tail: WholeActionTail,
) -> CanonicalResult<CandidateMeasurement> {
    let special_primes = &SPECIAL_PRIMES[..topology.special_prime_count];
    validate_key_switch_special_basis_dominates_data_blocks(
        &DATA_PRIMES,
        special_primes,
        topology.data_primes_per_block,
    )?;
    let bounds = compiled_target_bounds(
        trace,
        prepared_constants,
        topology.data_primes_per_block,
        special_primes,
        Some(tail.dither_threshold),
    )?;
    let deterministic_bounds = compiled_target_bounds(
        trace,
        prepared_constants,
        topology.data_primes_per_block,
        special_primes,
        None,
    )?;
    if bounds.len() != deterministic_bounds.len()
        || bounds.iter().zip(&deterministic_bounds).any(
            |(stochastic_bound, deterministic_bound)| {
                stochastic_bound.top_count != deterministic_bound.top_count
                    || &stochastic_bound.target_identifier.error_coefficient_bound
                        > &deterministic_bound
                            .target_identifier
                            .error_coefficient_bound
                    || &stochastic_bound.target_order.error_coefficient_bound
                        > &deterministic_bound.target_order.error_coefficient_bound
                    || &stochastic_bound.target_identifier.minimum_decryption_margin
                        < &deterministic_bound
                            .target_identifier
                            .minimum_decryption_margin
                    || &stochastic_bound.target_order.minimum_decryption_margin
                        < &deterministic_bound.target_order.minimum_decryption_margin
            },
        )
    {
        return Err(invalid_recurrence(
            "stochastic rounding did not monotonically improve the same topology",
        ));
    }
    if bounds.len() != SELECTED_OPTION_COUNT
        || !bounds
            .iter()
            .enumerate()
            .all(|(index, bound)| bound.top_count == index + 1)
    {
        return Err(invalid_recurrence(
            "compiled recurrence omitted a selected top count",
        ));
    }
    let (
        stochastic_maximum_error_bound,
        stochastic_minimum_decryption_margin,
        stochastic_factor_four_c2_margin,
        stochastic_factor_four_conditions_hold,
    ) = summarize_target_bounds(&bounds)?;
    let (
        deterministic_maximum_error_bound,
        deterministic_minimum_decryption_margin,
        deterministic_factor_four_c2_margin,
        deterministic_factor_four_conditions_hold,
    ) = summarize_target_bounds(&deterministic_bounds)?;
    let resource_costs = candidate_resource_costs(trace, topology)?;
    Ok(CandidateMeasurement {
        baby_step_count: CURRENT_COMPARISON_BABY_STEP_COUNT,
        topology,
        tail,
        stochastic_target_bounds: bounds,
        stochastic_maximum_error_bound,
        stochastic_minimum_decryption_margin,
        stochastic_factor_four_c2_margin,
        stochastic_factor_four_conditions_hold,
        deterministic_target_bounds: deterministic_bounds,
        deterministic_maximum_error_bound,
        deterministic_minimum_decryption_margin,
        deterministic_factor_four_c2_margin,
        deterministic_factor_four_conditions_hold,
        resource_costs,
    })
}

#[test]
fn compiled_factor_four_candidate_reports_exact_action_wide_measurement() {
    let qrom_query_count = (BigUint::from(1_u8) << 80_usize) - BigUint::from(1_u8);
    let grinding_factor =
        BigUint::from(DITHER_DENSITY_DIVISOR) * (&qrom_query_count + BigUint::from(1_u8)).pow(2);
    assert_eq!(
        grinding_factor,
        BigUint::from(DITHER_DENSITY_DIVISOR) << 160_usize
    );
    let dither_relation_density_denominator =
        BigUint::from(DITHER_DENSITY_DIVISOR) << DITHER_DENSITY_POWER_OF_TWO as usize;
    let sampler_relation_density_denominator =
        BigUint::from(DITHER_DENSITY_DIVISOR) << SAMPLER_DENSITY_POWER_OF_TWO as usize;
    assert_eq!(
        &grinding_factor << 88_usize,
        dither_relation_density_denominator
    );
    assert_eq!(
        &grinding_factor << 96_usize,
        sampler_relation_density_denominator
    );
    assert_eq!(
        direct_comparison_baby_step_count(SELECTED_SCORE_DOMAIN_MAXIMUM)
            .expect("selected comparison split is defined"),
        CURRENT_COMPARISON_BABY_STEP_COUNT
    );

    let selected_program = selected_evaluator_program_set().expect("selected evaluator compiles");
    let selected_program_bytes = selected_program
        .encode()
        .expect("selected evaluator program encodes");
    let selected_program = EvaluatorProgramSet::decode(&selected_program_bytes)
        .expect("selected evaluator program decodes");
    let selected_action_catalog = exact_action_correction_catalog(selected_program.streams());
    assert_eq!(selected_action_catalog.len(), SELECTED_OPTION_COUNT);
    assert!(
        selected_action_catalog
            .iter()
            .enumerate()
            .all(|(index, (top_count, _))| *top_count == index + 1)
    );
    assert!(
        selected_action_catalog[..19]
            .iter()
            .all(|(_, correction_count)| *correction_count == 736)
    );
    assert_eq!(selected_action_catalog[19], (20, 598));

    let candidate_trace =
        compile_factor_four_candidate_recurrence_trace(MINIMUM_TARGET_LEVEL, &DATA_PRIMES)
            .expect("factor-four recurrence trace compiles for every top count");
    let candidate_trace_bytes = candidate_trace
        .encode()
        .expect("factor-four recurrence trace has canonical program bytes");
    let candidate_trace = CandidateEvaluatorRecurrenceTrace::decode(&candidate_trace_bytes)
        .expect("factor-four recurrence trace decodes from canonical program bytes");
    assert_eq!(candidate_trace.streams().len(), SELECTED_OPTION_COUNT);
    let prepared_candidate_constants = prepare_compiled_constants_once(&candidate_trace)
        .expect("factor-four recurrence constants prepare once");
    let (candidate_relinearization_level, candidate_galois_positions) =
        compiled_key_catalog(&candidate_trace).expect("candidate key catalog derives from opcodes");
    assert_eq!(candidate_relinearization_level, 25);
    assert_eq!(candidate_galois_positions.len(), 3);
    assert!(
        candidate_galois_positions
            .iter()
            .all(|(_, catalog_level)| *catalog_level == 15)
    );
    let candidate_action_catalog = exact_action_correction_catalog(candidate_trace.streams());
    assert!(candidate_action_catalog.iter().enumerate().all(
        |(index, (top_count, correction_count))| {
            *top_count == index + 1 && *correction_count > 0
        }
    ));
    let correction_count = candidate_action_catalog
        .iter()
        .map(|(_, correction_count)| *correction_count)
        .max()
        .expect("candidate action catalog is nonempty");

    let malicious_shift_secret_squared_l2_bound = bounded_malicious_shift_secret_squared_l2_bound();
    let honest_secret_squared_l2_bound = honest_secret_squared_l2_bound();
    assert_eq!(honest_secret_squared_l2_bound, 464_514);
    assert_eq!(malicious_shift_secret_squared_l2_bound, 938_314);
    let reference_honest_tail = whole_action_tail(1_387, honest_secret_squared_l2_bound);
    let reference_malicious_shift_tail =
        whole_action_tail(1_387, malicious_shift_secret_squared_l2_bound);
    let reference_action_density_denominator = (BigUint::from(2_u8)
        * BigUint::from(1_387_u16)
        * BigUint::from(POLYNOMIAL_DEGREE as u64)
        * BigUint::from(DITHER_DENSITY_DIVISOR))
        << DITHER_DENSITY_POWER_OF_TWO as usize;
    let reference_logarithmic_tail_parameter =
        natural_log_integer_upper_bound(&reference_action_density_denominator);
    assert!(!action_tail_threshold_condition(
        7_430,
        honest_secret_squared_l2_bound,
        &reference_logarithmic_tail_parameter,
    ));
    assert!(action_tail_threshold_condition(
        7_431,
        honest_secret_squared_l2_bound,
        &reference_logarithmic_tail_parameter,
    ));
    assert!(!action_tail_threshold_condition(
        10_263,
        malicious_shift_secret_squared_l2_bound,
        &reference_logarithmic_tail_parameter,
    ));
    assert!(action_tail_threshold_condition(
        10_264,
        malicious_shift_secret_squared_l2_bound,
        &reference_logarithmic_tail_parameter,
    ));
    assert_eq!(reference_honest_tail.dither_threshold, 7_431);
    assert_eq!(reference_malicious_shift_tail.dither_threshold, 10_264);
    assert_eq!(reference_malicious_shift_tail.sampler_cap_bits, 291);
    assert!(!secret_squared_l2_bernstein_condition(
        honest_secret_squared_l2_bound - 1,
        &PositiveRational::new(BigUint::from(20_u8), BigUint::from(3_u8)),
        &PositiveRational::new(BigUint::from(740_u16), BigUint::from(9_u8)),
        &PositiveRational::new(BigUint::from(280_u16), BigUint::from(3_u8)),
    ));
    assert!(!secret_squared_l2_bernstein_condition(
        malicious_shift_secret_squared_l2_bound - 1,
        &PositiveRational::new(BigUint::from(41_u8), BigUint::from(3_u8)),
        &PositiveRational::new(BigUint::from(1_862_u16), BigUint::from(9_u8)),
        &PositiveRational::new(BigUint::from(286_u16), BigUint::from(3_u8)),
    ));
    let honest_tail = whole_action_tail(correction_count, honest_secret_squared_l2_bound);
    let malicious_shift_tail =
        whole_action_tail(correction_count, malicious_shift_secret_squared_l2_bound);
    assert_eq!(honest_tail.correction_count, correction_count);
    assert_eq!(
        honest_tail.combined_row_count,
        POLYNOMIAL_DEGREE as u64 * correction_count as u64
    );
    assert_eq!(
        honest_tail.bernoulli_draw_count,
        2 * honest_tail.combined_row_count
    );
    assert!(
        (BigUint::from(DITHER_DENSITY_DIVISOR) * BigUint::from(honest_tail.bernoulli_draw_count)
            << SAMPLER_DENSITY_POWER_OF_TWO as usize)
            <= (BigUint::from(1_u8) << honest_tail.sampler_cap_bits as usize)
    );
    assert!(honest_tail.dither_threshold < malicious_shift_tail.dither_threshold);
    let candidate_topologies = [
        CandidateTopology {
            special_prime_count: 5,
            data_primes_per_block: 6,
        },
        CandidateTopology {
            special_prime_count: 5,
            data_primes_per_block: 7,
        },
        CandidateTopology {
            special_prime_count: 6,
            data_primes_per_block: 6,
        },
        CandidateTopology {
            special_prime_count: 6,
            data_primes_per_block: 7,
        },
        CandidateTopology {
            special_prime_count: 7,
            data_primes_per_block: 7,
        },
        CandidateTopology {
            special_prime_count: 8,
            data_primes_per_block: 9,
        },
        CandidateTopology {
            special_prime_count: 9,
            data_primes_per_block: 10,
        },
    ];
    let mut feasible_candidate_count = 0_usize;

    for topology in candidate_topologies {
        match measure_candidate(
            &candidate_trace,
            &prepared_candidate_constants,
            topology,
            malicious_shift_tail,
        ) {
            Ok(measurement) => {
                let deterministic_no_wrap = measurement
                    .deterministic_minimum_decryption_margin
                    .is_positive();
                let stochastic_no_wrap = measurement
                    .stochastic_minimum_decryption_margin
                    .is_positive();
                let stream_fits = measurement.resource_costs.ceremony_wire_byte_length
                    <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH;
                if deterministic_no_wrap
                    && measurement.deterministic_factor_four_conditions_hold
                    && stream_fits
                {
                    feasible_candidate_count += 1;
                }
                println!(
                    "compiledFactorFourCandidate babyStepCount={} specialPrimeCount={} dataPrimesPerBlock={} targetLevel={} correctionCount={} combinedRows={} bernoulliDraws={} honestSecretSquaredL2Bound={} honestDitherThreshold={} maliciousShiftSecretSquaredL2Bound={} maliciousShiftDitherThreshold={} samplerCapBits={} deterministicMaximumErrorBits={} deterministicMarginsPositive={} deterministicFactorFourC2MarginPositive={} deterministicFactorFour={} stochasticMaximumErrorBits={} stochasticMarginsPositive={} stochasticFactorFourC2MarginPositive={} stochasticFactorFour={} relinearizationCatalogLevel={} galoisCatalogPositions={} relinearizationCatalogWireBytes={} galoisCatalogWireBytes={} participantSourceWireBytes={} finalStoreWireBytes={} ceremonyWireBytes={} streamFits={} finalStoreResidentBytes={} maximumSingleKeyComponentResidentBytes={} evaluatorAggregateSourcePolynomials={}",
                    measurement.baby_step_count,
                    measurement.topology.special_prime_count,
                    measurement.topology.data_primes_per_block,
                    MINIMUM_TARGET_LEVEL,
                    measurement.tail.correction_count,
                    measurement.tail.combined_row_count,
                    measurement.tail.bernoulli_draw_count,
                    honest_tail.secret_squared_l2_bound,
                    honest_tail.dither_threshold,
                    measurement.tail.secret_squared_l2_bound,
                    measurement.tail.dither_threshold,
                    measurement.tail.sampler_cap_bits,
                    measurement.deterministic_maximum_error_bound.bits(),
                    deterministic_no_wrap,
                    measurement
                        .deterministic_factor_four_c2_margin
                        .is_positive(),
                    measurement.deterministic_factor_four_conditions_hold,
                    measurement.stochastic_maximum_error_bound.bits(),
                    stochastic_no_wrap,
                    measurement.stochastic_factor_four_c2_margin.is_positive(),
                    measurement.stochastic_factor_four_conditions_hold,
                    measurement.resource_costs.relinearization_catalog_level,
                    measurement.resource_costs.galois_catalog_position_count,
                    measurement
                        .resource_costs
                        .relinearization_catalog_wire_byte_length,
                    measurement.resource_costs.galois_catalog_wire_byte_length,
                    measurement
                        .resource_costs
                        .participant_source_wire_byte_length,
                    measurement.resource_costs.final_store_wire_byte_length,
                    measurement.resource_costs.ceremony_wire_byte_length,
                    stream_fits,
                    measurement.resource_costs.final_store_resident_byte_length,
                    measurement
                        .resource_costs
                        .maximum_single_key_component_resident_byte_length,
                    measurement
                        .resource_costs
                        .evaluator_aggregate_source_polynomial_count,
                );
                for bound in &measurement.deterministic_target_bounds {
                    println!(
                        "compiledFactorFourDeterministicTarget specialPrimeCount={} dataPrimesPerBlock={} topCount={} identifierErrorBits={} identifierMinimumMarginPositive={} identifierFinalMarginPositive={} orderErrorBits={} orderMinimumMarginPositive={} orderFinalMarginPositive={}",
                        measurement.topology.special_prime_count,
                        measurement.topology.data_primes_per_block,
                        bound.top_count,
                        bound.target_identifier.error_coefficient_bound.bits(),
                        bound
                            .target_identifier
                            .minimum_decryption_margin
                            .is_positive(),
                        bound
                            .target_identifier
                            .final_decryption_margin()
                            .is_positive(),
                        bound.target_order.error_coefficient_bound.bits(),
                        bound.target_order.minimum_decryption_margin.is_positive(),
                        bound.target_order.final_decryption_margin().is_positive(),
                    );
                }
                println!(
                    "compiledFactorFourStochasticResearchTargetCount={}",
                    measurement.stochastic_target_bounds.len()
                );
            }
            Err(error) => println!(
                "compiledFactorFourCandidate babyStepCount={} specialPrimeCount={} dataPrimesPerBlock={} targetLevel={} rejected={}",
                CURRENT_COMPARISON_BABY_STEP_COUNT,
                topology.special_prime_count,
                topology.data_primes_per_block,
                MINIMUM_TARGET_LEVEL,
                error,
            ),
        }
    }
    println!("compiledFactorFourCandidate survivorCount={feasible_candidate_count}");
}
