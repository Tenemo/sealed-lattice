use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::bgv::{
    evaluator::{
        program::{EvaluatorOpcode, selected_evaluator_program_set},
        top_k::SELECTED_EVALUATOR_WORKING_LEVEL,
    },
    parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
};

const STOCHASTIC_MODULUS_DOWN_EXPERIMENT_DOMAIN: &[u8] =
    b"sealed-lattice-bgv-evaluator/test-stochastic-modulus-down";
const MAXIMUM_BERNOULLI_COMPARISON_BITS: usize = 4_096;
const DIRECT_ORACLE_ANSWER_MAXIMUM_BITS_PER_DRAW: u64 = 320;

#[derive(Clone, Copy)]
struct StochasticRoundingDomain {
    operation_ordinal: u64,
    component_index: u64,
    coefficient_index: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct BernoulliComparisonLimit {
    compared_bit_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct BernoulliSample {
    is_selected: bool,
    compared_bit_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum DirectOracleAnswerSampleError {
    AnswerLengthExceeded {
        required_bit_count: u64,
        maximum_bit_count: u64,
    },
    ComparisonLimit(BernoulliComparisonLimit),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ComputationNode {
    opcode: u16,
    input_node_identifiers: Vec<u64>,
    immediate: u64,
    constant_hash: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
struct ActionStochasticCorrectionCounts {
    corrections_by_top_count: Vec<(u16, u64)>,
    separate_stream_correction_count: u64,
    hash_consed_correction_count: u64,
}

#[derive(Debug, PartialEq)]
struct DitherTheoremRow {
    secret_squared_l2_bound: u64,
    logarithmic_tail_parameter: f64,
    threshold: f64,
    integer_threshold: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct StochasticModulusDownOutcome {
    quotient: BigInt,
    deterministic_quotient: BigInt,
    centered_scaled_residue: BigInt,
    adjusted_scaled_residue: BigInt,
    is_bernoulli_selected: bool,
    compared_bit_count: usize,
}

struct DomainSeparatedBitReader {
    reader: <Shake256 as ExtendableOutput>::Reader,
    current_byte: u8,
    unread_bit_count: u8,
}

// The theorem-facing experiment consumes one fixed-length oracle answer through
// an XOF reader. Its resident state is the XOF state, one byte, and counters;
// the answer-length ceiling is never materialized as an in-memory byte string.
struct DirectOracleAnswerBitReader<Reader: XofReader> {
    reader: Reader,
    maximum_bit_count: u64,
    consumed_bit_count: u64,
    current_byte: u8,
    unread_bit_count: u8,
}

struct FixedBytesXofReader<'a> {
    bytes: &'a [u8],
    next_byte_index: usize,
}

impl XofReader for FixedBytesXofReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) {
        let end_byte_index = self
            .next_byte_index
            .checked_add(buffer.len())
            .expect("the test XOF byte index fits usize");
        buffer.copy_from_slice(
            self.bytes
                .get(self.next_byte_index..end_byte_index)
                .expect("the direct-answer test fixture has enough bytes"),
        );
        self.next_byte_index = end_byte_index;
    }
}

impl<Reader: XofReader> DirectOracleAnswerBitReader<Reader> {
    fn new(reader: Reader, maximum_bit_count: u64) -> Self {
        Self {
            reader,
            maximum_bit_count,
            consumed_bit_count: 0,
            current_byte: 0,
            unread_bit_count: 0,
        }
    }

    fn next_bit(&mut self) -> Result<u8, DirectOracleAnswerSampleError> {
        if self.consumed_bit_count >= self.maximum_bit_count {
            return Err(DirectOracleAnswerSampleError::AnswerLengthExceeded {
                required_bit_count: self
                    .consumed_bit_count
                    .checked_add(1)
                    .expect("the required direct-answer bit count fits u64"),
                maximum_bit_count: self.maximum_bit_count,
            });
        }
        if self.unread_bit_count == 0 {
            let mut next_byte = [0_u8; 1];
            self.reader.read(&mut next_byte);
            self.current_byte = next_byte[0];
            self.unread_bit_count = 8;
        }
        self.unread_bit_count -= 1;
        self.consumed_bit_count += 1;
        Ok((self.current_byte >> self.unread_bit_count) & 1)
    }

    fn consumed_bit_count(&self) -> u64 {
        self.consumed_bit_count
    }
}

impl DomainSeparatedBitReader {
    fn new(seed: &[u8; 64], domain: StochasticRoundingDomain) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(STOCHASTIC_MODULUS_DOWN_EXPERIMENT_DOMAIN);
        hasher.update(seed);
        hasher.update(&domain.operation_ordinal.to_le_bytes());
        hasher.update(&domain.component_index.to_le_bytes());
        hasher.update(&domain.coefficient_index.to_le_bytes());
        Self {
            reader: hasher.finalize_xof(),
            current_byte: 0,
            unread_bit_count: 0,
        }
    }

    fn next_bit(&mut self) -> u8 {
        if self.unread_bit_count == 0 {
            let mut next_byte = [0_u8; 1];
            self.reader.read(&mut next_byte);
            self.current_byte = next_byte[0];
            self.unread_bit_count = 8;
        }
        self.unread_bit_count -= 1;
        (self.current_byte >> self.unread_bit_count) & 1
    }

    fn read_bytes(&mut self, byte_count: usize) -> Vec<u8> {
        assert_eq!(
            self.unread_bit_count, 0,
            "byte reads require a fresh domain-separated stream"
        );
        let mut bytes = vec![0_u8; byte_count];
        self.reader.read(&mut bytes);
        bytes
    }
}

// This seeded mode probes only algebra, deterministic replay, and grinding. The
// theorem accounting below instead uses one streamed direct oracle answer
// because expanding an intermediate seed through a downstream hash is not the
// sampled relation.
fn sample_exact_bernoulli(
    numerator: &BigUint,
    denominator: &BigUint,
    seed: &[u8; 64],
    domain: StochasticRoundingDomain,
    maximum_bit_count: usize,
) -> Result<BernoulliSample, BernoulliComparisonLimit> {
    let mut bit_reader = DomainSeparatedBitReader::new(seed, domain);
    compare_exact_bernoulli_bits(numerator, denominator, maximum_bit_count, || {
        bit_reader.next_bit()
    })
}

// All draws consume the same explicit answer sequentially in canonical action
// order and most-significant-bit-first byte order. The per-draw cap is fixed,
// but a resolved draw consumes only the bits it compared.
fn sample_exact_bernoulli_from_direct_oracle_answer<Reader: XofReader>(
    numerator: &BigUint,
    denominator: &BigUint,
    answer_reader: &mut DirectOracleAnswerBitReader<Reader>,
    maximum_bit_count: usize,
) -> Result<BernoulliSample, DirectOracleAnswerSampleError> {
    assert!(maximum_bit_count > 0);
    assert!(!denominator.is_zero());
    assert!(numerator < denominator);
    if numerator.is_zero() {
        return Ok(BernoulliSample {
            is_selected: false,
            compared_bit_count: 0,
        });
    }
    let mut threshold_remainder = numerator.clone();
    for bit_index in 0..maximum_bit_count {
        threshold_remainder <<= 1_usize;
        let threshold_bit = if threshold_remainder >= *denominator {
            threshold_remainder -= denominator;
            1
        } else {
            0
        };
        let random_bit = answer_reader.next_bit()?;
        if random_bit != threshold_bit {
            return Ok(BernoulliSample {
                is_selected: random_bit < threshold_bit,
                compared_bit_count: bit_index + 1,
            });
        }
    }
    Err(DirectOracleAnswerSampleError::ComparisonLimit(
        BernoulliComparisonLimit {
            compared_bit_count: maximum_bit_count,
        },
    ))
}

// Compare a uniform binary fraction against numerator/denominator exactly by
// expanding both one bit at a time. No floating-point approximation or
// modulo-biased finite draw enters the decision.
fn compare_exact_bernoulli_bits(
    numerator: &BigUint,
    denominator: &BigUint,
    maximum_bit_count: usize,
    mut next_bit: impl FnMut() -> u8,
) -> Result<BernoulliSample, BernoulliComparisonLimit> {
    assert!(!denominator.is_zero());
    assert!(numerator < denominator);
    if numerator.is_zero() {
        return Ok(BernoulliSample {
            is_selected: false,
            compared_bit_count: 0,
        });
    }

    let mut threshold_remainder = numerator.clone();
    for bit_index in 0..maximum_bit_count {
        threshold_remainder <<= 1_usize;
        let threshold_bit = if threshold_remainder >= *denominator {
            threshold_remainder -= denominator;
            1
        } else {
            0
        };
        let random_bit = next_bit();
        if random_bit != threshold_bit {
            return Ok(BernoulliSample {
                is_selected: random_bit < threshold_bit,
                compared_bit_count: bit_index + 1,
            });
        }
    }

    Err(BernoulliComparisonLimit {
        compared_bit_count: maximum_bit_count,
    })
}

fn experimental_stochastic_modulus_down(
    input: &BigInt,
    modulus: &BigInt,
    seed: &[u8; 64],
    domain: StochasticRoundingDomain,
) -> Result<StochasticModulusDownOutcome, BernoulliComparisonLimit> {
    assert!(modulus > &BigInt::one());
    let plaintext_modulus = BigInt::from(PLAINTEXT_MODULUS);
    let inverse_plaintext_modulus = modular_inverse(&plaintext_modulus, modulus);
    let canonical_scaled_residue = canonical_residue(&(input * inverse_plaintext_modulus), modulus);
    let half_modulus = modulus >> 1_usize;
    let centered_scaled_residue = if canonical_scaled_residue > half_modulus {
        canonical_scaled_residue - modulus
    } else {
        canonical_scaled_residue
    };
    let probability_numerator = centered_scaled_residue.magnitude().clone();
    let probability_denominator = modulus.to_biguint().expect("the modulus is positive");
    let sample = sample_exact_bernoulli(
        &probability_numerator,
        &probability_denominator,
        seed,
        domain,
        MAXIMUM_BERNOULLI_COMPARISON_BITS,
    )?;
    let signed_adjustment = match (sample.is_selected, centered_scaled_residue.sign()) {
        (false, _) | (_, Sign::NoSign) => BigInt::zero(),
        (true, Sign::Plus) => -BigInt::one(),
        (true, Sign::Minus) => BigInt::one(),
    };
    let adjusted_scaled_residue = &centered_scaled_residue + modulus * signed_adjustment;
    let corrected = input - &plaintext_modulus * &adjusted_scaled_residue;
    let corrected_remainder = &corrected % modulus;
    assert!(
        corrected_remainder.is_zero(),
        "the stochastic modulus-down correction must be exactly divisible"
    );
    let quotient = corrected / modulus;

    let deterministic_corrected = input - &plaintext_modulus * &centered_scaled_residue;
    let deterministic_remainder = &deterministic_corrected % modulus;
    assert!(
        deterministic_remainder.is_zero(),
        "the centered modulus-down correction must be exactly divisible"
    );
    let deterministic_quotient = deterministic_corrected / modulus;

    Ok(StochasticModulusDownOutcome {
        quotient,
        deterministic_quotient,
        centered_scaled_residue,
        adjusted_scaled_residue,
        is_bernoulli_selected: sample.is_selected,
        compared_bit_count: sample.compared_bit_count,
    })
}

fn canonical_residue(value: &BigInt, modulus: &BigInt) -> BigInt {
    let mut residue = value % modulus;
    if residue.sign() == Sign::Minus {
        residue += modulus;
    }
    residue
}

fn modular_inverse(value: &BigInt, modulus: &BigInt) -> BigInt {
    let mut old_remainder = value.clone();
    let mut remainder = modulus.clone();
    let mut old_coefficient = BigInt::one();
    let mut coefficient = BigInt::zero();
    while !remainder.is_zero() {
        let quotient = &old_remainder / &remainder;
        (old_remainder, remainder) = (remainder.clone(), old_remainder - &quotient * &remainder);
        (old_coefficient, coefficient) = (
            coefficient.clone(),
            old_coefficient - quotient * coefficient,
        );
    }
    assert_eq!(old_remainder, BigInt::one());
    canonical_residue(&old_coefficient, modulus)
}

fn domain_stream_prefix(
    seed: &[u8; 64],
    domain: StochasticRoundingDomain,
    byte_count: usize,
) -> Vec<u8> {
    DomainSeparatedBitReader::new(seed, domain).read_bytes(byte_count)
}

fn input_with_scaled_residue(
    centered_scaled_residue: &BigInt,
    modulus: &BigInt,
    quotient_offset: i64,
) -> BigInt {
    BigInt::from(PLAINTEXT_MODULUS) * centered_scaled_residue
        + modulus * BigInt::from(quotient_offset)
}

fn intern_computation_node(
    nodes: &mut BTreeMap<ComputationNode, u64>,
    next_node_identifier: &mut u64,
    node: ComputationNode,
) -> u64 {
    if let Some(identifier) = nodes.get(&node) {
        return *identifier;
    }
    let identifier = *next_node_identifier;
    *next_node_identifier = (*next_node_identifier)
        .checked_add(1)
        .expect("the test computation-node identifier fits u64");
    nodes.insert(node, identifier);
    identifier
}

fn selected_action_stochastic_correction_counts() -> ActionStochasticCorrectionCounts {
    let program =
        selected_evaluator_program_set().expect("the selected evaluator program compiles");
    let mut interned_nodes = BTreeMap::new();
    let mut next_node_identifier = 1_u64;
    let mut unique_stochastic_nodes = BTreeSet::new();
    let mut corrections_by_top_count = Vec::with_capacity(program.streams().len());

    for stream in program.streams() {
        let mut register_node_identifiers = vec![0_u64];
        let mut register_levels = vec![SELECTED_EVALUATOR_WORKING_LEVEL];
        let mut stream_correction_count = 0_u64;

        for instruction in stream.instructions() {
            if matches!(
                instruction.opcode(),
                EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput
            ) {
                continue;
            }
            let input_node_identifiers = instruction
                .input_registers()
                .iter()
                .map(|register| {
                    register_node_identifiers
                        [usize::try_from(*register).expect("the register index fits usize")]
                })
                .collect::<Vec<_>>();
            let input_levels = instruction
                .input_registers()
                .iter()
                .map(|register| {
                    register_levels
                        [usize::try_from(*register).expect("the register index fits usize")]
                })
                .collect::<Vec<_>>();
            let constant_hash = instruction
                .constant_hash()
                .map(|hash| hash.as_bytes().to_vec());

            let (output_node_identifier, output_level) = match instruction.opcode() {
                EvaluatorOpcode::ModulusSwitchToLevel => {
                    let target_level = usize::try_from(instruction.immediate0())
                        .expect("the target level fits usize");
                    let mut current_level = input_levels[0];
                    let mut current_node_identifier = input_node_identifiers[0];
                    assert!(target_level < current_level);
                    while current_level > target_level {
                        current_level -= 1;
                        current_node_identifier = intern_computation_node(
                            &mut interned_nodes,
                            &mut next_node_identifier,
                            ComputationNode {
                                opcode: EvaluatorOpcode::ModulusSwitchToLevel as u16,
                                input_node_identifiers: vec![current_node_identifier],
                                immediate: u64::try_from(current_level)
                                    .expect("the data level fits u64"),
                                constant_hash: None,
                            },
                        );
                        unique_stochastic_nodes.insert(current_node_identifier);
                        stream_correction_count += 1;
                    }
                    (current_node_identifier, current_level)
                }
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => {
                    assert_eq!(input_levels[0], input_levels[1]);
                    let relinearized_node_identifier = intern_computation_node(
                        &mut interned_nodes,
                        &mut next_node_identifier,
                        ComputationNode {
                            opcode: EvaluatorOpcode::CiphertextMultiplyAndRelinearize as u16,
                            input_node_identifiers,
                            immediate: 0,
                            constant_hash: None,
                        },
                    );
                    unique_stochastic_nodes.insert(relinearized_node_identifier);
                    let output_level = input_levels[0]
                        .checked_sub(1)
                        .expect("multiply-and-drop runs above level zero");
                    let dropped_node_identifier = intern_computation_node(
                        &mut interned_nodes,
                        &mut next_node_identifier,
                        ComputationNode {
                            opcode: EvaluatorOpcode::ModulusSwitchToLevel as u16,
                            input_node_identifiers: vec![relinearized_node_identifier],
                            immediate: u64::try_from(output_level)
                                .expect("the data level fits u64"),
                            constant_hash: None,
                        },
                    );
                    unique_stochastic_nodes.insert(dropped_node_identifier);
                    stream_correction_count += 2;
                    (dropped_node_identifier, output_level)
                }
                EvaluatorOpcode::CiphertextMultiplyAndRelinearize
                | EvaluatorOpcode::GaloisRotate => {
                    if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyAndRelinearize {
                        assert_eq!(input_levels[0], input_levels[1]);
                    }
                    let node_identifier = intern_computation_node(
                        &mut interned_nodes,
                        &mut next_node_identifier,
                        ComputationNode {
                            opcode: instruction.opcode() as u16,
                            input_node_identifiers,
                            immediate: instruction.immediate0(),
                            constant_hash,
                        },
                    );
                    unique_stochastic_nodes.insert(node_identifier);
                    stream_correction_count += 1;
                    (node_identifier, input_levels[0])
                }
                _ => {
                    let node_identifier = intern_computation_node(
                        &mut interned_nodes,
                        &mut next_node_identifier,
                        ComputationNode {
                            opcode: instruction.opcode() as u16,
                            input_node_identifiers,
                            immediate: instruction.immediate0(),
                            constant_hash,
                        },
                    );
                    (node_identifier, input_levels[0])
                }
            };

            assert_eq!(
                instruction.output_register(),
                Some(
                    u32::try_from(register_node_identifiers.len())
                        .expect("the output register count fits u32")
                )
            );
            register_node_identifiers.push(output_node_identifier);
            register_levels.push(output_level);
        }
        corrections_by_top_count.push((stream.top_count(), stream_correction_count));
    }

    ActionStochasticCorrectionCounts {
        separate_stream_correction_count: corrections_by_top_count
            .iter()
            .map(|(_, count)| *count)
            .sum(),
        hash_consed_correction_count: u64::try_from(unique_stochastic_nodes.len())
            .expect("the unique stochastic-node count fits u64"),
        corrections_by_top_count,
    }
}

fn action_stochastic_row_count(correction_count: u64) -> u64 {
    correction_count
        .checked_mul(u64::try_from(POLYNOMIAL_DEGREE).expect("the polynomial degree fits u64"))
        .expect("the action stochastic-row count fits u64")
}

fn action_bernoulli_draw_count(correction_count: u64) -> u64 {
    action_stochastic_row_count(correction_count)
        .checked_mul(2)
        .expect("the action Bernoulli-draw count fits u64")
}

fn canonical_action_draw_ordinal(
    stochastic_correction_ordinal: u64,
    component_index: u64,
    coefficient_index: u64,
) -> u64 {
    assert!(component_index < 2);
    assert!(coefficient_index < POLYNOMIAL_DEGREE as u64);
    stochastic_correction_ordinal
        .checked_mul(2)
        .and_then(|ordinal| ordinal.checked_add(component_index))
        .and_then(|ordinal| ordinal.checked_mul(POLYNOMIAL_DEGREE as u64))
        .and_then(|ordinal| ordinal.checked_add(coefficient_index))
        .expect("the canonical action draw ordinal fits u64")
}

// This is the maximum length of one streamed XOF answer, not resident memory.
fn direct_oracle_answer_maximum_byte_count(correction_count: u64, bits_per_draw: u64) -> u64 {
    action_bernoulli_draw_count(correction_count)
        .checked_mul(bits_per_draw)
        .and_then(|bit_count| bit_count.checked_add(7))
        .map(|rounded_bit_count| rounded_bit_count / 8)
        .expect("the direct oracle-answer byte count fits u64")
}

fn dither_theorem_rows_for_union_count(union_count: u64) -> [DitherTheoremRow; 3] {
    const SECRET_SQUARED_L2_BOUNDS: [u64; 3] = [100 * POLYNOMIAL_DEGREE as u64, 464_514, 938_314];
    const BOUNDED_INCREMENT: f64 = 10.0;
    const DITHER_ACTION_NEGATIVE_LOG2_DELTA: f64 = 255.247_927_513_443_6;
    let logarithmic_tail_parameter = (2.0 * union_count as f64).ln()
        + DITHER_ACTION_NEGATIVE_LOG2_DELTA * core::f64::consts::LN_2;

    SECRET_SQUARED_L2_BOUNDS.map(|secret_squared_l2_bound| {
        let variance = (1.0 + secret_squared_l2_bound as f64) / 4.0;
        let linear_term = BOUNDED_INCREMENT * logarithmic_tail_parameter / 3.0;
        let threshold = linear_term
            + (2.0 * variance * logarithmic_tail_parameter + linear_term * linear_term).sqrt();
        DitherTheoremRow {
            secret_squared_l2_bound,
            logarithmic_tail_parameter,
            threshold,
            integer_threshold: threshold.ceil() as u64,
        }
    })
}

fn operative_dither_theorem_rows(correction_count: u64) -> [DitherTheoremRow; 3] {
    dither_theorem_rows_for_union_count(action_stochastic_row_count(correction_count))
}

// This deliberately larger union over coefficient draws is retained only as a
// conservative cross-check. The operative evaluator tail union is over rows.
fn conservative_draw_union_dither_theorem_rows(correction_count: u64) -> [DitherTheoremRow; 3] {
    dither_theorem_rows_for_union_count(action_bernoulli_draw_count(correction_count))
}

fn minimum_sampler_cap_bits(correction_count: u64) -> u64 {
    let negative_log2_sampler_delta = 263.247_927_513_443_6;
    (negative_log2_sampler_delta + (action_bernoulli_draw_count(correction_count) as f64).log2())
        .ceil() as u64
}

#[test]
fn stochastic_modulus_down_is_integral_and_plaintext_preserving_at_boundaries() {
    let modulus = BigInt::from(DATA_PRIMES[0]);
    let half_modulus = &modulus >> 1_usize;
    let centered_boundaries = [
        BigInt::zero(),
        BigInt::one(),
        -BigInt::one(),
        &half_modulus - BigInt::one(),
        half_modulus.clone(),
        -(&half_modulus - BigInt::one()),
        -half_modulus,
    ];
    let seed = [0x5a_u8; 64];
    for (coefficient_index, centered_scaled_residue) in centered_boundaries.iter().enumerate() {
        for quotient_offset in [-3_i64, 2_i64] {
            let input =
                input_with_scaled_residue(centered_scaled_residue, &modulus, quotient_offset);
            let outcome = experimental_stochastic_modulus_down(
                &input,
                &modulus,
                &seed,
                StochasticRoundingDomain {
                    operation_ordinal: 7,
                    component_index: u64::try_from(quotient_offset + 3)
                        .expect("the test component index is nonnegative"),
                    coefficient_index: u64::try_from(coefficient_index)
                        .expect("the coefficient index fits u64"),
                },
            )
            .expect("the exact Bernoulli comparison resolves");

            assert_eq!(outcome.centered_scaled_residue, *centered_scaled_residue);
            assert_eq!(
                (&input - BigInt::from(PLAINTEXT_MODULUS) * &outcome.adjusted_scaled_residue)
                    % &modulus,
                BigInt::zero()
            );
            assert_eq!(
                canonical_residue(
                    &(&outcome.quotient - &outcome.deterministic_quotient),
                    &BigInt::from(PLAINTEXT_MODULUS),
                ),
                BigInt::zero()
            );
            assert!(outcome.adjusted_scaled_residue.abs() <= modulus);
            if centered_scaled_residue.is_zero() {
                assert!(!outcome.is_bernoulli_selected);
                assert_eq!(outcome.compared_bit_count, 0);
            }
        }
    }
}

#[test]
fn stochastic_modulus_down_handles_data_and_special_moduli_for_signed_inputs() {
    let special_basis_modulus = SPECIAL_PRIMES
        .iter()
        .map(|modulus| BigInt::from(*modulus))
        .product::<BigInt>();
    let moduli = [BigInt::from(DATA_PRIMES[7]), special_basis_modulus];
    let seed = [0xc3_u8; 64];
    for (modulus_ordinal, modulus) in moduli.iter().enumerate() {
        let scaled_residue_magnitude = modulus / BigInt::from(3_u8);
        for (sign, quotient_offset) in [(1_i8, 4_i64), (-1_i8, -4_i64)] {
            let centered_scaled_residue = BigInt::from(sign) * &scaled_residue_magnitude;
            let input =
                input_with_scaled_residue(&centered_scaled_residue, modulus, quotient_offset);
            assert_eq!(input.sign(), BigInt::from(sign).sign());
            let outcome = experimental_stochastic_modulus_down(
                &input,
                modulus,
                &seed,
                StochasticRoundingDomain {
                    operation_ordinal: 19,
                    component_index: u64::try_from(modulus_ordinal)
                        .expect("the modulus ordinal fits u64"),
                    coefficient_index: if sign > 0 { 0 } else { 1 },
                },
            )
            .expect("the exact Bernoulli comparison resolves");

            assert_eq!(outcome.centered_scaled_residue, centered_scaled_residue);
            assert_eq!(
                (&input - BigInt::from(PLAINTEXT_MODULUS) * &outcome.adjusted_scaled_residue)
                    % modulus,
                BigInt::zero()
            );
            assert_eq!(
                canonical_residue(&outcome.quotient, &BigInt::from(PLAINTEXT_MODULUS),),
                canonical_residue(
                    &outcome.deterministic_quotient,
                    &BigInt::from(PLAINTEXT_MODULUS),
                )
            );
            assert!(outcome.adjusted_scaled_residue.abs() <= *modulus);
        }
    }
}

#[test]
fn seeded_domain_stream_and_modulus_down_replay_byte_exactly() {
    let seed =
        core::array::from_fn(|index| u8::try_from(index).expect("the 64-byte seed index fits u8"));
    let domain = StochasticRoundingDomain {
        operation_ordinal: 0x41,
        component_index: 2,
        coefficient_index: 65_535,
    };
    let first_prefix = domain_stream_prefix(&seed, domain, 32);
    let second_prefix = domain_stream_prefix(&seed, domain, 32);
    assert_eq!(first_prefix, second_prefix);
    assert_eq!(
        first_prefix,
        vec![
            0x8c, 0x92, 0x53, 0xf3, 0xfa, 0x37, 0x4d, 0xad, 0x29, 0x00, 0x1d, 0xf9, 0x97, 0x0e,
            0x60, 0xa7, 0xd7, 0x74, 0xeb, 0xb9, 0xb0, 0x8f, 0xe9, 0xd0, 0x72, 0x62, 0x19, 0x6a,
            0x98, 0xa8, 0x74, 0xc4,
        ]
    );

    let modulus = BigInt::from(DATA_PRIMES[4]);
    let centered_scaled_residue = &modulus / BigInt::from(5_u8);
    let input = input_with_scaled_residue(&centered_scaled_residue, &modulus, -2);
    let first = experimental_stochastic_modulus_down(&input, &modulus, &seed, domain)
        .expect("the first comparison resolves");
    let replay = experimental_stochastic_modulus_down(&input, &modulus, &seed, domain)
        .expect("the reset comparison resolves");
    assert_eq!(first, replay);
    assert_eq!(
        first.quotient.to_signed_bytes_le(),
        replay.quotient.to_signed_bytes_le()
    );
}

#[test]
fn operation_component_and_coefficient_domains_are_separated() {
    let seed = [0x91_u8; 64];
    let base_domain = StochasticRoundingDomain {
        operation_ordinal: 3,
        component_index: 4,
        coefficient_index: 5,
    };
    let base_prefix = domain_stream_prefix(&seed, base_domain, 32);
    let operation_prefix = domain_stream_prefix(
        &seed,
        StochasticRoundingDomain {
            operation_ordinal: 4,
            ..base_domain
        },
        32,
    );
    let component_prefix = domain_stream_prefix(
        &seed,
        StochasticRoundingDomain {
            component_index: 5,
            ..base_domain
        },
        32,
    );
    let coefficient_prefix = domain_stream_prefix(
        &seed,
        StochasticRoundingDomain {
            coefficient_index: 6,
            ..base_domain
        },
        32,
    );
    assert_ne!(base_prefix, operation_prefix);
    assert_ne!(base_prefix, component_prefix);
    assert_ne!(base_prefix, coefficient_prefix);
    assert_ne!(operation_prefix, component_prefix);
    assert_ne!(operation_prefix, coefficient_prefix);
    assert_ne!(component_prefix, coefficient_prefix);
}

#[test]
fn exact_bernoulli_comparison_reports_draw_count_and_exhaustion() {
    let seed = [0_u8; 64];
    let domain = StochasticRoundingDomain {
        operation_ordinal: 29,
        component_index: 0,
        coefficient_index: 7,
    };
    let exhausted = sample_exact_bernoulli(&BigUint::one(), &BigUint::from(4_u8), &seed, domain, 4);
    assert_eq!(
        exhausted,
        Err(BernoulliComparisonLimit {
            compared_bit_count: 4
        })
    );
    assert_eq!(
        sample_exact_bernoulli(&BigUint::one(), &BigUint::from(4_u8), &seed, domain, 5,),
        Ok(BernoulliSample {
            is_selected: false,
            compared_bit_count: 5,
        })
    );
}

#[test]
fn direct_fixed_length_answer_streams_draws_in_canonical_order() {
    let answer_bytes = [0b0010_0000_u8];
    let numerator = BigUint::one();
    let denominator = BigUint::from(4_u8);
    let mut answer_reader = DirectOracleAnswerBitReader::new(
        FixedBytesXofReader {
            bytes: &answer_bytes,
            next_byte_index: 0,
        },
        8,
    );
    assert_eq!(
        sample_exact_bernoulli_from_direct_oracle_answer(
            &numerator,
            &denominator,
            &mut answer_reader,
            4,
        ),
        Ok(BernoulliSample {
            is_selected: true,
            compared_bit_count: 2,
        })
    );
    assert_eq!(answer_reader.consumed_bit_count(), 2);
    assert_eq!(
        sample_exact_bernoulli_from_direct_oracle_answer(
            &numerator,
            &denominator,
            &mut answer_reader,
            4,
        ),
        Ok(BernoulliSample {
            is_selected: false,
            compared_bit_count: 1,
        })
    );
    assert_eq!(answer_reader.consumed_bit_count(), 3);

    let matching_answer_bytes = [0b0100_0000_u8];
    let mut comparison_limit_reader = DirectOracleAnswerBitReader::new(
        FixedBytesXofReader {
            bytes: &matching_answer_bytes,
            next_byte_index: 0,
        },
        8,
    );
    assert_eq!(
        sample_exact_bernoulli_from_direct_oracle_answer(
            &numerator,
            &denominator,
            &mut comparison_limit_reader,
            4,
        ),
        Err(DirectOracleAnswerSampleError::ComparisonLimit(
            BernoulliComparisonLimit {
                compared_bit_count: 4,
            }
        ))
    );
    assert_eq!(comparison_limit_reader.consumed_bit_count(), 4);

    let mut answer_limit_reader = DirectOracleAnswerBitReader::new(
        FixedBytesXofReader {
            bytes: &matching_answer_bytes,
            next_byte_index: 0,
        },
        8,
    );
    assert_eq!(
        sample_exact_bernoulli_from_direct_oracle_answer(
            &numerator,
            &denominator,
            &mut answer_limit_reader,
            9,
        ),
        Err(DirectOracleAnswerSampleError::AnswerLengthExceeded {
            required_bit_count: 9,
            maximum_bit_count: 8,
        })
    );
    assert_eq!(answer_limit_reader.consumed_bit_count(), 8);
}

#[test]
fn seeded_samples_have_the_expected_mean_and_variance_without_floating_point() {
    const SAMPLE_COUNT: u64 = 4_096;
    let modulus = BigUint::from(DATA_PRIMES[2]);
    let positive_scaled_residue = &modulus / BigUint::from(3_u8);
    let seed = [0x74_u8; 64];
    let mut selected_count = 0_u64;
    let mut adjusted_sum = BigInt::zero();
    let mut adjusted_square_sum = BigInt::zero();
    let mut total_compared_bits = 0_u64;
    let modulus_bigint = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let residue_bigint = BigInt::from_biguint(Sign::Plus, positive_scaled_residue.clone());

    for coefficient_index in 0..SAMPLE_COUNT {
        let sample = sample_exact_bernoulli(
            &positive_scaled_residue,
            &modulus,
            &seed,
            StochasticRoundingDomain {
                operation_ordinal: 23,
                component_index: 1,
                coefficient_index,
            },
            MAXIMUM_BERNOULLI_COMPARISON_BITS,
        )
        .expect("the exact Bernoulli comparison resolves");
        selected_count += u64::from(sample.is_selected);
        total_compared_bits +=
            u64::try_from(sample.compared_bit_count).expect("the compared bit count fits u64");
        let adjusted = if sample.is_selected {
            &residue_bigint - &modulus_bigint
        } else {
            residue_bigint.clone()
        };
        adjusted_sum += &adjusted;
        adjusted_square_sum += &adjusted * &adjusted;
    }

    let sample_count_bigint = BigInt::from(SAMPLE_COUNT);
    let mean_numerator_bound = &modulus_bigint * BigInt::from(128_u16);
    assert!(adjusted_sum.abs() <= mean_numerator_bound);

    let empirical_variance_numerator =
        &sample_count_bigint * adjusted_square_sum - &adjusted_sum * &adjusted_sum;
    let theoretical_variance_numerator = &sample_count_bigint
        * &sample_count_bigint
        * &residue_bigint
        * (&modulus_bigint - &residue_bigint);
    let variance_tolerance =
        &sample_count_bigint * &sample_count_bigint * &modulus_bigint * &modulus_bigint
            / BigInt::from(50_u8);
    assert!(
        (empirical_variance_numerator - theoretical_variance_numerator).abs() <= variance_tolerance
    );
    assert_eq!(selected_count, 1_349);
    assert_eq!(total_compared_bits, 7_997);
}

#[test]
fn choosing_the_seed_can_select_a_favorable_rounding_branch() {
    let modulus = BigInt::from(DATA_PRIMES[3]);
    let centered_scaled_residue = &modulus / BigInt::from(4_u8);
    let input = input_with_scaled_residue(&centered_scaled_residue, &modulus, 0);
    let domain = StochasticRoundingDomain {
        operation_ordinal: 29,
        component_index: 0,
        coefficient_index: 7,
    };
    let mut first_selected = None;
    let mut first_unselected = None;
    for seed_variation in 0_u64..64 {
        let mut seed = [0_u8; 64];
        seed[..8].copy_from_slice(&seed_variation.to_le_bytes());
        let outcome = experimental_stochastic_modulus_down(&input, &modulus, &seed, domain)
            .expect("the exact Bernoulli comparison resolves");
        if outcome.is_bernoulli_selected {
            first_selected.get_or_insert((seed_variation, outcome));
        } else {
            first_unselected.get_or_insert((seed_variation, outcome));
        }
        if first_selected.is_some() && first_unselected.is_some() {
            break;
        }
    }

    let (selected_seed, selected) = first_selected.expect("a selected branch is found");
    let (unselected_seed, unselected) = first_unselected.expect("an unselected branch is found");
    assert_eq!(selected_seed, 4);
    assert_eq!(unselected_seed, 0);
    assert!(unselected.adjusted_scaled_residue.abs() < selected.adjusted_scaled_residue.abs());
}

#[test]
fn selected_action_counts_every_stochastic_correction_and_theorem_input() {
    let counts = selected_action_stochastic_correction_counts();
    let mut expected_corrections_by_top_count = (1_u16..=19)
        .map(|top_count| (top_count, 736_u64))
        .collect::<Vec<_>>();
    expected_corrections_by_top_count.push((20, 598));
    assert_eq!(
        counts,
        ActionStochasticCorrectionCounts {
            corrections_by_top_count: expected_corrections_by_top_count,
            separate_stream_correction_count: 14_582,
            hash_consed_correction_count: 1_388,
        }
    );

    assert_eq!(canonical_action_draw_ordinal(0, 0, 0), 0);
    assert_eq!(
        canonical_action_draw_ordinal(0, 1, 0),
        POLYNOMIAL_DEGREE as u64
    );
    assert_eq!(
        canonical_action_draw_ordinal(1, 0, 0),
        2 * POLYNOMIAL_DEGREE as u64
    );

    assert_eq!(action_stochastic_row_count(14_582), 955_645_952);
    assert_eq!(action_bernoulli_draw_count(14_582), 1_911_291_904);
    assert_eq!(minimum_sampler_cap_bits(14_582), 295);
    assert_eq!(
        direct_oracle_answer_maximum_byte_count(14_582, DIRECT_ORACLE_ANSWER_MAXIMUM_BITS_PER_DRAW),
        76_451_676_160
    );
    assert_eq!(
        operative_dither_theorem_rows(14_582).map(|row| row.integer_threshold),
        [26_161, 7_480, 10_329]
    );
    assert_eq!(
        conservative_draw_union_dither_theorem_rows(14_582).map(|row| row.integer_threshold),
        [26_208, 7_494, 10_349]
    );

    assert_eq!(action_stochastic_row_count(1_388), 90_963_968);
    assert_eq!(action_bernoulli_draw_count(1_388), 181_927_936);
    assert_eq!(minimum_sampler_cap_bits(1_388), 291);
    assert_eq!(
        direct_oracle_answer_maximum_byte_count(1_388, DIRECT_ORACLE_ANSWER_MAXIMUM_BITS_PER_DRAW),
        7_277_117_440
    );
    assert_eq!(
        operative_dither_theorem_rows(1_388).map(|row| row.integer_threshold),
        [26_001, 7_431, 10_264]
    );
    assert_eq!(
        conservative_draw_union_dither_theorem_rows(1_388).map(|row| row.integer_threshold),
        [26_048, 7_446, 10_283]
    );
}
