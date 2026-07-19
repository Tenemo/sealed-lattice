//! Exact symbolic error recurrence for the selected direct-pair-character evaluator.
//!
//! The recurrence follows the production instruction stream and its fixed
//! Q/P key topology. It is evidence only: no transported bound or verdict can
//! influence evaluator or target-release acceptance.

use std::collections::BTreeMap;

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};

use crate::{
    bgv::{
        evaluator::{
            program::{EvaluatorInstruction, EvaluatorOpcode, selected_evaluator_program_set},
            top_k::{
                CANONICAL_TARGET_CIPHERTEXT_LEVEL, CHARACTER_OUTPUT_LEVEL,
                SELECTED_EVALUATOR_MODULUS_SCHEDULE, SELECTED_EVALUATOR_WORKING_LEVEL,
            },
        },
        key_switch_topology::{
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK, key_switch_special_basis_modulus_product,
        },
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{FOUNDATION_PROFILE, Hash512},
};

const CENTERED_PLAINTEXT_BOUND: u64 = PLAINTEXT_MODULUS / 2;
const FRESH_ERROR_COEFFICIENT_BOUND: u64 = 2;
const FRESH_RANDOMIZER_COEFFICIENT_BOUND: u64 = 1;
const CANONICAL_PLAINTEXT_LIFT_OFFSET_BOUND: u64 = 1;
const PAIR_CHARACTER_MESSAGE_WIDTH: usize = 19;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymbolicCiphertextBound {
    pub(crate) level: usize,
    pub(crate) decrypt_scaling: u64,
    pub(crate) message_coefficient_bound: BigUint,
    pub(crate) error_coefficient_bound: BigUint,
    pub(crate) component_count: usize,
    pub(crate) collective_secret_coefficient_bound: u64,
    pub(crate) minimum_decryption_margin: BigInt,
}

impl SymbolicCiphertextBound {
    fn from_state(state: SymbolicState, collective_secret_coefficient_bound: u64) -> Self {
        Self {
            level: state.level,
            decrypt_scaling: 1,
            message_coefficient_bound: state.message_bound,
            error_coefficient_bound: state.error_bound,
            component_count: 2,
            collective_secret_coefficient_bound,
            minimum_decryption_margin: state.minimum_margin,
        }
    }

    pub(crate) fn final_decryption_margin(&self) -> BigInt {
        decryption_margin(
            self.level,
            &self.message_coefficient_bound,
            &self.error_coefficient_bound,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectBallotTargetNoiseBound {
    pub(crate) top_count: usize,
    pub(crate) target_identifier: SymbolicCiphertextBound,
    pub(crate) target_order: SymbolicCiphertextBound,
}

impl DirectBallotTargetNoiseBound {
    pub(crate) fn maximum_error_coefficient_bound(&self) -> &BigUint {
        if self.target_identifier.error_coefficient_bound
            >= self.target_order.error_coefficient_bound
        {
            &self.target_identifier.error_coefficient_bound
        } else {
            &self.target_order.error_coefficient_bound
        }
    }

    pub(crate) fn every_decryption_margin_is_positive(&self) -> bool {
        self.target_identifier
            .minimum_decryption_margin
            .is_positive()
            && self.target_order.minimum_decryption_margin.is_positive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolicState {
    level: usize,
    message_bound: BigUint,
    error_bound: BigUint,
    minimum_margin: BigInt,
}

impl SymbolicState {
    fn new(level: usize, message_bound: BigUint, error_bound: BigUint) -> Self {
        let minimum_margin = decryption_margin(level, &message_bound, &error_bound);
        Self {
            level,
            message_bound,
            error_bound,
            minimum_margin,
        }
    }

    fn derived(
        &self,
        level: usize,
        message_bound: BigUint,
        error_bound: BigUint,
        other_minimum_margin: Option<&BigInt>,
    ) -> Self {
        let current_margin = decryption_margin(level, &message_bound, &error_bound);
        let minimum_margin = other_minimum_margin.map_or_else(
            || self.minimum_margin.clone(),
            |other| self.minimum_margin.clone().min(other.clone()),
        );
        Self {
            level,
            message_bound,
            error_bound,
            minimum_margin: minimum_margin.min(current_margin),
        }
    }

    fn add(&self, other: &Self) -> CanonicalResult<Self> {
        require_same_level(self, other, "addition")?;
        let unreduced_message_bound = &self.message_bound + &other.message_bound;
        let error_bound = &self.error_bound
            + &other.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound);
        Ok(self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            Some(&other.minimum_margin),
        ))
    }

    fn plaintext_add(&self, coefficients: &[u32]) -> Self {
        let (infinity_norm, _, lift_offset) = plaintext_norms(coefficients);
        let unreduced_message_bound = &self.message_bound + &infinity_norm;
        let error_bound = &self.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound)
            + lift_offset;
        self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            None,
        )
    }

    fn plaintext_multiply(&self, coefficients: &[u32]) -> Self {
        let (_, l1_norm, _) = plaintext_norms(coefficients);
        let unreduced_message_bound = &self.message_bound * &l1_norm;
        let error_bound = (&self.error_bound * l1_norm)
            + centered_reduction_carry_bound(&unreduced_message_bound);
        self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            None,
        )
    }

    fn rotate(&self, participant_count: u64) -> CanonicalResult<Self> {
        let error_bound = &self.error_bound
            + hybrid_key_switch_error_bound(self.level, participant_count, false)?;
        Ok(self.derived(self.level, self.message_bound.clone(), error_bound, None))
    }

    fn fixed_subring_multiply(
        &self,
        other: &Self,
        participant_count: u64,
    ) -> CanonicalResult<Self> {
        require_same_level(self, other, "fixed-subring multiplication")?;
        let centered_bound = BigUint::from(CENTERED_PLAINTEXT_BOUND);
        let unreduced_message_bound = &centered_bound * &self.message_bound * &other.message_bound;
        let error_bound = &centered_bound * &self.message_bound * &other.error_bound
            + &centered_bound * &other.message_bound * &self.error_bound
            + BigUint::from(PLAINTEXT_MODULUS)
                * BigUint::from(POLYNOMIAL_DEGREE)
                * &self.error_bound
                * &other.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound)
            + hybrid_key_switch_error_bound(self.level, participant_count, true)?;
        Ok(self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            Some(&other.minimum_margin),
        ))
    }

    fn character_multiply(
        &self,
        other: &Self,
        left_width: usize,
        right_width: usize,
        participant_count: u64,
    ) -> CanonicalResult<Self> {
        require_same_level(self, other, "pair-character multiplication")?;
        let centered_bound = BigUint::from(CENTERED_PLAINTEXT_BOUND);
        let left_structure_norm = &centered_bound * BigUint::from(left_width);
        let right_structure_norm = &centered_bound * BigUint::from(right_width);
        let product_structure_norm = &centered_bound * BigUint::from(left_width.min(right_width));
        let unreduced_message_bound =
            &product_structure_norm * &self.message_bound * &other.message_bound;
        let error_bound = left_structure_norm * &self.message_bound * &other.error_bound
            + right_structure_norm * &other.message_bound * &self.error_bound
            + BigUint::from(PLAINTEXT_MODULUS)
                * BigUint::from(POLYNOMIAL_DEGREE)
                * &self.error_bound
                * &other.error_bound
            + centered_reduction_carry_bound(&unreduced_message_bound)
            + hybrid_key_switch_error_bound(self.level, participant_count, true)?;
        Ok(self.derived(
            self.level,
            canonical_message_bound(unreduced_message_bound),
            error_bound,
            Some(&other.minimum_margin),
        ))
    }

    fn modulus_switch_to(
        &self,
        target_level: usize,
        participant_count: u64,
    ) -> CanonicalResult<Self> {
        if target_level > self.level {
            return Err(invalid_recurrence(
                "symbolic modulus switch cannot raise the ciphertext level",
            ));
        }
        let mut state = self.clone();
        while state.level > target_level {
            state = state.modulus_switch_once(participant_count)?;
        }
        Ok(state)
    }

    fn modulus_switch_once(&self, participant_count: u64) -> CanonicalResult<Self> {
        if self.level == 0 {
            return Err(invalid_recurrence(
                "symbolic modulus switch cannot drop level zero",
            ));
        }
        let dropped_modulus = DATA_PRIMES[self.level];
        if dropped_modulus % PLAINTEXT_MODULUS != 1 {
            return Err(invalid_recurrence(
                "selected data modulus is not one modulo the plaintext modulus",
            ));
        }
        let correction_bound = BigUint::from(dropped_modulus / 2)
            * (BigUint::one()
                + BigUint::from(POLYNOMIAL_DEGREE) * BigUint::from(participant_count));
        let scaling_transition_bound =
            BigUint::from((dropped_modulus - 1) / PLAINTEXT_MODULUS) * &self.message_bound;
        let numerator = &self.error_bound + correction_bound + scaling_transition_bound;
        let error_bound = divide_with_ceiling(&numerator, &BigUint::from(dropped_modulus));
        Ok(self.derived(
            self.level - 1,
            self.message_bound.clone(),
            error_bound,
            None,
        ))
    }
}

/// Runs the exact production recurrence for all twenty selected target counts.
/// Other roster sizes and score domains are intentionally unsupported by the
/// current cryptographic prototype.
pub(crate) fn direct_ballot_target_noise_bounds(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    if participant_count != u64::from(FOUNDATION_PROFILE.participant_count)
        || ballot_count != usize::from(FOUNDATION_PROFILE.participant_count)
        || option_count != usize::from(FOUNDATION_PROFILE.option_count)
        || minimum_score != u64::from(FOUNDATION_PROFILE.minimum_score)
        || maximum_score != u64::from(FOUNDATION_PROFILE.maximum_score)
        || PLAINTEXT_MODULUS != 257
        || POLYNOMIAL_DEGREE != 32_768
        || DATA_PRIMES.len() != SELECTED_EVALUATOR_WORKING_LEVEL + 1
        || CANONICAL_TARGET_CIPHERTEXT_LEVEL != 7
    {
        return Err(invalid_recurrence(
            "noise recurrence is defined only for the exact selected direct-ballot suite",
        ));
    }

    let aggregate_character_bound = selected_pair_character_product_bound(participant_count)?;
    if aggregate_character_bound.level != CHARACTER_OUTPUT_LEVEL {
        return Err(invalid_recurrence(
            "pair-character product reached the wrong selected level",
        ));
    }
    let program = selected_evaluator_program_set()?;
    let constants_by_hash = program
        .constants()
        .iter()
        .map(|constant| Ok((*constant.constant_hash()?.as_bytes(), constant.values())))
        .collect::<CanonicalResult<BTreeMap<_, _>>>()?;

    program
        .streams()
        .iter()
        .map(|stream| {
            let (target_identifier, target_order) = evaluate_selected_stream(
                stream.instructions(),
                &constants_by_hash,
                &aggregate_character_bound,
                participant_count,
            )?;
            Ok(DirectBallotTargetNoiseBound {
                top_count: usize::from(stream.top_count()),
                target_identifier: SymbolicCiphertextBound::from_state(
                    target_identifier,
                    participant_count,
                ),
                target_order: SymbolicCiphertextBound::from_state(target_order, participant_count),
            })
        })
        .collect()
}

fn selected_pair_character_product_bound(participant_count: u64) -> CanonicalResult<SymbolicState> {
    let fresh_error = BigUint::from(2_u8)
        * BigUint::from(POLYNOMIAL_DEGREE)
        * BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND)
        * BigUint::from(FRESH_RANDOMIZER_COEFFICIENT_BOUND)
        * BigUint::from(participant_count)
        + BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND)
        + BigUint::from(CANONICAL_PLAINTEXT_LIFT_OFFSET_BOUND);
    let fresh = SymbolicState::new(
        SELECTED_EVALUATOR_WORKING_LEVEL,
        BigUint::from(CENTERED_PLAINTEXT_BOUND),
        fresh_error,
    );
    let drops = SELECTED_EVALUATOR_MODULUS_SCHEDULE.character_depth_drop_counts;

    let first_round = fresh
        .character_multiply(
            &fresh,
            PAIR_CHARACTER_MESSAGE_WIDTH,
            PAIR_CHARACTER_MESSAGE_WIDTH,
            participant_count,
        )?
        .modulus_switch_to(
            SELECTED_EVALUATOR_WORKING_LEVEL - drops[0],
            participant_count,
        )?;
    let second_round = first_round
        .character_multiply(&first_round, 37, 37, participant_count)?
        .modulus_switch_to(first_round.level - drops[1], participant_count)?;
    let third_round = second_round
        .character_multiply(&second_round, 73, 73, participant_count)?
        .modulus_switch_to(second_round.level - drops[2], participant_count)?;
    let carried_first_round =
        first_round.modulus_switch_to(third_round.level, participant_count)?;
    third_round
        .character_multiply(&carried_first_round, 145, 37, participant_count)?
        .modulus_switch_to(third_round.level - drops[3], participant_count)
}

fn evaluate_selected_stream(
    instructions: &[EvaluatorInstruction],
    constants_by_hash: &BTreeMap<[u8; Hash512::BYTE_LENGTH], &[u32]>,
    aggregate_character_bound: &SymbolicState,
    participant_count: u64,
) -> CanonicalResult<(SymbolicState, SymbolicState)> {
    let mut registers = vec![
        Some(aggregate_character_bound.clone()),
        Some(aggregate_character_bound.clone()),
    ];
    let mut target_identifier = None;
    let mut target_order = None;
    for instruction in instructions {
        let inputs = instruction
            .input_registers()
            .iter()
            .map(|register| read_symbolic_register(&registers, *register))
            .collect::<CanonicalResult<Vec<_>>>()?;
        let output = match instruction.opcode() {
            EvaluatorOpcode::ModulusSwitchToLevel => Some(inputs[0].modulus_switch_to(
                usize::try_from(instruction.immediate0()).map_err(|_| {
                    invalid_recurrence("symbolic target level does not fit the host index")
                })?,
                participant_count,
            )?),
            EvaluatorOpcode::NormalizeDecryptionMultiplier => Some(inputs[0].clone()),
            EvaluatorOpcode::CiphertextAdd | EvaluatorOpcode::CiphertextSubtract => {
                Some(inputs[0].add(inputs[1])?)
            }
            EvaluatorOpcode::CiphertextNegate => Some(inputs[0].clone()),
            EvaluatorOpcode::PlaintextAdd => {
                Some(inputs[0].plaintext_add(instruction_constant(instruction, constants_by_hash)?))
            }
            EvaluatorOpcode::PlaintextMultiply => Some(
                inputs[0].plaintext_multiply(instruction_constant(instruction, constants_by_hash)?),
            ),
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => Some(
                inputs[0]
                    .fixed_subring_multiply(inputs[1], participant_count)?
                    .modulus_switch_to(inputs[0].level - 1, participant_count)?,
            ),
            EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                Some(inputs[0].fixed_subring_multiply(inputs[1], participant_count)?)
            }
            EvaluatorOpcode::GaloisRotate => Some(inputs[0].rotate(participant_count)?),
            EvaluatorOpcode::DropRegister => {
                let register = usize::try_from(instruction.input_registers()[0]).map_err(|_| {
                    invalid_recurrence("symbolic drop register does not fit the host index")
                })?;
                registers
                    .get_mut(register)
                    .ok_or_else(|| invalid_recurrence("symbolic drop register is undefined"))?
                    .take()
                    .ok_or_else(|| invalid_recurrence("symbolic register was already dropped"))?;
                None
            }
            EvaluatorOpcode::DeclareOutput => {
                let target = inputs[0].clone();
                match instruction.immediate0() {
                    1 => target_identifier = Some(target),
                    2 => target_order = Some(target),
                    _ => {
                        return Err(invalid_recurrence(
                            "symbolic evaluator output role is unassigned",
                        ));
                    }
                }
                None
            }
        };
        if let Some(output) = output {
            let output_register = usize::try_from(
                instruction
                    .output_register()
                    .ok_or_else(|| invalid_recurrence("symbolic output register is absent"))?,
            )
            .map_err(|_| invalid_recurrence("symbolic output register does not fit usize"))?;
            if output_register != registers.len() {
                return Err(invalid_recurrence(
                    "symbolic evaluator registers are not consecutive",
                ));
            }
            registers.push(Some(output));
        }
    }
    let target_identifier = target_identifier
        .ok_or_else(|| invalid_recurrence("symbolic target identifier was not declared"))?;
    let target_order =
        target_order.ok_or_else(|| invalid_recurrence("symbolic target order was not declared"))?;
    if target_identifier.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
        || target_order.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
    {
        return Err(invalid_recurrence(
            "symbolic evaluator targets reached the wrong selected level",
        ));
    }
    Ok((target_identifier, target_order))
}

fn instruction_constant<'a>(
    instruction: &EvaluatorInstruction,
    constants_by_hash: &'a BTreeMap<[u8; Hash512::BYTE_LENGTH], &[u32]>,
) -> CanonicalResult<&'a [u32]> {
    let hash = instruction
        .constant_hash()
        .ok_or_else(|| invalid_recurrence("symbolic plaintext instruction has no constant"))?;
    constants_by_hash
        .get(hash.as_bytes())
        .copied()
        .ok_or_else(|| invalid_recurrence("symbolic plaintext constant is not in the program"))
}

fn read_symbolic_register(
    registers: &[Option<SymbolicState>],
    register: u32,
) -> CanonicalResult<&SymbolicState> {
    registers
        .get(
            usize::try_from(register)
                .map_err(|_| invalid_recurrence("symbolic register does not fit usize"))?,
        )
        .and_then(Option::as_ref)
        .ok_or_else(|| invalid_recurrence("symbolic evaluator used an unavailable register"))
}

fn hybrid_key_switch_error_bound(
    level: usize,
    participant_count: u64,
    relinearization: bool,
) -> CanonicalResult<BigUint> {
    if level >= DATA_PRIMES.len() {
        return Err(invalid_recurrence(
            "symbolic key-switch level is outside the selected data basis",
        ));
    }
    let active_block_count = (level + 1).div_ceil(KEY_SWITCH_DATA_PRIMES_PER_BLOCK);
    let maximum_block_modulus = DATA_PRIMES[..=level]
        .chunks(KEY_SWITCH_DATA_PRIMES_PER_BLOCK)
        .map(|block| {
            block
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>()
        })
        .max()
        .ok_or_else(|| invalid_recurrence("symbolic key-switch basis is empty"))?;
    let twice_participant_count = BigUint::from(2_u8) * BigUint::from(participant_count);
    let evaluation_key_error = if relinearization {
        BigUint::from(2_u8)
            * BigUint::from(POLYNOMIAL_DEGREE)
            * BigUint::from(participant_count)
            * &twice_participant_count
            + &twice_participant_count
    } else {
        twice_participant_count
    };
    let decomposed_numerator = BigUint::from(active_block_count)
        * BigUint::from(POLYNOMIAL_DEGREE)
        * maximum_block_modulus
        * evaluation_key_error;
    let decomposed_error = divide_with_ceiling(
        &decomposed_numerator,
        &(BigUint::from(2_u8) * key_switch_special_basis_modulus_product()),
    );
    Ok(decomposed_error
        + BigUint::one()
        + divide_with_ceiling(
            &(BigUint::from(POLYNOMIAL_DEGREE) * BigUint::from(participant_count)),
            &BigUint::from(2_u8),
        ))
}

fn plaintext_norms(coefficients: &[u32]) -> (BigUint, BigUint, BigUint) {
    let mut infinity_norm = BigUint::zero();
    let mut l1_norm = BigUint::zero();
    let mut lift_offset = BigUint::zero();
    for coefficient in coefficients {
        let residue = u64::from(*coefficient);
        let centered_absolute = residue.min(PLAINTEXT_MODULUS - residue);
        infinity_norm = infinity_norm.max(BigUint::from(centered_absolute));
        l1_norm += BigUint::from(centered_absolute);
        if residue > CENTERED_PLAINTEXT_BOUND {
            lift_offset = BigUint::one();
        }
    }
    (infinity_norm, l1_norm, lift_offset)
}

fn require_same_level(
    left: &SymbolicState,
    right: &SymbolicState,
    operation: &str,
) -> CanonicalResult<()> {
    if left.level != right.level {
        return Err(invalid_recurrence(format!(
            "symbolic {operation} requires equal ciphertext levels",
        )));
    }
    Ok(())
}

fn decryption_margin(level: usize, message_bound: &BigUint, error_bound: &BigUint) -> BigInt {
    let active_modulus = DATA_PRIMES[..=level]
        .iter()
        .map(|prime| BigUint::from(*prime))
        .product::<BigUint>();
    let raw_decryption_bound = message_bound + BigUint::from(PLAINTEXT_MODULUS) * error_bound;
    BigInt::from(active_modulus) - BigInt::from(BigUint::from(2_u8) * raw_decryption_bound)
}

fn centered_reduction_carry_bound(unreduced_bound: &BigUint) -> BigUint {
    (unreduced_bound + BigUint::from(CENTERED_PLAINTEXT_BOUND)) / BigUint::from(PLAINTEXT_MODULUS)
}

fn canonical_message_bound(unreduced_bound: BigUint) -> BigUint {
    unreduced_bound.min(BigUint::from(CENTERED_PLAINTEXT_BOUND))
}

fn divide_with_ceiling(numerator: &BigUint, denominator: &BigUint) -> BigUint {
    let quotient = numerator / denominator;
    if numerator % denominator == BigUint::zero() {
        quotient
    } else {
        quotient + BigUint::one()
    }
}

fn invalid_recurrence(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_recurrence_pins_the_exact_worst_target_error() {
        let bounds =
            direct_ballot_target_noise_bounds(10, 10, 20, 1, 10).expect("selected recurrence");
        assert_eq!(bounds.len(), 20);
        let worst = bounds
            .iter()
            .max_by_key(|bound| bound.maximum_error_coefficient_bound())
            .expect("selected target bounds");
        assert_eq!(worst.top_count, 8);
        assert_eq!(
            worst.maximum_error_coefficient_bound().to_str_radix(10),
            "16870171037775988578755335442628",
        );
        assert!(
            bounds
                .iter()
                .all(DirectBallotTargetNoiseBound::every_decryption_margin_is_positive)
        );
    }

    #[test]
    fn selected_recurrence_rejects_nonselected_dimensions() {
        assert!(direct_ballot_target_noise_bounds(9, 9, 20, 1, 10).is_err());
        assert!(direct_ballot_target_noise_bounds(10, 10, 19, 1, 10).is_err());
        assert!(direct_ballot_target_noise_bounds(10, 10, 20, 0, 10).is_err());
    }
}
