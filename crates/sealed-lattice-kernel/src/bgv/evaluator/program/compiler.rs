use std::collections::{BTreeMap, BTreeSet};

use crate::{
    bgv::{
        modular_arithmetic::mul_mod,
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalErrorCode, CanonicalResult},
    foundation::{FOUNDATION_PROFILE, Hash512},
};

use super::{
    EvaluatorConstant, EvaluatorConstantKind, EvaluatorInstruction, EvaluatorInstructionStream,
    EvaluatorOpcode, EvaluatorProgramSet, RegisterState, SELECTED_OPTION_COUNT, program_error,
};
use crate::bgv::evaluator::top_k::{
    CANONICAL_TARGET_CIPHERTEXT_LEVEL, DIRECT_COMPARISON_OUTPUT_LEVEL, RANK_LOOKUP_BABY_STEP_COUNT,
    SELECTED_EVALUATOR_WORKING_LEVEL, comparison_polynomials, direct_comparison_baby_step_count,
    galois_power, generator_exponent_or_conjugated, generator_inverse_power_basis_for_exponent,
    generator_power_basis_for_exponent, interpolate_coefficients,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Register(u32);

#[derive(Default)]
struct ConstantCatalog {
    constants_by_hash: BTreeMap<[u8; Hash512::BYTE_LENGTH], EvaluatorConstant>,
}

impl ConstantCatalog {
    fn insert(
        &mut self,
        kind: EvaluatorConstantKind,
        values: Vec<u32>,
    ) -> CanonicalResult<Hash512> {
        let constant = EvaluatorConstant::new(kind, values)?;
        let hash = constant.constant_hash()?;
        match self.constants_by_hash.get(hash.as_bytes()) {
            Some(existing) if existing != &constant => {
                return Err(program_error(
                    "evaluator constant hash collision joined different constants",
                ));
            }
            Some(_) => {}
            None => {
                self.constants_by_hash.insert(*hash.as_bytes(), constant);
            }
        }
        Ok(hash)
    }

    fn into_sorted_constants(self) -> Vec<EvaluatorConstant> {
        self.constants_by_hash.into_values().collect()
    }
}

struct ProgramBuilder<'catalog> {
    constants: &'catalog mut ConstantCatalog,
    instructions: Vec<EvaluatorInstruction>,
    register_states: Vec<RegisterState>,
}

impl<'catalog> ProgramBuilder<'catalog> {
    fn new(constants: &'catalog mut ConstantCatalog) -> Self {
        Self {
            constants,
            instructions: Vec::new(),
            register_states: vec![RegisterState {
                level: SELECTED_EVALUATOR_WORKING_LEVEL,
                decryption_multiplier: 1,
            }],
        }
    }

    fn input(&self) -> Register {
        Register(0)
    }

    fn state(&self, register: Register) -> RegisterState {
        self.register_states[register.0 as usize]
    }

    fn emit_register(
        &mut self,
        opcode: EvaluatorOpcode,
        inputs: &[Register],
        immediate0: u64,
        constant_hash: Option<Hash512>,
        state: RegisterState,
    ) -> CanonicalResult<Register> {
        let output_register = u32::try_from(self.register_states.len()).map_err(|_| {
            program_error("compiled evaluator register count does not fit canonical u32")
        })?;
        self.instructions.push(EvaluatorInstruction::new(
            opcode,
            Some(output_register),
            inputs.iter().map(|register| register.0).collect(),
            immediate0,
            0,
            constant_hash,
        )?);
        self.register_states.push(state);
        Ok(Register(output_register))
    }

    fn modulus_switch_to(
        &mut self,
        register: Register,
        target_level: usize,
    ) -> CanonicalResult<Register> {
        let input = self.state(register);
        if input.level <= target_level {
            return Ok(register);
        }
        let mut multiplier = input.decryption_multiplier;
        for dropped_level in ((target_level + 1)..=input.level).rev() {
            multiplier = mul_mod(
                multiplier,
                DATA_PRIMES[dropped_level] % PLAINTEXT_MODULUS,
                PLAINTEXT_MODULUS,
            )?;
        }
        self.emit_register(
            EvaluatorOpcode::ModulusSwitchToLevel,
            &[register],
            u64::try_from(target_level)
                .map_err(|_| program_error("compiled evaluator level does not fit u64"))?,
            None,
            RegisterState {
                level: target_level,
                decryption_multiplier: multiplier,
            },
        )
    }

    fn normalize(&mut self, register: Register) -> CanonicalResult<Register> {
        let input = self.state(register);
        if input.decryption_multiplier == 1 {
            return Ok(register);
        }
        self.emit_register(
            EvaluatorOpcode::NormalizeDecryptionMultiplier,
            &[register],
            1,
            None,
            RegisterState {
                level: input.level,
                decryption_multiplier: 1,
            },
        )
    }

    fn add(&mut self, left: Register, right: Register) -> CanonicalResult<Register> {
        let left_state = self.state(left);
        if left_state != self.state(right) {
            return Err(program_error(
                "compiled evaluator addition operands are not aligned",
            ));
        }
        self.emit_register(
            EvaluatorOpcode::CiphertextAdd,
            &[left, right],
            0,
            None,
            left_state,
        )
    }

    fn subtract(&mut self, left: Register, right: Register) -> CanonicalResult<Register> {
        let left_state = self.state(left);
        if left_state != self.state(right) {
            return Err(program_error(
                "compiled evaluator subtraction operands are not aligned",
            ));
        }
        self.emit_register(
            EvaluatorOpcode::CiphertextSubtract,
            &[left, right],
            0,
            None,
            left_state,
        )
    }

    fn negate(&mut self, register: Register) -> CanonicalResult<Register> {
        self.emit_register(
            EvaluatorOpcode::CiphertextNegate,
            &[register],
            0,
            None,
            self.state(register),
        )
    }

    fn plaintext_add_slots(
        &mut self,
        register: Register,
        slots: Vec<u32>,
    ) -> CanonicalResult<Register> {
        let constant_hash = self
            .constants
            .insert(EvaluatorConstantKind::SlotVector, slots)?;
        self.emit_register(
            EvaluatorOpcode::PlaintextAdd,
            &[register],
            0,
            Some(constant_hash),
            self.state(register),
        )
    }

    fn plaintext_multiply_slots(
        &mut self,
        register: Register,
        slots: Vec<u32>,
    ) -> CanonicalResult<Register> {
        let constant_hash = self
            .constants
            .insert(EvaluatorConstantKind::SlotVector, slots)?;
        self.emit_register(
            EvaluatorOpcode::PlaintextMultiply,
            &[register],
            0,
            Some(constant_hash),
            self.state(register),
        )
    }

    fn plaintext_multiply_scalar(
        &mut self,
        register: Register,
        scalar: u64,
    ) -> CanonicalResult<Register> {
        let constant_hash = self.constants.insert(
            EvaluatorConstantKind::CoefficientVector,
            vec![field_value(scalar)?],
        )?;
        self.emit_register(
            EvaluatorOpcode::PlaintextMultiply,
            &[register],
            0,
            Some(constant_hash),
            self.state(register),
        )
    }

    fn multiply(&mut self, left: Register, right: Register) -> CanonicalResult<Register> {
        let target_level = self.state(left).level.min(self.state(right).level);
        let left = self.modulus_switch_to(left, target_level)?;
        let right = self.modulus_switch_to(right, target_level)?;
        let left_state = self.state(left);
        let right_state = self.state(right);
        if target_level == 0 {
            return Err(program_error(
                "compiled evaluator multiply-and-drop exhausted the data basis",
            ));
        }
        let product_multiplier = mul_mod(
            left_state.decryption_multiplier,
            right_state.decryption_multiplier,
            PLAINTEXT_MODULUS,
        )?;
        let output_multiplier = mul_mod(
            product_multiplier,
            DATA_PRIMES[target_level] % PLAINTEXT_MODULUS,
            PLAINTEXT_MODULUS,
        )?;
        self.emit_register(
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop,
            &[left, right],
            0,
            None,
            RegisterState {
                level: target_level - 1,
                decryption_multiplier: output_multiplier,
            },
        )
    }

    fn multiply_without_drop(
        &mut self,
        left: Register,
        right: Register,
    ) -> CanonicalResult<Register> {
        let target_level = self.state(left).level.min(self.state(right).level);
        let left = self.modulus_switch_to(left, target_level)?;
        let right = self.modulus_switch_to(right, target_level)?;
        let output_multiplier = mul_mod(
            self.state(left).decryption_multiplier,
            self.state(right).decryption_multiplier,
            PLAINTEXT_MODULUS,
        )?;
        self.emit_register(
            EvaluatorOpcode::CiphertextMultiplyAndRelinearize,
            &[left, right],
            0,
            None,
            RegisterState {
                level: target_level,
                decryption_multiplier: output_multiplier,
            },
        )
    }

    fn rotate(&mut self, register: Register, galois_element: usize) -> CanonicalResult<Register> {
        self.emit_register(
            EvaluatorOpcode::GaloisRotate,
            &[register],
            u64::try_from(galois_element)
                .map_err(|_| program_error("compiled Galois element does not fit u64"))?,
            None,
            self.state(register),
        )
    }

    fn sum_aligned(&mut self, registers: &[Register]) -> CanonicalResult<Register> {
        let target_level = registers
            .iter()
            .map(|register| self.state(*register).level)
            .min()
            .ok_or_else(|| program_error("compiled evaluator cannot sum an empty register set"))?;
        let first = self.modulus_switch_to(registers[0], target_level)?;
        let mut accumulator = self.normalize(first)?;
        for register in &registers[1..] {
            let aligned = self.modulus_switch_to(*register, target_level)?;
            let aligned = self.normalize(aligned)?;
            accumulator = self.add(accumulator, aligned)?;
        }
        Ok(accumulator)
    }

    fn add_to_aligned_sum(
        &mut self,
        accumulator: &mut Option<Register>,
        term: Register,
    ) -> CanonicalResult<()> {
        *accumulator = Some(match accumulator.take() {
            Some(current) => self.sum_aligned(&[current, term])?,
            None => term,
        });
        Ok(())
    }

    fn finish(
        mut self,
        top_count: u16,
        target_identifier: Register,
        target_order: Register,
    ) -> CanonicalResult<EvaluatorInstructionStream> {
        self.instructions.push(EvaluatorInstruction::new(
            EvaluatorOpcode::DeclareOutput,
            None,
            vec![target_identifier.0],
            1,
            0,
            None,
        )?);
        self.instructions.push(EvaluatorInstruction::new(
            EvaluatorOpcode::DeclareOutput,
            None,
            vec![target_order.0],
            2,
            0,
            None,
        )?);

        let output_registers = BTreeSet::from([target_identifier.0, target_order.0]);
        let mut last_use = BTreeMap::new();
        for (instruction_index, instruction) in self.instructions.iter().enumerate() {
            for register in &instruction.input_registers {
                last_use.insert(*register, instruction_index);
            }
        }
        for register_index in 0..self.register_states.len() {
            let register = u32::try_from(register_index)
                .map_err(|_| program_error("compiled register index does not fit u32"))?;
            if !output_registers.contains(&register) && !last_use.contains_key(&register) {
                return Err(program_error(
                    "compiled evaluator created a register that has no operative use",
                ));
            }
        }

        let mut instructions_with_drops = Vec::with_capacity(
            self.instructions
                .len()
                .saturating_add(self.register_states.len()),
        );
        for (instruction_index, instruction) in self.instructions.into_iter().enumerate() {
            let last_used_registers = instruction
                .input_registers
                .iter()
                .copied()
                .filter(|register| last_use.get(register) == Some(&instruction_index))
                .filter(|register| !output_registers.contains(register))
                .collect::<BTreeSet<_>>();
            instructions_with_drops.push(instruction);
            for register in last_used_registers {
                instructions_with_drops.push(EvaluatorInstruction::new(
                    EvaluatorOpcode::DropRegister,
                    None,
                    vec![register],
                    0,
                    0,
                    None,
                )?);
            }
        }
        EvaluatorInstructionStream::new(top_count, instructions_with_drops)
    }
}

pub(crate) fn selected_evaluator_program_set() -> CanonicalResult<EvaluatorProgramSet> {
    if usize::from(FOUNDATION_PROFILE.option_count) != SELECTED_OPTION_COUNT {
        return Err(program_error(
            "selected evaluator option count disagrees with the foundation profile",
        ));
    }
    let score_span = u64::from(
        FOUNDATION_PROFILE
            .maximum_score
            .checked_sub(FOUNDATION_PROFILE.minimum_score)
            .ok_or_else(|| program_error("selected score range is inverted"))?,
    );
    let score_domain_max = score_span
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(|| program_error("selected comparison domain overflowed u64"))?;

    let mut constants = ConstantCatalog::default();
    let mut streams = Vec::with_capacity(SELECTED_OPTION_COUNT);
    for top_count in 1..=SELECTED_OPTION_COUNT {
        streams.push(compile_stream(
            &mut constants,
            u16::try_from(top_count).expect("selected top count fits u16"),
            score_domain_max,
        )?);
    }
    EvaluatorProgramSet::new(constants.into_sorted_constants(), streams)
}

pub(crate) fn selected_evaluator_program_set_bytes() -> CanonicalResult<Vec<u8>> {
    selected_evaluator_program_set()?.encode()
}

fn compile_stream(
    constants: &mut ConstantCatalog,
    top_count: u16,
    score_domain_max: u64,
) -> CanonicalResult<EvaluatorInstructionStream> {
    let mut builder = ProgramBuilder::new(constants);
    let aggregate_input = builder.input();
    let packed_scores = pack_direct_score_slots(&mut builder, aggregate_input)?;
    let packed_ranks = evaluate_packed_ranks(&mut builder, packed_scores, score_domain_max)?;
    let (target_identifier, target_order) =
        project_sparse_target(&mut builder, packed_ranks, usize::from(top_count))?;
    builder.finish(top_count, target_identifier, target_order)
}

fn pack_direct_score_slots(
    builder: &mut ProgramBuilder<'_>,
    aggregate: Register,
) -> CanonicalResult<Register> {
    let aggregate = builder.normalize(aggregate)?;
    let selected_scores =
        builder.plaintext_multiply_slots(aggregate, slot_selector(0..SELECTED_OPTION_COUNT)?)?;
    let duplicated_scores = rotate_inverse(builder, selected_scores, SELECTED_OPTION_COUNT)?;
    builder.sum_aligned(&[selected_scores, duplicated_scores])
}

fn evaluate_packed_ranks(
    builder: &mut ProgramBuilder<'_>,
    packed_scores: Register,
    score_domain_max: u64,
) -> CanonicalResult<Register> {
    let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_max)?;
    let comparison_point_count = score_domain_max
        .checked_mul(2)
        .and_then(|maximum| maximum.checked_add(1))
        .and_then(|point_count| usize::try_from(point_count).ok())
        .ok_or_else(|| program_error("selected comparison domain does not fit usize"))?;
    if greater_or_equal_polynomial.len() != comparison_point_count {
        return Err(program_error(
            "selected comparison interpolation has the wrong roster-derived degree",
        ));
    }
    let mut comparison_input_sum = None;
    let mut pair_windows = Vec::with_capacity(SELECTED_OPTION_COUNT - 1);
    let mut next_window_offset = 0_usize;
    for shift in 1..SELECTED_OPTION_COUNT {
        let pair_window_size = SELECTED_OPTION_COUNT - shift;
        pair_windows.push((shift, next_window_offset, pair_window_size));
        let shifted_scores = rotate_positive(builder, packed_scores, galois_power(shift)?)?;
        let difference = builder.subtract(packed_scores, shifted_scores)?;
        let difference = builder.normalize(difference)?;
        let shifted_difference =
            builder.plaintext_add_slots(difference, broadcast_slots(score_domain_max)?)?;
        let shifted_difference = builder.normalize(shifted_difference)?;
        let lower_pair_inputs =
            builder.plaintext_multiply_slots(shifted_difference, lower_pair_mask(shift)?)?;
        let windowed_inputs = if next_window_offset == 0 {
            lower_pair_inputs
        } else {
            rotate_inverse(builder, lower_pair_inputs, next_window_offset)?
        };
        builder.add_to_aligned_sum(&mut comparison_input_sum, windowed_inputs)?;
        next_window_offset += pair_window_size;
    }
    let comparison_inputs = comparison_input_sum
        .ok_or_else(|| program_error("selected evaluator produced no comparison inputs"))?;
    let comparison_input_target_level = builder.state(comparison_inputs).level.saturating_sub(2);
    let comparison_inputs =
        builder.modulus_switch_to(comparison_inputs, comparison_input_target_level)?;
    let baby_step_count = direct_comparison_baby_step_count(score_domain_max)?;
    let comparison_outputs = evaluate_polynomial(
        builder,
        comparison_inputs,
        &greater_or_equal_polynomial,
        baby_step_count,
    )?;
    if builder.state(comparison_outputs).level != DIRECT_COMPARISON_OUTPUT_LEVEL {
        return Err(program_error(
            "selected comparison schedule reached the wrong output level",
        ));
    }

    let mut rank_sum = None;
    for (shift, window_offset, pair_window_size) in pair_windows {
        let comparison_outputs_normalized = builder.normalize(comparison_outputs)?;
        let windowed_lower_beats_higher = builder.plaintext_multiply_slots(
            comparison_outputs_normalized,
            slot_selector(window_offset..window_offset + pair_window_size)?,
        )?;
        let lower_beats_higher = if window_offset == 0 {
            windowed_lower_beats_higher
        } else {
            rotate_positive(
                builder,
                windowed_lower_beats_higher,
                galois_power(window_offset)?,
            )?
        };
        let lower_pair_mask = lower_pair_mask(shift)?;
        let lower_beats_higher = builder.normalize(lower_beats_higher)?;
        let lower_beats_higher_for_lower_slots =
            builder.plaintext_multiply_slots(lower_beats_higher, lower_pair_mask.clone())?;
        let lower_for_negation = builder.normalize(lower_beats_higher_for_lower_slots)?;
        let higher_beats_lower_for_lower_slots = builder.negate(lower_for_negation)?;
        let higher_beats_lower_for_lower_slots =
            builder.plaintext_add_slots(higher_beats_lower_for_lower_slots, lower_pair_mask)?;
        let lower_beats_higher_for_return = builder.modulus_switch_to(
            lower_beats_higher_for_lower_slots,
            DIRECT_COMPARISON_OUTPUT_LEVEL,
        )?;
        let lower_beats_higher_at_higher_slot =
            rotate_inverse(builder, lower_beats_higher_for_return, shift)?;
        builder.add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        builder.add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }
    rank_sum.ok_or_else(|| program_error("selected evaluator produced no packed-rank terms"))
}

fn project_sparse_target(
    builder: &mut ProgramBuilder<'_>,
    packed_ranks: Register,
    top_count: usize,
) -> CanonicalResult<(Register, Register)> {
    let identifier_selector = weighted_slot_selector(
        (0..SELECTED_OPTION_COUNT).map(|option_index| (option_index, option_index + 1)),
    )?;
    let option_slot_mask = slot_selector(0..SELECTED_OPTION_COUNT)?;
    if top_count == SELECTED_OPTION_COUNT {
        let normalized_ranks = builder.normalize(packed_ranks)?;
        let encrypted_zero = builder.plaintext_multiply_scalar(normalized_ranks, 0)?;
        let target_identifier = builder.plaintext_add_slots(encrypted_zero, identifier_selector)?;
        let target_order = builder.plaintext_add_slots(normalized_ranks, option_slot_mask)?;
        return Ok((
            builder.modulus_switch_to(target_identifier, CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
            builder.modulus_switch_to(target_order, CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
        ));
    }

    let normalized_ranks =
        builder.modulus_switch_to(packed_ranks, SELECTED_EVALUATOR_WORKING_LEVEL)?;
    let normalized_ranks = builder.normalize(normalized_ranks)?;
    let indicator_values = (0..SELECTED_OPTION_COUNT)
        .map(|rank| u64::from(rank < top_count))
        .collect::<Vec<_>>();
    let order_values = (0..SELECTED_OPTION_COUNT)
        .map(|rank| {
            if rank < top_count {
                (rank + 1) as u64
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let indicator = evaluate_rank_lookup(builder, normalized_ranks, &indicator_values)?;
    let order_value = evaluate_rank_lookup(builder, normalized_ranks, &order_values)?;
    let indicator = builder.normalize(indicator)?;
    let order_value = builder.normalize(order_value)?;
    let target_identifier = builder.plaintext_multiply_slots(indicator, identifier_selector)?;
    let target_order = builder.plaintext_multiply_slots(order_value, option_slot_mask)?;
    Ok((
        builder.modulus_switch_to(target_identifier, CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
        builder.modulus_switch_to(target_order, CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
    ))
}

fn evaluate_rank_lookup(
    builder: &mut ProgramBuilder<'_>,
    rank: Register,
    values: &[u64],
) -> CanonicalResult<Register> {
    let polynomial = interpolate_coefficients(values)?;
    if polynomial.len() != 20 || RANK_LOOKUP_BABY_STEP_COUNT != 5 {
        return Err(program_error(
            "selected rank lookup does not match the frozen degree and baby-step schedule",
        ));
    }
    evaluate_polynomial(builder, rank, &polynomial, RANK_LOOKUP_BABY_STEP_COUNT)
}

fn evaluate_polynomial(
    builder: &mut ProgramBuilder<'_>,
    input: Register,
    coefficients: &[u64],
    baby_step_count: usize,
) -> CanonicalResult<Register> {
    if coefficients.is_empty() || baby_step_count < 2 {
        return Err(program_error(
            "compiled polynomial has an invalid coefficient or baby-step count",
        ));
    }
    let degree = coefficients.len() - 1;
    if degree == 0 || degree < baby_step_count {
        return evaluate_polynomial_by_power_table(builder, input, coefficients);
    }
    let block_count = coefficients.len().div_ceil(baby_step_count);
    let working_input = builder.modulus_switch_to(input, SELECTED_EVALUATOR_WORKING_LEVEL)?;
    let baby_powers = build_power_table(builder, working_input, baby_step_count)?;
    let giant_base = baby_powers[baby_step_count]
        .ok_or_else(|| program_error("compiled evaluator omitted its giant-step base"))?;
    let giant_powers = build_power_table(builder, giant_base, block_count.saturating_sub(1))?;

    let mut terms = Vec::new();
    for (block_index, giant_power) in giant_powers.iter().enumerate().take(block_count) {
        let start = block_index * baby_step_count;
        let end = coefficients.len().min(start + baby_step_count);
        let block_coefficients = &coefficients[start..end];
        if block_coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            continue;
        }
        let block_value = linear_combination_from_powers(
            builder,
            working_input,
            &baby_powers,
            block_coefficients,
        )?;
        if block_index == 0 {
            terms.push(block_value);
            continue;
        }
        let giant_power =
            giant_power.ok_or_else(|| program_error("compiled evaluator omitted a giant power"))?;
        if block_coefficients[1..]
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            terms.push(builder.plaintext_multiply_scalar(giant_power, block_coefficients[0])?);
        } else {
            terms.push(builder.multiply_without_drop(block_value, giant_power)?);
        }
    }
    if terms.is_empty() {
        return evaluate_polynomial_by_power_table(builder, input, &[0]);
    }
    builder.sum_aligned(&terms)
}

fn evaluate_polynomial_by_power_table(
    builder: &mut ProgramBuilder<'_>,
    input: Register,
    coefficients: &[u64],
) -> CanonicalResult<Register> {
    let degree = coefficients.len() - 1;
    let working_input = builder.modulus_switch_to(input, SELECTED_EVALUATOR_WORKING_LEVEL)?;
    let mut powers = vec![None; degree + 1];
    if degree >= 1 {
        powers[1] = Some(working_input);
    }
    for power in 2..=degree {
        if coefficients[power] == 0
            && !coefficients[power..]
                .iter()
                .any(|coefficient| *coefficient != 0)
        {
            continue;
        }
        let lower = power / 2;
        let upper = power - lower;
        powers[power] = Some(builder.multiply(
            powers[lower].ok_or_else(|| program_error("compiled power table is incomplete"))?,
            powers[upper].ok_or_else(|| program_error("compiled power table is incomplete"))?,
        )?);
    }
    linear_combination_from_powers(builder, working_input, &powers, coefficients)
}

fn build_power_table(
    builder: &mut ProgramBuilder<'_>,
    base: Register,
    highest_power: usize,
) -> CanonicalResult<Vec<Option<Register>>> {
    let mut powers = vec![None; highest_power + 1];
    if highest_power >= 1 {
        powers[1] = Some(base);
    }
    for power in 2..=highest_power {
        let lower = power / 2;
        let upper = power - lower;
        powers[power] = Some(builder.multiply(
            powers[lower].ok_or_else(|| program_error("compiled power table is incomplete"))?,
            powers[upper].ok_or_else(|| program_error("compiled power table is incomplete"))?,
        )?);
    }
    Ok(powers)
}

fn linear_combination_from_powers(
    builder: &mut ProgramBuilder<'_>,
    reference: Register,
    powers: &[Option<Register>],
    coefficients: &[u64],
) -> CanonicalResult<Register> {
    let target_level = coefficients
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, coefficient)| **coefficient != 0)
        .filter_map(|(power, _)| powers[power].map(|register| builder.state(register).level))
        .min();
    let anchor_level = target_level.unwrap_or(builder.state(reference).level);
    let anchor = builder.modulus_switch_to(reference, anchor_level)?;
    let anchor = builder.normalize(anchor)?;
    let encrypted_zero = builder.plaintext_multiply_scalar(anchor, 0)?;
    let mut result =
        builder.plaintext_add_slots(encrypted_zero, broadcast_slots(coefficients[0])?)?;
    for power in 1..coefficients.len() {
        if coefficients[power] == 0 {
            continue;
        }
        let power_register = powers[power]
            .ok_or_else(|| program_error("compiled linear combination is missing a power"))?;
        let power_register = builder.modulus_switch_to(power_register, anchor_level)?;
        let power_register = builder.normalize(power_register)?;
        let scaled = builder.plaintext_multiply_scalar(power_register, coefficients[power])?;
        result = builder.add(result, scaled)?;
    }
    Ok(result)
}

fn rotate_positive(
    builder: &mut ProgramBuilder<'_>,
    register: Register,
    galois_element: usize,
) -> CanonicalResult<Register> {
    if galois_element == 1 {
        return Ok(register);
    }
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let (requires_conjugation, exponent) = generator_exponent_or_conjugated(galois_element)?;
    let mut rotated = register;
    if requires_conjugation {
        rotated = builder.rotate(rotated, ring_order - 1)?;
    }
    for basis_rotation in generator_power_basis_for_exponent(exponent)? {
        rotated = builder.rotate(rotated, basis_rotation)?;
    }
    Ok(rotated)
}

fn rotate_inverse(
    builder: &mut ProgramBuilder<'_>,
    register: Register,
    shift: usize,
) -> CanonicalResult<Register> {
    let mut rotated = register;
    for basis_rotation in generator_inverse_power_basis_for_exponent(shift)? {
        rotated = builder.rotate(rotated, basis_rotation)?;
    }
    Ok(rotated)
}

fn lower_pair_mask(shift: usize) -> CanonicalResult<Vec<u32>> {
    slot_selector(0..SELECTED_OPTION_COUNT - shift)
}

fn slot_selector(indices: impl IntoIterator<Item = usize>) -> CanonicalResult<Vec<u32>> {
    weighted_slot_selector(indices.into_iter().map(|index| (index, 1)))
}

fn weighted_slot_selector(
    weights: impl IntoIterator<Item = (usize, usize)>,
) -> CanonicalResult<Vec<u32>> {
    let mut slots = vec![0_u32; POLYNOMIAL_DEGREE];
    for (index, weight) in weights {
        let slot = slots
            .get_mut(index)
            .ok_or_else(|| program_error("compiled slot selector index is outside the ring"))?;
        *slot = field_value(
            u64::try_from(weight)
                .map_err(|_| program_error("compiled slot-selector weight does not fit u64"))?,
        )?;
    }
    Ok(slots)
}

fn broadcast_slots(value: u64) -> CanonicalResult<Vec<u32>> {
    Ok(vec![field_value(value)?; POLYNOMIAL_DEGREE])
}

fn field_value(value: u64) -> CanonicalResult<u32> {
    u32::try_from(value % PLAINTEXT_MODULUS).map_err(|_| {
        crate::encoding::CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "plaintext-field residue does not fit the evaluator constant representation",
        )
    })
}
