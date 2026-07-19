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
#[cfg(test)]
use crate::bgv::evaluator::top_k::ScheduledMultiplicationLevelTrace;
use crate::bgv::evaluator::top_k::{
    CANONICAL_TARGET_CIPHERTEXT_LEVEL, EvaluatorModulusSchedule, NEGATIVE_ONE_GALOIS_ELEMENT,
    NEGATIVE_SEVEN_GALOIS_ELEMENT, POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT,
    RANK_LOOKUP_BABY_STEP_COUNT, SELECTED_EVALUATOR_MODULUS_SCHEDULE, comparison_polynomials,
    direct_comparison_baby_step_count, forward_pair_window_rotation_path, interpolate_coefficients,
    inverse_pair_shift_rotation_path, scheduled_power_table_products,
};

#[cfg(test)]
use super::super::top_k::SELECTED_EVALUATOR_WORKING_LEVEL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Register(u32);

const SELECTED_PAIR_COUNT: usize = SELECTED_OPTION_COUNT * (SELECTED_OPTION_COUNT - 1) / 2;
// Ten is the smallest fixed width that covers the nineteen pair windows in
// two tiles. Widths eleven through fifteen retain more ciphertexts with the
// same ten Galois phases. Widths sixteen through eighteen save only one phase
// while sharply increasing the live set, width nine requires a third tile and
// four additional phases, and the one-tile width nineteen exceeds the
// execution-memory bound once its live ciphertexts and resident key-switch
// workspace coexist.
const SELECTED_PAIR_WINDOW_TILE_WIDTH: usize = 10;

struct PreparedPairWindow {
    shift: usize,
    register: Register,
    rotation_path: Box<[usize]>,
    next_rotation_ordinal: usize,
}

struct PreparedPairWindowTerms {
    higher_beats_lower: Register,
    lower_beats_higher: PreparedPairWindow,
}

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
    data_primes: &'catalog [u64],
    working_level: usize,
    instructions: Vec<EvaluatorInstruction>,
    register_states: Vec<RegisterState>,
    #[cfg(test)]
    scheduled_multiplication_level_trace: Vec<ScheduledMultiplicationLevelTrace>,
}

impl<'catalog> ProgramBuilder<'catalog> {
    fn new_with_data_primes(
        constants: &'catalog mut ConstantCatalog,
        data_primes: &'catalog [u64],
    ) -> CanonicalResult<Self> {
        let working_level = data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| program_error("compiled evaluator data basis is empty"))?;
        Ok(Self {
            constants,
            data_primes,
            working_level,
            instructions: Vec::new(),
            register_states: vec![RegisterState {
                level: working_level,
                decryption_multiplier: 1,
            }],
            #[cfg(test)]
            scheduled_multiplication_level_trace: Vec::new(),
        })
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
                self.data_primes[dropped_level] % PLAINTEXT_MODULUS,
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

    fn multiply_with_modulus_drop_count(
        &mut self,
        left: Register,
        right: Register,
        modulus_drop_count: usize,
    ) -> CanonicalResult<Register> {
        let target_level = self.state(left).level.min(self.state(right).level);
        let left = self.modulus_switch_to(left, target_level)?;
        let right = self.modulus_switch_to(right, target_level)?;
        let left_state = self.state(left);
        let right_state = self.state(right);
        if modulus_drop_count > target_level {
            return Err(program_error(
                "compiled evaluator multiplication received an invalid modulus-drop count",
            ));
        }
        if modulus_drop_count == 0 {
            return self.multiply_without_drop(left, right);
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
        let product = self.emit_register(
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop,
            &[left, right],
            0,
            None,
            RegisterState {
                level: target_level - 1,
                decryption_multiplier: output_multiplier,
            },
        )?;
        self.modulus_switch_to(product, target_level - modulus_drop_count)
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
    let maximum_aggregate_score_difference = score_span
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(|| program_error("selected comparison domain overflowed u64"))?;

    let mut constants = ConstantCatalog::default();
    let mut streams = Vec::with_capacity(SELECTED_OPTION_COUNT);
    for top_count in 1..=SELECTED_OPTION_COUNT {
        streams.push(compile_stream(
            &mut constants,
            u16::try_from(top_count).expect("selected top count fits u16"),
            maximum_aggregate_score_difference,
            &SELECTED_EVALUATOR_MODULUS_SCHEDULE,
            &DATA_PRIMES,
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )?);
    }
    EvaluatorProgramSet::new(constants.into_sorted_constants(), streams)
}

#[cfg(test)]
pub(crate) fn selected_evaluator_program_set_with_pair_window_tile_width(
    pair_window_tile_width: usize,
) -> CanonicalResult<EvaluatorProgramSet> {
    let score_span = u64::from(
        FOUNDATION_PROFILE
            .maximum_score
            .checked_sub(FOUNDATION_PROFILE.minimum_score)
            .ok_or_else(|| program_error("selected score range is inverted"))?,
    );
    let maximum_aggregate_score_difference = score_span
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(|| program_error("selected comparison domain overflowed u64"))?;
    let mut constants = ConstantCatalog::default();
    let mut streams = Vec::with_capacity(SELECTED_OPTION_COUNT);
    for top_count in 1..=SELECTED_OPTION_COUNT {
        streams.push(compile_stream_with_pair_window_tile_width(
            &mut constants,
            u16::try_from(top_count).expect("selected top count fits u16"),
            maximum_aggregate_score_difference,
            &SELECTED_EVALUATOR_MODULUS_SCHEDULE,
            &DATA_PRIMES,
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            pair_window_tile_width,
        )?);
    }
    EvaluatorProgramSet::new(constants.into_sorted_constants(), streams)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CandidateCompiledEvaluatorMeasurement {
    pub(crate) minimum_instruction_count: usize,
    pub(crate) maximum_instruction_count: usize,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CandidateEvaluatorRecurrenceTrace {
    constants: Vec<EvaluatorConstant>,
    streams: Vec<EvaluatorInstructionStream>,
}

#[cfg(test)]
impl CandidateEvaluatorRecurrenceTrace {
    pub(crate) fn constants(&self) -> &[EvaluatorConstant] {
        &self.constants
    }

    pub(crate) fn streams(&self) -> &[EvaluatorInstructionStream] {
        &self.streams
    }

    pub(crate) fn encode(&self) -> CanonicalResult<Vec<u8>> {
        super::codec::encode_candidate_recurrence_trace(&self.constants, &self.streams)
    }

    pub(crate) fn decode(bytes: &[u8]) -> CanonicalResult<Self> {
        let (constants, streams) = super::codec::decode_candidate_recurrence_trace(bytes)?;
        Ok(Self { constants, streams })
    }
}

#[cfg(test)]
const FACTOR_FOUR_CANDIDATE_MODULUS_SCHEDULE: EvaluatorModulusSchedule = EvaluatorModulusSchedule {
    pre_comparison_drop_count: 0,
    comparison_depth_drop_counts: [2, 1, 1, 1, 1, 1, 1, 2],
    rank_depth_drop_counts: [5, 1, 2, 0, 2],
};

/// Compiles the exact factor-four candidate into the same instruction and
/// constant types as the runtime program. This deliberately returns a
/// compiler-owned recurrence trace instead of a validated selected-suite
/// program: the candidate's first multiplication is above the currently
/// frozen relinearization-key catalog level, so it must not be mistaken for
/// an executable selected-suite program before the suite is replaced.
#[cfg(test)]
pub(crate) fn compile_factor_four_candidate_recurrence_trace(
    target_level: usize,
    data_primes: &[u64],
) -> CanonicalResult<CandidateEvaluatorRecurrenceTrace> {
    let score_span = u64::from(
        FOUNDATION_PROFILE
            .maximum_score
            .checked_sub(FOUNDATION_PROFILE.minimum_score)
            .ok_or_else(|| program_error("selected score range is inverted"))?,
    );
    let maximum_aggregate_score_difference = score_span
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(|| program_error("selected comparison domain overflowed u64"))?;
    let mut constants = ConstantCatalog::default();
    let mut streams = Vec::with_capacity(SELECTED_OPTION_COUNT);
    for top_count in 1..=SELECTED_OPTION_COUNT {
        streams.push(compile_stream(
            &mut constants,
            u16::try_from(top_count).expect("selected top count fits u16"),
            maximum_aggregate_score_difference,
            &FACTOR_FOUR_CANDIDATE_MODULUS_SCHEDULE,
            data_primes,
            target_level,
        )?);
    }
    Ok(CandidateEvaluatorRecurrenceTrace {
        constants: constants.into_sorted_constants(),
        streams,
    })
}

#[cfg(test)]
pub(crate) fn compile_candidate_evaluator_program_measurement(
    modulus_schedule: &EvaluatorModulusSchedule,
    target_level: usize,
    data_primes: &[u64],
) -> CanonicalResult<CandidateCompiledEvaluatorMeasurement> {
    let program_set =
        compile_candidate_evaluator_program_set(modulus_schedule, target_level, data_primes)?;
    let minimum_instruction_count = program_set
        .streams()
        .iter()
        .map(|stream| stream.instructions().len())
        .min()
        .expect("candidate evaluator has a stream for every selected top count");
    let maximum_instruction_count = program_set
        .streams()
        .iter()
        .map(|stream| stream.instructions().len())
        .max()
        .expect("candidate evaluator has a stream for every selected top count");
    Ok(CandidateCompiledEvaluatorMeasurement {
        minimum_instruction_count,
        maximum_instruction_count,
    })
}

#[cfg(test)]
pub(crate) fn compile_candidate_evaluator_program_set(
    modulus_schedule: &EvaluatorModulusSchedule,
    target_level: usize,
    data_primes: &[u64],
) -> CanonicalResult<EvaluatorProgramSet> {
    let score_span = u64::from(
        FOUNDATION_PROFILE
            .maximum_score
            .checked_sub(FOUNDATION_PROFILE.minimum_score)
            .ok_or_else(|| program_error("selected score range is inverted"))?,
    );
    let maximum_aggregate_score_difference = score_span
        .checked_mul(u64::from(FOUNDATION_PROFILE.participant_count))
        .ok_or_else(|| program_error("selected comparison domain overflowed u64"))?;
    let mut constants = ConstantCatalog::default();
    let mut streams = Vec::with_capacity(SELECTED_OPTION_COUNT);
    for top_count in 1..=SELECTED_OPTION_COUNT {
        streams.push(compile_stream(
            &mut constants,
            u16::try_from(top_count).expect("selected top count fits u16"),
            maximum_aggregate_score_difference,
            modulus_schedule,
            data_primes,
            target_level,
        )?);
    }
    EvaluatorProgramSet::new(constants.into_sorted_constants(), streams)
}

#[cfg(test)]
pub(crate) fn compiled_prepared_power_level_trace(
    input_level: usize,
    coefficient_count: usize,
    baby_step_count: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<Vec<ScheduledMultiplicationLevelTrace>> {
    if input_level > SELECTED_EVALUATOR_WORKING_LEVEL {
        return Err(program_error(
            "compiled power trace input exceeds the evaluator working level",
        ));
    }
    let mut constants = ConstantCatalog::default();
    let mut builder =
        ProgramBuilder::new_with_data_primes(&mut constants, &DATA_PRIMES[..=input_level])?;
    let input = builder.input();
    let input = builder.modulus_switch_to(input, input_level)?;
    prepare_polynomial_powers(
        &mut builder,
        input,
        coefficient_count,
        baby_step_count,
        depth_drop_counts,
    )?;
    Ok(builder.scheduled_multiplication_level_trace)
}

#[cfg(test)]
pub(crate) fn compiled_prepared_power_instruction_count(
    input_level: usize,
    coefficient_count: usize,
    baby_step_count: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<usize> {
    if input_level > SELECTED_EVALUATOR_WORKING_LEVEL {
        return Err(program_error(
            "compiled power instruction count input exceeds the evaluator working level",
        ));
    }
    let mut constants = ConstantCatalog::default();
    let mut builder =
        ProgramBuilder::new_with_data_primes(&mut constants, &DATA_PRIMES[..=input_level])?;
    let input = builder.input();
    let input = builder.modulus_switch_to(input, input_level)?;
    let instruction_count_before_preparation = builder.instructions.len();
    prepare_polynomial_powers(
        &mut builder,
        input,
        coefficient_count,
        baby_step_count,
        depth_drop_counts,
    )?;
    Ok(builder.instructions.len() - instruction_count_before_preparation)
}

fn compile_stream(
    constants: &mut ConstantCatalog,
    top_count: u16,
    maximum_aggregate_score_difference: u64,
    modulus_schedule: &EvaluatorModulusSchedule,
    data_primes: &[u64],
    target_level: usize,
) -> CanonicalResult<EvaluatorInstructionStream> {
    compile_stream_with_pair_window_tile_width(
        constants,
        top_count,
        maximum_aggregate_score_difference,
        modulus_schedule,
        data_primes,
        target_level,
        SELECTED_PAIR_WINDOW_TILE_WIDTH,
    )
}

fn compile_stream_with_pair_window_tile_width(
    constants: &mut ConstantCatalog,
    top_count: u16,
    maximum_aggregate_score_difference: u64,
    modulus_schedule: &EvaluatorModulusSchedule,
    data_primes: &[u64],
    target_level: usize,
    pair_window_tile_width: usize,
) -> CanonicalResult<EvaluatorInstructionStream> {
    let mut builder = ProgramBuilder::new_with_data_primes(constants, data_primes)?;
    let working_level = builder.working_level;
    if target_level >= working_level
        || modulus_schedule.total_drop_count() != working_level - target_level
    {
        return Err(program_error(
            "compiled evaluator schedule does not consume its exact target-level budget",
        ));
    }
    let aggregate_pair_differences = builder.input();
    let packed_ranks = evaluate_packed_ranks(
        &mut builder,
        aggregate_pair_differences,
        maximum_aggregate_score_difference,
        modulus_schedule,
        pair_window_tile_width,
    )?;
    let (target_identifier, target_order) = project_sparse_target(
        &mut builder,
        packed_ranks,
        usize::from(top_count),
        modulus_schedule,
        target_level,
    )?;
    if builder.state(target_identifier).level != target_level
        || builder.state(target_order).level != target_level
    {
        return Err(program_error(
            "compiled evaluator target registers reached the wrong level",
        ));
    }
    builder.finish(top_count, target_identifier, target_order)
}

fn evaluate_packed_ranks(
    builder: &mut ProgramBuilder<'_>,
    aggregate_pair_differences: Register,
    maximum_aggregate_score_difference: u64,
    modulus_schedule: &EvaluatorModulusSchedule,
    pair_window_tile_width: usize,
) -> CanonicalResult<Register> {
    if !(1..SELECTED_OPTION_COUNT).contains(&pair_window_tile_width) {
        return Err(program_error(
            "compiled evaluator pair-window tile width is outside the selected geometry",
        ));
    }
    let (_, greater_or_equal_polynomial) =
        comparison_polynomials(maximum_aggregate_score_difference)?;
    let comparison_point_count = maximum_aggregate_score_difference
        .checked_mul(2)
        .and_then(|maximum| maximum.checked_add(1))
        .and_then(|point_count| usize::try_from(point_count).ok())
        .ok_or_else(|| program_error("selected comparison domain does not fit usize"))?;
    if greater_or_equal_polynomial.len() != comparison_point_count {
        return Err(program_error(
            "selected comparison interpolation has the wrong roster-derived degree",
        ));
    }
    let aggregate_pair_differences = builder.normalize(aggregate_pair_differences)?;
    // The ballot relation binds every slot outside the canonical pair-difference
    // prefix to zero. Reapplying that slot mask is plaintext-equivalent, but its
    // dense coefficient encoding needlessly amplifies ciphertext error before
    // both polynomial evaluations.
    let comparison_inputs = builder.plaintext_add_slots(
        aggregate_pair_differences,
        pair_difference_shift_slots(maximum_aggregate_score_difference)?,
    )?;
    let comparison_input_target_level = builder
        .state(comparison_inputs)
        .level
        .checked_sub(modulus_schedule.pre_comparison_drop_count)
        .ok_or_else(|| program_error("compiled comparison pre-drop exceeds the active level"))?;
    let comparison_inputs =
        builder.modulus_switch_to(comparison_inputs, comparison_input_target_level)?;
    let baby_step_count = direct_comparison_baby_step_count(maximum_aggregate_score_difference)?;
    let comparison_outputs = evaluate_polynomial(
        builder,
        comparison_inputs,
        &greater_or_equal_polynomial,
        baby_step_count,
        &modulus_schedule.comparison_depth_drop_counts,
    )?;
    let comparison_output_level = builder
        .working_level
        .checked_sub(modulus_schedule.pre_comparison_drop_count)
        .and_then(|level| level.checked_sub(modulus_schedule.comparison_drop_count()))
        .ok_or_else(|| program_error("compiled comparison schedule exceeds the active level"))?;
    if builder.state(comparison_outputs).level != comparison_output_level {
        return Err(program_error(
            "selected comparison schedule reached the wrong output level",
        ));
    }

    let comparison_outputs_normalized = builder.normalize(comparison_outputs)?;
    let mut pair_window_geometries = Vec::with_capacity(SELECTED_OPTION_COUNT - 1);
    let mut window_offset = 0_usize;
    for shift in 1..SELECTED_OPTION_COUNT {
        let pair_window_size = SELECTED_OPTION_COUNT - shift;
        pair_window_geometries.push((shift, window_offset, pair_window_size));
        window_offset += pair_window_size;
    }
    if window_offset != SELECTED_PAIR_COUNT {
        return Err(program_error(
            "selected evaluator did not consume the complete pair-difference layout",
        ));
    }

    let mut rank_sum = None;
    for geometry_tile in pair_window_geometries.chunks(pair_window_tile_width) {
        let mut prepared_windows = Vec::with_capacity(geometry_tile.len());
        for (shift, window_offset, pair_window_size) in geometry_tile.iter().copied() {
            let windowed_lower_beats_higher = builder.plaintext_multiply_slots(
                comparison_outputs_normalized,
                slot_selector(window_offset..window_offset + pair_window_size)?,
            )?;
            prepared_windows.push(PreparedPairWindow {
                shift,
                register: windowed_lower_beats_higher,
                rotation_path: forward_pair_window_rotation_path(window_offset)?.into_boxed_slice(),
                next_rotation_ordinal: 0,
            });
        }

        // Every window depends only on its disjoint masked input until the
        // final ordered sum. Interleaving equal-key path segments therefore
        // preserves each path while making the canonical stream itself own
        // the one-key-at-a-time execution phases.
        rotate_prepared_pair_window_phase(
            builder,
            &mut prepared_windows,
            POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT,
        )?;
        rotate_prepared_pair_window_phase(
            builder,
            &mut prepared_windows,
            NEGATIVE_SEVEN_GALOIS_ELEMENT,
        )?;
        rotate_prepared_pair_window_phase(
            builder,
            &mut prepared_windows,
            NEGATIVE_ONE_GALOIS_ELEMENT,
        )?;
        require_completed_pair_window_paths(&prepared_windows)?;

        let mut prepared_terms = Vec::with_capacity(prepared_windows.len());
        for prepared_window in prepared_windows {
            let lower_pair_mask = lower_pair_mask(prepared_window.shift)?;
            // The pre-rotation selector has exact source support
            // `window_offset..window_offset + pair_window_size`. The directed
            // Galois path maps that support bijectively to
            // `0..pair_window_size`, which is this lower-pair mask. Applying
            // the mask again is plaintext-equivalent, but it would convolve
            // the error introduced by the Galois key switches with the dense
            // coefficient encoding. Keep the mask only for constructing
            // `1 - lower_beats_higher` below.
            let lower_beats_higher_for_lower_slots = builder.normalize(prepared_window.register)?;
            let lower_for_negation = builder.normalize(lower_beats_higher_for_lower_slots)?;
            let higher_beats_lower = builder.negate(lower_for_negation)?;
            let higher_beats_lower =
                builder.plaintext_add_slots(higher_beats_lower, lower_pair_mask)?;
            let lower_beats_higher_for_return = builder
                .modulus_switch_to(lower_beats_higher_for_lower_slots, comparison_output_level)?;
            prepared_terms.push(PreparedPairWindowTerms {
                higher_beats_lower,
                lower_beats_higher: PreparedPairWindow {
                    shift: prepared_window.shift,
                    register: lower_beats_higher_for_return,
                    rotation_path: inverse_pair_shift_rotation_path(prepared_window.shift)?
                        .into_boxed_slice(),
                    next_rotation_ordinal: 0,
                },
            });
        }

        rotate_prepared_pair_window_term_phase(
            builder,
            &mut prepared_terms,
            NEGATIVE_SEVEN_GALOIS_ELEMENT,
        )?;
        rotate_prepared_pair_window_term_phase(
            builder,
            &mut prepared_terms,
            NEGATIVE_ONE_GALOIS_ELEMENT,
        )?;
        for prepared_terms in &prepared_terms {
            require_completed_pair_window_paths(core::slice::from_ref(
                &prepared_terms.lower_beats_higher,
            ))?;
        }

        // Preserve the original higher-term then returned-lower-term order so
        // the ciphertext output is identical, not merely plaintext-equivalent.
        for prepared_terms in prepared_terms {
            builder.add_to_aligned_sum(&mut rank_sum, prepared_terms.higher_beats_lower)?;
            builder
                .add_to_aligned_sum(&mut rank_sum, prepared_terms.lower_beats_higher.register)?;
        }
    }

    rank_sum.ok_or_else(|| program_error("selected evaluator produced no packed-rank terms"))
}

fn project_sparse_target(
    builder: &mut ProgramBuilder<'_>,
    packed_ranks: Register,
    top_count: usize,
    modulus_schedule: &EvaluatorModulusSchedule,
    target_level: usize,
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
            builder.modulus_switch_to(target_identifier, target_level)?,
            builder.modulus_switch_to(target_order, target_level)?,
        ));
    }

    let working_level = builder.working_level;
    let normalized_ranks = builder.modulus_switch_to(packed_ranks, working_level)?;
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
    let indicator_polynomial = interpolate_coefficients(&indicator_values)?;
    let order_polynomial = interpolate_coefficients(&order_values)?;
    if indicator_polynomial.len() != 20
        || indicator_polynomial.len() != order_polynomial.len()
        || RANK_LOOKUP_BABY_STEP_COUNT != 5
    {
        return Err(program_error(
            "selected paired rank lookups do not match the frozen polynomial geometry",
        ));
    }
    let prepared_rank_powers = prepare_polynomial_powers(
        builder,
        normalized_ranks,
        indicator_polynomial.len(),
        RANK_LOOKUP_BABY_STEP_COUNT,
        &modulus_schedule.rank_depth_drop_counts,
    )?;
    let indicator = evaluate_polynomial_from_prepared_powers(
        builder,
        &prepared_rank_powers,
        &indicator_polynomial,
    )?;
    let order_value = evaluate_polynomial_from_prepared_powers(
        builder,
        &prepared_rank_powers,
        &order_polynomial,
    )?;
    let indicator = builder.normalize(indicator)?;
    let order_value = builder.normalize(order_value)?;
    let target_identifier = builder.plaintext_multiply_slots(indicator, identifier_selector)?;
    let target_order = builder.plaintext_multiply_slots(order_value, option_slot_mask)?;
    Ok((
        builder.modulus_switch_to(target_identifier, target_level)?,
        builder.modulus_switch_to(target_order, target_level)?,
    ))
}

#[derive(Debug, Clone, Copy)]
struct ScheduledRegisterPower {
    register: Register,
    multiplication_depth: usize,
}

struct PreparedRegisterPowers {
    working_input: Register,
    baby_step_count: usize,
    block_count: usize,
    baby_powers: Vec<Option<ScheduledRegisterPower>>,
    giant_powers: Vec<Option<ScheduledRegisterPower>>,
}

fn scheduled_power_product(
    builder: &mut ProgramBuilder<'_>,
    left: ScheduledRegisterPower,
    right: ScheduledRegisterPower,
    depth_drop_counts: &[usize],
) -> CanonicalResult<ScheduledRegisterPower> {
    let multiplication_depth = left
        .multiplication_depth
        .max(right.multiplication_depth)
        .checked_add(1)
        .ok_or_else(|| program_error("compiled multiplication depth overflowed"))?;
    let drop_count = *depth_drop_counts
        .get(multiplication_depth - 1)
        .ok_or_else(|| program_error("compiled multiplication exceeded its depth schedule"))?;
    #[cfg(test)]
    let left_input_level = builder.state(left.register).level;
    #[cfg(test)]
    let right_input_level = builder.state(right.register).level;
    let register =
        builder.multiply_with_modulus_drop_count(left.register, right.register, drop_count)?;
    #[cfg(test)]
    builder
        .scheduled_multiplication_level_trace
        .push(ScheduledMultiplicationLevelTrace {
            multiplication_depth,
            left_input_level,
            right_input_level,
            modulus_drop_count: drop_count,
            output_level: builder.state(register).level,
        });
    Ok(ScheduledRegisterPower {
        register,
        multiplication_depth,
    })
}

fn evaluate_polynomial(
    builder: &mut ProgramBuilder<'_>,
    input: Register,
    coefficients: &[u64],
    baby_step_count: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<Register> {
    if coefficients.is_empty() || baby_step_count < 2 {
        return Err(program_error(
            "compiled polynomial has an invalid coefficient or baby-step count",
        ));
    }
    let degree = coefficients.len() - 1;
    if degree == 0 || degree < baby_step_count {
        return evaluate_polynomial_by_power_table(builder, input, coefficients, depth_drop_counts);
    }
    let prepared_powers = prepare_polynomial_powers(
        builder,
        input,
        coefficients.len(),
        baby_step_count,
        depth_drop_counts,
    )?;
    evaluate_polynomial_from_prepared_powers(builder, &prepared_powers, coefficients)
}

fn prepare_polynomial_powers(
    builder: &mut ProgramBuilder<'_>,
    input: Register,
    coefficient_count: usize,
    baby_step_count: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<PreparedRegisterPowers> {
    if coefficient_count <= baby_step_count || baby_step_count < 2 {
        return Err(program_error(
            "prepared compiled powers require nontrivial Paterson-Stockmeyer geometry",
        ));
    }
    let block_count = coefficient_count.div_ceil(baby_step_count);
    let working_level = builder.working_level;
    let working_input = builder.modulus_switch_to(input, working_level)?;
    let baby_powers = build_power_table(
        builder,
        ScheduledRegisterPower {
            register: working_input,
            multiplication_depth: 0,
        },
        baby_step_count,
        depth_drop_counts,
    )?;
    let giant_base = baby_powers[baby_step_count]
        .ok_or_else(|| program_error("compiled evaluator omitted its giant-step base"))?;
    let giant_powers = build_power_table(
        builder,
        giant_base,
        block_count.saturating_sub(1),
        depth_drop_counts,
    )?;
    Ok(PreparedRegisterPowers {
        working_input,
        baby_step_count,
        block_count,
        baby_powers,
        giant_powers,
    })
}

fn evaluate_polynomial_from_prepared_powers(
    builder: &mut ProgramBuilder<'_>,
    prepared_powers: &PreparedRegisterPowers,
    coefficients: &[u64],
) -> CanonicalResult<Register> {
    if coefficients.len().div_ceil(prepared_powers.baby_step_count) != prepared_powers.block_count {
        return Err(program_error(
            "compiled polynomial does not match its prepared power geometry",
        ));
    }

    let accumulated_term_level = (0..prepared_powers.block_count)
        .map(|block_index| {
            prepared_polynomial_block_term_level(
                builder,
                prepared_powers,
                coefficients,
                block_index,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?
        .into_iter()
        .flatten()
        .min();
    let Some(accumulated_term_level) = accumulated_term_level else {
        return builder.plaintext_multiply_scalar(prepared_powers.working_input, 0);
    };
    let mut accumulated_terms = None;
    for (block_index, giant_power) in prepared_powers
        .giant_powers
        .iter()
        .enumerate()
        .take(prepared_powers.block_count)
    {
        let start = block_index * prepared_powers.baby_step_count;
        let end = coefficients
            .len()
            .min(start + prepared_powers.baby_step_count);
        let block_coefficients = &coefficients[start..end];
        if block_coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            continue;
        }
        let block_value = linear_combination_from_powers(
            builder,
            prepared_powers.working_input,
            &prepared_powers.baby_powers,
            block_coefficients,
        )?;
        let term = if block_index == 0 {
            block_value
        } else {
            let giant_power = giant_power
                .ok_or_else(|| program_error("compiled evaluator omitted a giant power"))?;
            if block_coefficients[1..]
                .iter()
                .all(|coefficient| *coefficient == 0)
            {
                builder.plaintext_multiply_scalar(giant_power.register, block_coefficients[0])?
            } else {
                builder.multiply_without_drop(block_value, giant_power.register)?
            }
        };
        // The original ordered fold aligns every block term to this global
        // minimum. Deriving it before emission lets each term be aligned,
        // normalized, and folded immediately, retaining the exact operation
        // order and ciphertext output without keeping every term resident.
        let term = builder.modulus_switch_to(term, accumulated_term_level)?;
        let term = builder.normalize(term)?;
        accumulated_terms = Some(match accumulated_terms {
            Some(accumulated_terms) => builder.add(accumulated_terms, term)?,
            None => term,
        });
    }
    accumulated_terms.ok_or_else(|| program_error("compiled polynomial produced no block terms"))
}

fn prepared_polynomial_block_term_level(
    builder: &ProgramBuilder<'_>,
    prepared_powers: &PreparedRegisterPowers,
    coefficients: &[u64],
    block_index: usize,
) -> CanonicalResult<Option<usize>> {
    let start = block_index
        .checked_mul(prepared_powers.baby_step_count)
        .ok_or_else(|| program_error("compiled polynomial block offset overflowed"))?;
    let end = coefficients
        .len()
        .min(start + prepared_powers.baby_step_count);
    let block_coefficients = coefficients
        .get(start..end)
        .ok_or_else(|| program_error("compiled polynomial block is outside its coefficients"))?;
    if block_coefficients
        .iter()
        .all(|coefficient| *coefficient == 0)
    {
        return Ok(None);
    }

    let block_value_level = block_coefficients
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, coefficient)| **coefficient != 0)
        .filter_map(|(power, _)| {
            prepared_powers.baby_powers[power].map(|power| builder.state(power.register).level)
        })
        .min()
        .unwrap_or_else(|| builder.state(prepared_powers.working_input).level);
    if block_index == 0 {
        return Ok(Some(block_value_level));
    }
    let giant_power = prepared_powers
        .giant_powers
        .get(block_index)
        .and_then(|power| *power)
        .ok_or_else(|| program_error("compiled evaluator omitted a giant power"))?;
    let giant_power_level = builder.state(giant_power.register).level;
    if block_coefficients[1..]
        .iter()
        .all(|coefficient| *coefficient == 0)
    {
        Ok(Some(giant_power_level))
    } else {
        Ok(Some(block_value_level.min(giant_power_level)))
    }
}

fn evaluate_polynomial_by_power_table(
    builder: &mut ProgramBuilder<'_>,
    input: Register,
    coefficients: &[u64],
    depth_drop_counts: &[usize],
) -> CanonicalResult<Register> {
    let degree = coefficients.len() - 1;
    let working_level = builder.working_level;
    let working_input = builder.modulus_switch_to(input, working_level)?;
    let mut powers: Vec<Option<ScheduledRegisterPower>> = vec![None; degree + 1];
    if degree >= 1 {
        powers[1] = Some(ScheduledRegisterPower {
            register: working_input,
            multiplication_depth: 0,
        });
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
        powers[power] = Some(scheduled_power_product(
            builder,
            powers[lower].ok_or_else(|| program_error("compiled power table is incomplete"))?,
            powers[upper].ok_or_else(|| program_error("compiled power table is incomplete"))?,
            depth_drop_counts,
        )?);
    }
    linear_combination_from_powers(builder, working_input, &powers, coefficients)
}

fn build_power_table(
    builder: &mut ProgramBuilder<'_>,
    base: ScheduledRegisterPower,
    highest_power: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<Vec<Option<ScheduledRegisterPower>>> {
    let mut powers: Vec<Option<ScheduledRegisterPower>> = vec![None; highest_power + 1];
    if highest_power >= 1 {
        powers[1] = Some(base);
    }
    for product in scheduled_power_table_products(highest_power, base.multiplication_depth)? {
        powers[product.output_power] = Some(scheduled_power_product(
            builder,
            powers[product.lower_power]
                .ok_or_else(|| program_error("compiled power table is incomplete"))?,
            powers[product.upper_power]
                .ok_or_else(|| program_error("compiled power table is incomplete"))?,
            depth_drop_counts,
        )?);
    }
    Ok(powers)
}

fn linear_combination_from_powers(
    builder: &mut ProgramBuilder<'_>,
    reference: Register,
    powers: &[Option<ScheduledRegisterPower>],
    coefficients: &[u64],
) -> CanonicalResult<Register> {
    let target_level = coefficients
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, coefficient)| **coefficient != 0)
        .filter_map(|(power, _)| powers[power].map(|power| builder.state(power.register).level))
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
        let power_register = builder.modulus_switch_to(power_register.register, anchor_level)?;
        let power_register = builder.normalize(power_register)?;
        let scaled = builder.plaintext_multiply_scalar(power_register, coefficients[power])?;
        result = builder.add(result, scaled)?;
    }
    Ok(result)
}

fn rotate_prepared_pair_window_phase(
    builder: &mut ProgramBuilder<'_>,
    prepared_windows: &mut [PreparedPairWindow],
    galois_element: usize,
) -> CanonicalResult<()> {
    for prepared_window in prepared_windows {
        rotate_one_prepared_pair_window_phase(builder, prepared_window, galois_element)?;
    }
    Ok(())
}

fn rotate_prepared_pair_window_term_phase(
    builder: &mut ProgramBuilder<'_>,
    prepared_terms: &mut [PreparedPairWindowTerms],
    galois_element: usize,
) -> CanonicalResult<()> {
    for prepared_terms in prepared_terms {
        rotate_one_prepared_pair_window_phase(
            builder,
            &mut prepared_terms.lower_beats_higher,
            galois_element,
        )?;
    }
    Ok(())
}

fn rotate_one_prepared_pair_window_phase(
    builder: &mut ProgramBuilder<'_>,
    prepared_window: &mut PreparedPairWindow,
    galois_element: usize,
) -> CanonicalResult<()> {
    while prepared_window
        .rotation_path
        .get(prepared_window.next_rotation_ordinal)
        .copied()
        == Some(galois_element)
    {
        prepared_window.register = builder.rotate(prepared_window.register, galois_element)?;
        prepared_window.next_rotation_ordinal = prepared_window
            .next_rotation_ordinal
            .checked_add(1)
            .ok_or_else(|| program_error("prepared pair-window rotation ordinal overflowed"))?;
    }
    Ok(())
}

fn require_completed_pair_window_paths(
    prepared_windows: &[PreparedPairWindow],
) -> CanonicalResult<()> {
    if prepared_windows.iter().any(|prepared_window| {
        prepared_window.next_rotation_ordinal != prepared_window.rotation_path.len()
    }) {
        return Err(program_error(
            "prepared pair-window phase order did not consume an exact directed path",
        ));
    }
    Ok(())
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

fn pair_difference_shift_slots(score_difference_bound: u64) -> CanonicalResult<Vec<u32>> {
    let shifted_value = field_value(score_difference_bound)?;
    let mut slots = vec![0_u32; POLYNOMIAL_DEGREE];
    slots[..SELECTED_PAIR_COUNT].fill(shifted_value);
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
