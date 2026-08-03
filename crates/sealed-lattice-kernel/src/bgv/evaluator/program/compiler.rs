use std::collections::{BTreeMap, BTreeSet};

use crate::{
    bgv::{
        direct_ballots::{
            PAIR_CHARACTER_CIPHERTEXT_COUNT, PAIR_CHARACTER_LANE_COUNT, PAIR_CHARACTER_LANE_DEGREE,
            pair_character_lane_assignments, pair_character_lane_idempotent_coefficients,
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalErrorCode, CanonicalResult},
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_OPTION_COUNT,
    },
};

use super::{
    EvaluatorConstant, EvaluatorConstantKind, EvaluatorInstruction, EvaluatorInstructionStream,
    EvaluatorOpcode, EvaluatorProgramSet, RegisterState, SELECTED_OPTION_COUNT, program_error,
};
use crate::bgv::evaluator::top_k::{
    CANONICAL_TARGET_CIPHERTEXT_LEVEL, CHARACTER_OUTPUT_LEVEL, RANK_INPUT_LEVEL,
    RANK_LOOKUP_BABY_STEP_COUNT, SCATTER_KEY_LEVEL, SCATTER_ROUTES,
    SELECTED_EVALUATOR_MODULUS_SCHEDULE, ScatterRoute, TRACE_GALOIS_PATHS, TRACE_KEY_LEVEL,
    interpolate_coefficients, scheduled_power_table_products,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Register(u32);

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EvaluatorCompilerStage {
    NormalizedCharacterProductInput { ciphertext_ordinal: usize },
    PretraceAfterLevelSwitch { ciphertext_ordinal: usize },
    ComparisonMaskedPretrace { ciphertext_ordinal: usize },
    FinalTraceOutput { ciphertext_ordinal: usize },
    RoutedScatterContribution { route_ordinal: usize },
    RawScatterSum,
    RankBaseAdjusted,
    RankInputAfterLevelSwitch,
    PreparedBabyRankPower { rank_exponent: usize },
    PreparedGiantRankPower { rank_exponent: usize },
    IdentifierPolynomialBeforeSelector,
    OrderPolynomialBeforeSelector,
    FinalIdentifierTarget,
    FinalOrderTarget,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EvaluatorCompilerStageRegister {
    stage: EvaluatorCompilerStage,
    register_ordinal: u32,
}

#[cfg(test)]
impl EvaluatorCompilerStageRegister {
    pub(crate) const fn stage(self) -> EvaluatorCompilerStage {
        self.stage
    }

    pub(crate) const fn register_ordinal(self) -> u32 {
        self.register_ordinal
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatorCompilerStreamStageRegisters {
    top_count: u16,
    stage_registers: Vec<EvaluatorCompilerStageRegister>,
}

#[cfg(test)]
impl EvaluatorCompilerStreamStageRegisters {
    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) fn stage_registers(&self) -> &[EvaluatorCompilerStageRegister] {
        &self.stage_registers
    }
}

struct CompiledEvaluatorInstructionStream {
    instruction_stream: EvaluatorInstructionStream,
    #[cfg(test)]
    stage_registers: EvaluatorCompilerStreamStageRegisters,
}

struct CompiledEvaluatorProgramSet {
    program_set: EvaluatorProgramSet,
    #[cfg(test)]
    stream_stage_registers: Vec<EvaluatorCompilerStreamStageRegisters>,
}

#[derive(Default)]
struct ConstantCatalog {
    constants_by_hash: BTreeMap<[u8; Hash512::BYTE_LENGTH], EvaluatorConstant>,
}

impl ConstantCatalog {
    fn insert(&mut self, values: Vec<u32>) -> CanonicalResult<Hash512> {
        let constant = EvaluatorConstant::new(EvaluatorConstantKind::CoefficientVector, values)?;
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
    #[cfg(test)]
    stage_registers: Vec<EvaluatorCompilerStageRegister>,
}

impl<'catalog> ProgramBuilder<'catalog> {
    fn new(constants: &'catalog mut ConstantCatalog) -> Self {
        Self {
            constants,
            instructions: Vec::new(),
            register_states: vec![
                RegisterState {
                    level: CHARACTER_OUTPUT_LEVEL,
                    decryption_multiplier: 1,
                };
                PAIR_CHARACTER_CIPHERTEXT_COUNT
            ],
            #[cfg(test)]
            stage_registers: Vec::new(),
        }
    }

    #[cfg(test)]
    fn record_stage(&mut self, stage: EvaluatorCompilerStage, register: Register) {
        self.stage_registers.push(EvaluatorCompilerStageRegister {
            stage,
            register_ordinal: register.0,
        });
    }

    fn input(&self, ciphertext_ordinal: usize) -> CanonicalResult<Register> {
        if ciphertext_ordinal >= PAIR_CHARACTER_CIPHERTEXT_COUNT {
            return Err(program_error(
                "compiled evaluator input ciphertext ordinal is outside the selected catalog",
            ));
        }
        Ok(Register(u32::try_from(ciphertext_ordinal).map_err(
            |_| program_error("compiled evaluator input ordinal does not fit u32"),
        )?))
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

    fn plaintext_add(
        &mut self,
        register: Register,
        coefficients: Vec<u32>,
    ) -> CanonicalResult<Register> {
        let constant_hash = self.constants.insert(coefficients)?;
        self.emit_register(
            EvaluatorOpcode::PlaintextAdd,
            &[register],
            0,
            Some(constant_hash),
            self.state(register),
        )
    }

    fn plaintext_multiply(
        &mut self,
        register: Register,
        coefficients: Vec<u32>,
    ) -> CanonicalResult<Register> {
        let constant_hash = self.constants.insert(coefficients)?;
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
        self.plaintext_multiply(register, vec![field_value(scalar)?])
    }

    fn multiply_with_drop_count(
        &mut self,
        left: Register,
        right: Register,
        drop_count: usize,
    ) -> CanonicalResult<Register> {
        let multiplication_level = self.state(left).level.min(self.state(right).level);
        let left = self.modulus_switch_to(left, multiplication_level)?;
        let right = self.modulus_switch_to(right, multiplication_level)?;
        if drop_count > multiplication_level {
            return Err(program_error(
                "compiled evaluator multiplication drop exceeds its active level",
            ));
        }
        let product_multiplier = mul_mod(
            self.state(left).decryption_multiplier,
            self.state(right).decryption_multiplier,
            PLAINTEXT_MODULUS,
        )?;
        let product = if drop_count == 0 {
            self.emit_register(
                EvaluatorOpcode::CiphertextMultiplyAndRelinearize,
                &[left, right],
                0,
                None,
                RegisterState {
                    level: multiplication_level,
                    decryption_multiplier: product_multiplier,
                },
            )?
        } else {
            let output_multiplier = mul_mod(
                product_multiplier,
                DATA_PRIMES[multiplication_level] % PLAINTEXT_MODULUS,
                PLAINTEXT_MODULUS,
            )?;
            self.emit_register(
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop,
                &[left, right],
                0,
                None,
                RegisterState {
                    level: multiplication_level - 1,
                    decryption_multiplier: output_multiplier,
                },
            )?
        };
        self.modulus_switch_to(product, multiplication_level - drop_count)
    }

    fn multiply_without_drop(
        &mut self,
        left: Register,
        right: Register,
    ) -> CanonicalResult<Register> {
        self.multiply_with_drop_count(left, right, 0)
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

    fn finish(
        mut self,
        top_count: u16,
        target_identifier: Register,
        target_order: Register,
    ) -> CanonicalResult<CompiledEvaluatorInstructionStream> {
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
        for register_index in PAIR_CHARACTER_CIPHERTEXT_COUNT..self.register_states.len() {
            let register = u32::try_from(register_index)
                .map_err(|_| program_error("compiled register index does not fit u32"))?;
            if !output_registers.contains(&register) && !last_use.contains_key(&register) {
                return Err(program_error(format!(
                    "compiled evaluator top-count {top_count} created register {register} with no operative use",
                )));
            }
        }

        let unused_input_registers = (0..PAIR_CHARACTER_CIPHERTEXT_COUNT)
            .map(|register| {
                u32::try_from(register)
                    .map_err(|_| program_error("compiled input register index does not fit u32"))
            })
            .collect::<CanonicalResult<Vec<_>>>()?
            .into_iter()
            .filter(|register| !last_use.contains_key(register))
            .collect::<Vec<_>>();
        let mut instructions_with_drops = Vec::with_capacity(
            self.instructions
                .len()
                .saturating_add(self.register_states.len())
                .saturating_add(unused_input_registers.len()),
        );
        for register in unused_input_registers {
            instructions_with_drops.push(EvaluatorInstruction::new(
                EvaluatorOpcode::DropRegister,
                None,
                vec![register],
                0,
                0,
                None,
            )?);
        }
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
        let instruction_stream =
            EvaluatorInstructionStream::new(top_count, instructions_with_drops)?;
        Ok(CompiledEvaluatorInstructionStream {
            instruction_stream,
            #[cfg(test)]
            stage_registers: EvaluatorCompilerStreamStageRegisters {
                top_count,
                stage_registers: self.stage_registers,
            },
        })
    }
}

#[derive(Clone)]
struct RouteSourceMask {
    ciphertext_ordinal: usize,
    coefficients: Vec<u32>,
}

struct SelectedPlaintextTopology {
    comparison_trace_mask: Vec<u32>,
    active_ciphertext_ordinals: Vec<usize>,
    scatter_routes: Vec<ScatterRoute>,
    route_source_masks: Vec<Vec<RouteSourceMask>>,
    rank_base: Vec<u32>,
    identifier_selector: Vec<u32>,
    order_selector: Vec<u32>,
}

pub(crate) fn selected_evaluator_program_set() -> CanonicalResult<EvaluatorProgramSet> {
    Ok(compile_evaluator_program_set(SELECTED_OPTION_COUNT)?.program_set)
}

pub(in crate::bgv::evaluator) fn evaluator_program_set_for_option_count(
    option_count: usize,
) -> CanonicalResult<EvaluatorProgramSet> {
    Ok(compile_evaluator_program_set(option_count)?.program_set)
}

#[cfg(test)]
pub(crate) fn selected_evaluator_program_set_with_stage_registers() -> CanonicalResult<(
    EvaluatorProgramSet,
    Vec<EvaluatorCompilerStreamStageRegisters>,
)> {
    let compiled = compile_evaluator_program_set(SELECTED_OPTION_COUNT)?;
    Ok((compiled.program_set, compiled.stream_stage_registers))
}

fn compile_evaluator_program_set(
    option_count: usize,
) -> CanonicalResult<CompiledEvaluatorProgramSet> {
    if !(usize::from(MINIMUM_CONFIGURABLE_OPTION_COUNT)
        ..=usize::from(MAXIMUM_CONFIGURABLE_OPTION_COUNT))
        .contains(&option_count)
        || usize::from(FOUNDATION_PROFILE.participant_count) != 10
        || FOUNDATION_PROFILE.minimum_score != 1
        || FOUNDATION_PROFILE.maximum_score != 10
        || PLAINTEXT_MODULUS != 257
        || POLYNOMIAL_DEGREE != 32_768
        || DATA_PRIMES.len() != 23
    {
        return Err(program_error(
            "selected evaluator compiler received incompatible suite geometry",
        ));
    }
    let plaintext_topology = selected_plaintext_topology(option_count)?;
    let mut constants = ConstantCatalog::default();
    let mut streams = Vec::with_capacity(option_count);
    #[cfg(test)]
    let mut stream_stage_registers = Vec::with_capacity(option_count);
    for top_count in 1..=option_count {
        let compiled_stream = compile_stream(
            &mut constants,
            &plaintext_topology,
            option_count,
            u16::try_from(top_count).expect("selected top count fits u16"),
        )?;
        #[cfg(test)]
        stream_stage_registers.push(compiled_stream.stage_registers);
        streams.push(compiled_stream.instruction_stream);
    }
    let program_set = EvaluatorProgramSet::new(constants.into_sorted_constants(), streams)?;
    Ok(CompiledEvaluatorProgramSet {
        program_set,
        #[cfg(test)]
        stream_stage_registers,
    })
}

fn compile_stream(
    constants: &mut ConstantCatalog,
    plaintext_topology: &SelectedPlaintextTopology,
    option_count: usize,
    top_count: u16,
) -> CanonicalResult<CompiledEvaluatorInstructionStream> {
    let mut builder = ProgramBuilder::new(constants);
    let traced_ciphertexts = plaintext_topology
        .active_ciphertext_ordinals
        .iter()
        .copied()
        .map(|ciphertext_ordinal| {
            let ciphertext = builder.input(ciphertext_ordinal)?;
            #[cfg(test)]
            builder.record_stage(
                EvaluatorCompilerStage::NormalizedCharacterProductInput { ciphertext_ordinal },
                ciphertext,
            );
            let traced = trace_pair_character_ciphertext(
                &mut builder,
                ciphertext,
                ciphertext_ordinal,
                &plaintext_topology.comparison_trace_mask,
            )?;
            Ok((ciphertext_ordinal, traced))
        })
        .collect::<CanonicalResult<BTreeMap<_, _>>>()?;
    let ranks = scatter_pair_comparisons(&mut builder, &traced_ciphertexts, plaintext_topology)?;
    let ranks = builder.modulus_switch_to(ranks, RANK_INPUT_LEVEL)?;
    #[cfg(test)]
    builder.record_stage(EvaluatorCompilerStage::RankInputAfterLevelSwitch, ranks);
    let prepared_powers = prepare_rank_powers(&mut builder, ranks, option_count)?;

    let top_count = usize::from(top_count);
    let identifier_values = (0..option_count)
        .map(|rank| u64::from(rank < top_count))
        .collect::<Vec<_>>();
    let order_values = (0..option_count)
        .map(|rank| {
            if rank < top_count {
                u64::try_from(rank + 1).expect("selected rank fits u64")
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let identifier_polynomial = interpolate_coefficients(&identifier_values)?;
    let order_polynomial = interpolate_coefficients(&order_values)?;
    let identifier_polynomial_output =
        evaluate_rank_polynomial(&mut builder, &prepared_powers, &identifier_polynomial)?;
    #[cfg(test)]
    builder.record_stage(
        EvaluatorCompilerStage::IdentifierPolynomialBeforeSelector,
        identifier_polynomial_output,
    );
    let order_polynomial_output =
        evaluate_rank_polynomial(&mut builder, &prepared_powers, &order_polynomial)?;
    #[cfg(test)]
    builder.record_stage(
        EvaluatorCompilerStage::OrderPolynomialBeforeSelector,
        order_polynomial_output,
    );
    let identifier = builder.plaintext_multiply(
        identifier_polynomial_output,
        plaintext_topology.identifier_selector.clone(),
    )?;
    #[cfg(test)]
    builder.record_stage(EvaluatorCompilerStage::FinalIdentifierTarget, identifier);
    let order = builder.plaintext_multiply(
        order_polynomial_output,
        plaintext_topology.order_selector.clone(),
    )?;
    #[cfg(test)]
    builder.record_stage(EvaluatorCompilerStage::FinalOrderTarget, order);
    if builder.state(identifier).level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
        || builder.state(order).level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
    {
        return Err(program_error(
            "compiled evaluator targets reached the wrong terminal level",
        ));
    }
    builder.finish(
        u16::try_from(top_count).expect("selected top count fits u16"),
        identifier,
        order,
    )
}

fn trace_pair_character_ciphertext(
    builder: &mut ProgramBuilder<'_>,
    ciphertext: Register,
    _ciphertext_ordinal: usize,
    comparison_trace_mask: &[u32],
) -> CanonicalResult<Register> {
    let ciphertext = builder.modulus_switch_to(ciphertext, TRACE_KEY_LEVEL)?;
    #[cfg(test)]
    builder.record_stage(
        EvaluatorCompilerStage::PretraceAfterLevelSwitch {
            ciphertext_ordinal: _ciphertext_ordinal,
        },
        ciphertext,
    );
    let mut trace = builder.plaintext_multiply(ciphertext, comparison_trace_mask.to_vec())?;
    #[cfg(test)]
    builder.record_stage(
        EvaluatorCompilerStage::ComparisonMaskedPretrace {
            ciphertext_ordinal: _ciphertext_ordinal,
        },
        trace,
    );
    for path in TRACE_GALOIS_PATHS {
        let mut rotated = trace;
        for galois_element in path {
            rotated = builder.rotate(rotated, *galois_element)?;
        }
        trace = builder.add(trace, rotated)?;
    }
    let trace = builder.modulus_switch_to(trace, SCATTER_KEY_LEVEL)?;
    #[cfg(test)]
    builder.record_stage(
        EvaluatorCompilerStage::FinalTraceOutput {
            ciphertext_ordinal: _ciphertext_ordinal,
        },
        trace,
    );
    Ok(trace)
}

fn scatter_pair_comparisons(
    builder: &mut ProgramBuilder<'_>,
    traced_ciphertexts: &BTreeMap<usize, Register>,
    plaintext_topology: &SelectedPlaintextTopology,
) -> CanonicalResult<Register> {
    if traced_ciphertexts.len() != plaintext_topology.active_ciphertext_ordinals.len()
        || plaintext_topology.route_source_masks.len() != plaintext_topology.scatter_routes.len()
    {
        return Err(program_error(
            "selected evaluator scatter input does not match its suite-fixed topology",
        ));
    }
    let mut routed_terms = Vec::with_capacity(plaintext_topology.scatter_routes.len());
    for (route, source_masks) in plaintext_topology
        .scatter_routes
        .iter()
        .copied()
        .zip(&plaintext_topology.route_source_masks)
    {
        let mut source_terms = Vec::with_capacity(source_masks.len());
        for source_mask in source_masks {
            let traced_ciphertext = traced_ciphertexts
                .get(&source_mask.ciphertext_ordinal)
                .copied()
                .ok_or_else(|| {
                    program_error("selected evaluator scatter source ciphertext is unavailable")
                })?;
            source_terms.push(
                builder.plaintext_multiply(traced_ciphertext, source_mask.coefficients.clone())?,
            );
        }
        let mut routed = builder.sum_aligned(&source_terms)?;
        for galois_element in route.galois_path() {
            routed = builder.rotate(routed, *galois_element)?;
        }
        #[cfg(test)]
        builder.record_stage(
            EvaluatorCompilerStage::RoutedScatterContribution {
                route_ordinal: routed_terms.len(),
            },
            routed,
        );
        routed_terms.push(routed);
    }
    let raw_scatter_sum = builder.sum_aligned(&routed_terms)?;
    #[cfg(test)]
    builder.record_stage(EvaluatorCompilerStage::RawScatterSum, raw_scatter_sum);
    let ranks = builder.plaintext_add(raw_scatter_sum, plaintext_topology.rank_base.clone())?;
    #[cfg(test)]
    builder.record_stage(EvaluatorCompilerStage::RankBaseAdjusted, ranks);
    Ok(ranks)
}

fn selected_plaintext_topology(option_count: usize) -> CanonicalResult<SelectedPlaintextTopology> {
    let mut comparison_trace_mask = vec![0_u32; POLYNOMIAL_DEGREE];
    comparison_trace_mask[0] = field_value(PLAINTEXT_MODULUS - 1)?;
    let strict_comparison_exponent_bound = usize::from(FOUNDATION_PROFILE.participant_count)
        .checked_mul(usize::from(
            FOUNDATION_PROFILE.maximum_score - FOUNDATION_PROFILE.minimum_score,
        ))
        .ok_or_else(|| program_error("selected comparison exponent bound overflowed"))?;
    for exponent in 1..strict_comparison_exponent_bound {
        comparison_trace_mask[POLYNOMIAL_DEGREE - exponent] = 1;
    }

    let assignments = pair_character_lane_assignments(option_count)?;
    let active_ciphertext_ordinals = assignments
        .iter()
        .map(|assignment| usize::from(assignment.ciphertext_ordinal()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut assignments_by_route_and_ciphertext =
        BTreeMap::<(u16, u16, usize), Vec<(usize, bool)>>::new();
    for assignment in assignments {
        let ciphertext_ordinal = usize::from(assignment.ciphertext_ordinal());
        let lane_ordinal = usize::from(assignment.lane_ordinal());
        let lower_option_ordinal = usize::from(assignment.lower_option_ordinal());
        let higher_option_ordinal = usize::from(assignment.higher_option_ordinal());
        let shift = higher_option_ordinal - lower_option_ordinal;
        let bank_ordinal = lane_ordinal / (PAIR_CHARACTER_LANE_COUNT / 2);
        let lane_within_bank = lane_ordinal % (PAIR_CHARACTER_LANE_COUNT / 2);
        let lane_start = (lane_within_bank + PAIR_CHARACTER_LANE_COUNT / 2 - lower_option_ordinal)
            % (PAIR_CHARACTER_LANE_COUNT / 2);
        assignments_by_route_and_ciphertext
            .entry((
                u16::try_from(bank_ordinal).expect("selected bank fits u16"),
                u16::try_from(lane_start).expect("selected lane start fits u16"),
                ciphertext_ordinal,
            ))
            .or_default()
            .push((lane_ordinal, true));
        let higher_start =
            (lane_start + PAIR_CHARACTER_LANE_COUNT / 2 - shift) % (PAIR_CHARACTER_LANE_COUNT / 2);
        assignments_by_route_and_ciphertext
            .entry((
                u16::try_from(bank_ordinal).expect("selected bank fits u16"),
                u16::try_from(higher_start).expect("selected lane start fits u16"),
                ciphertext_ordinal,
            ))
            .or_default()
            .push((lane_ordinal, false));
    }

    let expected_source_mask_count = assignments_by_route_and_ciphertext.len();
    let mut scatter_routes = Vec::with_capacity(SCATTER_ROUTES.len());
    let mut route_source_masks = Vec::with_capacity(SCATTER_ROUTES.len());
    let mut source_mask_count = 0_usize;
    for route in SCATTER_ROUTES {
        let coordinate = route.coordinate();
        let mut source_masks = Vec::new();
        for ciphertext_ordinal in 0..PAIR_CHARACTER_CIPHERTEXT_COUNT {
            let Some(lane_signs) = assignments_by_route_and_ciphertext.remove(&(
                coordinate.bank_ordinal(),
                coordinate.lane_start(),
                ciphertext_ordinal,
            )) else {
                continue;
            };
            source_masks.push(RouteSourceMask {
                ciphertext_ordinal,
                coefficients: signed_lane_mask(&lane_signs)?,
            });
            source_mask_count += 1;
        }
        if source_masks.is_empty() {
            continue;
        }
        scatter_routes.push(route);
        route_source_masks.push(source_masks);
    }
    if !assignments_by_route_and_ciphertext.is_empty()
        || source_mask_count != expected_source_mask_count
        || scatter_routes.is_empty()
    {
        return Err(program_error(
            "selected evaluator scatter catalog omits or duplicates a source mask",
        ));
    }

    let rank_base = scalar_lane_coefficients(
        &(0..option_count)
            .map(|option_ordinal| {
                u64::try_from(option_ordinal).expect("selected option ordinal fits u64")
            })
            .collect::<Vec<_>>(),
    )?;
    let identifier_selector = scalar_lane_coefficients(
        &(0..option_count)
            .map(|option_ordinal| {
                u64::try_from(option_ordinal + 1).expect("selected option identifier fits u64")
            })
            .collect::<Vec<_>>(),
    )?;
    let order_selector = scalar_lane_coefficients(&vec![1; option_count])?;
    Ok(SelectedPlaintextTopology {
        comparison_trace_mask,
        active_ciphertext_ordinals,
        scatter_routes,
        route_source_masks,
        rank_base,
        identifier_selector,
        order_selector,
    })
}

fn signed_lane_mask(lane_signs: &[(usize, bool)]) -> CanonicalResult<Vec<u32>> {
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    for (lane_ordinal, positive) in lane_signs {
        for (lane_coefficient_ordinal, idempotent_coefficient) in
            pair_character_lane_idempotent_coefficients(*lane_ordinal)?
                .into_iter()
                .enumerate()
        {
            let coefficient_ordinal = lane_coefficient_ordinal * PAIR_CHARACTER_LANE_DEGREE;
            coefficients[coefficient_ordinal] = if *positive {
                add_mod(
                    coefficients[coefficient_ordinal],
                    idempotent_coefficient,
                    PLAINTEXT_MODULUS,
                )?
            } else {
                sub_mod(
                    coefficients[coefficient_ordinal],
                    idempotent_coefficient,
                    PLAINTEXT_MODULUS,
                )?
            };
        }
    }
    coefficients.into_iter().map(field_value).collect()
}

fn scalar_lane_coefficients(lane_values: &[u64]) -> CanonicalResult<Vec<u32>> {
    if lane_values.len() > PAIR_CHARACTER_LANE_COUNT {
        return Err(program_error(
            "selected evaluator scalar lane vector exceeds the plaintext lane count",
        ));
    }
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    for (lane_ordinal, value) in lane_values.iter().copied().enumerate() {
        for (lane_coefficient_ordinal, idempotent_coefficient) in
            pair_character_lane_idempotent_coefficients(lane_ordinal)?
                .into_iter()
                .enumerate()
        {
            let coefficient_ordinal = lane_coefficient_ordinal * PAIR_CHARACTER_LANE_DEGREE;
            coefficients[coefficient_ordinal] = add_mod(
                coefficients[coefficient_ordinal],
                mul_mod(value, idempotent_coefficient, PLAINTEXT_MODULUS)?,
                PLAINTEXT_MODULUS,
            )?;
        }
    }
    coefficients.into_iter().map(field_value).collect()
}

#[derive(Clone, Copy)]
struct ScheduledRegisterPower {
    register: Register,
    multiplication_depth: usize,
}

struct PreparedRankPowers {
    input: Register,
    coefficient_count: usize,
    baby_powers: Vec<Option<ScheduledRegisterPower>>,
    giant_powers: Vec<Option<ScheduledRegisterPower>>,
}

fn prepare_rank_powers(
    builder: &mut ProgramBuilder<'_>,
    input: Register,
    coefficient_count: usize,
) -> CanonicalResult<PreparedRankPowers> {
    if !(usize::from(MINIMUM_CONFIGURABLE_OPTION_COUNT)
        ..=usize::from(MAXIMUM_CONFIGURABLE_OPTION_COUNT))
        .contains(&coefficient_count)
    {
        return Err(program_error(
            "compiled rank power schedule received an invalid coefficient count",
        ));
    }
    let block_count = coefficient_count.div_ceil(RANK_LOOKUP_BABY_STEP_COUNT);
    let highest_baby_power = if block_count > 1 {
        RANK_LOOKUP_BABY_STEP_COUNT
    } else {
        coefficient_count - 1
    };
    let depth_drop_counts = &SELECTED_EVALUATOR_MODULUS_SCHEDULE.rank_depth_drop_counts;
    let baby_powers = build_power_table(
        builder,
        ScheduledRegisterPower {
            register: input,
            multiplication_depth: 0,
        },
        highest_baby_power,
        depth_drop_counts,
    )?;
    let giant_powers = if block_count > 1 {
        let giant_base = baby_powers[RANK_LOOKUP_BABY_STEP_COUNT]
            .ok_or_else(|| program_error("compiled evaluator omitted rank giant-step base"))?;
        build_power_table(builder, giant_base, block_count - 1, depth_drop_counts)?
    } else {
        vec![None]
    };
    #[cfg(test)]
    for (rank_exponent, scheduled_power) in baby_powers.iter().enumerate() {
        if let Some(scheduled_power) = scheduled_power {
            builder.record_stage(
                EvaluatorCompilerStage::PreparedBabyRankPower { rank_exponent },
                scheduled_power.register,
            );
        }
    }
    #[cfg(test)]
    for (giant_power, scheduled_power) in giant_powers.iter().enumerate() {
        if let Some(scheduled_power) = scheduled_power {
            builder.record_stage(
                EvaluatorCompilerStage::PreparedGiantRankPower {
                    rank_exponent: giant_power * RANK_LOOKUP_BABY_STEP_COUNT,
                },
                scheduled_power.register,
            );
        }
    }
    Ok(PreparedRankPowers {
        input,
        coefficient_count,
        baby_powers,
        giant_powers,
    })
}

fn build_power_table(
    builder: &mut ProgramBuilder<'_>,
    base: ScheduledRegisterPower,
    highest_power: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<Vec<Option<ScheduledRegisterPower>>> {
    let mut powers = vec![None; highest_power + 1];
    if highest_power >= 1 {
        powers[1] = Some(base);
    }
    for product in scheduled_power_table_products(highest_power, base.multiplication_depth)? {
        let left = powers[product.lower_power]
            .ok_or_else(|| program_error("compiled rank power table is incomplete"))?;
        let right = powers[product.upper_power]
            .ok_or_else(|| program_error("compiled rank power table is incomplete"))?;
        let multiplication_depth = left
            .multiplication_depth
            .max(right.multiplication_depth)
            .checked_add(1)
            .ok_or_else(|| program_error("compiled rank multiplication depth overflowed"))?;
        let drop_count = *depth_drop_counts
            .get(multiplication_depth - 1)
            .ok_or_else(|| program_error("compiled rank multiplication exceeded its schedule"))?;
        powers[product.output_power] = Some(ScheduledRegisterPower {
            register: builder.multiply_with_drop_count(
                left.register,
                right.register,
                drop_count,
            )?,
            multiplication_depth,
        });
    }
    Ok(powers)
}

fn evaluate_rank_polynomial(
    builder: &mut ProgramBuilder<'_>,
    prepared: &PreparedRankPowers,
    coefficients: &[u64],
) -> CanonicalResult<Register> {
    if coefficients.len() != prepared.coefficient_count {
        return Err(program_error(
            "compiled rank polynomial does not match its power schedule",
        ));
    }
    let mut terms = Vec::with_capacity(coefficients.len().div_ceil(RANK_LOOKUP_BABY_STEP_COUNT));
    for (block_index, block) in coefficients.chunks(RANK_LOOKUP_BABY_STEP_COUNT).enumerate() {
        let block_value = linear_combination_from_baby_powers(builder, prepared, block)?;
        let term = if block_index == 0 {
            block_value
        } else {
            let giant_power = prepared.giant_powers[block_index]
                .ok_or_else(|| program_error("compiled evaluator omitted a rank giant power"))?;
            builder.multiply_without_drop(block_value, giant_power.register)?
        };
        terms.push(term);
    }
    let result = builder.sum_aligned(&terms)?;
    let result = builder.modulus_switch_to(result, CANONICAL_TARGET_CIPHERTEXT_LEVEL)?;
    builder.normalize(result)
}

fn linear_combination_from_baby_powers(
    builder: &mut ProgramBuilder<'_>,
    prepared: &PreparedRankPowers,
    coefficients: &[u64],
) -> CanonicalResult<Register> {
    if coefficients.is_empty() || coefficients.len() > RANK_LOOKUP_BABY_STEP_COUNT {
        return Err(program_error(
            "compiled rank polynomial block has an invalid coefficient count",
        ));
    }
    let anchor_level = prepared.baby_powers[1..coefficients.len()]
        .iter()
        .flatten()
        .map(|power| builder.state(power.register).level)
        .min()
        .unwrap_or_else(|| builder.state(prepared.input).level);
    let anchor = builder.modulus_switch_to(prepared.input, anchor_level)?;
    let anchor = builder.normalize(anchor)?;
    let encrypted_zero = builder.plaintext_multiply_scalar(anchor, 0)?;
    let mut result = builder.plaintext_add(encrypted_zero, vec![field_value(coefficients[0])?])?;
    for (scheduled_power, coefficient) in prepared.baby_powers[1..coefficients.len()]
        .iter()
        .zip(&coefficients[1..])
    {
        let power_register =
            scheduled_power.ok_or_else(|| program_error("compiled rank baby power is missing"))?;
        let power_register = builder.modulus_switch_to(power_register.register, anchor_level)?;
        let power_register = builder.normalize(power_register)?;
        let scaled = builder.plaintext_multiply_scalar(power_register, *coefficient)?;
        result = builder.add(result, scaled)?;
    }
    Ok(result)
}

fn field_value(value: u64) -> CanonicalResult<u32> {
    if value >= PLAINTEXT_MODULUS {
        return Err(program_error(
            "compiled evaluator constant is outside the plaintext field",
        ));
    }
    u32::try_from(value).map_err(|_| {
        crate::encoding::CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "compiled evaluator field value does not fit u32",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn centered_l1(coefficients: &[u32]) -> u64 {
        coefficients
            .iter()
            .map(|coefficient| {
                let coefficient = u64::from(*coefficient);
                coefficient.min(PLAINTEXT_MODULUS - coefficient)
            })
            .sum()
    }

    #[test]
    fn selected_plaintext_topology_covers_every_pair_contribution_once() {
        let topology = selected_plaintext_topology(SELECTED_OPTION_COUNT)
            .expect("selected plaintext topology");
        assert_eq!(centered_l1(&topology.comparison_trace_mask), 90);
        let expected_source_mask_count = pair_character_lane_assignments(SELECTED_OPTION_COUNT)
            .expect("selected pair assignments derive")
            .into_iter()
            .flat_map(|assignment| {
                let lane_ordinal = usize::from(assignment.lane_ordinal());
                let lower_option_ordinal = usize::from(assignment.lower_option_ordinal());
                let higher_option_ordinal = usize::from(assignment.higher_option_ordinal());
                let bank_lane_count = PAIR_CHARACTER_LANE_COUNT / 2;
                let bank_ordinal = lane_ordinal / bank_lane_count;
                let lane_within_bank = lane_ordinal % bank_lane_count;
                let lower_start =
                    (lane_within_bank + bank_lane_count - lower_option_ordinal) % bank_lane_count;
                let shift = higher_option_ordinal - lower_option_ordinal;
                let higher_start = (lower_start + bank_lane_count - shift) % bank_lane_count;
                [
                    (
                        bank_ordinal,
                        lower_start,
                        usize::from(assignment.ciphertext_ordinal()),
                    ),
                    (
                        bank_ordinal,
                        higher_start,
                        usize::from(assignment.ciphertext_ordinal()),
                    ),
                ]
            })
            .collect::<BTreeSet<_>>()
            .len();
        assert_eq!(
            topology
                .route_source_masks
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
            expected_source_mask_count
        );
        assert_eq!(
            topology.scatter_routes.len(),
            topology.route_source_masks.len()
        );
        assert!(topology.route_source_masks.iter().flatten().all(|mask| {
            mask.coefficients.len() == POLYNOMIAL_DEGREE && centered_l1(&mask.coefficients) > 0
        }));
        assert!(centered_l1(&topology.rank_base) > 0);
        assert!(centered_l1(&topology.identifier_selector) > 0);
        assert!(centered_l1(&topology.order_selector) > 0);
    }

    #[test]
    fn evaluator_program_compiler_derives_every_configurable_option_count() {
        for option_count in usize::from(MINIMUM_CONFIGURABLE_OPTION_COUNT)
            ..=usize::from(MAXIMUM_CONFIGURABLE_OPTION_COUNT)
        {
            let program = evaluator_program_set_for_option_count(option_count)
                .expect("bounded evaluator program derives");
            assert_eq!(program.streams().len(), option_count);
            assert!(
                program
                    .streams()
                    .iter()
                    .enumerate()
                    .all(|(stream_index, stream)| usize::from(stream.top_count())
                        == stream_index + 1)
            );
            assert_eq!(
                program
                    .key_positions()
                    .expect("bounded program key positions derive")
                    .streams()
                    .len(),
                option_count
            );
        }
        assert!(evaluator_program_set_for_option_count(1).is_err());
        assert!(evaluator_program_set_for_option_count(21).is_err());
    }

    #[test]
    fn selected_stage_registers_cover_semantic_boundaries_without_changing_instruction_bytes() {
        let canonical_program =
            selected_evaluator_program_set().expect("canonical selected evaluator program");
        let (observed_program, stream_stage_registers) =
            selected_evaluator_program_set_with_stage_registers()
                .expect("selected evaluator program with test-only stage registers");
        assert_eq!(
            canonical_program.encode().expect("canonical program bytes"),
            observed_program.encode().expect("observed program bytes"),
        );
        assert_eq!(
            stream_stage_registers.len(),
            observed_program.streams().len()
        );

        let selected_scatter_route_count = selected_plaintext_topology(SELECTED_OPTION_COUNT)
            .expect("selected topology derives")
            .scatter_routes
            .len();
        for (stream, stage_registers) in observed_program
            .streams()
            .iter()
            .zip(&stream_stage_registers)
        {
            assert_eq!(stage_registers.top_count(), stream.top_count());
            let produced_registers = stream
                .instructions()
                .iter()
                .filter_map(EvaluatorInstruction::output_register)
                .collect::<BTreeSet<_>>();
            let mut normalized_inputs = Vec::new();
            let mut switched_pretraces = Vec::new();
            let mut masked_pretraces = Vec::new();
            let mut final_traces = Vec::new();
            let mut scatter_routes = Vec::new();
            let mut raw_scatter_sums = Vec::new();
            let mut adjusted_ranks = Vec::new();
            let mut rank_inputs = Vec::new();
            let mut baby_rank_powers = Vec::new();
            let mut giant_rank_powers = Vec::new();
            let mut identifier_polynomials = Vec::new();
            let mut order_polynomials = Vec::new();
            let mut final_identifiers = Vec::new();
            let mut final_orders = Vec::new();

            for stage_register in stage_registers.stage_registers() {
                let register_ordinal = stage_register.register_ordinal();
                match stage_register.stage() {
                    EvaluatorCompilerStage::NormalizedCharacterProductInput {
                        ciphertext_ordinal,
                    } => normalized_inputs.push((ciphertext_ordinal, register_ordinal)),
                    EvaluatorCompilerStage::PretraceAfterLevelSwitch { ciphertext_ordinal } => {
                        switched_pretraces.push((ciphertext_ordinal, register_ordinal))
                    }
                    EvaluatorCompilerStage::ComparisonMaskedPretrace { ciphertext_ordinal } => {
                        masked_pretraces.push((ciphertext_ordinal, register_ordinal))
                    }
                    EvaluatorCompilerStage::FinalTraceOutput { ciphertext_ordinal } => {
                        final_traces.push((ciphertext_ordinal, register_ordinal))
                    }
                    EvaluatorCompilerStage::RoutedScatterContribution { route_ordinal } => {
                        scatter_routes.push((route_ordinal, register_ordinal));
                    }
                    EvaluatorCompilerStage::RawScatterSum => {
                        raw_scatter_sums.push(register_ordinal);
                    }
                    EvaluatorCompilerStage::RankBaseAdjusted => {
                        adjusted_ranks.push(register_ordinal);
                    }
                    EvaluatorCompilerStage::RankInputAfterLevelSwitch => {
                        rank_inputs.push(register_ordinal);
                    }
                    EvaluatorCompilerStage::PreparedBabyRankPower { rank_exponent } => {
                        baby_rank_powers.push((rank_exponent, register_ordinal));
                    }
                    EvaluatorCompilerStage::PreparedGiantRankPower { rank_exponent } => {
                        giant_rank_powers.push((rank_exponent, register_ordinal));
                    }
                    EvaluatorCompilerStage::IdentifierPolynomialBeforeSelector => {
                        identifier_polynomials.push(register_ordinal);
                    }
                    EvaluatorCompilerStage::OrderPolynomialBeforeSelector => {
                        order_polynomials.push(register_ordinal);
                    }
                    EvaluatorCompilerStage::FinalIdentifierTarget => {
                        final_identifiers.push(register_ordinal);
                    }
                    EvaluatorCompilerStage::FinalOrderTarget => {
                        final_orders.push(register_ordinal);
                    }
                }
                if !matches!(
                    stage_register.stage(),
                    EvaluatorCompilerStage::NormalizedCharacterProductInput { .. }
                ) {
                    assert!(
                        produced_registers.contains(&register_ordinal),
                        "compiler stage references register {register_ordinal} without a producing instruction",
                    );
                }
            }

            assert_eq!(normalized_inputs, vec![(0, 0), (1, 1)]);
            assert_eq!(
                switched_pretraces
                    .iter()
                    .map(|(ciphertext_ordinal, _)| *ciphertext_ordinal)
                    .collect::<Vec<_>>(),
                vec![0, 1]
            );
            assert_eq!(
                masked_pretraces
                    .iter()
                    .map(|(ciphertext_ordinal, _)| *ciphertext_ordinal)
                    .collect::<Vec<_>>(),
                vec![0, 1]
            );
            assert_eq!(
                final_traces
                    .iter()
                    .map(|(ciphertext_ordinal, _)| *ciphertext_ordinal)
                    .collect::<Vec<_>>(),
                vec![0, 1]
            );
            assert_eq!(
                scatter_routes
                    .iter()
                    .map(|(route_ordinal, _)| *route_ordinal)
                    .collect::<Vec<_>>(),
                (0..selected_scatter_route_count).collect::<Vec<_>>()
            );
            assert_eq!(raw_scatter_sums.len(), 1);
            assert_eq!(adjusted_ranks.len(), 1);
            assert_eq!(rank_inputs.len(), 1);
            assert_eq!(
                baby_rank_powers
                    .iter()
                    .map(|(rank_exponent, _)| *rank_exponent)
                    .collect::<Vec<_>>(),
                (1..=RANK_LOOKUP_BABY_STEP_COUNT).collect::<Vec<_>>()
            );
            assert_eq!(
                giant_rank_powers
                    .iter()
                    .map(|(rank_exponent, _)| *rank_exponent)
                    .collect::<Vec<_>>(),
                (1..SELECTED_OPTION_COUNT.div_ceil(RANK_LOOKUP_BABY_STEP_COUNT))
                    .map(|giant_power| giant_power * RANK_LOOKUP_BABY_STEP_COUNT)
                    .collect::<Vec<_>>()
            );
            assert_eq!(identifier_polynomials.len(), 1);
            assert_eq!(order_polynomials.len(), 1);
            assert_eq!(final_identifiers.len(), 1);
            assert_eq!(final_orders.len(), 1);

            let instructions = stream.instructions();
            assert_eq!(
                final_identifiers[0],
                instructions[instructions.len() - 2].input_registers()[0]
            );
            assert_eq!(
                final_orders[0],
                instructions[instructions.len() - 1].input_registers()[0]
            );
        }
    }

    #[test]
    fn selected_rank_indicator_coefficients_pin_worst_top_count() {
        let values = (0..SELECTED_OPTION_COUNT)
            .map(|rank| u64::from(rank < 8))
            .collect::<Vec<_>>();
        let coefficients = interpolate_coefficients(&values).expect("rank indicator polynomial");
        assert_eq!(coefficients.len(), SELECTED_OPTION_COUNT);
        for (rank, expected) in values.into_iter().enumerate() {
            let rank = u64::try_from(rank).expect("rank fits u64");
            let observed = coefficients.iter().rev().fold(0_u64, |value, coefficient| {
                (value * rank + coefficient) % PLAINTEXT_MODULUS
            });
            assert_eq!(observed, expected);
        }
    }
}

#[cfg(test)]
mod semantic_tests;
