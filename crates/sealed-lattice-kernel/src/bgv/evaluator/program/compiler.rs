use std::collections::{BTreeMap, BTreeSet};

use crate::{
    bgv::{
        direct_ballots::{
            PAIR_CHARACTER_CIPHERTEXT_COUNT, PAIR_CHARACTER_LANE_COUNT, PAIR_CHARACTER_LANE_DEGREE,
            pair_character_lane_idempotent_coefficients, selected_pair_character_lane_assignments,
        },
        modular_arithmetic::{add_mod, mul_mod, sub_mod},
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
    CANONICAL_TARGET_CIPHERTEXT_LEVEL, CHARACTER_OUTPUT_LEVEL, RANK_INPUT_LEVEL,
    RANK_LOOKUP_BABY_STEP_COUNT, SCATTER_KEY_LEVEL, SCATTER_ROUTES,
    SELECTED_EVALUATOR_MODULUS_SCHEDULE, TRACE_GALOIS_PATHS, TRACE_KEY_LEVEL,
    interpolate_coefficients, scheduled_power_table_products,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Register(u32);

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
        }
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

#[derive(Clone)]
struct RouteSourceMask {
    ciphertext_ordinal: usize,
    coefficients: Vec<u32>,
}

struct SelectedPlaintextTopology {
    comparison_trace_mask: Vec<u32>,
    route_source_masks: Vec<Vec<RouteSourceMask>>,
    rank_base: Vec<u32>,
    identifier_selector: Vec<u32>,
    order_selector: Vec<u32>,
}

pub(crate) fn selected_evaluator_program_set() -> CanonicalResult<EvaluatorProgramSet> {
    if usize::from(FOUNDATION_PROFILE.option_count) != SELECTED_OPTION_COUNT
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
    let plaintext_topology = selected_plaintext_topology()?;
    let mut constants = ConstantCatalog::default();
    let mut streams = Vec::with_capacity(SELECTED_OPTION_COUNT);
    for top_count in 1..=SELECTED_OPTION_COUNT {
        streams.push(compile_stream(
            &mut constants,
            &plaintext_topology,
            u16::try_from(top_count).expect("selected top count fits u16"),
        )?);
    }
    EvaluatorProgramSet::new(constants.into_sorted_constants(), streams)
}

fn compile_stream(
    constants: &mut ConstantCatalog,
    plaintext_topology: &SelectedPlaintextTopology,
    top_count: u16,
) -> CanonicalResult<EvaluatorInstructionStream> {
    let mut builder = ProgramBuilder::new(constants);
    let traced_ciphertexts = (0..PAIR_CHARACTER_CIPHERTEXT_COUNT)
        .map(|ciphertext_ordinal| {
            let ciphertext = builder.input(ciphertext_ordinal)?;
            trace_pair_character_ciphertext(
                &mut builder,
                ciphertext,
                &plaintext_topology.comparison_trace_mask,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let ranks = scatter_pair_comparisons(&mut builder, &traced_ciphertexts, plaintext_topology)?;
    let ranks = builder.modulus_switch_to(ranks, RANK_INPUT_LEVEL)?;
    let prepared_powers = prepare_rank_powers(&mut builder, ranks)?;

    let top_count = usize::from(top_count);
    let identifier_values = (0..SELECTED_OPTION_COUNT)
        .map(|rank| u64::from(rank < top_count))
        .collect::<Vec<_>>();
    let order_values = (0..SELECTED_OPTION_COUNT)
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
    let identifier =
        evaluate_rank_polynomial(&mut builder, &prepared_powers, &identifier_polynomial)?;
    let order = evaluate_rank_polynomial(&mut builder, &prepared_powers, &order_polynomial)?;
    let identifier =
        builder.plaintext_multiply(identifier, plaintext_topology.identifier_selector.clone())?;
    let order = builder.plaintext_multiply(order, plaintext_topology.order_selector.clone())?;
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
    comparison_trace_mask: &[u32],
) -> CanonicalResult<Register> {
    let ciphertext = builder.modulus_switch_to(ciphertext, TRACE_KEY_LEVEL)?;
    let mut trace = builder.plaintext_multiply(ciphertext, comparison_trace_mask.to_vec())?;
    for path in TRACE_GALOIS_PATHS {
        let mut rotated = trace;
        for galois_element in path {
            rotated = builder.rotate(rotated, *galois_element)?;
        }
        trace = builder.add(trace, rotated)?;
    }
    builder.modulus_switch_to(trace, SCATTER_KEY_LEVEL)
}

fn scatter_pair_comparisons(
    builder: &mut ProgramBuilder<'_>,
    traced_ciphertexts: &[Register],
    plaintext_topology: &SelectedPlaintextTopology,
) -> CanonicalResult<Register> {
    if traced_ciphertexts.len() != PAIR_CHARACTER_CIPHERTEXT_COUNT
        || plaintext_topology.route_source_masks.len() != SCATTER_ROUTES.len()
    {
        return Err(program_error(
            "selected evaluator scatter input does not match its suite-fixed topology",
        ));
    }
    let mut routed_terms = Vec::with_capacity(SCATTER_ROUTES.len());
    for (route, source_masks) in SCATTER_ROUTES
        .iter()
        .copied()
        .zip(&plaintext_topology.route_source_masks)
    {
        let mut source_terms = Vec::with_capacity(source_masks.len());
        for source_mask in source_masks {
            source_terms.push(builder.plaintext_multiply(
                traced_ciphertexts[source_mask.ciphertext_ordinal],
                source_mask.coefficients.clone(),
            )?);
        }
        let mut routed = builder.sum_aligned(&source_terms)?;
        for galois_element in route.galois_path() {
            routed = builder.rotate(routed, *galois_element)?;
        }
        routed_terms.push(routed);
    }
    let ranks = builder.sum_aligned(&routed_terms)?;
    builder.plaintext_add(ranks, plaintext_topology.rank_base.clone())
}

fn selected_plaintext_topology() -> CanonicalResult<SelectedPlaintextTopology> {
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

    let assignments = selected_pair_character_lane_assignments()?;
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
        let higher_bank = 1 - bank_ordinal;
        let higher_start =
            (lane_start + PAIR_CHARACTER_LANE_COUNT / 2 - shift) % (PAIR_CHARACTER_LANE_COUNT / 2);
        assignments_by_route_and_ciphertext
            .entry((
                u16::try_from(higher_bank).expect("selected bank fits u16"),
                u16::try_from(higher_start).expect("selected lane start fits u16"),
                ciphertext_ordinal,
            ))
            .or_default()
            .push((lane_ordinal, false));
    }

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
            return Err(program_error(
                "selected evaluator scatter route has no pair contribution",
            ));
        }
        route_source_masks.push(source_masks);
    }
    if !assignments_by_route_and_ciphertext.is_empty() || source_mask_count != 29 {
        return Err(program_error(
            "selected evaluator scatter catalog does not contain exactly twenty-nine source masks",
        ));
    }

    let rank_base = scalar_lane_coefficients(
        &(0..SELECTED_OPTION_COUNT)
            .map(|option_ordinal| {
                u64::try_from(option_ordinal).expect("selected option ordinal fits u64")
            })
            .collect::<Vec<_>>(),
    )?;
    let identifier_selector = scalar_lane_coefficients(
        &(0..SELECTED_OPTION_COUNT)
            .map(|option_ordinal| {
                u64::try_from(option_ordinal + 1).expect("selected option identifier fits u64")
            })
            .collect::<Vec<_>>(),
    )?;
    let order_selector = scalar_lane_coefficients(&[1; SELECTED_OPTION_COUNT])?;
    Ok(SelectedPlaintextTopology {
        comparison_trace_mask,
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
    baby_powers: Vec<Option<ScheduledRegisterPower>>,
    giant_powers: Vec<Option<ScheduledRegisterPower>>,
}

fn prepare_rank_powers(
    builder: &mut ProgramBuilder<'_>,
    input: Register,
) -> CanonicalResult<PreparedRankPowers> {
    let depth_drop_counts = &SELECTED_EVALUATOR_MODULUS_SCHEDULE.rank_depth_drop_counts;
    let baby_powers = build_power_table(
        builder,
        ScheduledRegisterPower {
            register: input,
            multiplication_depth: 0,
        },
        RANK_LOOKUP_BABY_STEP_COUNT,
        depth_drop_counts,
    )?;
    let giant_base = baby_powers[RANK_LOOKUP_BABY_STEP_COUNT]
        .ok_or_else(|| program_error("compiled evaluator omitted rank giant-step base"))?;
    let giant_powers = build_power_table(builder, giant_base, 3, depth_drop_counts)?;
    Ok(PreparedRankPowers {
        input,
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
    if coefficients.len() != SELECTED_OPTION_COUNT {
        return Err(program_error(
            "compiled rank polynomial does not have degree nineteen",
        ));
    }
    let mut terms = Vec::with_capacity(4);
    for block_index in 0..4 {
        let start = block_index * RANK_LOOKUP_BABY_STEP_COUNT;
        let block = &coefficients[start..start + RANK_LOOKUP_BABY_STEP_COUNT];
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
    builder.sum_aligned(&terms)
}

fn linear_combination_from_baby_powers(
    builder: &mut ProgramBuilder<'_>,
    prepared: &PreparedRankPowers,
    coefficients: &[u64],
) -> CanonicalResult<Register> {
    let anchor_level = prepared.baby_powers[1..RANK_LOOKUP_BABY_STEP_COUNT]
        .iter()
        .flatten()
        .map(|power| builder.state(power.register).level)
        .min()
        .ok_or_else(|| program_error("compiled rank baby powers are empty"))?;
    let anchor = builder.modulus_switch_to(prepared.input, anchor_level)?;
    let anchor = builder.normalize(anchor)?;
    let encrypted_zero = builder.plaintext_multiply_scalar(anchor, 0)?;
    let mut result = builder.plaintext_add(encrypted_zero, vec![field_value(coefficients[0])?])?;
    for (scheduled_power, coefficient) in prepared.baby_powers[1..RANK_LOOKUP_BABY_STEP_COUNT]
        .iter()
        .zip(&coefficients[1..RANK_LOOKUP_BABY_STEP_COUNT])
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
    fn selected_plaintext_topology_pins_all_twenty_nine_route_masks() {
        let topology = selected_plaintext_topology().expect("selected plaintext topology");
        assert_eq!(centered_l1(&topology.comparison_trace_mask), 90);
        assert_eq!(
            topology
                .route_source_masks
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
            29
        );
        assert_eq!(
            topology
                .route_source_masks
                .iter()
                .map(|masks| masks
                    .iter()
                    .map(|mask| centered_l1(&mask.coefficients))
                    .collect())
                .collect::<Vec<Vec<u64>>>(),
            vec![
                vec![8_256, 8_443],
                vec![8_669],
                vec![7_943, 8_327],
                vec![5_756, 8_223],
                vec![8_689],
                vec![8_453],
                vec![7_680],
                vec![8_015],
                vec![7_586, 7_625],
                vec![7_778, 7_387],
                vec![7_943, 8_524],
                vec![8_354, 7_937],
                vec![8_089, 8_327],
                vec![5_756, 8_416],
                vec![7_520],
                vec![7_240],
                vec![8_256, 7_823],
                vec![7_942, 8_015],
            ]
        );
        assert_eq!(centered_l1(&topology.rank_base), 8_395);
        assert_eq!(centered_l1(&topology.identifier_selector), 8_607);
        assert_eq!(centered_l1(&topology.order_selector), 8_042);
    }

    #[test]
    fn selected_rank_indicator_coefficients_pin_worst_top_count() {
        let values = (0..SELECTED_OPTION_COUNT)
            .map(|rank| u64::from(rank < 8))
            .collect::<Vec<_>>();
        assert_eq!(
            interpolate_coefficients(&values).expect("rank indicator polynomial"),
            vec![
                1, 128, 180, 129, 245, 129, 182, 222, 125, 132, 203, 129, 64, 92, 191, 155, 230,
                230, 110, 208,
            ]
        );
    }
}
