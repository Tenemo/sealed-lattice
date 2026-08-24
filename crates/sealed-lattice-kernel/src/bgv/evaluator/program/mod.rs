use std::collections::{BTreeMap, BTreeSet};

use crate::{
    bgv::{
        direct_ballots::PAIR_CHARACTER_CIPHERTEXT_COUNT,
        modular_arithmetic::mul_mod,
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_OPTION_COUNT,
    },
};

use super::top_k::{
    CANONICAL_TARGET_CIPHERTEXT_LEVEL, CHARACTER_OUTPUT_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL,
    selected_evaluator_rotation_key_schedule,
};

mod codec;
mod compiler;
mod executor;
mod runtime;

pub(crate) use codec::verify_canonical_program_set;
pub(super) use compiler::evaluator_program_set_for_option_count;
pub(crate) use compiler::selected_evaluator_program_set;
#[cfg(test)]
pub(crate) use compiler::{
    EvaluatorCompilerStage, EvaluatorCompilerStreamStageRegisters,
    selected_evaluator_program_set_with_stage_registers,
};
pub(crate) use executor::{
    PreparedSelectedEvaluatorReplay, SelectedEvaluatorExecutionProgress,
    SelectedEvaluatorProgramExecution, VerifiedEvaluatorAggregate,
    VerifiedEvaluatorAggregateContext, VerifiedEvaluatorAggregateExecutionAuthority,
    VerifiedEvaluatorAggregationAuthority,
};
pub(crate) const EVALUATOR_PROGRAM_SET_SCHEMA_IDENTIFIER: u16 = 0x1500;
pub(crate) const EVALUATOR_INSTRUCTION_SCHEMA_IDENTIFIER: u16 = 0x1501;
pub(crate) const EVALUATOR_CONSTANT_SCHEMA_IDENTIFIER: u16 = 0x1503;
pub(crate) const EVALUATOR_INSTRUCTION_STREAM_SCHEMA_IDENTIFIER: u16 = 0x1504;

const EVALUATOR_PROGRAM_SCHEMA_VERSION: u16 = 1;
const EVALUATOR_CONSTANT_HASH_DOMAIN: &str = "sealed-lattice/evaluator/constant/v1";
const SELECTED_OPTION_COUNT: usize = FOUNDATION_PROFILE.option_count as usize;
const MAXIMUM_EVALUATOR_STREAM_COUNT: usize = MAXIMUM_CONFIGURABLE_OPTION_COUNT as usize;
const MAXIMUM_EVALUATOR_CONSTANT_COUNT: usize = 1_024;
const MAXIMUM_INSTRUCTIONS_PER_STREAM: usize = 4_096;
const MAXIMUM_LIVE_REGISTER_COUNT: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum EvaluatorConstantKind {
    CoefficientVector = 1,
}

impl EvaluatorConstantKind {
    const fn canonical_code(self) -> u16 {
        self as u16
    }

    fn from_canonical_code(code: u16) -> CanonicalResult<Self> {
        match code {
            1 => Ok(Self::CoefficientVector),
            _ => Err(program_error(
                "evaluator constant kind is outside the selected profile",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatorConstant {
    kind: EvaluatorConstantKind,
    values: Vec<u32>,
}

impl EvaluatorConstant {
    fn new(kind: EvaluatorConstantKind, values: Vec<u32>) -> CanonicalResult<Self> {
        let constant = Self { kind, values };
        constant.validate()?;
        Ok(constant)
    }

    pub(crate) const fn kind(&self) -> EvaluatorConstantKind {
        self.kind
    }

    pub(crate) fn values(&self) -> &[u32] {
        &self.values
    }

    fn validate(&self) -> CanonicalResult<()> {
        if self.values.is_empty() {
            return Err(program_error("evaluator constant values must be nonempty"));
        }
        if self.values.len() > POLYNOMIAL_DEGREE {
            return Err(program_error(
                "evaluator coefficient vector exceeds the selected ring degree",
            ));
        }
        if self
            .values
            .iter()
            .any(|value| u64::from(*value) >= PLAINTEXT_MODULUS)
        {
            return Err(program_error(
                "evaluator constant contains a noncanonical plaintext-field element",
            ));
        }
        Ok(())
    }

    pub(crate) fn constant_hash(&self) -> CanonicalResult<Hash512> {
        codec::hash_constant(self, EVALUATOR_CONSTANT_HASH_DOMAIN)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum EvaluatorOpcode {
    ModulusSwitchToLevel = 1,
    NormalizeDecryptionMultiplier = 2,
    CiphertextAdd = 3,
    PlaintextAdd = 6,
    PlaintextMultiply = 7,
    CiphertextMultiplyRelinearizeAndDrop = 8,
    CiphertextMultiplyAndRelinearize = 9,
    GaloisRotate = 10,
    DropRegister = 11,
    DeclareOutput = 12,
}

impl EvaluatorOpcode {
    const fn canonical_code(self) -> u16 {
        self as u16
    }

    fn from_canonical_code(code: u16) -> CanonicalResult<Self> {
        match code {
            1 => Ok(Self::ModulusSwitchToLevel),
            2 => Ok(Self::NormalizeDecryptionMultiplier),
            3 => Ok(Self::CiphertextAdd),
            6 => Ok(Self::PlaintextAdd),
            7 => Ok(Self::PlaintextMultiply),
            8 => Ok(Self::CiphertextMultiplyRelinearizeAndDrop),
            9 => Ok(Self::CiphertextMultiplyAndRelinearize),
            10 => Ok(Self::GaloisRotate),
            11 => Ok(Self::DropRegister),
            12 => Ok(Self::DeclareOutput),
            _ => Err(program_error(
                "evaluator opcode is outside the selected profile",
            )),
        }
    }

    const fn produces_register(self) -> bool {
        !matches!(self, Self::DropRegister | Self::DeclareOutput)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatorInstruction {
    opcode: EvaluatorOpcode,
    output_register: Option<u32>,
    input_registers: Vec<u32>,
    immediate0: u64,
    immediate1: u64,
    constant_hash: Option<Hash512>,
}

impl EvaluatorInstruction {
    fn new(
        opcode: EvaluatorOpcode,
        output_register: Option<u32>,
        input_registers: Vec<u32>,
        immediate0: u64,
        immediate1: u64,
        constant_hash: Option<Hash512>,
    ) -> CanonicalResult<Self> {
        let instruction = Self {
            opcode,
            output_register,
            input_registers,
            immediate0,
            immediate1,
            constant_hash,
        };
        instruction.validate_shape()?;
        Ok(instruction)
    }

    fn validate_shape(&self) -> CanonicalResult<()> {
        if self.immediate1 != 0 {
            return Err(program_error(
                "version-one evaluator instruction immediate one must be zero",
            ));
        }
        let (expected_input_count, output_required, immediate_rule, constant_rule) = match self
            .opcode
        {
            EvaluatorOpcode::ModulusSwitchToLevel => {
                (1, true, ImmediateRule::Any, ConstantRule::Absent)
            }
            EvaluatorOpcode::NormalizeDecryptionMultiplier => {
                (1, true, ImmediateRule::Nonzero, ConstantRule::Absent)
            }
            EvaluatorOpcode::CiphertextAdd => (2, true, ImmediateRule::Zero, ConstantRule::Absent),
            EvaluatorOpcode::PlaintextAdd | EvaluatorOpcode::PlaintextMultiply => {
                (1, true, ImmediateRule::Zero, ConstantRule::Present)
            }
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                (2, true, ImmediateRule::Zero, ConstantRule::Absent)
            }
            EvaluatorOpcode::GaloisRotate => {
                (1, true, ImmediateRule::Nonzero, ConstantRule::Absent)
            }
            EvaluatorOpcode::DropRegister => (1, false, ImmediateRule::Zero, ConstantRule::Absent),
            EvaluatorOpcode::DeclareOutput => {
                (1, false, ImmediateRule::OutputRole, ConstantRule::Absent)
            }
        };
        if self.input_registers.len() != expected_input_count {
            return Err(program_error(
                "evaluator instruction input-register arity is invalid",
            ));
        }
        if self.output_register.is_some() != output_required {
            return Err(program_error(
                "evaluator instruction output-register presence is invalid",
            ));
        }
        match immediate_rule {
            ImmediateRule::Zero if self.immediate0 != 0 => {
                return Err(program_error(
                    "evaluator instruction immediate zero must be zero",
                ));
            }
            ImmediateRule::Nonzero if self.immediate0 == 0 => {
                return Err(program_error(
                    "evaluator instruction immediate zero must be nonzero",
                ));
            }
            ImmediateRule::OutputRole if !matches!(self.immediate0, 1 | 2) => {
                return Err(program_error("evaluator output role is unassigned"));
            }
            _ => {}
        }
        if self.constant_hash.is_some() != matches!(constant_rule, ConstantRule::Present) {
            return Err(program_error(
                "evaluator instruction constant-hash presence is invalid",
            ));
        }
        Ok(())
    }

    pub(super) const fn opcode(&self) -> EvaluatorOpcode {
        self.opcode
    }

    pub(super) const fn output_register(&self) -> Option<u32> {
        self.output_register
    }

    pub(super) fn input_registers(&self) -> &[u32] {
        &self.input_registers
    }

    pub(super) const fn immediate0(&self) -> u64 {
        self.immediate0
    }

    pub(super) const fn constant_hash(&self) -> Option<Hash512> {
        self.constant_hash
    }
}

#[derive(Debug, Clone, Copy)]
enum ImmediateRule {
    Any,
    Zero,
    Nonzero,
    OutputRole,
}

#[derive(Debug, Clone, Copy)]
enum ConstantRule {
    Absent,
    Present,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatorInstructionStream {
    top_count: u16,
    instructions: Vec<EvaluatorInstruction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EvaluatorGaloisKeyPosition {
    catalog_level: usize,
    galois_element: usize,
}

impl EvaluatorGaloisKeyPosition {
    pub(crate) const fn galois_element(self) -> usize {
        self.galois_element
    }

    pub(crate) const fn catalog_level(self) -> usize {
        self.catalog_level
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatorStreamKeyPositions {
    top_count: u16,
    relinearization_catalog_levels: Vec<usize>,
    galois_catalog_positions: Vec<EvaluatorGaloisKeyPosition>,
}

impl EvaluatorStreamKeyPositions {
    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) fn relinearization_catalog_levels(&self) -> &[usize] {
        &self.relinearization_catalog_levels
    }

    pub(crate) fn galois_catalog_positions(&self) -> &[EvaluatorGaloisKeyPosition] {
        &self.galois_catalog_positions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatorProgramKeyPositions {
    streams: Vec<EvaluatorStreamKeyPositions>,
    relinearization_catalog_levels: Vec<usize>,
    galois_catalog_positions: Vec<EvaluatorGaloisKeyPosition>,
}

impl EvaluatorProgramKeyPositions {
    pub(crate) fn streams(&self) -> &[EvaluatorStreamKeyPositions] {
        &self.streams
    }

    pub(crate) fn relinearization_catalog_levels(&self) -> &[usize] {
        &self.relinearization_catalog_levels
    }

    pub(crate) fn galois_catalog_positions(&self) -> &[EvaluatorGaloisKeyPosition] {
        &self.galois_catalog_positions
    }
}

impl EvaluatorInstructionStream {
    fn new(top_count: u16, instructions: Vec<EvaluatorInstruction>) -> CanonicalResult<Self> {
        if top_count == 0 || usize::from(top_count) > MAXIMUM_EVALUATOR_STREAM_COUNT {
            return Err(program_error(
                "evaluator instruction-stream top count is outside the selected range",
            ));
        }
        if instructions.is_empty() || instructions.len() > MAXIMUM_INSTRUCTIONS_PER_STREAM {
            return Err(program_error(
                "evaluator instruction-stream length is outside the selected bound",
            ));
        }
        Ok(Self {
            top_count,
            instructions,
        })
    }

    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(super) fn instructions(&self) -> &[EvaluatorInstruction] {
        &self.instructions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvaluatorProgramSet {
    constants: Vec<EvaluatorConstant>,
    streams: Vec<EvaluatorInstructionStream>,
}

impl EvaluatorProgramSet {
    fn new(
        constants: Vec<EvaluatorConstant>,
        streams: Vec<EvaluatorInstructionStream>,
    ) -> CanonicalResult<Self> {
        let program_set = Self { constants, streams };
        program_set.validate()?;
        Ok(program_set)
    }

    pub(crate) fn constants(&self) -> &[EvaluatorConstant] {
        &self.constants
    }

    pub(crate) fn streams(&self) -> &[EvaluatorInstructionStream] {
        &self.streams
    }

    #[cfg(test)]
    pub(crate) fn encode(&self) -> CanonicalResult<Vec<u8>> {
        codec::encode_program_set(self)
    }

    /// Returns the exact sorted evaluation-key catalog positions reached by
    /// each validated stream and by their union. Each Galois element retains
    /// its selected catalog level; an opcode at that level or a lower CRT
    /// prefix maps to the same serialized setup position rather than creating
    /// a duplicate key for every runtime level.
    pub(crate) fn key_positions(&self) -> CanonicalResult<EvaluatorProgramKeyPositions> {
        let constant_kinds_by_hash = self.validated_constant_catalog()?;
        validate_stream_catalog_shape(&self.streams)?;
        let option_count = self.streams.len();
        let streams = self
            .streams
            .iter()
            .map(|stream| {
                validate_instruction_stream(stream, &constant_kinds_by_hash, option_count)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let relinearization_catalog_levels = streams
            .iter()
            .flat_map(|positions| positions.relinearization_catalog_levels.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let galois_catalog_positions = streams
            .iter()
            .flat_map(|positions| positions.galois_catalog_positions.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(EvaluatorProgramKeyPositions {
            streams,
            relinearization_catalog_levels,
            galois_catalog_positions,
        })
    }

    fn validate(&self) -> CanonicalResult<()> {
        let constant_kinds_by_hash = self.validated_constant_catalog()?;
        validate_stream_catalog_shape(&self.streams)?;
        let option_count = self.streams.len();
        for stream in &self.streams {
            validate_instruction_stream(stream, &constant_kinds_by_hash, option_count)?;
        }
        Ok(())
    }

    fn validated_constant_catalog(
        &self,
    ) -> CanonicalResult<BTreeMap<[u8; Hash512::BYTE_LENGTH], EvaluatorConstantKind>> {
        if self.constants.is_empty() || self.constants.len() > MAXIMUM_EVALUATOR_CONSTANT_COUNT {
            return Err(program_error(
                "evaluator constant catalog length is outside the selected bound",
            ));
        }
        let mut constant_kinds_by_hash = BTreeMap::new();
        let mut previous_hash = None;
        for constant in &self.constants {
            constant.validate()?;
            let constant_hash = constant.constant_hash()?;
            if previous_hash.is_some_and(|previous: [u8; Hash512::BYTE_LENGTH]| {
                previous >= *constant_hash.as_bytes()
            }) {
                return Err(program_error(
                    "evaluator constants are not strictly sorted by ascending hash",
                ));
            }
            previous_hash = Some(*constant_hash.as_bytes());
            if constant_kinds_by_hash
                .insert(*constant_hash.as_bytes(), constant.kind)
                .is_some()
            {
                return Err(program_error("evaluator constant hash is duplicated"));
            }
        }

        Ok(constant_kinds_by_hash)
    }
}

fn validate_stream_catalog_shape(streams: &[EvaluatorInstructionStream]) -> CanonicalResult<()> {
    if !(usize::from(MINIMUM_CONFIGURABLE_OPTION_COUNT)
        ..=usize::from(MAXIMUM_CONFIGURABLE_OPTION_COUNT))
        .contains(&streams.len())
    {
        return Err(program_error(
            "evaluator program set stream count is outside the configurable range",
        ));
    }
    for (stream_index, stream) in streams.iter().enumerate() {
        if usize::from(stream.top_count) != stream_index + 1 {
            return Err(program_error(
                "evaluator streams are not ordered by increasing top count",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegisterState {
    level: usize,
    decryption_multiplier: u64,
}

fn validate_instruction_stream(
    stream: &EvaluatorInstructionStream,
    constant_kinds_by_hash: &BTreeMap<[u8; Hash512::BYTE_LENGTH], EvaluatorConstantKind>,
    option_count: usize,
) -> CanonicalResult<EvaluatorStreamKeyPositions> {
    let instructions = &stream.instructions;
    if instructions.len() < 2 {
        return Err(program_error(
            "evaluator stream is missing terminal output declarations",
        ));
    }
    let identifier_declaration = &instructions[instructions.len() - 2];
    let order_declaration = &instructions[instructions.len() - 1];
    if identifier_declaration.opcode != EvaluatorOpcode::DeclareOutput
        || identifier_declaration.immediate0 != 1
        || order_declaration.opcode != EvaluatorOpcode::DeclareOutput
        || order_declaration.immediate0 != 2
    {
        return Err(program_error(
            "evaluator stream must end with identifier then order output declarations",
        ));
    }
    if instructions[..instructions.len() - 2]
        .iter()
        .any(|instruction| instruction.opcode == EvaluatorOpcode::DeclareOutput)
    {
        return Err(program_error(
            "evaluator stream declares an output before its terminal instructions",
        ));
    }
    let identifier_register = identifier_declaration.input_registers[0];
    let order_register = order_declaration.input_registers[0];
    if identifier_register == order_register {
        return Err(program_error(
            "evaluator target identifier and order must use distinct registers",
        ));
    }
    let output_registers = BTreeSet::from([identifier_register, order_register]);

    let mut last_non_drop_use = BTreeMap::new();
    for (instruction_index, instruction) in instructions.iter().enumerate() {
        if instruction.opcode != EvaluatorOpcode::DropRegister {
            for register in &instruction.input_registers {
                last_non_drop_use.insert(*register, instruction_index);
            }
        }
    }

    let scheduled_galois_levels = selected_evaluator_rotation_key_schedule(option_count)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let mut register_states = vec![
        Some(RegisterState {
            level: CHARACTER_OUTPUT_LEVEL,
            decryption_multiplier: 1,
        });
        PAIR_CHARACTER_CIPHERTEXT_COUNT
    ];
    let mut expected_output_register = u32::try_from(PAIR_CHARACTER_CIPHERTEXT_COUNT)
        .map_err(|_| program_error("evaluator input register count does not fit u32"))?;
    let mut pending_drops = BTreeSet::new();
    let mut maximum_live_register_count = 2_usize;
    let mut relinearization_catalog_levels = BTreeSet::new();
    let mut galois_catalog_positions = BTreeSet::new();

    for (instruction_index, instruction) in instructions.iter().enumerate() {
        instruction.validate_shape()?;
        if instruction.opcode == EvaluatorOpcode::DropRegister {
            let register = instruction.input_registers[0];
            let register_index = usize::try_from(register).map_err(|_| {
                program_error("evaluator register number does not fit the host index")
            })?;
            let releases_never_used_input = register_index < PAIR_CHARACTER_CIPHERTEXT_COUNT
                && !last_non_drop_use.contains_key(&register)
                && instructions[..instruction_index]
                    .iter()
                    .all(|prior| prior.opcode == EvaluatorOpcode::DropRegister);
            if !pending_drops.remove(&register) && !releases_never_used_input {
                return Err(program_error(
                    "evaluator register is not dropped exactly after its last use",
                ));
            }
            let state = register_states
                .get_mut(register_index)
                .ok_or_else(|| program_error("evaluator drop uses an undefined register"))?;
            if state.take().is_none() {
                return Err(program_error(
                    "evaluator register is dropped more than once",
                ));
            }
            continue;
        }
        if !pending_drops.is_empty() {
            return Err(program_error(
                "evaluator register drop is missing after its last use",
            ));
        }

        let input_states = instruction
            .input_registers
            .iter()
            .map(|register| read_live_register(&register_states, *register))
            .collect::<CanonicalResult<Vec<_>>>()?;
        let output_state = evaluate_instruction_transition(
            instruction,
            &input_states,
            constant_kinds_by_hash,
            &scheduled_galois_levels,
        )?;
        match instruction.opcode {
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                relinearization_catalog_levels.insert(SELECTED_RELINEARIZATION_KEY_LEVEL);
            }
            EvaluatorOpcode::GaloisRotate => {
                let galois_element = usize::try_from(instruction.immediate0)
                    .map_err(|_| program_error("evaluator Galois element does not fit usize"))?;
                let catalog_level =
                    *scheduled_galois_levels
                        .get(&galois_element)
                        .ok_or_else(|| {
                            program_error(
                                "evaluator rotation is absent from the selected suite catalog",
                            )
                        })?;
                galois_catalog_positions.insert(EvaluatorGaloisKeyPosition {
                    galois_element,
                    catalog_level,
                });
            }
            _ => {}
        }

        if instruction.opcode.produces_register() {
            let output_register = instruction
                .output_register
                .expect("shape validation requires an output register");
            if output_register != expected_output_register {
                return Err(program_error(
                    "evaluator registers are not consecutive by first definition",
                ));
            }
            register_states.push(Some(
                output_state.expect("register-producing opcode has a transition state"),
            ));
            expected_output_register =
                expected_output_register.checked_add(1).ok_or_else(|| {
                    program_error("evaluator output-register numbering overflowed u32")
                })?;
        } else if output_state.is_some() {
            return Err(program_error(
                "evaluator non-producing opcode unexpectedly produced register state",
            ));
        }

        maximum_live_register_count = maximum_live_register_count.max(
            register_states
                .iter()
                .filter(|state| state.is_some())
                .count(),
        );
        if maximum_live_register_count > MAXIMUM_LIVE_REGISTER_COUNT {
            return Err(program_error(
                "evaluator stream exceeds the selected live-register bound",
            ));
        }

        for register in &instruction.input_registers {
            if last_non_drop_use.get(register) == Some(&instruction_index)
                && !output_registers.contains(register)
            {
                pending_drops.insert(*register);
            }
        }
    }
    if !pending_drops.is_empty() {
        return Err(program_error(
            "evaluator stream ends before its required register drops",
        ));
    }

    for (register_index, state) in register_states.iter().enumerate() {
        let register = u32::try_from(register_index)
            .map_err(|_| program_error("evaluator register index does not fit u32"))?;
        if output_registers.contains(&register) {
            if state.is_none() {
                return Err(program_error("evaluator output register was dropped"));
            }
        } else if state.is_some() {
            return Err(program_error(
                "evaluator non-output register remains live at stream end",
            ));
        }
    }
    Ok(EvaluatorStreamKeyPositions {
        top_count: stream.top_count,
        relinearization_catalog_levels: relinearization_catalog_levels.into_iter().collect(),
        galois_catalog_positions: galois_catalog_positions.into_iter().collect(),
    })
}

fn read_live_register(
    register_states: &[Option<RegisterState>],
    register: u32,
) -> CanonicalResult<RegisterState> {
    register_states
        .get(
            usize::try_from(register)
                .map_err(|_| program_error("evaluator register number does not fit usize"))?,
        )
        .ok_or_else(|| program_error("evaluator instruction uses a register before definition"))?
        .ok_or_else(|| program_error("evaluator instruction uses a dropped register"))
}

fn evaluate_instruction_transition(
    instruction: &EvaluatorInstruction,
    inputs: &[RegisterState],
    constant_kinds_by_hash: &BTreeMap<[u8; Hash512::BYTE_LENGTH], EvaluatorConstantKind>,
    scheduled_galois_levels: &BTreeMap<usize, usize>,
) -> CanonicalResult<Option<RegisterState>> {
    let first = inputs.first().copied();
    let transition = match instruction.opcode {
        EvaluatorOpcode::ModulusSwitchToLevel => {
            let input = first.expect("shape validation requires one input");
            let target_level = usize::try_from(instruction.immediate0)
                .map_err(|_| program_error("evaluator target level does not fit usize"))?;
            if target_level >= input.level {
                return Err(program_error(
                    "evaluator modulus switch must strictly lower the level",
                ));
            }
            let mut multiplier = input.decryption_multiplier;
            for dropped_level in ((target_level + 1)..=input.level).rev() {
                let dropped_prime = *DATA_PRIMES.get(dropped_level).ok_or_else(|| {
                    program_error("evaluator modulus switch level is outside the data basis")
                })?;
                multiplier = mul_mod(
                    multiplier,
                    dropped_prime % PLAINTEXT_MODULUS,
                    PLAINTEXT_MODULUS,
                )?;
            }
            Some(RegisterState {
                level: target_level,
                decryption_multiplier: multiplier,
            })
        }
        EvaluatorOpcode::NormalizeDecryptionMultiplier => {
            let input = first.expect("shape validation requires one input");
            let target_multiplier = instruction.immediate0;
            if target_multiplier >= PLAINTEXT_MODULUS
                || target_multiplier == input.decryption_multiplier
            {
                return Err(program_error(
                    "evaluator multiplier normalization target is not a distinct nonzero field element",
                ));
            }
            Some(RegisterState {
                level: input.level,
                decryption_multiplier: target_multiplier,
            })
        }
        EvaluatorOpcode::CiphertextAdd => {
            require_matching_register_states(inputs)?;
            first
        }
        EvaluatorOpcode::PlaintextAdd | EvaluatorOpcode::PlaintextMultiply => {
            let constant_hash = instruction
                .constant_hash
                .expect("shape validation requires a constant hash");
            let constant_kind = constant_kinds_by_hash
                .get(constant_hash.as_bytes())
                .ok_or_else(|| {
                    program_error("evaluator instruction references an unknown constant")
                })?;
            let _ = constant_kind;
            first
        }
        EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
        | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
            require_matching_levels(inputs)?;
            let left = inputs[0];
            let right = inputs[1];
            if left.level > SELECTED_RELINEARIZATION_KEY_LEVEL {
                return Err(program_error(
                    "evaluator multiplication requires an unavailable relinearization-key level",
                ));
            }
            let mut multiplier = mul_mod(
                left.decryption_multiplier,
                right.decryption_multiplier,
                PLAINTEXT_MODULUS,
            )?;
            let level =
                if instruction.opcode == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop {
                    if left.level == 0 {
                        return Err(program_error(
                            "evaluator multiply-and-drop cannot run at level zero",
                        ));
                    }
                    multiplier = mul_mod(
                        multiplier,
                        DATA_PRIMES[left.level] % PLAINTEXT_MODULUS,
                        PLAINTEXT_MODULUS,
                    )?;
                    left.level - 1
                } else {
                    left.level
                };
            Some(RegisterState {
                level,
                decryption_multiplier: multiplier,
            })
        }
        EvaluatorOpcode::GaloisRotate => {
            let input = first.expect("shape validation requires one input");
            let galois_element = usize::try_from(instruction.immediate0)
                .map_err(|_| program_error("evaluator Galois element does not fit usize"))?;
            let catalog_level = scheduled_galois_levels
                .get(&galois_element)
                .copied()
                .ok_or_else(|| {
                    program_error(
                        "evaluator rotation is not supported by the selected suite catalog",
                    )
                })?;
            if galois_element == 1
                || galois_element.is_multiple_of(2)
                || input.level > catalog_level
            {
                return Err(program_error(
                    "evaluator rotation is not supported by the selected suite catalog",
                ));
            }
            first
        }
        EvaluatorOpcode::DropRegister => None,
        EvaluatorOpcode::DeclareOutput => {
            let output = first.expect("shape validation requires one input");
            if output.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL
                || output.decryption_multiplier != 1
            {
                return Err(program_error(
                    "evaluator output does not reach the selected terminal level and multiplier",
                ));
            }
            None
        }
    };
    Ok(transition)
}

fn require_matching_register_states(inputs: &[RegisterState]) -> CanonicalResult<()> {
    require_matching_levels(inputs)?;
    if inputs[0].decryption_multiplier != inputs[1].decryption_multiplier {
        return Err(program_error(
            "evaluator addition operands have different decryption multipliers",
        ));
    }
    Ok(())
}

fn require_matching_levels(inputs: &[RegisterState]) -> CanonicalResult<()> {
    if inputs[0].level != inputs[1].level {
        return Err(program_error(
            "evaluator binary-operation operands have different levels",
        ));
    }
    Ok(())
}

fn program_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}
