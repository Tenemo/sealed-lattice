use std::collections::{BTreeMap, BTreeSet};

use crate::{
    bgv::{
        evaluator::{
            engine::{
                Ciphertext, add_plaintext_coefficients, ciphertext_add, ciphertext_canonical_bytes,
                ciphertext_tensor, modulus_switch, modulus_switch_to, normalize_scaling,
                plaintext_mul,
            },
            replay::{
                EvaluatorKeyStoreReadRequest, VerifiedEvaluatorKeyReplay,
                VerifiedEvaluatorKeyResolver,
            },
            top_k::{
                SELECTED_EVALUATOR_WORKING_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL,
                selected_evaluator_rotation_key_schedule,
            },
        },
        key_switch_topology::KeySwitchDecompositionTopology,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        proof_suite::{SelectedEvaluatorEntryKind, SelectedEvaluatorEntryPosition},
        setup::{
            VerifiedAcceptedSetupAuthorityHandle, take_verified_evaluator_execution_authority,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode},
    foundation::{
        CanonicalDecodeLimits, CanonicalStreamDomain, CanonicalStreamWriter, FOUNDATION_PROFILE,
        Hash512, RefusalReason, VerifiedCanonicalStreamSummary, VerifiedEvaluatorReplay,
        VerifiedTranscriptObject, encode_evaluator_replay_carrier,
    },
};

use super::{
    EvaluatorConstant, EvaluatorConstantKind, EvaluatorInstruction, EvaluatorOpcode,
    EvaluatorProgramSet, selected_evaluator_program_set,
};

/// Exact context copied from the positively verified ballots and aggregate
/// object before the aggregate authority is constructed.
pub(crate) struct VerifiedEvaluatorAggregateContext {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
}

impl VerifiedEvaluatorAggregateContext {
    pub(in crate::bgv::evaluator) const fn from_verified_sources(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
        verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            verified_setup_source_hash,
            verified_aggregate_source_hash,
        }
    }
}

/// Verifier-owned aggregate input for the deterministic evaluator. Its
/// constructor lives with the accepted ballot aggregation bridge; detached
/// ciphertext bytes and copied hashes cannot create this capability.
pub(crate) struct VerifiedEvaluatorAggregate {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
    top_count: u16,
    aggregate_ciphertext: Ciphertext,
}

impl VerifiedEvaluatorAggregate {
    pub(in crate::bgv::evaluator) fn from_verified_ballot_aggregate(
        context: VerifiedEvaluatorAggregateContext,
        ballot_count: u16,
        top_count: u16,
        aggregate_ciphertext: Ciphertext,
    ) -> Result<Self, RefusalReason> {
        validate_aggregate_ciphertext(&aggregate_ciphertext)?;
        if ballot_count == 0
            || ballot_count > FOUNDATION_PROFILE.participant_count
            || top_count == 0
            || top_count > FOUNDATION_PROFILE.option_count
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        Ok(Self {
            protocol_version: context.protocol_version,
            suite_identifier: context.suite_identifier,
            ceremony_context_hash: context.ceremony_context_hash,
            action_context_hash: context.action_context_hash,
            roster_hash: context.roster_hash,
            verified_setup_source_hash: context.verified_setup_source_hash,
            verified_aggregate_source_hash: context.verified_aggregate_source_hash,
            top_count,
            aggregate_ciphertext,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedEvaluatorExecutionProgress {
    StoreReadRequired(EvaluatorKeyStoreReadRequest),
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreparedEvaluatorKeyIdentity {
    Relinearization {
        catalog_level: usize,
    },
    Galois {
        galois_element: usize,
        catalog_level: usize,
    },
}

impl PreparedEvaluatorKeyIdentity {
    fn matches_position(self, position: SelectedEvaluatorEntryPosition) -> bool {
        match (self, position.key_kind()) {
            (
                Self::Relinearization { catalog_level },
                SelectedEvaluatorEntryKind::Relinearization {
                    catalog_level: position_level,
                },
            ) => catalog_level == position_level,
            (
                Self::Galois {
                    galois_element,
                    catalog_level,
                },
                SelectedEvaluatorEntryKind::Galois {
                    galois_element: position_element,
                    catalog_level: position_level,
                },
            ) => galois_element == position_element && catalog_level == position_level,
            _ => false,
        }
    }

    const fn catalog_level(self) -> usize {
        match self {
            Self::Relinearization { catalog_level } | Self::Galois { catalog_level, .. } => {
                catalog_level
            }
        }
    }

    const fn physical_store_component_count(self) -> u64 {
        match self {
            Self::Relinearization { .. } => 2,
            Self::Galois { .. } => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SelectedEvaluatorExecutionAccounting {
    key_operation_count: usize,
    key_load_count: usize,
    key_store_read_byte_count: u64,
    key_store_reread_byte_count: u64,
    key_ntt_transform_count: usize,
    maximum_live_ciphertext_count: usize,
    maximum_live_ciphertext_coefficient_byte_count: u64,
}

struct PreparedEvaluatorExecutionSchedule {
    required_keys: Box<[Option<PreparedEvaluatorKeyIdentity>]>,
    next_required_keys: Box<[Option<PreparedEvaluatorKeyIdentity>]>,
    accounting: SelectedEvaluatorExecutionAccounting,
}

struct PendingEvaluatorKeyLoad {
    key_identity: PreparedEvaluatorKeyIdentity,
    counts_as_reread: bool,
    replay: VerifiedEvaluatorKeyReplay,
}

impl PreparedEvaluatorExecutionSchedule {
    /// Derives key-resident phases without changing canonical instruction
    /// order. Non-key instructions between two uses of the same key remain in
    /// their original positions while that one verified NTT key stays
    /// resident. The first different key ends the phase. This makes the
    /// canonical stream, its register numbering, and every last-use drop the
    /// complete dependency proof for the prepared schedule.
    fn derive(instructions: &[EvaluatorInstruction]) -> Result<Self, RefusalReason> {
        if instructions.is_empty() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let galois_catalog_levels =
            selected_evaluator_rotation_key_schedule(usize::from(FOUNDATION_PROFILE.option_count))
                .map_err(evaluator_refusal)?
                .into_iter()
                .collect::<BTreeMap<_, _>>();
        let mut required_keys = Vec::with_capacity(instructions.len());
        let mut live_register_levels = vec![Some(SELECTED_EVALUATOR_WORKING_LEVEL)];
        let mut live_ciphertext_count = 1_usize;
        let mut maximum_live_ciphertext_count = 1_usize;
        let mut live_ciphertext_coefficient_byte_count =
            ciphertext_coefficient_byte_count(SELECTED_EVALUATOR_WORKING_LEVEL)?;
        let mut maximum_live_ciphertext_coefficient_byte_count =
            live_ciphertext_coefficient_byte_count;
        for instruction in instructions {
            for register in instruction.input_registers() {
                let register_index = usize::try_from(*register)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                if live_register_levels
                    .get(register_index)
                    .and_then(|level| *level)
                    .is_none()
                {
                    return Err(RefusalReason::MissingPrerequisite);
                }
            }

            let required_key = match instruction.opcode() {
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                    Some(PreparedEvaluatorKeyIdentity::Relinearization {
                        catalog_level: SELECTED_RELINEARIZATION_KEY_LEVEL,
                    })
                }
                EvaluatorOpcode::GaloisRotate => {
                    let galois_element = usize::try_from(instruction.immediate0())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                    let catalog_level = galois_catalog_levels
                        .get(&galois_element)
                        .copied()
                        .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
                    Some(PreparedEvaluatorKeyIdentity::Galois {
                        galois_element,
                        catalog_level,
                    })
                }
                _ => None,
            };
            required_keys.push(required_key);

            if instruction.opcode() == EvaluatorOpcode::DropRegister {
                let register = *instruction
                    .input_registers()
                    .first()
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let register_index = usize::try_from(register)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                let live_level = live_register_levels
                    .get_mut(register_index)
                    .ok_or(RefusalReason::MissingPrerequisite)?;
                let live_level = live_level
                    .take()
                    .ok_or(RefusalReason::MissingPrerequisite)?;
                live_ciphertext_count = live_ciphertext_count
                    .checked_sub(1)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                live_ciphertext_coefficient_byte_count = live_ciphertext_coefficient_byte_count
                    .checked_sub(ciphertext_coefficient_byte_count(live_level)?)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
            } else if let Some(output_register) = instruction.output_register() {
                if usize::try_from(output_register).ok() != Some(live_register_levels.len()) {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                let output_level =
                    prepared_instruction_output_level(instruction, &live_register_levels)?
                        .ok_or(RefusalReason::WrongTypeOrLength)?;
                live_register_levels.push(Some(output_level));
                live_ciphertext_count = live_ciphertext_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                live_ciphertext_coefficient_byte_count = live_ciphertext_coefficient_byte_count
                    .checked_add(ciphertext_coefficient_byte_count(output_level)?)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                maximum_live_ciphertext_count =
                    maximum_live_ciphertext_count.max(live_ciphertext_count);
                if live_ciphertext_coefficient_byte_count
                    > maximum_live_ciphertext_coefficient_byte_count
                {
                    maximum_live_ciphertext_coefficient_byte_count =
                        live_ciphertext_coefficient_byte_count;
                }
            }
        }
        if live_ciphertext_count != 2 {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let mut next_required_keys = vec![None; required_keys.len() + 1];
        let mut next_required_key = None;
        for instruction_ordinal in (0..required_keys.len()).rev() {
            if let Some(required_key) = required_keys[instruction_ordinal] {
                next_required_key = Some(required_key);
            }
            next_required_keys[instruction_ordinal] = next_required_key;
        }

        let mut accounting = SelectedEvaluatorExecutionAccounting {
            maximum_live_ciphertext_count,
            maximum_live_ciphertext_coefficient_byte_count,
            ..SelectedEvaluatorExecutionAccounting::default()
        };
        let mut active_key = None;
        let mut loaded_keys = BTreeSet::new();
        for required_key in required_keys.iter().flatten().copied() {
            accounting.key_operation_count = accounting
                .key_operation_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if active_key == Some(required_key) {
                continue;
            }
            active_key = Some(required_key);
            accounting.key_load_count = accounting
                .key_load_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let topology = KeySwitchDecompositionTopology::for_level(required_key.catalog_level())
                .map_err(evaluator_refusal)?;
            let component_byte_count = topology
                .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
                .map_err(evaluator_refusal)?;
            let key_store_byte_count = component_byte_count
                .checked_mul(required_key.physical_store_component_count())
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            accounting.key_store_read_byte_count = accounting
                .key_store_read_byte_count
                .checked_add(key_store_byte_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if !loaded_keys.insert(required_key) {
                accounting.key_store_reread_byte_count = accounting
                    .key_store_reread_byte_count
                    .checked_add(key_store_byte_count)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            let transformed_limb_count = topology
                .data_block_count()
                .checked_mul(topology.extended_limb_count())
                .and_then(|limb_count| limb_count.checked_mul(2))
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            accounting.key_ntt_transform_count = accounting
                .key_ntt_transform_count
                .checked_add(transformed_limb_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }

        Ok(Self {
            required_keys: required_keys.into_boxed_slice(),
            next_required_keys: next_required_keys.into_boxed_slice(),
            accounting,
        })
    }

    fn required_key(
        &self,
        instruction_ordinal: usize,
    ) -> Result<Option<PreparedEvaluatorKeyIdentity>, RefusalReason> {
        self.required_keys
            .get(instruction_ordinal)
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn next_required_key(
        &self,
        next_instruction_ordinal: usize,
    ) -> Result<Option<PreparedEvaluatorKeyIdentity>, RefusalReason> {
        self.next_required_keys
            .get(next_instruction_ordinal)
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    const fn accounting(&self) -> SelectedEvaluatorExecutionAccounting {
        self.accounting
    }
}

fn prepared_instruction_output_level(
    instruction: &EvaluatorInstruction,
    live_register_levels: &[Option<usize>],
) -> Result<Option<usize>, RefusalReason> {
    let input_level = |input_ordinal: usize| -> Result<usize, RefusalReason> {
        let register = instruction
            .input_registers()
            .get(input_ordinal)
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        live_register_levels
            .get(usize::try_from(register).map_err(|_| RefusalReason::OutsideSupportedProfile)?)
            .and_then(|level| *level)
            .ok_or(RefusalReason::MissingPrerequisite)
    };
    match instruction.opcode() {
        EvaluatorOpcode::ModulusSwitchToLevel => {
            let source_level = input_level(0)?;
            let target_level = usize::try_from(instruction.immediate0())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            if target_level >= source_level {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            Ok(Some(target_level))
        }
        EvaluatorOpcode::NormalizeDecryptionMultiplier
        | EvaluatorOpcode::PlaintextAdd
        | EvaluatorOpcode::PlaintextMultiply
        | EvaluatorOpcode::GaloisRotate => Ok(Some(input_level(0)?)),
        EvaluatorOpcode::CiphertextAdd => {
            let left_level = input_level(0)?;
            if input_level(1)? != left_level {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            Ok(Some(left_level))
        }
        EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
            let left_level = input_level(0)?;
            if input_level(1)? != left_level {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            Ok(Some(left_level))
        }
        EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop => {
            let left_level = input_level(0)?;
            if input_level(1)? != left_level {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            Ok(Some(
                left_level
                    .checked_sub(1)
                    .ok_or(RefusalReason::WrongTypeOrLength)?,
            ))
        }
        EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput => Ok(None),
    }
}

fn ciphertext_coefficient_byte_count(level: usize) -> Result<u64, RefusalReason> {
    u64::try_from(level)
        .ok()
        .and_then(|level| level.checked_add(1))
        .and_then(|limb_count| {
            u64::try_from(POLYNOMIAL_DEGREE)
                .ok()
                .and_then(|degree| limb_count.checked_mul(degree))
        })
        .and_then(|coefficient_count| coefficient_count.checked_mul(2))
        .and_then(|coefficient_count| coefficient_count.checked_mul(u64::from(u64::BITS / 8)))
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

/// Pollable execution of one suite-fixed evaluator stream. The worker runs
/// non-key instructions until it reaches an evaluator-key opcode, then yields
/// exact authenticated store ranges. Only one replay/key guard can be live,
/// and dropping or refusing the execution discards every partial NTT buffer.
pub(crate) struct SelectedEvaluatorProgramExecution {
    resolver: VerifiedEvaluatorKeyResolver,
    program: EvaluatorProgramSet,
    constant_ordinals: BTreeMap<[u8; Hash512::BYTE_LENGTH], usize>,
    selected_stream_ordinal: usize,
    execution_schedule: PreparedEvaluatorExecutionSchedule,
    next_instruction_ordinal: usize,
    registers: Vec<Option<Ciphertext>>,
    live_ciphertext_count: usize,
    live_ciphertext_coefficient_byte_count: u64,
    resident_key_context: Option<super::super::replay::VerifiedEvaluatorKeyContext>,
    pending_key_load: Option<PendingEvaluatorKeyLoad>,
    loaded_key_identities: BTreeSet<PreparedEvaluatorKeyIdentity>,
    execution_accounting: SelectedEvaluatorExecutionAccounting,
    target_identifier_register: Option<u32>,
    target_order_register: Option<u32>,
    evaluator_replay_context_hash: [u8; Hash512::BYTE_LENGTH],
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
    top_count: u16,
    refusal_reason: Option<RefusalReason>,
}

impl SelectedEvaluatorProgramExecution {
    pub(crate) fn begin(
        aggregate: VerifiedEvaluatorAggregate,
        accepted_setup_handle: &VerifiedAcceptedSetupAuthorityHandle,
    ) -> Result<Self, RefusalReason> {
        let top_count = aggregate.top_count;
        if top_count == 0 || top_count > FOUNDATION_PROFILE.option_count {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        validate_aggregate_ciphertext(&aggregate.aggregate_ciphertext)?;

        let program = selected_evaluator_program_set().map_err(evaluator_refusal)?;
        let selected_stream_ordinal = usize::from(top_count - 1);
        if program
            .streams()
            .get(selected_stream_ordinal)
            .map(|stream| stream.top_count())
            != Some(top_count)
        {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        let execution_schedule = PreparedEvaluatorExecutionSchedule::derive(
            program
                .streams()
                .get(selected_stream_ordinal)
                .ok_or(RefusalReason::UnsupportedVersionOrSuite)?
                .instructions(),
        )?;
        let mut constant_ordinals = BTreeMap::new();
        for (constant_ordinal, constant) in program.constants().iter().enumerate() {
            let constant_hash = constant.constant_hash().map_err(evaluator_refusal)?;
            if constant_ordinals
                .insert(*constant_hash.as_bytes(), constant_ordinal)
                .is_some()
            {
                return Err(RefusalReason::MalformedEncoding);
            }
        }
        let execution_authority =
            take_verified_evaluator_execution_authority(accepted_setup_handle, |accepted_setup| {
                aggregate.protocol_version == accepted_setup.protocol_version()
                    && aggregate.suite_identifier == accepted_setup.suite_identifier()
                    && aggregate.ceremony_context_hash == accepted_setup.ceremony_context_hash()
                    && aggregate.action_context_hash == accepted_setup.action_context_hash()
                    && aggregate.roster_hash == accepted_setup.roster_hash()
                    && aggregate.verified_setup_source_hash
                        == accepted_setup.exact_verified_setup_source_hash()
                    && accepted_setup.verified_evaluator_top_count() == Some(top_count)
            })?;
        if execution_authority.top_count() != top_count {
            return Err(RefusalReason::WrongContext);
        }
        let evaluator_replay_context_hash = execution_authority.evaluator_replay_context_hash();
        let resolver = VerifiedEvaluatorKeyResolver::from_execution_authority(execution_authority)?;

        Ok(Self {
            resolver,
            program,
            constant_ordinals,
            selected_stream_ordinal,
            execution_schedule,
            next_instruction_ordinal: 0,
            registers: vec![Some(aggregate.aggregate_ciphertext)],
            live_ciphertext_count: 1,
            live_ciphertext_coefficient_byte_count: ciphertext_coefficient_byte_count(
                SELECTED_EVALUATOR_WORKING_LEVEL,
            )?,
            resident_key_context: None,
            pending_key_load: None,
            loaded_key_identities: BTreeSet::new(),
            execution_accounting: SelectedEvaluatorExecutionAccounting {
                maximum_live_ciphertext_count: 1,
                maximum_live_ciphertext_coefficient_byte_count: ciphertext_coefficient_byte_count(
                    SELECTED_EVALUATOR_WORKING_LEVEL,
                )?,
                ..SelectedEvaluatorExecutionAccounting::default()
            },
            target_identifier_register: None,
            target_order_register: None,
            evaluator_replay_context_hash,
            suite_identifier: aggregate.suite_identifier,
            ceremony_context_hash: aggregate.ceremony_context_hash,
            action_context_hash: aggregate.action_context_hash,
            roster_hash: aggregate.roster_hash,
            verified_setup_source_hash: aggregate.verified_setup_source_hash,
            verified_aggregate_source_hash: aggregate.verified_aggregate_source_hash,
            top_count,
            refusal_reason: None,
        })
    }

    pub(crate) fn advance(&mut self) -> Result<SelectedEvaluatorExecutionProgress, RefusalReason> {
        if let Some(reason) = self.refusal_reason {
            return Err(reason);
        }
        let result = self.advance_inner();
        if let Err(reason) = result {
            self.refuse(reason);
        }
        result
    }

    fn advance_inner(&mut self) -> Result<SelectedEvaluatorExecutionProgress, RefusalReason> {
        loop {
            if let Some(pending) = self.pending_key_load.as_ref() {
                if let Some(request) = pending.replay.next_read_request() {
                    return Ok(SelectedEvaluatorExecutionProgress::StoreReadRequired(
                        request,
                    ));
                }
                let pending = self
                    .pending_key_load
                    .take()
                    .ok_or(RefusalReason::ConsumedState)?;
                let key_context = pending.replay.finish()?;
                if key_context.resolver_context_hash() != self.evaluator_replay_context_hash
                    || !pending
                        .key_identity
                        .matches_position(key_context.position())
                {
                    return Err(RefusalReason::WrongContext);
                }
                self.execution_accounting.key_ntt_transform_count = self
                    .execution_accounting
                    .key_ntt_transform_count
                    .checked_add(key_context.ntt_transform_count())
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                let was_first_load = self.loaded_key_identities.insert(pending.key_identity);
                if was_first_load == pending.counts_as_reread {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                self.resident_key_context = Some(key_context);
                continue;
            }

            let instruction_count = self.selected_instructions()?.len();
            if self.next_instruction_ordinal == instruction_count {
                if self.target_identifier_register.is_none() || self.target_order_register.is_none()
                {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                return Ok(SelectedEvaluatorExecutionProgress::Complete);
            }
            let instruction = self
                .selected_instructions()?
                .get(self.next_instruction_ordinal)
                .cloned()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let required_key = self
                .execution_schedule
                .required_key(self.next_instruction_ordinal)?;
            if let Some(required_key) = required_key {
                let resident_matches = self
                    .resident_key_context
                    .as_ref()
                    .is_some_and(|context| required_key.matches_position(context.position()));
                if !resident_matches {
                    self.resident_key_context = None;
                    self.begin_key_load(required_key)?;
                    continue;
                }
                let output = {
                    let key_context = self
                        .resident_key_context
                        .as_ref()
                        .ok_or(RefusalReason::ConsumedState)?;
                    self.execute_key_instruction(&instruction, key_context)?
                };
                self.push_instruction_output(&instruction, output)?;
                self.execution_accounting.key_operation_count = self
                    .execution_accounting
                    .key_operation_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            } else {
                self.execute_non_key_instruction(&instruction)?;
            }
            self.next_instruction_ordinal = self
                .next_instruction_ordinal
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            self.release_resident_key_after_completed_phase()?;
        }
    }

    fn begin_key_load(
        &mut self,
        key_identity: PreparedEvaluatorKeyIdentity,
    ) -> Result<(), RefusalReason> {
        if self.resident_key_context.is_some() || self.pending_key_load.is_some() {
            return Err(RefusalReason::ConsumedState);
        }
        let replay = match key_identity {
            PreparedEvaluatorKeyIdentity::Relinearization { .. } => {
                self.resolver.begin_relinearization_key_replay()?
            }
            PreparedEvaluatorKeyIdentity::Galois { galois_element, .. } => {
                self.resolver.begin_galois_key_replay(galois_element)?
            }
        };
        let counts_as_reread = self.loaded_key_identities.contains(&key_identity);
        self.execution_accounting.key_load_count = self
            .execution_accounting
            .key_load_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.pending_key_load = Some(PendingEvaluatorKeyLoad {
            key_identity,
            counts_as_reread,
            replay,
        });
        Ok(())
    }

    fn release_resident_key_after_completed_phase(&mut self) -> Result<(), RefusalReason> {
        let Some(resident_position) = self
            .resident_key_context
            .as_ref()
            .map(|context| context.position())
        else {
            return Ok(());
        };
        let next_required_key = self
            .execution_schedule
            .next_required_key(self.next_instruction_ordinal)?;
        if !next_required_key.is_some_and(|key| key.matches_position(resident_position)) {
            self.resident_key_context = None;
        }
        Ok(())
    }

    pub(crate) fn absorb_next_store_chunk(
        &mut self,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if let Some(reason) = self.refusal_reason {
            return Err(reason);
        }
        let (counts_as_reread, result) = match self.pending_key_load.as_mut() {
            Some(pending) => (
                pending.counts_as_reread,
                pending
                    .replay
                    .absorb_next_store_chunk(store_byte_offset, chunk_bytes),
            ),
            None => (false, Err(RefusalReason::ConsumedState)),
        };
        let result = result.and_then(|()| {
            let chunk_byte_count = u64::try_from(chunk_bytes.len())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            self.execution_accounting.key_store_read_byte_count = self
                .execution_accounting
                .key_store_read_byte_count
                .checked_add(chunk_byte_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if counts_as_reread {
                self.execution_accounting.key_store_reread_byte_count = self
                    .execution_accounting
                    .key_store_reread_byte_count
                    .checked_add(chunk_byte_count)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            Ok(())
        });
        if let Err(reason) = result {
            self.refuse(reason);
        }
        result
    }

    pub(crate) fn finish(mut self) -> Result<VerifiedSelectedEvaluatorExecution, RefusalReason> {
        if let Some(reason) = self.refusal_reason {
            return Err(reason);
        }
        if self.pending_key_load.is_some()
            || self.resident_key_context.is_some()
            || self.next_instruction_ordinal != self.selected_instructions()?.len()
            || self.live_ciphertext_count != 2
        {
            return Err(RefusalReason::ConsumedState);
        }
        if self.execution_accounting != self.execution_schedule.accounting() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let target_identifier_register = self
            .target_identifier_register
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let target_order_register = self
            .target_order_register
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let target_identifier = take_register(&mut self.registers, target_identifier_register)?;
        let target_order = take_register(&mut self.registers, target_order_register)?;
        if self.registers.iter().any(Option::is_some)
            || target_identifier.level != target_order.level
            || target_identifier.decrypt_scaling != target_order.decrypt_scaling
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(VerifiedSelectedEvaluatorExecution {
            suite_identifier: self.suite_identifier,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            verified_setup_source_hash: self.verified_setup_source_hash,
            verified_aggregate_source_hash: self.verified_aggregate_source_hash,
            top_count: self.top_count,
            target_identifier,
            target_order,
        })
    }

    fn selected_instructions(&self) -> Result<&[EvaluatorInstruction], RefusalReason> {
        self.program
            .streams()
            .get(self.selected_stream_ordinal)
            .map(|stream| stream.instructions())
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    fn execute_non_key_instruction(
        &mut self,
        instruction: &EvaluatorInstruction,
    ) -> Result<(), RefusalReason> {
        let output = match instruction.opcode() {
            EvaluatorOpcode::ModulusSwitchToLevel => {
                let input = self.input_register(instruction, 0)?;
                let target_level = usize::try_from(instruction.immediate0())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                Some(modulus_switch_to(input, target_level).map_err(evaluator_refusal)?)
            }
            EvaluatorOpcode::NormalizeDecryptionMultiplier => {
                if instruction.immediate0() != 1 {
                    return Err(RefusalReason::UnsupportedVersionOrSuite);
                }
                Some(
                    normalize_scaling(self.input_register(instruction, 0)?)
                        .map_err(evaluator_refusal)?,
                )
            }
            EvaluatorOpcode::CiphertextAdd => Some(
                ciphertext_add(
                    self.input_register(instruction, 0)?,
                    self.input_register(instruction, 1)?,
                )
                .map_err(evaluator_refusal)?,
            ),
            EvaluatorOpcode::PlaintextAdd => {
                let plaintext = self.constant_coefficients(instruction)?;
                Some(
                    add_plaintext_coefficients(self.input_register(instruction, 0)?, &plaintext)
                        .map_err(evaluator_refusal)?,
                )
            }
            EvaluatorOpcode::PlaintextMultiply => {
                let plaintext = self.constant_coefficients(instruction)?;
                Some(
                    plaintext_mul(self.input_register(instruction, 0)?, &plaintext)
                        .map_err(evaluator_refusal)?,
                )
            }
            EvaluatorOpcode::DropRegister => {
                let register = *instruction
                    .input_registers()
                    .first()
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let dropped = take_register(&mut self.registers, register)?;
                self.live_ciphertext_count = self
                    .live_ciphertext_count
                    .checked_sub(1)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                self.live_ciphertext_coefficient_byte_count = self
                    .live_ciphertext_coefficient_byte_count
                    .checked_sub(ciphertext_coefficient_byte_count(dropped.level)?)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                None
            }
            EvaluatorOpcode::DeclareOutput => {
                let register = *instruction
                    .input_registers()
                    .first()
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                self.live_register(register)?;
                match instruction.immediate0() {
                    1 if self.target_identifier_register.replace(register).is_none() => {}
                    2 if self.target_order_register.replace(register).is_none() => {}
                    _ => return Err(RefusalReason::WrongTypeOrLength),
                }
                None
            }
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize
            | EvaluatorOpcode::GaloisRotate => return Err(RefusalReason::ConsumedState),
        };
        if let Some(output) = output {
            self.push_instruction_output(instruction, output)?;
        } else if instruction.output_register().is_some() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(())
    }

    fn execute_key_instruction(
        &self,
        instruction: &EvaluatorInstruction,
        key_context: &super::super::replay::VerifiedEvaluatorKeyContext,
    ) -> Result<Ciphertext, RefusalReason> {
        let required_key = self
            .execution_schedule
            .required_key(self.next_instruction_ordinal)?
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if !required_key.matches_position(key_context.position()) {
            return Err(RefusalReason::WrongContext);
        }
        match instruction.opcode() {
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                let tensor = ciphertext_tensor(
                    self.input_register(instruction, 0)?,
                    self.input_register(instruction, 1)?,
                )
                .map_err(evaluator_refusal)?;
                let relinearized = key_context
                    .relinearize(&tensor)
                    .map_err(evaluator_refusal)?;
                if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop {
                    modulus_switch(&relinearized).map_err(evaluator_refusal)
                } else {
                    Ok(relinearized)
                }
            }
            EvaluatorOpcode::GaloisRotate => key_context
                .rotate(self.input_register(instruction, 0)?)
                .map_err(evaluator_refusal),
            _ => Err(RefusalReason::WrongTypeOrLength),
        }
    }

    fn input_register(
        &self,
        instruction: &EvaluatorInstruction,
        input_ordinal: usize,
    ) -> Result<&Ciphertext, RefusalReason> {
        let register = instruction
            .input_registers()
            .get(input_ordinal)
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        self.live_register(register)
    }

    fn live_register(&self, register: u32) -> Result<&Ciphertext, RefusalReason> {
        self.registers
            .get(usize::try_from(register).map_err(|_| RefusalReason::OutsideSupportedProfile)?)
            .and_then(Option::as_ref)
            .ok_or(RefusalReason::MissingPrerequisite)
    }

    fn push_instruction_output(
        &mut self,
        instruction: &EvaluatorInstruction,
        output: Ciphertext,
    ) -> Result<(), RefusalReason> {
        let output_register = instruction
            .output_register()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        if usize::try_from(output_register).ok() != Some(self.registers.len()) {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let output_coefficient_byte_count = ciphertext_coefficient_byte_count(output.level)?;
        self.registers.push(Some(output));
        self.live_ciphertext_count = self
            .live_ciphertext_count
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.live_ciphertext_coefficient_byte_count = self
            .live_ciphertext_coefficient_byte_count
            .checked_add(output_coefficient_byte_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.execution_accounting.maximum_live_ciphertext_count = self
            .execution_accounting
            .maximum_live_ciphertext_count
            .max(self.live_ciphertext_count);
        self.execution_accounting
            .maximum_live_ciphertext_coefficient_byte_count = self
            .execution_accounting
            .maximum_live_ciphertext_coefficient_byte_count
            .max(self.live_ciphertext_coefficient_byte_count);
        Ok(())
    }

    fn constant_coefficients(
        &self,
        instruction: &EvaluatorInstruction,
    ) -> Result<Vec<u64>, RefusalReason> {
        let constant_hash = instruction
            .constant_hash()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let constant_ordinal = self
            .constant_ordinals
            .get(constant_hash.as_bytes())
            .copied()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let constant = self
            .program
            .constants()
            .get(constant_ordinal)
            .ok_or(RefusalReason::MissingPrerequisite)?;
        encode_constant_coefficients(constant)
    }

    fn refuse(&mut self, reason: RefusalReason) {
        self.pending_key_load = None;
        self.resident_key_context = None;
        self.registers.clear();
        self.live_ciphertext_count = 0;
        self.live_ciphertext_coefficient_byte_count = 0;
        self.refusal_reason = Some(reason);
    }
}

/// Opaque result of running the canonical instruction stream with only
/// accepted aggregate and complete-store capabilities.
pub(crate) struct VerifiedSelectedEvaluatorExecution {
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
    top_count: u16,
    target_identifier: Ciphertext,
    target_order: Ciphertext,
}

impl VerifiedSelectedEvaluatorExecution {
    /// Prepares the exact deterministic replay carrier from recomputed output
    /// streams. The large ciphertexts remain inside Rust and are discarded
    /// after their verifier-owned summaries have been retained.
    pub(crate) fn prepare_replay(self) -> Result<PreparedSelectedEvaluatorReplay, RefusalReason> {
        let target_level = u16::try_from(self.target_identifier.level)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        if self.target_identifier.level != self.target_order.level
            || self.target_identifier.decrypt_scaling != self.target_order.decrypt_scaling
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let decrypt_scaling = self.target_identifier.decrypt_scaling;
        let target_identifier_bytes =
            ciphertext_canonical_bytes(&self.target_identifier).map_err(evaluator_refusal)?;
        let target_identifier_stream = canonical_ciphertext_stream_summary(
            CanonicalStreamDomain::ReplayTargetIdentifierCiphertext,
            &target_identifier_bytes,
        )?;
        drop(target_identifier_bytes);
        let target_order_bytes =
            ciphertext_canonical_bytes(&self.target_order).map_err(evaluator_refusal)?;
        let target_order_stream = canonical_ciphertext_stream_summary(
            CanonicalStreamDomain::ReplayTargetOrderCiphertext,
            &target_order_bytes,
        )?;
        drop(target_order_bytes);

        let canonical_replay_carrier = encode_evaluator_replay_carrier(
            Hash512::from_bytes(self.suite_identifier),
            Hash512::from_bytes(self.ceremony_context_hash),
            Hash512::from_bytes(self.action_context_hash),
            Hash512::from_bytes(self.verified_setup_source_hash),
            Hash512::from_bytes(self.verified_aggregate_source_hash),
            target_identifier_stream.stream_descriptor().clone(),
            target_order_stream.stream_descriptor().clone(),
        )
        .map_err(|error| error.refusal_reason)?;

        Ok(PreparedSelectedEvaluatorReplay {
            canonical_replay_carrier: canonical_replay_carrier.into_boxed_slice(),
            suite_identifier: self.suite_identifier,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            verified_setup_source_hash: self.verified_setup_source_hash,
            verified_aggregate_source_hash: self.verified_aggregate_source_hash,
            top_count: self.top_count,
            target_level,
            decrypt_scaling,
            target_identifier_stream,
            target_order_stream,
        })
    }
}

/// Opaque completed evaluator result awaiting publication and positive board
/// ingestion of its exact deterministic replay carrier.
pub(crate) struct PreparedSelectedEvaluatorReplay {
    canonical_replay_carrier: Box<[u8]>,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
    top_count: u16,
    target_level: u16,
    decrypt_scaling: u64,
    target_identifier_stream: VerifiedCanonicalStreamSummary,
    target_order_stream: VerifiedCanonicalStreamSummary,
}

impl PreparedSelectedEvaluatorReplay {
    pub(crate) fn canonical_replay_carrier(&self) -> &[u8] {
        &self.canonical_replay_carrier
    }

    /// Joins only the byte-identical board-ingested replay object to the
    /// retained recomputed stream summaries. A failed preflight leaves this
    /// authority reusable so relay or object-selection mistakes do not force
    /// the expensive deterministic evaluation to be repeated.
    pub(crate) fn verify_board_object(
        &self,
        replay_object: &VerifiedTranscriptObject,
        limits: &CanonicalDecodeLimits,
    ) -> Result<VerifiedEvaluatorReplay, RefusalReason> {
        if replay_object.canonical_carrier_bytes() != self.canonical_replay_carrier.as_ref() {
            return Err(RefusalReason::WrongHashOrRoot);
        }

        let verified_replay = VerifiedEvaluatorReplay::from_verified_relation(
            replay_object,
            crate::foundation::VerifiedEvaluatorReplayRelationOutput {
                roster_hash: Hash512::from_bytes(self.roster_hash),
                top_count: self.top_count,
                target_level: self.target_level,
                decrypt_scaling: self.decrypt_scaling,
                target_identifier_stream: self.target_identifier_stream.clone(),
                target_order_stream: self.target_order_stream.clone(),
            },
            limits,
        )
        .map_err(|error| error.refusal_reason)?;
        if verified_replay.suite_identifier() != Hash512::from_bytes(self.suite_identifier)
            || verified_replay.ceremony_context_hash()
                != Hash512::from_bytes(self.ceremony_context_hash)
            || verified_replay.action_context_hash()
                != Hash512::from_bytes(self.action_context_hash)
            || verified_replay.roster_hash() != Hash512::from_bytes(self.roster_hash)
            || verified_replay.verified_setup_source_hash()
                != Hash512::from_bytes(self.verified_setup_source_hash)
            || verified_replay.verified_aggregate_source_hash()
                != Hash512::from_bytes(self.verified_aggregate_source_hash)
            || verified_replay.top_count() != self.top_count
            || verified_replay.target_level() != self.target_level
            || verified_replay.decrypt_scaling() != self.decrypt_scaling
        {
            return Err(RefusalReason::WrongContext);
        }
        Ok(verified_replay)
    }
}

fn canonical_ciphertext_stream_summary(
    stream_domain: CanonicalStreamDomain,
    bytes: &[u8],
) -> Result<VerifiedCanonicalStreamSummary, RefusalReason> {
    let total_byte_length =
        u64::try_from(bytes.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let mut writer = CanonicalStreamWriter::new(stream_domain, total_byte_length)?;
    for (chunk_index, chunk_bytes) in bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        writer.absorb_chunk(chunk_index, chunk_bytes)?;
    }
    writer.finish_generated_summary()
}

pub(crate) fn encode_constant_coefficients(
    constant: &EvaluatorConstant,
) -> Result<Vec<u64>, RefusalReason> {
    let values = constant
        .values()
        .iter()
        .copied()
        .map(u64::from)
        .collect::<Vec<_>>();
    if constant.kind() != EvaluatorConstantKind::CoefficientVector {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }
    let mut coefficients = values;
    coefficients.resize(POLYNOMIAL_DEGREE, 0);
    Ok(coefficients)
}

fn take_register(
    registers: &mut [Option<Ciphertext>],
    register: u32,
) -> Result<Ciphertext, RefusalReason> {
    registers
        .get_mut(usize::try_from(register).map_err(|_| RefusalReason::OutsideSupportedProfile)?)
        .and_then(Option::take)
        .ok_or(RefusalReason::MissingPrerequisite)
}

fn validate_aggregate_ciphertext(ciphertext: &Ciphertext) -> Result<(), RefusalReason> {
    if ciphertext.level != SELECTED_EVALUATOR_WORKING_LEVEL
        || ciphertext.decrypt_scaling != 1
        || ciphertext.components.len() != 2
        || ciphertext
            .components
            .iter()
            .any(|component| component.len() != SELECTED_EVALUATOR_WORKING_LEVEL + 1)
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    for component in &ciphertext.components {
        for (limb_index, limb) in component.iter().enumerate() {
            let modulus = *DATA_PRIMES
                .get(limb_index)
                .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
            if limb.len() != POLYNOMIAL_DEGREE
                || limb.iter().any(|coefficient| *coefficient >= modulus)
            {
                return Err(RefusalReason::MalformedEncoding);
            }
        }
    }
    Ok(())
}

fn evaluator_refusal(error: CanonicalError) -> RefusalReason {
    match error.code {
        CanonicalErrorCode::MalformedLength | CanonicalErrorCode::ComponentMismatch => {
            RefusalReason::WrongTypeOrLength
        }
        CanonicalErrorCode::UnsupportedObjectVersion => RefusalReason::UnsupportedVersionOrSuite,
        CanonicalErrorCode::DuplicateField
        | CanonicalErrorCode::InvalidEnum
        | CanonicalErrorCode::InvalidProtocolObject
        | CanonicalErrorCode::InvalidHex
        | CanonicalErrorCode::InvalidUtf8
        | CanonicalErrorCode::MalformedMagic
        | CanonicalErrorCode::MalformedVarUint
        | CanonicalErrorCode::NonCanonicalVarUint
        | CanonicalErrorCode::TrailingBytes => RefusalReason::MalformedEncoding,
    }
}
