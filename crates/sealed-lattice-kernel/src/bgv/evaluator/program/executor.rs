use std::collections::BTreeMap;

use crate::{
    bgv::{
        evaluator::{
            engine::{
                Ciphertext, add_plaintext_coefficients, ciphertext_add, ciphertext_canonical_bytes,
                ciphertext_negate, ciphertext_sub, ciphertext_tensor, encode_slots_to_coefficients,
                modulus_switch, modulus_switch_to, normalize_scaling, plaintext_mul,
            },
            replay::{
                EvaluatorKeyStoreReadRequest, VerifiedEvaluatorKeyReplay,
                VerifiedEvaluatorKeyResolver,
            },
            top_k::SELECTED_EVALUATOR_WORKING_LEVEL,
        },
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
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
    ballot_count: u16,
    top_count: u16,
    aggregate_ciphertext: Ciphertext,
}

impl VerifiedEvaluatorAggregate {
    pub(in crate::bgv::evaluator) fn from_verified_ballot_aggregate(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
        verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
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
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            verified_setup_source_hash,
            verified_aggregate_source_hash,
            ballot_count,
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

struct PendingEvaluatorKeyOperation {
    instruction: EvaluatorInstruction,
    replay: VerifiedEvaluatorKeyReplay,
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
    next_instruction_ordinal: usize,
    registers: Vec<Option<Ciphertext>>,
    pending_key_operation: Option<PendingEvaluatorKeyOperation>,
    target_identifier_register: Option<u32>,
    target_order_register: Option<u32>,
    evaluator_replay_context_hash: [u8; Hash512::BYTE_LENGTH],
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
    ballot_count: u16,
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
            next_instruction_ordinal: 0,
            registers: vec![Some(aggregate.aggregate_ciphertext)],
            pending_key_operation: None,
            target_identifier_register: None,
            target_order_register: None,
            evaluator_replay_context_hash,
            suite_identifier: aggregate.suite_identifier,
            ceremony_context_hash: aggregate.ceremony_context_hash,
            action_context_hash: aggregate.action_context_hash,
            roster_hash: aggregate.roster_hash,
            verified_setup_source_hash: aggregate.verified_setup_source_hash,
            verified_aggregate_source_hash: aggregate.verified_aggregate_source_hash,
            ballot_count: aggregate.ballot_count,
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
            if let Some(pending) = self.pending_key_operation.as_ref() {
                if let Some(request) = pending.replay.next_read_request() {
                    return Ok(SelectedEvaluatorExecutionProgress::StoreReadRequired(
                        request,
                    ));
                }
                let pending = self
                    .pending_key_operation
                    .take()
                    .ok_or(RefusalReason::ConsumedState)?;
                let key_context = pending.replay.finish()?;
                if key_context.resolver_context_hash() != self.evaluator_replay_context_hash {
                    return Err(RefusalReason::WrongContext);
                }
                let output = self.execute_key_instruction(&pending.instruction, &key_context)?;
                drop(key_context);
                self.push_instruction_output(&pending.instruction, output)?;
                self.next_instruction_ordinal = self
                    .next_instruction_ordinal
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
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
            match instruction.opcode() {
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                    let replay = self.resolver.begin_relinearization_key_replay()?;
                    self.pending_key_operation = Some(PendingEvaluatorKeyOperation {
                        instruction,
                        replay,
                    });
                }
                EvaluatorOpcode::GaloisRotate => {
                    let galois_element = usize::try_from(instruction.immediate0())
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                    let replay = self.resolver.begin_galois_key_replay(galois_element)?;
                    self.pending_key_operation = Some(PendingEvaluatorKeyOperation {
                        instruction,
                        replay,
                    });
                }
                _ => {
                    self.execute_non_key_instruction(&instruction)?;
                    self.next_instruction_ordinal = self
                        .next_instruction_ordinal
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                }
            }
        }
    }

    pub(crate) fn absorb_next_store_chunk(
        &mut self,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if let Some(reason) = self.refusal_reason {
            return Err(reason);
        }
        let result = self
            .pending_key_operation
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)
            .and_then(|pending| {
                pending
                    .replay
                    .absorb_next_store_chunk(store_byte_offset, chunk_bytes)
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
        if self.pending_key_operation.is_some()
            || self.next_instruction_ordinal != self.selected_instructions()?.len()
        {
            return Err(RefusalReason::ConsumedState);
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
            evaluator_replay_context_hash: self.evaluator_replay_context_hash,
            suite_identifier: self.suite_identifier,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            verified_setup_source_hash: self.verified_setup_source_hash,
            verified_aggregate_source_hash: self.verified_aggregate_source_hash,
            ballot_count: self.ballot_count,
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
            EvaluatorOpcode::CiphertextSubtract => Some(
                ciphertext_sub(
                    self.input_register(instruction, 0)?,
                    self.input_register(instruction, 1)?,
                )
                .map_err(evaluator_refusal)?,
            ),
            EvaluatorOpcode::CiphertextNegate => Some(
                ciphertext_negate(self.input_register(instruction, 0)?)
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
                take_register(&mut self.registers, register)?;
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
        self.registers.push(Some(output));
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
        self.pending_key_operation = None;
        self.registers.clear();
        self.refusal_reason = Some(reason);
    }
}

/// Opaque result of running the canonical instruction stream with only
/// accepted aggregate and complete-store capabilities.
pub(crate) struct VerifiedSelectedEvaluatorExecution {
    evaluator_replay_context_hash: [u8; Hash512::BYTE_LENGTH],
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    verified_aggregate_source_hash: [u8; Hash512::BYTE_LENGTH],
    ballot_count: u16,
    top_count: u16,
    target_identifier: Ciphertext,
    target_order: Ciphertext,
}

impl VerifiedSelectedEvaluatorExecution {
    pub(crate) const fn evaluator_replay_context_hash(&self) -> [u8; 64] {
        self.evaluator_replay_context_hash
    }

    pub(crate) const fn verified_setup_source_hash(&self) -> [u8; 64] {
        self.verified_setup_source_hash
    }

    pub(crate) const fn verified_aggregate_source_hash(&self) -> [u8; 64] {
        self.verified_aggregate_source_hash
    }

    pub(crate) const fn ballot_count(&self) -> u16 {
        self.ballot_count
    }

    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) const fn target_identifier(&self) -> &Ciphertext {
        &self.target_identifier
    }

    pub(crate) const fn target_order(&self) -> &Ciphertext {
        &self.target_order
    }

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
            Hash512::from_bytes(self.roster_hash),
            self.top_count,
            self.target_level,
            self.decrypt_scaling,
            self.target_identifier_stream.clone(),
            self.target_order_stream.clone(),
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

fn encode_constant_coefficients(constant: &EvaluatorConstant) -> Result<Vec<u64>, RefusalReason> {
    let values = constant
        .values()
        .iter()
        .copied()
        .map(u64::from)
        .collect::<Vec<_>>();
    match constant.kind() {
        EvaluatorConstantKind::CoefficientVector => {
            let mut coefficients = values;
            coefficients.resize(POLYNOMIAL_DEGREE, 0);
            Ok(coefficients)
        }
        EvaluatorConstantKind::SlotVector => {
            encode_slots_to_coefficients(&values).map_err(evaluator_refusal)
        }
    }
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
