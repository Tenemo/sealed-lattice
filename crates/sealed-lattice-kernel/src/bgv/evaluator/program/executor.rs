use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroize;

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
                CHARACTER_OUTPUT_LEVEL, SELECTED_RELINEARIZATION_KEY_LEVEL,
                selected_evaluator_rotation_key_schedule,
            },
        },
        key_switch_topology::KeySwitchDecompositionTopology,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        proof_suite::{SelectedEvaluatorEntryKind, SelectedEvaluatorEntryPosition},
        setup::{
            VerifiedAcceptedSetupAuthority, VerifiedAcceptedSetupAuthorityHandle,
            VerifiedEvaluatorExecutionAuthority, take_verified_evaluator_execution_authority,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode},
    foundation::{
        CanonicalDecodeLimits, CanonicalStreamDomain, CanonicalStreamWriter, FOUNDATION_PROFILE,
        Hash512, RefusalReason, VerifiedCanonicalStreamSummary, VerifiedEvaluatorReplay,
        VerifiedTranscriptObject, encode_evaluator_replay_carrier,
    },
};

#[cfg(test)]
use crate::bgv::parameters::SPECIAL_PRIMES;

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

/// Verifier-owned ordered ciphertext pair for the deterministic evaluator. Its
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
    aggregate_ciphertexts: [Ciphertext; 2],
}

impl VerifiedEvaluatorAggregate {
    pub(in crate::bgv::evaluator) fn from_verified_ballot_aggregate(
        context: VerifiedEvaluatorAggregateContext,
        ballot_count: u16,
        top_count: u16,
        mut aggregate_ciphertexts: [Ciphertext; 2],
    ) -> Result<Self, RefusalReason> {
        if let Err(refusal_reason) = validate_aggregate_ciphertexts(&aggregate_ciphertexts) {
            zeroize_ciphertexts(&mut aggregate_ciphertexts);
            return Err(refusal_reason);
        }
        if ballot_count == 0
            || ballot_count > FOUNDATION_PROFILE.participant_count
            || top_count == 0
            || top_count > FOUNDATION_PROFILE.option_count
        {
            zeroize_ciphertexts(&mut aggregate_ciphertexts);
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
            aggregate_ciphertexts,
        })
    }

    fn take_aggregate_ciphertexts(&mut self) -> [Ciphertext; 2] {
        core::mem::replace(
            &mut self.aggregate_ciphertexts,
            core::array::from_fn(|_| empty_ciphertext()),
        )
    }
}

impl Drop for VerifiedEvaluatorAggregate {
    fn drop(&mut self) {
        zeroize_ciphertexts(&mut self.aggregate_ciphertexts);
    }
}

/// Sole evaluator-store authority taken during ballot aggregation. It owns the
/// resolver across product construction and later transfers that same resolver
/// into evaluator replay; the accepted setup cannot be consumed a second time.
pub(crate) struct VerifiedEvaluatorAggregationAuthority {
    setup_context: EvaluatorExecutionSetupContextBinding,
    evaluator_replay_context_hash: [u8; Hash512::BYTE_LENGTH],
    resolver: VerifiedEvaluatorKeyResolver,
}

impl VerifiedEvaluatorAggregationAuthority {
    /// Validates the borrowed first-ballot context and suite-maximal store
    /// while the accepted-setup registry is locked, then atomically takes the
    /// one physical-store authority.
    pub(crate) fn take_from_accepted_setup(
        accepted_setup_handle: &VerifiedAcceptedSetupAuthorityHandle,
        validate_first_ballot: impl FnOnce(&VerifiedAcceptedSetupAuthority) -> bool,
    ) -> Result<Self, RefusalReason> {
        let mut setup_context = None;
        let execution_authority =
            take_verified_evaluator_execution_authority(accepted_setup_handle, |accepted_setup| {
                if !validate_first_ballot(accepted_setup)
                    || !evaluator_store_top_count_is_suite_maximal(
                        accepted_setup.verified_evaluator_store_top_count(),
                    )
                {
                    return false;
                }
                setup_context = Some(
                    EvaluatorExecutionSetupContextBinding::from_verified_accepted_setup(
                        accepted_setup,
                    ),
                );
                true
            })?;
        let setup_context = setup_context.ok_or(RefusalReason::WrongContext)?;
        Self::from_execution_authority(execution_authority, setup_context)
    }

    fn from_execution_authority(
        execution_authority: VerifiedEvaluatorExecutionAuthority,
        setup_context: EvaluatorExecutionSetupContextBinding,
    ) -> Result<Self, RefusalReason> {
        if execution_authority.protocol_version() != setup_context.protocol_version
            || execution_authority.suite_identifier() != setup_context.suite_identifier
            || execution_authority.ceremony_context_hash() != setup_context.ceremony_context_hash
            || execution_authority.action_context_hash() != setup_context.action_context_hash
            || execution_authority.roster_hash() != setup_context.roster_hash
            || !evaluator_store_top_count_is_suite_maximal(Some(
                execution_authority.verified_store_top_count(),
            ))
        {
            return Err(RefusalReason::WrongContext);
        }
        let evaluator_replay_context_hash = execution_authority.evaluator_replay_context_hash();
        let resolver = VerifiedEvaluatorKeyResolver::from_execution_authority(execution_authority)?;
        Ok(Self {
            setup_context,
            evaluator_replay_context_hash,
            resolver,
        })
    }

    pub(crate) fn resolver(&self) -> &VerifiedEvaluatorKeyResolver {
        &self.resolver
    }

    pub(crate) const fn evaluator_replay_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.evaluator_replay_context_hash
    }

    pub(crate) fn bind_aggregate(
        self,
        aggregate: VerifiedEvaluatorAggregate,
    ) -> Result<VerifiedEvaluatorAggregateExecutionAuthority, RefusalReason> {
        if EvaluatorExecutionSetupContextBinding::from_verified_aggregate(&aggregate)
            != self.setup_context
        {
            return Err(RefusalReason::WrongContext);
        }
        validate_aggregate_ciphertexts(&aggregate.aggregate_ciphertexts)?;
        Ok(VerifiedEvaluatorAggregateExecutionAuthority {
            aggregate,
            aggregation_authority: self,
        })
    }
}

/// One-shot handoff from the positively bound aggregate into evaluator
/// execution. Both ciphertexts and their authenticated store resolver move as
/// one opaque value.
pub(crate) struct VerifiedEvaluatorAggregateExecutionAuthority {
    aggregate: VerifiedEvaluatorAggregate,
    aggregation_authority: VerifiedEvaluatorAggregationAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EvaluatorExecutionSetupContextBinding {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
}

impl EvaluatorExecutionSetupContextBinding {
    const fn from_verified_aggregate(aggregate: &VerifiedEvaluatorAggregate) -> Self {
        Self {
            protocol_version: aggregate.protocol_version,
            suite_identifier: aggregate.suite_identifier,
            ceremony_context_hash: aggregate.ceremony_context_hash,
            action_context_hash: aggregate.action_context_hash,
            roster_hash: aggregate.roster_hash,
            verified_setup_source_hash: aggregate.verified_setup_source_hash,
        }
    }

    fn from_verified_accepted_setup(accepted_setup: &VerifiedAcceptedSetupAuthority) -> Self {
        Self {
            protocol_version: accepted_setup.protocol_version(),
            suite_identifier: accepted_setup.suite_identifier(),
            ceremony_context_hash: accepted_setup.ceremony_context_hash(),
            action_context_hash: accepted_setup.action_context_hash(),
            roster_hash: accepted_setup.roster_hash(),
            verified_setup_source_hash: accepted_setup.exact_verified_setup_source_hash(),
        }
    }

    #[cfg(test)]
    const fn from_test_values(
        protocol_version: u16,
        suite_identifier: [u8; Hash512::BYTE_LENGTH],
        ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
        action_context_hash: [u8; Hash512::BYTE_LENGTH],
        roster_hash: [u8; Hash512::BYTE_LENGTH],
        verified_setup_source_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            verified_setup_source_hash,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedEvaluatorExecutionRequestBinding {
    setup_context: EvaluatorExecutionSetupContextBinding,
    action_top_count: u16,
}

impl SelectedEvaluatorExecutionRequestBinding {
    const fn from_verified_aggregate(aggregate: &VerifiedEvaluatorAggregate) -> Self {
        Self {
            setup_context: EvaluatorExecutionSetupContextBinding::from_verified_aggregate(
                aggregate,
            ),
            action_top_count: aggregate.top_count,
        }
    }

    fn selected_stream_ordinal(self) -> Result<usize, RefusalReason> {
        if self.action_top_count == 0 || self.action_top_count > FOUNDATION_PROFILE.option_count {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        Ok(usize::from(self.action_top_count - 1))
    }

    #[cfg(test)]
    fn accepts_verified_store(self, store: AcceptedEvaluatorStoreAuthorityBinding) -> bool {
        self.setup_context == store.setup_context
            && evaluator_store_top_count_is_suite_maximal(store.verified_store_top_count)
    }

    #[cfg(test)]
    const fn from_test_values(
        setup_context: EvaluatorExecutionSetupContextBinding,
        action_top_count: u16,
    ) -> Self {
        Self {
            setup_context,
            action_top_count,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AcceptedEvaluatorStoreAuthorityBinding {
    setup_context: EvaluatorExecutionSetupContextBinding,
    verified_store_top_count: Option<u16>,
}

#[cfg(test)]
impl AcceptedEvaluatorStoreAuthorityBinding {
    const fn from_test_values(
        setup_context: EvaluatorExecutionSetupContextBinding,
        verified_store_top_count: Option<u16>,
    ) -> Self {
        Self {
            setup_context,
            verified_store_top_count,
        }
    }
}

const fn evaluator_store_top_count_is_suite_maximal(verified_store_top_count: Option<u16>) -> bool {
    matches!(
        verified_store_top_count,
        Some(top_count) if top_count == FOUNDATION_PROFILE.option_count
    )
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
    maximum_resident_key_count: usize,
    maximum_live_ciphertext_count: usize,
    maximum_live_ciphertext_coefficient_byte_count: u64,
}

/// Exact production-derived work and coefficient-buffer accounting for one
/// canonical evaluator instruction stream. The memory fields count owned
/// coefficient payloads rather than allocator metadata: live ciphertexts are
/// the register payloads retained across instructions, resident key bytes are
/// the two NTT components held by the one-key replay guard, and operation
/// scratch includes every output and temporary coefficient buffer owned while
/// an instruction executes. The combined peak is derived per instruction, so
/// maxima from unrelated phases are never added together.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorExecutionResourceTotals {
    instruction_count: usize,
    key_operation_count: usize,
    key_load_count: usize,
    key_store_read_request_count: u64,
    key_store_reread_request_count: u64,
    key_store_read_byte_count: u64,
    key_store_reread_byte_count: u64,
    key_ntt_transform_count: usize,
    rotation_count: usize,
    ciphertext_multiplication_count: usize,
    plaintext_multiplication_count: usize,
    modulus_switch_count: usize,
    maximum_live_ciphertext_byte_count: u64,
    maximum_resident_key_byte_count: u64,
    maximum_operation_scratch_byte_count: u64,
    peak_combined_wasm_resident_byte_count: u64,
}

#[cfg(test)]
impl SelectedEvaluatorExecutionResourceTotals {
    pub(crate) const fn instruction_count(self) -> usize {
        self.instruction_count
    }

    pub(crate) const fn key_operation_count(self) -> usize {
        self.key_operation_count
    }

    pub(crate) const fn key_load_count(self) -> usize {
        self.key_load_count
    }

    pub(crate) const fn key_store_read_request_count(self) -> u64 {
        self.key_store_read_request_count
    }

    pub(crate) const fn key_store_reread_request_count(self) -> u64 {
        self.key_store_reread_request_count
    }

    pub(crate) const fn key_store_read_byte_count(self) -> u64 {
        self.key_store_read_byte_count
    }

    pub(crate) const fn key_store_reread_byte_count(self) -> u64 {
        self.key_store_reread_byte_count
    }

    pub(crate) const fn key_ntt_transform_count(self) -> usize {
        self.key_ntt_transform_count
    }

    pub(crate) const fn rotation_count(self) -> usize {
        self.rotation_count
    }

    pub(crate) const fn ciphertext_multiplication_count(self) -> usize {
        self.ciphertext_multiplication_count
    }

    pub(crate) const fn plaintext_multiplication_count(self) -> usize {
        self.plaintext_multiplication_count
    }

    pub(crate) const fn modulus_switch_count(self) -> usize {
        self.modulus_switch_count
    }

    pub(crate) const fn maximum_live_ciphertext_byte_count(self) -> u64 {
        self.maximum_live_ciphertext_byte_count
    }

    pub(crate) const fn maximum_resident_key_byte_count(self) -> u64 {
        self.maximum_resident_key_byte_count
    }

    pub(crate) const fn maximum_operation_scratch_byte_count(self) -> u64 {
        self.maximum_operation_scratch_byte_count
    }

    pub(crate) const fn peak_combined_wasm_resident_byte_count(self) -> u64 {
        self.peak_combined_wasm_resident_byte_count
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorExecutionResourceRow {
    top_count: u16,
    totals: SelectedEvaluatorExecutionResourceTotals,
}

#[cfg(test)]
impl SelectedEvaluatorExecutionResourceRow {
    pub(crate) const fn top_count(self) -> u16 {
        self.top_count
    }

    pub(crate) const fn totals(self) -> SelectedEvaluatorExecutionResourceTotals {
        self.totals
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorExecutionResourceLedger {
    ordered_streams: Box<[SelectedEvaluatorExecutionResourceRow]>,
    catalog_totals: SelectedEvaluatorExecutionResourceTotals,
}

#[cfg(test)]
impl SelectedEvaluatorExecutionResourceLedger {
    pub(crate) fn ordered_streams(&self) -> &[SelectedEvaluatorExecutionResourceRow] {
        &self.ordered_streams
    }

    /// Sums work and I/O across the complete alternative-stream catalog while
    /// retaining the maximum of each phase-local memory dimension.
    pub(crate) const fn catalog_totals(&self) -> SelectedEvaluatorExecutionResourceTotals {
        self.catalog_totals
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EvaluatorInstructionMemoryPhase {
    live_ciphertext_byte_count_before_instruction: u64,
    live_ciphertext_byte_count_after_instruction: u64,
    operation_scratch_byte_count: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparedEvaluatorKeyLoadAccounting {
    store_read_request_count: u64,
    store_read_byte_count: u64,
    ntt_transform_count: usize,
    resident_byte_count: u64,
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

struct ZeroizingOwnedCiphertext(Option<Ciphertext>);

impl ZeroizingOwnedCiphertext {
    fn new(ciphertext: Ciphertext) -> Self {
        Self(Some(ciphertext))
    }

    fn as_ref(&self) -> &Ciphertext {
        self.0
            .as_ref()
            .expect("zeroizing ciphertext remains owned until its explicit transfer")
    }

    fn into_inner(mut self) -> Ciphertext {
        self.0
            .take()
            .expect("zeroizing ciphertext can transfer ownership only once")
    }
}

impl Drop for ZeroizingOwnedCiphertext {
    fn drop(&mut self) {
        if let Some(ciphertext) = self.0.as_mut() {
            zeroize_ciphertext(ciphertext);
        }
    }
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
        let mut live_register_levels = vec![Some(CHARACTER_OUTPUT_LEVEL); 2];
        let mut live_ciphertext_count = 2_usize;
        let mut maximum_live_ciphertext_count = 2_usize;
        let mut live_ciphertext_coefficient_byte_count =
            initial_evaluator_ciphertext_coefficient_byte_count()?;
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

            if matches!(
                instruction.opcode(),
                EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                    | EvaluatorOpcode::CiphertextMultiplyAndRelinearize
            ) {
                let input_register = *instruction
                    .input_registers()
                    .first()
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let input_level = live_register_levels
                    .get(
                        usize::try_from(input_register)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                    .and_then(|level| *level)
                    .ok_or(RefusalReason::MissingPrerequisite)?;
                maximum_live_ciphertext_count = maximum_live_ciphertext_count.max(
                    live_ciphertext_count
                        .checked_add(2)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?,
                );
                maximum_live_ciphertext_coefficient_byte_count =
                    maximum_live_ciphertext_coefficient_byte_count.max(
                        live_ciphertext_coefficient_byte_count
                            .checked_add(multiplication_transient_coefficient_byte_count(
                                input_level,
                            )?)
                            .ok_or(RefusalReason::OutsideSupportedProfile)?,
                    );
            }

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
            accounting.maximum_resident_key_count = 1;
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

/// Derives exact accounting for every canonical `topCount` stream. All rows
/// come from the same production program and key schedule used by execution;
/// callers cannot inject instructions, levels, or key positions.
#[cfg(test)]
pub(crate) fn selected_evaluator_execution_resource_ledger()
-> Result<SelectedEvaluatorExecutionResourceLedger, RefusalReason> {
    let program = selected_evaluator_program_set().map_err(evaluator_refusal)?;
    let mut ordered_streams = Vec::with_capacity(program.streams().len());
    let mut catalog_totals = SelectedEvaluatorExecutionResourceTotals::default();
    for (stream_ordinal, stream) in program.streams().iter().enumerate() {
        let expected_top_count = u16::try_from(stream_ordinal)
            .ok()
            .and_then(|ordinal| ordinal.checked_add(1))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if stream.top_count() != expected_top_count {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let totals = derive_evaluator_stream_resource_totals(stream.instructions())?;
        accumulate_evaluator_catalog_totals(&mut catalog_totals, totals)?;
        ordered_streams.push(SelectedEvaluatorExecutionResourceRow {
            top_count: stream.top_count(),
            totals,
        });
    }
    if ordered_streams.len() != usize::from(FOUNDATION_PROFILE.option_count) {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(SelectedEvaluatorExecutionResourceLedger {
        ordered_streams: ordered_streams.into_boxed_slice(),
        catalog_totals,
    })
}

#[cfg(test)]
fn derive_evaluator_stream_resource_totals(
    instructions: &[EvaluatorInstruction],
) -> Result<SelectedEvaluatorExecutionResourceTotals, RefusalReason> {
    let schedule = PreparedEvaluatorExecutionSchedule::derive(instructions)?;
    let mut live_register_levels = vec![Some(CHARACTER_OUTPUT_LEVEL); 2];
    let mut live_ciphertext_byte_count = initial_evaluator_ciphertext_coefficient_byte_count()?;
    let mut totals = SelectedEvaluatorExecutionResourceTotals {
        instruction_count: instructions.len(),
        maximum_live_ciphertext_byte_count: live_ciphertext_byte_count,
        peak_combined_wasm_resident_byte_count: live_ciphertext_byte_count,
        ..SelectedEvaluatorExecutionResourceTotals::default()
    };
    let mut memory_phases = Vec::with_capacity(instructions.len());

    for instruction in instructions {
        let live_ciphertext_byte_count_before_instruction = live_ciphertext_byte_count;
        let operation_scratch_byte_count =
            evaluator_instruction_operation_scratch_byte_count(instruction, &live_register_levels)?;
        totals.maximum_operation_scratch_byte_count = totals
            .maximum_operation_scratch_byte_count
            .max(operation_scratch_byte_count);
        match instruction.opcode() {
            EvaluatorOpcode::NormalizeDecryptionMultiplier | EvaluatorOpcode::PlaintextMultiply => {
                totals.plaintext_multiplication_count = totals
                    .plaintext_multiplication_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
                totals.ciphertext_multiplication_count = totals
                    .ciphertext_multiplication_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                totals.key_operation_count = totals
                    .key_operation_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop {
                    totals.modulus_switch_count = totals
                        .modulus_switch_count
                        .checked_add(1)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                }
            }
            EvaluatorOpcode::GaloisRotate => {
                totals.rotation_count = totals
                    .rotation_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                totals.key_operation_count = totals
                    .key_operation_count
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            EvaluatorOpcode::ModulusSwitchToLevel => {
                let source_level =
                    evaluator_instruction_input_level(instruction, &live_register_levels, 0)?;
                let target_level = usize::try_from(instruction.immediate0())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                let drop_count = source_level
                    .checked_sub(target_level)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                if drop_count == 0 {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                totals.modulus_switch_count = totals
                    .modulus_switch_count
                    .checked_add(drop_count)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            EvaluatorOpcode::CiphertextAdd
            | EvaluatorOpcode::PlaintextAdd
            | EvaluatorOpcode::DropRegister
            | EvaluatorOpcode::DeclareOutput => {}
        }

        if instruction.opcode() == EvaluatorOpcode::DropRegister {
            let register = *instruction
                .input_registers()
                .first()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let register_index =
                usize::try_from(register).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let level = live_register_levels
                .get_mut(register_index)
                .ok_or(RefusalReason::MissingPrerequisite)?
                .take()
                .ok_or(RefusalReason::MissingPrerequisite)?;
            live_ciphertext_byte_count = live_ciphertext_byte_count
                .checked_sub(ciphertext_coefficient_byte_count(level)?)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
        } else if let Some(output_register) = instruction.output_register() {
            if usize::try_from(output_register).ok() != Some(live_register_levels.len()) {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            let output_level =
                prepared_instruction_output_level(instruction, &live_register_levels)?
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
            live_register_levels.push(Some(output_level));
            live_ciphertext_byte_count = live_ciphertext_byte_count
                .checked_add(ciphertext_coefficient_byte_count(output_level)?)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            totals.maximum_live_ciphertext_byte_count = totals
                .maximum_live_ciphertext_byte_count
                .max(live_ciphertext_byte_count);
        }
        memory_phases.push(EvaluatorInstructionMemoryPhase {
            live_ciphertext_byte_count_before_instruction,
            live_ciphertext_byte_count_after_instruction: live_ciphertext_byte_count,
            operation_scratch_byte_count,
        });
    }
    if live_register_levels.iter().flatten().count() != 2 {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    let mut resident_key = None;
    let mut loaded_keys = BTreeSet::new();
    for (instruction_ordinal, memory_phase) in memory_phases.iter().copied().enumerate() {
        let required_key = schedule.required_key(instruction_ordinal)?;
        if let Some(required_key) = required_key
            && resident_key != Some(required_key)
        {
            let load = prepared_evaluator_key_load_accounting(required_key)?;
            let counts_as_reread = !loaded_keys.insert(required_key);
            totals.key_load_count = totals
                .key_load_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            totals.key_store_read_request_count = totals
                .key_store_read_request_count
                .checked_add(load.store_read_request_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            totals.key_store_read_byte_count = totals
                .key_store_read_byte_count
                .checked_add(load.store_read_byte_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            totals.key_ntt_transform_count = totals
                .key_ntt_transform_count
                .checked_add(load.ntt_transform_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if counts_as_reread {
                totals.key_store_reread_request_count = totals
                    .key_store_reread_request_count
                    .checked_add(load.store_read_request_count)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                totals.key_store_reread_byte_count = totals
                    .key_store_reread_byte_count
                    .checked_add(load.store_read_byte_count)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            resident_key = Some(required_key);
        }
        let resident_key_byte_count = resident_key
            .map(prepared_evaluator_key_load_accounting)
            .transpose()?
            .map_or(0, |accounting| accounting.resident_byte_count);
        totals.maximum_resident_key_byte_count = totals
            .maximum_resident_key_byte_count
            .max(resident_key_byte_count);
        let instruction_peak = memory_phase
            .live_ciphertext_byte_count_before_instruction
            .checked_add(resident_key_byte_count)
            .and_then(|byte_count| {
                byte_count.checked_add(memory_phase.operation_scratch_byte_count)
            })
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let post_instruction_peak = memory_phase
            .live_ciphertext_byte_count_after_instruction
            .checked_add(resident_key_byte_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        totals.peak_combined_wasm_resident_byte_count = totals
            .peak_combined_wasm_resident_byte_count
            .max(instruction_peak)
            .max(post_instruction_peak);

        let next_required_key = schedule.next_required_key(instruction_ordinal + 1)?;
        if resident_key.is_some() && resident_key != next_required_key {
            resident_key = None;
        }
    }
    if resident_key.is_some() {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    let schedule_accounting = schedule.accounting();
    if totals.key_operation_count != schedule_accounting.key_operation_count
        || totals.key_load_count != schedule_accounting.key_load_count
        || totals.key_store_read_byte_count != schedule_accounting.key_store_read_byte_count
        || totals.key_store_reread_byte_count != schedule_accounting.key_store_reread_byte_count
        || totals.key_ntt_transform_count != schedule_accounting.key_ntt_transform_count
        || schedule_accounting.maximum_resident_key_count != usize::from(totals.key_load_count > 0)
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(totals)
}

#[cfg(test)]
fn prepared_evaluator_key_load_accounting(
    key_identity: PreparedEvaluatorKeyIdentity,
) -> Result<PreparedEvaluatorKeyLoadAccounting, RefusalReason> {
    let topology = KeySwitchDecompositionTopology::for_level(key_identity.catalog_level())
        .map_err(evaluator_refusal)?;
    let component_wire_byte_count = topology
        .canonical_component_wire_byte_length(POLYNOMIAL_DEGREE)
        .map_err(evaluator_refusal)?;
    let physical_store_component_count = key_identity.physical_store_component_count();
    let store_read_byte_count = component_wire_byte_count
        .checked_mul(physical_store_component_count)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let chunk_byte_count = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let requests_per_component = component_wire_byte_count
        .checked_add(
            chunk_byte_count
                .checked_sub(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )
        .and_then(|byte_count| byte_count.checked_div(chunk_byte_count))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let store_read_request_count = requests_per_component
        .checked_mul(physical_store_component_count)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let ntt_transform_count = topology
        .data_block_count()
        .checked_mul(topology.extended_limb_count())
        .and_then(|count| count.checked_mul(2))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    // A Galois store carries only its non-common component, but replay derives
    // the common component and retains the same two-component NTT key shape as
    // relinearization.
    let resident_byte_count = topology
        .resident_component_byte_length(POLYNOMIAL_DEGREE)
        .map_err(evaluator_refusal)?
        .checked_mul(2)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    Ok(PreparedEvaluatorKeyLoadAccounting {
        store_read_request_count,
        store_read_byte_count,
        ntt_transform_count,
        resident_byte_count,
    })
}

#[cfg(test)]
fn evaluator_instruction_operation_scratch_byte_count(
    instruction: &EvaluatorInstruction,
    live_register_levels: &[Option<usize>],
) -> Result<u64, RefusalReason> {
    let input_level = evaluator_instruction_input_level(instruction, live_register_levels, 0)?;
    let data_limb_count = u64::try_from(input_level)
        .ok()
        .and_then(|level| level.checked_add(1))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let polynomial_byte_count = u64::try_from(POLYNOMIAL_DEGREE)
        .ok()
        .and_then(|degree| degree.checked_mul(u64::from(u64::BITS / 8)))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let ntt_twiddle_byte_count = polynomial_byte_count / 2;
    let key_switch_fixed_polynomial_count = u64::try_from(SPECIAL_PRIMES.len())
        .ok()
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(6))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let polynomial_multiple = |count: u64| {
        count
            .checked_mul(polynomial_byte_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)
    };
    match instruction.opcode() {
        EvaluatorOpcode::ModulusSwitchToLevel => polynomial_multiple(
            data_limb_count
                .checked_mul(4)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        ),
        EvaluatorOpcode::NormalizeDecryptionMultiplier | EvaluatorOpcode::CiphertextAdd => {
            polynomial_multiple(
                data_limb_count
                    .checked_mul(2)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )
        }
        EvaluatorOpcode::PlaintextAdd => polynomial_multiple(
            data_limb_count
                .checked_mul(2)
                .and_then(|count| count.checked_add(1))
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        ),
        EvaluatorOpcode::PlaintextMultiply => polynomial_multiple(
            data_limb_count
                .checked_mul(2)
                .and_then(|count| count.checked_add(5))
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        )?
        .checked_add(ntt_twiddle_byte_count)
        .ok_or(RefusalReason::OutsideSupportedProfile),
        EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
        | EvaluatorOpcode::CiphertextMultiplyAndRelinearize => {
            let tensor_construction_peak = polynomial_multiple(
                data_limb_count
                    .checked_mul(3)
                    .and_then(|count| count.checked_add(7))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?
            .checked_add(ntt_twiddle_byte_count)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
            // At key-switch peak the three-component tensor overlaps both
            // extended accumulators, centered CRT buffers, and one modulus-down
            // output. The later relinearization clone peak retains the tensor,
            // both switched components, and both output components.
            let key_switch_peak = polynomial_multiple(
                data_limb_count
                    .checked_mul(6)
                    .and_then(|count| count.checked_add(key_switch_fixed_polynomial_count))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
            let relinearization_clone_peak = polynomial_multiple(
                data_limb_count
                    .checked_mul(7)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )?;
            Ok(tensor_construction_peak
                .max(key_switch_peak)
                .max(relinearization_clone_peak))
        }
        EvaluatorOpcode::GaloisRotate => {
            // The rotated two-component ciphertext overlaps the hybrid
            // key-switch accumulators and modulus-down buffers. Fixed-size
            // terms account every extended special-prime limb in both
            // accumulators, centered i128 CRT buffers, and the current
            // residue/output limbs.
            polynomial_multiple(
                data_limb_count
                    .checked_mul(5)
                    .and_then(|count| count.checked_add(key_switch_fixed_polynomial_count))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            )
        }
        EvaluatorOpcode::DropRegister | EvaluatorOpcode::DeclareOutput => Ok(0),
    }
}

#[cfg(test)]
fn evaluator_instruction_input_level(
    instruction: &EvaluatorInstruction,
    live_register_levels: &[Option<usize>],
    input_ordinal: usize,
) -> Result<usize, RefusalReason> {
    let register = instruction
        .input_registers()
        .get(input_ordinal)
        .copied()
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    live_register_levels
        .get(usize::try_from(register).map_err(|_| RefusalReason::OutsideSupportedProfile)?)
        .and_then(|level| *level)
        .ok_or(RefusalReason::MissingPrerequisite)
}

#[cfg(test)]
fn accumulate_evaluator_catalog_totals(
    catalog: &mut SelectedEvaluatorExecutionResourceTotals,
    stream: SelectedEvaluatorExecutionResourceTotals,
) -> Result<(), RefusalReason> {
    macro_rules! checked_sum {
        ($field:ident) => {
            catalog.$field = catalog
                .$field
                .checked_add(stream.$field)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        };
    }
    checked_sum!(instruction_count);
    checked_sum!(key_operation_count);
    checked_sum!(key_load_count);
    checked_sum!(key_store_read_request_count);
    checked_sum!(key_store_reread_request_count);
    checked_sum!(key_store_read_byte_count);
    checked_sum!(key_store_reread_byte_count);
    checked_sum!(key_ntt_transform_count);
    checked_sum!(rotation_count);
    checked_sum!(ciphertext_multiplication_count);
    checked_sum!(plaintext_multiplication_count);
    checked_sum!(modulus_switch_count);
    catalog.maximum_live_ciphertext_byte_count = catalog
        .maximum_live_ciphertext_byte_count
        .max(stream.maximum_live_ciphertext_byte_count);
    catalog.maximum_resident_key_byte_count = catalog
        .maximum_resident_key_byte_count
        .max(stream.maximum_resident_key_byte_count);
    catalog.maximum_operation_scratch_byte_count = catalog
        .maximum_operation_scratch_byte_count
        .max(stream.maximum_operation_scratch_byte_count);
    catalog.peak_combined_wasm_resident_byte_count = catalog
        .peak_combined_wasm_resident_byte_count
        .max(stream.peak_combined_wasm_resident_byte_count);
    Ok(())
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

fn ciphertext_coefficient_byte_count_for_component_count(
    level: usize,
    component_count: usize,
) -> Result<u64, RefusalReason> {
    u64::try_from(level)
        .ok()
        .and_then(|level| level.checked_add(1))
        .and_then(|limb_count| {
            u64::try_from(POLYNOMIAL_DEGREE)
                .ok()
                .and_then(|degree| limb_count.checked_mul(degree))
        })
        .and_then(|coefficient_count| {
            u64::try_from(component_count)
                .ok()
                .and_then(|component_count| coefficient_count.checked_mul(component_count))
        })
        .and_then(|coefficient_count| coefficient_count.checked_mul(u64::from(u64::BITS / 8)))
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn ciphertext_coefficient_byte_count(level: usize) -> Result<u64, RefusalReason> {
    ciphertext_coefficient_byte_count_for_component_count(level, 2)
}

fn multiplication_transient_coefficient_byte_count(level: usize) -> Result<u64, RefusalReason> {
    ciphertext_coefficient_byte_count_for_component_count(level, 3)?
        .checked_add(ciphertext_coefficient_byte_count_for_component_count(
            level, 2,
        )?)
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn initial_evaluator_ciphertext_coefficient_byte_count() -> Result<u64, RefusalReason> {
    ciphertext_coefficient_byte_count(CHARACTER_OUTPUT_LEVEL)?
        .checked_mul(2)
        .ok_or(RefusalReason::OutsideSupportedProfile)
}

fn evaluate_non_key_register_output(
    instruction: &EvaluatorInstruction,
    registers: &[Option<Ciphertext>],
    plaintext_coefficients: Option<&[u64]>,
) -> Result<Ciphertext, RefusalReason> {
    match instruction.opcode() {
        EvaluatorOpcode::ModulusSwitchToLevel => {
            let target_level = usize::try_from(instruction.immediate0())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            modulus_switch_to(input_register(registers, instruction, 0)?, target_level)
                .map_err(evaluator_refusal)
        }
        EvaluatorOpcode::NormalizeDecryptionMultiplier => {
            if instruction.immediate0() != 1 {
                return Err(RefusalReason::UnsupportedVersionOrSuite);
            }
            normalize_scaling(input_register(registers, instruction, 0)?).map_err(evaluator_refusal)
        }
        EvaluatorOpcode::CiphertextAdd => ciphertext_add(
            input_register(registers, instruction, 0)?,
            input_register(registers, instruction, 1)?,
        )
        .map_err(evaluator_refusal),
        EvaluatorOpcode::PlaintextAdd => add_plaintext_coefficients(
            input_register(registers, instruction, 0)?,
            plaintext_coefficients.ok_or(RefusalReason::MissingPrerequisite)?,
        )
        .map_err(evaluator_refusal),
        EvaluatorOpcode::PlaintextMultiply => plaintext_mul(
            input_register(registers, instruction, 0)?,
            plaintext_coefficients.ok_or(RefusalReason::MissingPrerequisite)?,
        )
        .map_err(evaluator_refusal),
        EvaluatorOpcode::DropRegister
        | EvaluatorOpcode::DeclareOutput
        | EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
        | EvaluatorOpcode::CiphertextMultiplyAndRelinearize
        | EvaluatorOpcode::GaloisRotate => Err(RefusalReason::WrongTypeOrLength),
    }
}

fn input_register<'registers>(
    registers: &'registers [Option<Ciphertext>],
    instruction: &EvaluatorInstruction,
    input_ordinal: usize,
) -> Result<&'registers Ciphertext, RefusalReason> {
    let register = instruction
        .input_registers()
        .get(input_ordinal)
        .copied()
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    live_register(registers, register)
}

fn live_register(
    registers: &[Option<Ciphertext>],
    register: u32,
) -> Result<&Ciphertext, RefusalReason> {
    registers
        .get(usize::try_from(register).map_err(|_| RefusalReason::OutsideSupportedProfile)?)
        .and_then(Option::as_ref)
        .ok_or(RefusalReason::MissingPrerequisite)
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
        authority: VerifiedEvaluatorAggregateExecutionAuthority,
    ) -> Result<Self, RefusalReason> {
        let VerifiedEvaluatorAggregateExecutionAuthority {
            mut aggregate,
            aggregation_authority,
        } = authority;
        let top_count = aggregate.top_count;
        let execution_request_binding =
            SelectedEvaluatorExecutionRequestBinding::from_verified_aggregate(&aggregate);
        if execution_request_binding.setup_context != aggregation_authority.setup_context {
            return Err(RefusalReason::WrongContext);
        }
        let selected_stream_ordinal = execution_request_binding.selected_stream_ordinal()?;
        validate_aggregate_ciphertexts(&aggregate.aggregate_ciphertexts)?;
        let initial_ciphertext_coefficient_byte_count =
            initial_evaluator_ciphertext_coefficient_byte_count()?;

        let program = selected_evaluator_program_set().map_err(evaluator_refusal)?;
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
        let evaluator_replay_context_hash = aggregation_authority.evaluator_replay_context_hash;
        let resolver = aggregation_authority.resolver;
        let aggregate_ciphertexts = aggregate.take_aggregate_ciphertexts();
        let registers = ordered_evaluator_input_registers(aggregate_ciphertexts);

        Ok(Self {
            resolver,
            program,
            constant_ordinals,
            selected_stream_ordinal,
            execution_schedule,
            next_instruction_ordinal: 0,
            registers,
            live_ciphertext_count: 2,
            live_ciphertext_coefficient_byte_count: initial_ciphertext_coefficient_byte_count,
            resident_key_context: None,
            pending_key_load: None,
            loaded_key_identities: BTreeSet::new(),
            execution_accounting: SelectedEvaluatorExecutionAccounting {
                maximum_live_ciphertext_count: 2,
                maximum_live_ciphertext_coefficient_byte_count:
                    initial_ciphertext_coefficient_byte_count,
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
                self.execution_accounting.maximum_resident_key_count = 1;
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
                self.record_key_instruction_transient_peak(&instruction)?;
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
        let mut target_identifier = take_register(&mut self.registers, target_identifier_register)?;
        let mut target_order = match take_register(&mut self.registers, target_order_register) {
            Ok(target_order) => target_order,
            Err(refusal_reason) => {
                zeroize_ciphertext(&mut target_identifier);
                return Err(refusal_reason);
            }
        };
        if self.registers.iter().any(Option::is_some)
            || target_identifier.level != target_order.level
            || target_identifier.decrypt_scaling != target_order.decrypt_scaling
        {
            zeroize_ciphertext(&mut target_identifier);
            zeroize_ciphertext(&mut target_order);
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
            EvaluatorOpcode::DropRegister => {
                let register = *instruction
                    .input_registers()
                    .first()
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                let mut dropped = take_register(&mut self.registers, register)?;
                let updated_live_ciphertext_count = self
                    .live_ciphertext_count
                    .checked_sub(1)
                    .ok_or(RefusalReason::WrongTypeOrLength);
                let updated_live_ciphertext_coefficient_byte_count =
                    ciphertext_coefficient_byte_count(dropped.level).and_then(|byte_count| {
                        self.live_ciphertext_coefficient_byte_count
                            .checked_sub(byte_count)
                            .ok_or(RefusalReason::WrongTypeOrLength)
                    });
                zeroize_ciphertext(&mut dropped);
                self.live_ciphertext_count = updated_live_ciphertext_count?;
                self.live_ciphertext_coefficient_byte_count =
                    updated_live_ciphertext_coefficient_byte_count?;
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
            EvaluatorOpcode::ModulusSwitchToLevel
            | EvaluatorOpcode::NormalizeDecryptionMultiplier
            | EvaluatorOpcode::CiphertextAdd
            | EvaluatorOpcode::PlaintextAdd
            | EvaluatorOpcode::PlaintextMultiply => {
                let plaintext = match instruction.opcode() {
                    EvaluatorOpcode::PlaintextAdd | EvaluatorOpcode::PlaintextMultiply => {
                        Some(self.constant_coefficients(instruction)?)
                    }
                    _ => None,
                };
                Some(evaluate_non_key_register_output(
                    instruction,
                    &self.registers,
                    plaintext.as_deref(),
                )?)
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
                let tensor = ZeroizingOwnedCiphertext::new(
                    ciphertext_tensor(
                        self.input_register(instruction, 0)?,
                        self.input_register(instruction, 1)?,
                    )
                    .map_err(evaluator_refusal)?,
                );
                let relinearized = ZeroizingOwnedCiphertext::new(
                    key_context
                        .relinearize(tensor.as_ref())
                        .map_err(evaluator_refusal)?,
                );
                drop(tensor);
                if instruction.opcode() == EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop {
                    modulus_switch(relinearized.as_ref()).map_err(evaluator_refusal)
                } else {
                    Ok(relinearized.into_inner())
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
        input_register(&self.registers, instruction, input_ordinal)
    }

    fn record_key_instruction_transient_peak(
        &mut self,
        instruction: &EvaluatorInstruction,
    ) -> Result<(), RefusalReason> {
        if !matches!(
            instruction.opcode(),
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                | EvaluatorOpcode::CiphertextMultiplyAndRelinearize
        ) {
            return Ok(());
        }
        let input_level = self.input_register(instruction, 0)?.level;
        let transient_ciphertext_count = self
            .live_ciphertext_count
            .checked_add(2)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let transient_coefficient_byte_count = self
            .live_ciphertext_coefficient_byte_count
            .checked_add(multiplication_transient_coefficient_byte_count(
                input_level,
            )?)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.execution_accounting.maximum_live_ciphertext_count = self
            .execution_accounting
            .maximum_live_ciphertext_count
            .max(transient_ciphertext_count);
        self.execution_accounting
            .maximum_live_ciphertext_coefficient_byte_count = self
            .execution_accounting
            .maximum_live_ciphertext_coefficient_byte_count
            .max(transient_coefficient_byte_count);
        Ok(())
    }

    fn live_register(&self, register: u32) -> Result<&Ciphertext, RefusalReason> {
        live_register(&self.registers, register)
    }

    fn push_instruction_output(
        &mut self,
        instruction: &EvaluatorInstruction,
        mut output: Ciphertext,
    ) -> Result<(), RefusalReason> {
        let preflight = (|| {
            let output_register = instruction
                .output_register()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            if usize::try_from(output_register).ok() != Some(self.registers.len()) {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            let output_coefficient_byte_count = ciphertext_coefficient_byte_count(output.level)?;
            let updated_live_ciphertext_count = self
                .live_ciphertext_count
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let updated_live_ciphertext_coefficient_byte_count = self
                .live_ciphertext_coefficient_byte_count
                .checked_add(output_coefficient_byte_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            Ok::<_, RefusalReason>((
                updated_live_ciphertext_count,
                updated_live_ciphertext_coefficient_byte_count,
            ))
        })();
        let (updated_live_ciphertext_count, updated_live_ciphertext_coefficient_byte_count) =
            match preflight {
                Ok(accounting) => accounting,
                Err(refusal_reason) => {
                    zeroize_ciphertext(&mut output);
                    return Err(refusal_reason);
                }
            };
        self.registers.push(Some(output));
        self.live_ciphertext_count = updated_live_ciphertext_count;
        self.live_ciphertext_coefficient_byte_count =
            updated_live_ciphertext_coefficient_byte_count;
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
        zeroize_ciphertext_registers(&mut self.registers);
        self.registers.clear();
        self.live_ciphertext_count = 0;
        self.live_ciphertext_coefficient_byte_count = 0;
        self.refusal_reason = Some(reason);
    }
}

impl Drop for SelectedEvaluatorProgramExecution {
    fn drop(&mut self) {
        zeroize_ciphertext_registers(&mut self.registers);
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

impl Drop for VerifiedSelectedEvaluatorExecution {
    fn drop(&mut self) {
        zeroize_ciphertext(&mut self.target_identifier);
        zeroize_ciphertext(&mut self.target_order);
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

fn ordered_evaluator_input_registers(
    aggregate_ciphertexts: [Ciphertext; 2],
) -> Vec<Option<Ciphertext>> {
    aggregate_ciphertexts.into_iter().map(Some).collect()
}

fn empty_ciphertext() -> Ciphertext {
    Ciphertext {
        components: Vec::new(),
        level: 0,
        decrypt_scaling: 0,
    }
}

fn zeroize_ciphertext(ciphertext: &mut Ciphertext) {
    ciphertext.components.zeroize();
    ciphertext.level.zeroize();
    ciphertext.decrypt_scaling.zeroize();
}

fn zeroize_ciphertexts(ciphertexts: &mut [Ciphertext; 2]) {
    for ciphertext in ciphertexts {
        zeroize_ciphertext(ciphertext);
    }
}

fn zeroize_ciphertext_registers(registers: &mut [Option<Ciphertext>]) {
    for ciphertext in registers.iter_mut().flatten() {
        zeroize_ciphertext(ciphertext);
    }
}

fn validate_aggregate_ciphertexts(ciphertexts: &[Ciphertext; 2]) -> Result<(), RefusalReason> {
    for ciphertext in ciphertexts {
        validate_aggregate_ciphertext(ciphertext)?;
    }
    Ok(())
}

fn validate_aggregate_ciphertext(ciphertext: &Ciphertext) -> Result<(), RefusalReason> {
    if ciphertext.level != CHARACTER_OUTPUT_LEVEL
        || ciphertext.decrypt_scaling != 1
        || ciphertext.components.len() != 2
        || ciphertext
            .components
            .iter()
            .any(|component| component.len() != CHARACTER_OUTPUT_LEVEL + 1)
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

#[cfg(test)]
mod semantic_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregate_context() -> VerifiedEvaluatorAggregateContext {
        VerifiedEvaluatorAggregateContext::from_verified_sources(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; Hash512::BYTE_LENGTH],
            [0x22; Hash512::BYTE_LENGTH],
            [0x33; Hash512::BYTE_LENGTH],
            [0x44; Hash512::BYTE_LENGTH],
            [0x55; Hash512::BYTE_LENGTH],
            [0x66; Hash512::BYTE_LENGTH],
        )
    }

    fn aggregate_ciphertext(coefficient: u64) -> Ciphertext {
        Ciphertext {
            components: (0..2)
                .map(|_| {
                    DATA_PRIMES[..=CHARACTER_OUTPUT_LEVEL]
                        .iter()
                        .map(|modulus| vec![coefficient % modulus; POLYNOMIAL_DEGREE])
                        .collect()
                })
                .collect(),
            level: CHARACTER_OUTPUT_LEVEL,
            decrypt_scaling: 1,
        }
    }

    const fn matching_setup_context() -> EvaluatorExecutionSetupContextBinding {
        EvaluatorExecutionSetupContextBinding::from_test_values(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; Hash512::BYTE_LENGTH],
            [0x22; Hash512::BYTE_LENGTH],
            [0x33; Hash512::BYTE_LENGTH],
            [0x44; Hash512::BYTE_LENGTH],
            [0x55; Hash512::BYTE_LENGTH],
        )
    }

    #[test]
    fn verified_aggregate_requires_two_level_nineteen_inputs_and_preserves_order() {
        let mut aggregate = VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
            aggregate_context(),
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            [aggregate_ciphertext(3), aggregate_ciphertext(5)],
        )
        .expect("the exact ordered character aggregate is accepted");
        let mut registers =
            ordered_evaluator_input_registers(aggregate.take_aggregate_ciphertexts());
        assert_eq!(
            registers[0]
                .as_ref()
                .expect("the first input occupies register zero")
                .components[0][0][0],
            3,
        );
        assert_eq!(
            registers[1]
                .as_ref()
                .expect("the second input occupies register one")
                .components[0][0][0],
            5,
        );
        zeroize_ciphertext_registers(&mut registers);

        let mut wrong_level = [aggregate_ciphertext(3), aggregate_ciphertext(5)];
        wrong_level[1].level = CHARACTER_OUTPUT_LEVEL - 1;
        assert!(matches!(
            VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
                aggregate_context(),
                FOUNDATION_PROFILE.participant_count,
                FOUNDATION_PROFILE.option_count,
                wrong_level,
            ),
            Err(RefusalReason::WrongTypeOrLength)
        ));

        let mut wrong_scaling = [aggregate_ciphertext(3), aggregate_ciphertext(5)];
        wrong_scaling[0].decrypt_scaling = 2;
        assert!(matches!(
            VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
                aggregate_context(),
                FOUNDATION_PROFILE.participant_count,
                FOUNDATION_PROFILE.option_count,
                wrong_scaling,
            ),
            Err(RefusalReason::WrongTypeOrLength)
        ));

        let mut wrong_component_count = [aggregate_ciphertext(3), aggregate_ciphertext(5)];
        wrong_component_count[1].components.pop();
        assert!(matches!(
            VerifiedEvaluatorAggregate::from_verified_ballot_aggregate(
                aggregate_context(),
                FOUNDATION_PROFILE.participant_count,
                FOUNDATION_PROFILE.option_count,
                wrong_component_count,
            ),
            Err(RefusalReason::WrongTypeOrLength)
        ));
    }

    #[test]
    fn aggregate_and_register_cleanup_scrub_both_ciphertext_buffers() {
        let mut aggregate_ciphertexts = [aggregate_ciphertext(3), aggregate_ciphertext(5)];
        zeroize_ciphertexts(&mut aggregate_ciphertexts);
        for ciphertext in &aggregate_ciphertexts {
            assert_eq!(ciphertext.level, 0);
            assert_eq!(ciphertext.decrypt_scaling, 0);
            assert!(
                ciphertext
                    .components
                    .iter()
                    .flatten()
                    .flatten()
                    .all(|value| *value == 0)
            );
        }

        let mut registers = vec![
            Some(aggregate_ciphertext(7)),
            Some(aggregate_ciphertext(11)),
        ];
        zeroize_ciphertext_registers(&mut registers);
        for ciphertext in registers.iter().flatten() {
            assert_eq!(ciphertext.level, 0);
            assert_eq!(ciphertext.decrypt_scaling, 0);
            assert!(
                ciphertext
                    .components
                    .iter()
                    .flatten()
                    .flatten()
                    .all(|value| *value == 0)
            );
        }
    }

    #[test]
    fn every_selected_stream_prepares_and_executes_its_first_non_key_instruction() {
        let program = selected_evaluator_program_set().expect("the selected evaluator program");
        let mut registers = vec![Some(aggregate_ciphertext(0)), Some(aggregate_ciphertext(1))];
        for (stream_ordinal, stream) in program.streams().iter().enumerate() {
            assert_eq!(usize::from(stream.top_count()), stream_ordinal + 1);
            let schedule = PreparedEvaluatorExecutionSchedule::derive(stream.instructions())
                .expect("every selected stream prepares from two character inputs");
            let first_instruction = stream
                .instructions()
                .first()
                .expect("every selected stream has a first instruction");
            assert_eq!(
                schedule.required_key(0),
                Ok(None),
                "the first instruction must not require evaluator-key material",
            );
            assert_eq!(first_instruction.output_register(), Some(2));
            let expected_output_level = prepared_instruction_output_level(
                first_instruction,
                &[Some(CHARACTER_OUTPUT_LEVEL), Some(CHARACTER_OUTPUT_LEVEL)],
            )
            .expect("the first instruction transition accepts both initial registers")
            .expect("the first instruction produces a register");
            let plaintext_coefficients = first_instruction
                .constant_hash()
                .map(|constant_hash| {
                    program
                        .constants()
                        .iter()
                        .find(|constant| {
                            constant
                                .constant_hash()
                                .is_ok_and(|candidate_hash| candidate_hash == constant_hash)
                        })
                        .ok_or(RefusalReason::MissingPrerequisite)
                        .and_then(encode_constant_coefficients)
                })
                .transpose()
                .expect("the first instruction constant is present");
            let mut output = evaluate_non_key_register_output(
                first_instruction,
                &registers,
                plaintext_coefficients.as_deref(),
            )
            .expect("the first non-key instruction executes");
            assert_eq!(output.level, expected_output_level);
            zeroize_ciphertext(&mut output);
        }
        zeroize_ciphertext_registers(&mut registers);
    }

    #[test]
    fn suite_maximal_evaluator_store_authorizes_every_selected_action_stream() {
        let accepted_store = AcceptedEvaluatorStoreAuthorityBinding::from_test_values(
            matching_setup_context(),
            Some(FOUNDATION_PROFILE.option_count),
        );
        let program = selected_evaluator_program_set().expect("selected evaluator program");

        for action_top_count in 1..=FOUNDATION_PROFILE.option_count {
            let execution_request = SelectedEvaluatorExecutionRequestBinding::from_test_values(
                matching_setup_context(),
                action_top_count,
            );
            let selected_stream_ordinal = execution_request
                .selected_stream_ordinal()
                .expect("every supported action selects one stream");

            assert_eq!(selected_stream_ordinal, usize::from(action_top_count - 1));
            assert_eq!(
                program
                    .streams()
                    .get(selected_stream_ordinal)
                    .map(|stream| stream.top_count()),
                Some(action_top_count)
            );
            assert!(execution_request.accepts_verified_store(accepted_store));
        }
    }

    #[test]
    fn evaluator_execution_rejects_nonmaximal_store_and_every_setup_context_substitution() {
        let action_top_count = 7;
        let execution_request = SelectedEvaluatorExecutionRequestBinding::from_test_values(
            matching_setup_context(),
            action_top_count,
        );
        for wrong_store_top_count in [
            None,
            Some(action_top_count),
            Some(FOUNDATION_PROFILE.option_count - 1),
        ] {
            assert!(
                !execution_request.accepts_verified_store(
                    AcceptedEvaluatorStoreAuthorityBinding::from_test_values(
                        matching_setup_context(),
                        wrong_store_top_count,
                    ),
                ),
                "a nonmaximal or missing evaluator store must not authorize execution"
            );
        }

        let expected_context = matching_setup_context();
        let mut wrong_protocol_version = expected_context;
        wrong_protocol_version.protocol_version = expected_context.protocol_version + 1;
        let mut wrong_suite_identifier = expected_context;
        wrong_suite_identifier.suite_identifier[0] ^= 1;
        let mut wrong_ceremony_context_hash = expected_context;
        wrong_ceremony_context_hash.ceremony_context_hash[0] ^= 1;
        let mut wrong_action_context_hash = expected_context;
        wrong_action_context_hash.action_context_hash[0] ^= 1;
        let mut wrong_roster_hash = expected_context;
        wrong_roster_hash.roster_hash[0] ^= 1;
        let mut wrong_verified_setup_source_hash = expected_context;
        wrong_verified_setup_source_hash.verified_setup_source_hash[0] ^= 1;

        for (context_name, wrong_context) in [
            ("protocol version", wrong_protocol_version),
            ("suite identifier", wrong_suite_identifier),
            ("ceremony context", wrong_ceremony_context_hash),
            ("action context", wrong_action_context_hash),
            ("roster", wrong_roster_hash),
            ("verified setup source", wrong_verified_setup_source_hash),
        ] {
            assert!(
                !execution_request.accepts_verified_store(
                    AcceptedEvaluatorStoreAuthorityBinding::from_test_values(
                        wrong_context,
                        Some(FOUNDATION_PROFILE.option_count),
                    ),
                ),
                "a substituted {context_name} must not authorize execution"
            );
        }
    }

    #[test]
    fn evaluator_execution_rejects_action_top_counts_outside_the_selected_stream_catalog() {
        for unsupported_action_top_count in [0, FOUNDATION_PROFILE.option_count + 1] {
            assert_eq!(
                SelectedEvaluatorExecutionRequestBinding::from_test_values(
                    matching_setup_context(),
                    unsupported_action_top_count,
                )
                .selected_stream_ordinal(),
                Err(RefusalReason::OutsideSupportedProfile)
            );
        }
    }

    #[test]
    fn selected_execution_resource_ledger_covers_every_canonical_stream_and_operation() {
        let ledger = selected_evaluator_execution_resource_ledger()
            .expect("selected evaluator execution resources derive");
        let program = selected_evaluator_program_set().expect("selected evaluator program");
        assert_eq!(
            ledger.ordered_streams().len(),
            usize::from(FOUNDATION_PROFILE.option_count)
        );
        assert_eq!(ledger.ordered_streams().len(), program.streams().len());

        let mut observed_rotation = false;
        let mut observed_ciphertext_multiplication = false;
        let mut observed_plaintext_multiplication = false;
        let mut observed_modulus_switch = false;
        let mut observed_key_reread = false;
        for (stream_ordinal, (row, stream)) in ledger
            .ordered_streams()
            .iter()
            .zip(program.streams())
            .enumerate()
        {
            let expected_top_count =
                u16::try_from(stream_ordinal + 1).expect("selected stream ordinal fits u16");
            assert_eq!(row.top_count(), expected_top_count);
            assert_eq!(stream.top_count(), expected_top_count);
            let totals = row.totals();
            let expected_rotation_count = stream
                .instructions()
                .iter()
                .filter(|instruction| instruction.opcode() == EvaluatorOpcode::GaloisRotate)
                .count();
            let expected_ciphertext_multiplication_count = stream
                .instructions()
                .iter()
                .filter(|instruction| {
                    matches!(
                        instruction.opcode(),
                        EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop
                            | EvaluatorOpcode::CiphertextMultiplyAndRelinearize
                    )
                })
                .count();
            let expected_plaintext_multiplication_count = stream
                .instructions()
                .iter()
                .filter(|instruction| {
                    matches!(
                        instruction.opcode(),
                        EvaluatorOpcode::NormalizeDecryptionMultiplier
                            | EvaluatorOpcode::PlaintextMultiply
                    )
                })
                .count();
            assert_eq!(totals.instruction_count(), stream.instructions().len());
            assert_eq!(totals.rotation_count(), expected_rotation_count);
            assert_eq!(
                totals.ciphertext_multiplication_count(),
                expected_ciphertext_multiplication_count
            );
            assert_eq!(
                totals.plaintext_multiplication_count(),
                expected_plaintext_multiplication_count
            );
            assert_eq!(
                totals.key_operation_count(),
                expected_rotation_count + expected_ciphertext_multiplication_count
            );
            assert!(totals.key_load_count() <= totals.key_operation_count());
            assert!(
                totals.key_store_reread_request_count() <= totals.key_store_read_request_count()
            );
            assert!(totals.key_store_reread_byte_count() <= totals.key_store_read_byte_count());
            assert!(totals.key_store_read_request_count() > 0);
            assert!(totals.key_store_read_byte_count() > 0);
            assert!(totals.key_ntt_transform_count() > 0);
            assert!(totals.maximum_live_ciphertext_byte_count() > 0);
            assert!(totals.maximum_resident_key_byte_count() > 0);
            assert!(totals.maximum_operation_scratch_byte_count() > 0);
            assert!(
                totals.peak_combined_wasm_resident_byte_count()
                    >= totals.maximum_live_ciphertext_byte_count()
            );
            assert!(
                totals.peak_combined_wasm_resident_byte_count()
                    >= totals.maximum_resident_key_byte_count()
            );
            assert!(
                totals.peak_combined_wasm_resident_byte_count()
                    >= totals.maximum_operation_scratch_byte_count()
            );
            observed_rotation |= totals.rotation_count() > 0;
            observed_ciphertext_multiplication |= totals.ciphertext_multiplication_count() > 0;
            observed_plaintext_multiplication |= totals.plaintext_multiplication_count() > 0;
            observed_modulus_switch |= totals.modulus_switch_count() > 0;
            observed_key_reread |= totals.key_store_reread_byte_count() > 0;
        }
        assert!(observed_rotation);
        assert!(observed_ciphertext_multiplication);
        assert!(observed_plaintext_multiplication);
        assert!(observed_modulus_switch);
        assert!(observed_key_reread);
    }

    #[test]
    fn selected_execution_catalog_totals_sum_work_and_retain_only_memory_maxima() {
        let ledger = selected_evaluator_execution_resource_ledger()
            .expect("selected evaluator execution resources derive");
        let catalog = ledger.catalog_totals();
        let rows = ledger.ordered_streams();
        let sum_usize = |read: fn(SelectedEvaluatorExecutionResourceTotals) -> usize| {
            rows.iter().map(|row| read(row.totals())).sum::<usize>()
        };
        let sum_u64 = |read: fn(SelectedEvaluatorExecutionResourceTotals) -> u64| {
            rows.iter().map(|row| read(row.totals())).sum::<u64>()
        };
        let maximum_u64 = |read: fn(SelectedEvaluatorExecutionResourceTotals) -> u64| {
            rows.iter()
                .map(|row| read(row.totals()))
                .max()
                .expect("selected catalog is nonempty")
        };

        assert_eq!(
            catalog.instruction_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::instruction_count)
        );
        assert_eq!(
            catalog.key_operation_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::key_operation_count)
        );
        assert_eq!(
            catalog.key_load_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::key_load_count)
        );
        assert_eq!(
            catalog.key_store_read_request_count(),
            sum_u64(SelectedEvaluatorExecutionResourceTotals::key_store_read_request_count)
        );
        assert_eq!(
            catalog.key_store_reread_request_count(),
            sum_u64(SelectedEvaluatorExecutionResourceTotals::key_store_reread_request_count)
        );
        assert_eq!(
            catalog.key_store_read_byte_count(),
            sum_u64(SelectedEvaluatorExecutionResourceTotals::key_store_read_byte_count)
        );
        assert_eq!(
            catalog.key_store_reread_byte_count(),
            sum_u64(SelectedEvaluatorExecutionResourceTotals::key_store_reread_byte_count)
        );
        assert_eq!(
            catalog.key_ntt_transform_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::key_ntt_transform_count)
        );
        assert_eq!(
            catalog.rotation_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::rotation_count)
        );
        assert_eq!(
            catalog.ciphertext_multiplication_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::ciphertext_multiplication_count)
        );
        assert_eq!(
            catalog.plaintext_multiplication_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::plaintext_multiplication_count)
        );
        assert_eq!(
            catalog.modulus_switch_count(),
            sum_usize(SelectedEvaluatorExecutionResourceTotals::modulus_switch_count)
        );
        assert_eq!(
            catalog.maximum_live_ciphertext_byte_count(),
            maximum_u64(
                SelectedEvaluatorExecutionResourceTotals::maximum_live_ciphertext_byte_count
            )
        );
        assert_eq!(
            catalog.maximum_resident_key_byte_count(),
            maximum_u64(SelectedEvaluatorExecutionResourceTotals::maximum_resident_key_byte_count)
        );
        assert_eq!(
            catalog.maximum_operation_scratch_byte_count(),
            maximum_u64(
                SelectedEvaluatorExecutionResourceTotals::maximum_operation_scratch_byte_count
            )
        );
        assert_eq!(
            catalog.peak_combined_wasm_resident_byte_count(),
            maximum_u64(
                SelectedEvaluatorExecutionResourceTotals::peak_combined_wasm_resident_byte_count
            )
        );
    }

    #[test]
    fn evaluator_key_load_accounting_uses_physical_store_and_two_component_runtime_topologies() {
        let relinearization =
            prepared_evaluator_key_load_accounting(PreparedEvaluatorKeyIdentity::Relinearization {
                catalog_level: 14,
            })
            .expect("level-fourteen relinearization key accounting");
        let galois = prepared_evaluator_key_load_accounting(PreparedEvaluatorKeyIdentity::Galois {
            galois_element: 15,
            catalog_level: 14,
        })
        .expect("level-fourteen Galois key accounting");
        let topology = KeySwitchDecompositionTopology::for_level(14)
            .expect("level-fourteen key-switch topology");
        let expected_resident_byte_count = topology
            .resident_component_byte_length(POLYNOMIAL_DEGREE)
            .expect("resident component bytes")
            * 2;
        let expected_ntt_transform_count =
            topology.data_block_count() * topology.extended_limb_count() * 2;

        assert_eq!(
            relinearization.store_read_byte_count,
            2 * galois.store_read_byte_count
        );
        assert_eq!(
            relinearization.store_read_request_count,
            2 * galois.store_read_request_count
        );
        assert_eq!(
            relinearization.ntt_transform_count,
            expected_ntt_transform_count
        );
        assert_eq!(galois.ntt_transform_count, expected_ntt_transform_count);
        assert_eq!(
            relinearization.resident_byte_count,
            expected_resident_byte_count
        );
        assert_eq!(galois.resident_byte_count, expected_resident_byte_count);
    }

    #[test]
    fn evaluator_operation_scratch_matches_the_sequential_wasm_engine_buffers() {
        let live_register_levels = [Some(CHARACTER_OUTPUT_LEVEL), Some(CHARACTER_OUTPUT_LEVEL)];
        let instruction = |opcode, immediate0, constant_hash| {
            EvaluatorInstruction::new(opcode, Some(2), vec![0], immediate0, 0, constant_hash)
                .expect("accounting fixture instruction is canonical")
        };
        let modulus_switch = instruction(EvaluatorOpcode::ModulusSwitchToLevel, 18, None);
        let normalize = instruction(EvaluatorOpcode::NormalizeDecryptionMultiplier, 1, None);
        let plaintext_add = instruction(
            EvaluatorOpcode::PlaintextAdd,
            0,
            Some(Hash512::from_bytes([0x77; Hash512::BYTE_LENGTH])),
        );
        let plaintext_multiply = instruction(
            EvaluatorOpcode::PlaintextMultiply,
            0,
            Some(Hash512::from_bytes([0x77; Hash512::BYTE_LENGTH])),
        );
        let ciphertext_multiply = EvaluatorInstruction::new(
            EvaluatorOpcode::CiphertextMultiplyRelinearizeAndDrop,
            Some(2),
            vec![0, 1],
            0,
            0,
            None,
        )
        .expect("ciphertext multiplication fixture instruction is canonical");
        let rotate = instruction(EvaluatorOpcode::GaloisRotate, 257, None);
        let polynomial_byte_count =
            u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree") * u64::from(u64::BITS / 8);

        assert_eq!(
            evaluator_instruction_operation_scratch_byte_count(
                &modulus_switch,
                &live_register_levels
            ),
            Ok(80 * polynomial_byte_count)
        );
        assert_eq!(
            evaluator_instruction_operation_scratch_byte_count(&normalize, &live_register_levels),
            Ok(40 * polynomial_byte_count)
        );
        assert_eq!(
            evaluator_instruction_operation_scratch_byte_count(
                &plaintext_add,
                &live_register_levels
            ),
            Ok(41 * polynomial_byte_count)
        );
        assert_eq!(
            evaluator_instruction_operation_scratch_byte_count(
                &plaintext_multiply,
                &live_register_levels
            ),
            Ok(45 * polynomial_byte_count + polynomial_byte_count / 2)
        );
        assert_eq!(
            evaluator_instruction_operation_scratch_byte_count(
                &ciphertext_multiply,
                &live_register_levels
            ),
            Ok(140 * polynomial_byte_count)
        );
        assert_eq!(
            evaluator_instruction_operation_scratch_byte_count(&rotate, &live_register_levels),
            Ok(112 * polynomial_byte_count)
        );
    }
}
