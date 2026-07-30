//! Browser/WASM runtime adapter for the selected VSS share-linkage family.
//!
//! Prover statements are derived from retained setup-generation authority and
//! verifier statements are derived from the exact canonical-board randomness
//! transcript plus one dealer record. Roots, trace rows, masks, statement
//! fields, and public-randomness facts never cross the caller boundary.

use core::slice;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use crate::{
    bgv::setup::{
        SetupGenerationAuthorityHandle, SetupGenerationKeyRelationPreparationSource,
        SetupGenerationVssApplication, SetupGenerationVssPreparationSource,
        SetupVssGenerationPreparationError, VerifiedPublicRandomness,
        VerifiedVssShareLinkageTerminal, resolve_setup_generation_vss_preparation_source,
        verify_public_randomness_board_sources, with_setup_generation_vss_material,
    },
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, CanonicalDecodeLimits, FOUNDATION_PROFILE,
        FoundationObjectType, FoundationSchemaError, Hash512, ParticipantIdentity,
        PreparedActionProofAttemptSource, ProofApplicationBinding, ProofApplicationSlot,
        ProofApplicationSlotCeilings, ProofObjectHeader, RefusalReason,
        STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VerifiedBoardApplicationSource,
        VerifiedStateReservationRuntimeBinding, resolve_prepared_action_proof_attempt_source,
        resolve_verified_board_application_sources, verified_state_reservation_binding,
    },
};

use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    bind_generated_common_proof_to_verified_board_source,
    retain_common_proof_generation_family_adapter,
    retain_common_proof_verification_family_adapter_from_upstream,
    with_common_proof_selected_suite,
};
use super::{
    CommonProofGenerationPreparationError, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofSelectedSuiteCapabilityHandle, PreparedCommonProofGeneration, ProofProfileError,
    RelationPlanError, SelectedApplicationStatementContext, SelectedProofAccountingError,
    VerifiedSameSecretLowDegreePrerequisite, canonical_selected_vss_share_linkage_statement,
    compile_vss_share_linkage_relation_plan, decode_selected_vss_share_linkage_statement,
    selected_committed_material_relation_plan_input, selected_proof_runtime_limits,
    selected_relation_plan_check_context, verified_application_statement_hash,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const HANDLE_BYTE_LENGTH: usize = size_of::<u32>();

#[derive(Debug)]
pub(in crate::bgv::proof_suite) enum VssShareLinkageRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Runtime(CommonProofRuntimeError),
    GenerationPreparation(SetupVssGenerationPreparationError),
    Foundation(FoundationSchemaError),
    ActionRandomnessRuntime(u32),
    BoardRuntime(u32),
    StateRuntime(u32),
    Refusal(RefusalReason),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for VssShareLinkageRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for VssShareLinkageRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for VssShareLinkageRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for VssShareLinkageRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofRuntimeError> for VssShareLinkageRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<SetupVssGenerationPreparationError> for VssShareLinkageRuntimeError {
    fn from(error: SetupVssGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<FoundationSchemaError> for VssShareLinkageRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<RefusalReason> for VssShareLinkageRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

struct SingleActiveVssSourceRegistry<Source> {
    active: Option<(u32, Source)>,
    next_handle: u32,
}

impl<Source> Default for SingleActiveVssSourceRegistry<Source> {
    fn default() -> Self {
        Self {
            active: None,
            next_handle: 1,
        }
    }
}

impl<Source> SingleActiveVssSourceRegistry<Source> {
    fn retain(&mut self, source: Source) -> Result<u32, CommonProofRuntimeError> {
        if self.active.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        if handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.active = Some((handle, source));
        Ok(handle)
    }

    fn source(&self, handle: u32) -> Result<&Source, CommonProofRuntimeError> {
        self.active
            .as_ref()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take(&mut self, handle: u32) -> Result<Source, CommonProofRuntimeError> {
        self.source(handle)?;
        self.active
            .take()
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(&mut self, handle: u32, source: Source) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.active.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.active = Some((handle, source));
        Ok(())
    }
}

struct BoundedVssOutputRegistry<Output> {
    outputs: BTreeMap<u32, Output>,
    reserved_handle: Option<u32>,
    next_handle: u32,
}

impl<Output> Default for BoundedVssOutputRegistry<Output> {
    fn default() -> Self {
        Self {
            outputs: BTreeMap::new(),
            reserved_handle: None,
            next_handle: 1,
        }
    }
}

impl<Output> BoundedVssOutputRegistry<Output> {
    fn source(&self, handle: u32) -> Result<&Output, CommonProofRuntimeError> {
        self.outputs
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn reserve(&mut self) -> Result<u32, CommonProofRuntimeError> {
        let retained_count = self
            .outputs
            .len()
            .checked_add(usize::from(self.reserved_handle.is_some()))
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if retained_count >= usize::from(FOUNDATION_PROFILE.participant_count) {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        if self.reserved_handle.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        if handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.reserved_handle = Some(handle);
        Ok(handle)
    }

    fn commit_preflighted(&mut self, reserved_handle: u32, output: Output) -> u32 {
        assert_eq!(
            self.reserved_handle,
            Some(reserved_handle),
            "preflighted VSS output reservation must remain exclusively retained",
        );
        assert!(
            !self.outputs.contains_key(&reserved_handle),
            "preflighted VSS output handle must remain vacant",
        );
        self.reserved_handle = None;
        self.outputs.insert(reserved_handle, output);
        reserved_handle
    }

    fn release_reservation(&mut self, reserved_handle: u32) -> Result<(), CommonProofRuntimeError> {
        if self.reserved_handle != Some(reserved_handle) {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        self.reserved_handle = None;
        Ok(())
    }

    fn consume(&mut self, handle: u32) -> Result<Output, CommonProofRuntimeError> {
        self.outputs
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore_consumed(
        &mut self,
        handle: u32,
        output: Output,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.reserved_handle == Some(handle) || self.outputs.contains_key(&handle)
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.outputs.insert(handle, output);
        Ok(())
    }

    fn consume_ordered_exact(
        &mut self,
        ordered_handles: &[u32],
        expected_count: usize,
    ) -> Result<Vec<Output>, CommonProofRuntimeError> {
        if ordered_handles.len() != expected_count
            || ordered_handles.contains(&0)
            || ordered_handles
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != expected_count
            || ordered_handles
                .iter()
                .any(|handle| !self.outputs.contains_key(handle))
        {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        ordered_handles
            .iter()
            .map(|handle| {
                self.outputs
                    .remove(handle)
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            })
            .collect()
    }
}

#[derive(Clone)]
struct VssGenerationBoardBindingSource {
    preparation_source: SetupGenerationVssPreparationSource,
}

struct VssVerificationTerminalSource {
    canonical_application_statement_bytes: Vec<u8>,
    board_source: VerifiedBoardApplicationSource,
    verified_public_randomness: VerifiedPublicRandomness,
}

enum VerifiedVssLowDegreeEvidenceState {
    Available(VerifiedSameSecretLowDegreePrerequisite),
    AttachedToSameSecretGeneration {
        evidence: VerifiedSameSecretLowDegreePrerequisite,
        generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
    },
}

thread_local! {
    static VSS_GENERATION_BOARD_BINDING_SOURCE_REGISTRY:
        RefCell<SingleActiveVssSourceRegistry<VssGenerationBoardBindingSource>> =
        RefCell::new(SingleActiveVssSourceRegistry::default());
    static VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY:
        RefCell<SingleActiveVssSourceRegistry<VssVerificationTerminalSource>> =
        RefCell::new(SingleActiveVssSourceRegistry::default());
    static VERIFIED_VSS_SHARE_LINKAGE_TERMINAL_REGISTRY:
        RefCell<BoundedVssOutputRegistry<VerifiedVssShareLinkageTerminal>> =
        RefCell::new(BoundedVssOutputRegistry::default());
    static VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY:
        RefCell<BoundedVssOutputRegistry<VerifiedVssLowDegreeEvidenceState>> =
        RefCell::new(BoundedVssOutputRegistry::default());
}

pub(in crate::bgv) fn consume_verified_vss_low_degree_evidence(
    handle: u32,
) -> Result<VerifiedSameSecretLowDegreePrerequisite, CommonProofRuntimeError> {
    VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        match registry.consume(handle)? {
            VerifiedVssLowDegreeEvidenceState::Available(evidence) => Ok(evidence),
            attached @ VerifiedVssLowDegreeEvidenceState::AttachedToSameSecretGeneration {
                ..
            } => {
                registry.restore_consumed(handle, attached)?;
                Err(CommonProofRuntimeError::WrongOperationPhase)
            }
        }
    })
}

pub(in crate::bgv) fn attach_verified_vss_low_degree_evidence_to_same_secret_generation(
    handle: u32,
    generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
    generation_source: &SetupGenerationKeyRelationPreparationSource,
    ordered_degree_zero_roots: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<(), CommonProofRuntimeError> {
    if generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH] {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let state = registry.consume(handle)?;
        let evidence = match state {
            VerifiedVssLowDegreeEvidenceState::Available(evidence) => evidence,
            attached @ VerifiedVssLowDegreeEvidenceState::AttachedToSameSecretGeneration {
                ..
            } => {
                registry.restore_consumed(handle, attached)?;
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
        };
        if !evidence
            .matches_same_secret_generation_source(generation_source, ordered_degree_zero_roots)
        {
            registry.restore_consumed(
                handle,
                VerifiedVssLowDegreeEvidenceState::Available(evidence),
            )?;
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        registry.restore_consumed(
            handle,
            VerifiedVssLowDegreeEvidenceState::AttachedToSameSecretGeneration {
                evidence,
                generation_binding_hash,
            },
        )
    })
}

pub(in crate::bgv) fn detach_verified_vss_low_degree_evidence_from_same_secret_generation(
    handle: u32,
    generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
) -> Result<(), CommonProofRuntimeError> {
    VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let state = registry.consume(handle)?;
        match state {
            VerifiedVssLowDegreeEvidenceState::AttachedToSameSecretGeneration {
                evidence,
                generation_binding_hash: retained_binding_hash,
            } if retained_binding_hash == generation_binding_hash => registry.restore_consumed(
                handle,
                VerifiedVssLowDegreeEvidenceState::Available(evidence),
            ),
            other => {
                registry.restore_consumed(handle, other)?;
                Err(CommonProofRuntimeError::WrongVerificationBinding)
            }
        }
    })
}

pub(in crate::bgv) fn consume_attached_verified_vss_low_degree_evidence(
    handle: u32,
    generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
) -> Result<VerifiedSameSecretLowDegreePrerequisite, CommonProofRuntimeError> {
    VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let state = registry.consume(handle)?;
        match state {
            VerifiedVssLowDegreeEvidenceState::AttachedToSameSecretGeneration {
                evidence,
                generation_binding_hash: retained_binding_hash,
            } if retained_binding_hash == generation_binding_hash => Ok(evidence),
            other => {
                registry.restore_consumed(handle, other)?;
                Err(CommonProofRuntimeError::WrongVerificationBinding)
            }
        }
    })
}

pub(in crate::bgv) fn with_attached_verified_vss_low_degree_evidence<ResultValue>(
    handle: u32,
    generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
    inspect: impl FnOnce(
        &VerifiedSameSecretLowDegreePrerequisite,
    ) -> Result<ResultValue, CommonProofRuntimeError>,
) -> Result<ResultValue, CommonProofRuntimeError> {
    VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        match registry.source(handle)? {
            VerifiedVssLowDegreeEvidenceState::AttachedToSameSecretGeneration {
                evidence,
                generation_binding_hash: retained_binding_hash,
            } if *retained_binding_hash == generation_binding_hash => inspect(evidence),
            _ => Err(CommonProofRuntimeError::WrongVerificationBinding),
        }
    })
}

pub(in crate::bgv) fn consume_verified_vss_share_linkage_terminal(
    handle: u32,
) -> Result<VerifiedVssShareLinkageTerminal, CommonProofRuntimeError> {
    VERIFIED_VSS_SHARE_LINKAGE_TERMINAL_REGISTRY
        .with(|registry| registry.borrow_mut().consume(handle))
}

pub(in crate::bgv) fn consume_ordered_verified_vss_share_linkage_terminals(
    ordered_handles: &[u32],
) -> Result<Vec<VerifiedVssShareLinkageTerminal>, CommonProofRuntimeError> {
    VERIFIED_VSS_SHARE_LINKAGE_TERMINAL_REGISTRY.with(|registry| {
        registry.borrow_mut().consume_ordered_exact(
            ordered_handles,
            usize::from(FOUNDATION_PROFILE.participant_count),
        )
    })
}

pub(in crate::bgv::proof_suite) struct SelectedVssProofRuntimePlan {
    pub(in crate::bgv::proof_suite) relation_plan: CommonProofRelationPlanCapability,
    pub(in crate::bgv::proof_suite) limits: CommonProofRuntimeLimits,
}

pub(in crate::bgv::proof_suite) fn selected_vss_proof_runtime_plan(
    canonical_application_statement_bytes: &[u8],
) -> Result<SelectedVssProofRuntimePlan, VssShareLinkageRuntimeError> {
    let statement_schema_identifier =
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or(VssShareLinkageRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let input = selected_committed_material_relation_plan_input()?;
    let compiled_relation_plan =
        compile_vss_share_linkage_relation_plan(&input, &relation_context)?;
    let variant = compiled_relation_plan.select_variant(None, None)?;
    let limits = selected_proof_runtime_limits(
        statement_schema_identifier,
        canonical_application_statement_bytes,
        variant,
    )?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_relation_plan,
        &relation_context,
        None,
        None,
    )?;
    Ok(SelectedVssProofRuntimePlan {
        relation_plan,
        limits,
    })
}

fn require_selected_suite_matches_generation_source(
    selected_suite_handle: u32,
    source: &SetupGenerationVssPreparationSource,
) -> Result<(), VssShareLinkageRuntimeError> {
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != source.protocol_version()
            || selected_suite.suite_identifier() != source.suite_identifier()
        {
            return Err(VssShareLinkageRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(VssShareLinkageRuntimeError::Runtime)??;
    Ok(())
}

fn resolve_single_setup_intent_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
) -> Result<VerifiedBoardApplicationSource, VssShareLinkageRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[setup_intent_object_handle],
    )
    .map_err(VssShareLinkageRuntimeError::BoardRuntime)?;
    let source = sources.pop().ok_or(VssShareLinkageRuntimeError::Refusal(
        RefusalReason::MissingPrerequisite,
    ))?;
    if !sources.is_empty() {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    source.setup_intent_payload()?;
    Ok(source)
}

fn require_setup_intent_matches_generation_source(
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationVssPreparationSource,
) -> Result<(), VssShareLinkageRuntimeError> {
    if board_source.object_type() != FoundationObjectType::SetupIntent
        || board_source.suite_identifier().into_bytes() != source.suite_identifier()
        || board_source.manifest_hash().into_bytes() != source.manifest_hash()
        || board_source.ceremony_context_hash().into_bytes() != source.ceremony_context_hash()
        || board_source.action_context_hash().into_bytes() != source.action_context_hash()
        || board_source.roster_hash().into_bytes() != source.roster_hash()
        || board_source.object_hash().into_bytes() != source.source_setup_intent_object_hash()
        || board_source.producer_sequence() != 0
        || board_source.producer_roster_position() != Some(source.roster_position())
        || board_source
            .producer_participant_identity()
            .map(ParticipantIdentity::into_bytes)
            != Some(source.participant_identity())
    {
        return Err(VssShareLinkageRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_generation_reservation_binding(
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    source: &SetupGenerationVssPreparationSource,
) -> Result<VerifiedStateReservationRuntimeBinding, VssShareLinkageRuntimeError> {
    if state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    let binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(VssShareLinkageRuntimeError::StateRuntime)?;
    if binding.authorization_hash.into_bytes() != source.action_randomness_authorization_hash() {
        return Err(VssShareLinkageRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    Ok(binding)
}

fn resolve_vss_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationVssPreparationSource,
    checkpoint_continuation: crate::foundation::AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, VssShareLinkageRuntimeError> {
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(source.suite_identifier()),
        Hash512::from_bytes(source.ceremony_context_hash()),
        Hash512::from_bytes(source.action_context_hash()),
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(source.roster_position()),
        None,
        None,
    )?;
    let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        source.protocol_version(),
        source.suite_identifier(),
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        source.canonical_application_statement_bytes(),
    ));
    resolve_prepared_action_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        board_source,
        application_slot,
        application_statement_hash,
        checkpoint_continuation,
    )
    .map_err(VssShareLinkageRuntimeError::ActionRandomnessRuntime)
}

fn prepare_vss_common_generation(
    setup_generation_authority_handle: u32,
    preparation_source: &SetupGenerationVssPreparationSource,
    prepared_attempt: PreparedActionProofAttemptSource,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
) -> Result<PreparedCommonProofGeneration, VssShareLinkageRuntimeError> {
    let statement = decode_selected_vss_share_linkage_statement(
        preparation_source.canonical_application_statement_bytes(),
        SelectedApplicationStatementContext::new(
            preparation_source.protocol_version(),
            preparation_source.suite_identifier(),
            None,
            None,
        ),
    )
    .map_err(|_| VssShareLinkageRuntimeError::Refusal(RefusalReason::WrongContext))?;
    let application = SetupGenerationVssApplication::from_decoded_statement(
        prepared_attempt,
        preparation_source.canonical_application_statement_bytes(),
        &statement,
    );
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    with_setup_generation_vss_material(&authority_handle, &application, |source| {
        source.prepare_common_generation(relation_plan, limits)
    })
    .map_err(VssShareLinkageRuntimeError::GenerationPreparation)
}

fn resumed_generation_preparation_error(
    error: VssShareLinkageRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        VssShareLinkageRuntimeError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        VssShareLinkageRuntimeError::GenerationPreparation(
            SetupVssGenerationPreparationError::Runtime(error),
        ) => CommonProofGenerationPreparationError::Runtime(error),
        VssShareLinkageRuntimeError::GenerationPreparation(
            SetupVssGenerationPreparationError::Preparation(error),
        ) => error,
        VssShareLinkageRuntimeError::GenerationPreparation(
            SetupVssGenerationPreparationError::Refusal(RefusalReason::ConsumedState),
        ) => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::UnknownOrStaleHandle,
        ),
        _ => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding,
        ),
    }
}

#[derive(Clone, Copy)]
enum VssGenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
fn prepare_vss_generation(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: VssGenerationMode,
) -> Result<(u32, u32), VssShareLinkageRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    let preparation_source = resolve_setup_generation_vss_preparation_source(&authority_handle)?;
    require_selected_suite_matches_generation_source(selected_suite_handle, &preparation_source)?;
    let board_source = resolve_single_setup_intent_source(
        board_verifier_session_handle,
        board_verifier_session_capability,
        setup_intent_object_handle,
    )?;
    require_setup_intent_matches_generation_source(&board_source, &preparation_source)?;
    let verified_reservation_binding = resolve_generation_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
        &preparation_source,
    )?;
    let runtime_plan = selected_vss_proof_runtime_plan(
        preparation_source.canonical_application_statement_bytes(),
    )?;
    let checkpoint_schedule_digest = runtime_plan.relation_plan.checkpoint_schedule_digest()?;
    let fresh_continuation =
        crate::foundation::AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_prepared_attempt = resolve_vss_prepared_attempt(
        action_randomness_handle,
        verified_reservation_binding,
        &board_source,
        &preparation_source,
        fresh_continuation,
    )?;
    let generation_family_adapter = match generation_mode {
        VssGenerationMode::Fresh => {
            let prepared_generation = prepare_vss_common_generation(
                setup_generation_authority_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            CommonProofGenerationFamilyAdapter::fresh(prepared_generation)
        }
        VssGenerationMode::Resume => {
            let fresh_preparation = prepare_vss_common_generation(
                setup_generation_authority_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                fresh_preparation.application_statement_schema_identifier(),
                fresh_preparation.runtime_binding_hash(),
                fresh_preparation.generation_authorization_hash(),
                fresh_preparation.proof_attempt_lineage_identifier(),
            );
            drop(fresh_preparation);
            let resumed_preparation_source = preparation_source.clone();
            CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |authenticated_continuation| {
                    let resumed_runtime_plan = selected_vss_proof_runtime_plan(
                        resumed_preparation_source.canonical_application_statement_bytes(),
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    let prepared_attempt = resolve_vss_prepared_attempt(
                        action_randomness_handle,
                        verified_reservation_binding,
                        &board_source,
                        &resumed_preparation_source,
                        authenticated_continuation,
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    prepare_vss_common_generation(
                        setup_generation_authority_handle,
                        &resumed_preparation_source,
                        prepared_attempt,
                        resumed_runtime_plan.relation_plan,
                        resumed_runtime_plan.limits,
                    )
                    .map_err(resumed_generation_preparation_error)
                }),
            )
        }
    };
    let board_binding_source_handle =
        VSS_GENERATION_BOARD_BINDING_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .retain(VssGenerationBoardBindingSource { preparation_source })
        })?;
    match retain_common_proof_generation_family_adapter(generation_family_adapter) {
        Ok(adapter_handle) => Ok((adapter_handle, board_binding_source_handle)),
        Err(error) => {
            VSS_GENERATION_BOARD_BINDING_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(board_binding_source_handle))?;
            Err(VssShareLinkageRuntimeError::Runtime(error))
        }
    }
}

struct ExactVssBoardAuthority {
    verified_public_randomness: VerifiedPublicRandomness,
    dealer_record_source: VerifiedBoardApplicationSource,
    canonical_application_statement_bytes: Vec<u8>,
}

fn expected_vss_board_object_handle_count() -> Result<usize, VssShareLinkageRuntimeError> {
    usize::from(FOUNDATION_PROFILE.participant_count)
        .checked_mul(3)
        .and_then(|count| count.checked_add(1))
        .ok_or(VssShareLinkageRuntimeError::InvalidInput)
}

fn decode_vss_board_object_handles(
    canonical_handle_bytes: &[u8],
) -> Result<Vec<u32>, VssShareLinkageRuntimeError> {
    let expected_handle_count = expected_vss_board_object_handle_count()?;
    let expected_byte_length = expected_handle_count
        .checked_mul(HANDLE_BYTE_LENGTH)
        .ok_or(VssShareLinkageRuntimeError::InvalidInput)?;
    if canonical_handle_bytes.len() != expected_byte_length {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    canonical_handle_bytes
        .chunks_exact(HANDLE_BYTE_LENGTH)
        .map(|bytes| {
            <[u8; HANDLE_BYTE_LENGTH]>::try_from(bytes)
                .map(u32::from_le_bytes)
                .map_err(|_| VssShareLinkageRuntimeError::InvalidInput)
        })
        .collect()
}

fn require_board_source_matches_public_randomness(
    board_source: &VerifiedBoardApplicationSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<(), VssShareLinkageRuntimeError> {
    let context = verified_public_randomness.context();
    if board_source.suite_identifier() != context.suite_identifier()
        || board_source.manifest_hash() != context.manifest_hash()
        || board_source.ceremony_context_hash() != context.ceremony_context_hash()
        || board_source.action_context_hash() != context.action_context_hash()
        || board_source.roster_hash() != context.roster_hash()
    {
        return Err(VssShareLinkageRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_exact_vss_board_authority(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ordered_object_handles: &[u32],
) -> Result<ExactVssBoardAuthority, VssShareLinkageRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
        || ordered_object_handles.len() != expected_vss_board_object_handle_count()?
    {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    let sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ordered_object_handles,
    )
    .map_err(VssShareLinkageRuntimeError::BoardRuntime)?;
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let mut source_iterator = sources.into_iter();
    let setup_intent_sources = source_iterator
        .by_ref()
        .take(participant_count)
        .collect::<Vec<_>>();
    let commitment_sources = source_iterator
        .by_ref()
        .take(participant_count)
        .collect::<Vec<_>>();
    let reveal_sources = source_iterator
        .by_ref()
        .take(participant_count)
        .collect::<Vec<_>>();
    let dealer_record_source =
        source_iterator
            .next()
            .ok_or(VssShareLinkageRuntimeError::Refusal(
                RefusalReason::MissingPrerequisite,
            ))?;
    if source_iterator.next().is_some() {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    let verified_public_randomness = verify_public_randomness_board_sources(
        setup_intent_sources,
        commitment_sources,
        reveal_sources,
    )?;
    require_board_source_matches_public_randomness(
        &dealer_record_source,
        &verified_public_randomness,
    )?;
    let board_payload = dealer_record_source.dealer_public_record_payload()?;
    let producer_identity = dealer_record_source.producer_participant_identity().ok_or(
        VssShareLinkageRuntimeError::Refusal(RefusalReason::WrongContext),
    )?;
    let producer_roster_position = dealer_record_source.producer_roster_position().ok_or(
        VssShareLinkageRuntimeError::Refusal(RefusalReason::WrongContext),
    )?;
    if dealer_record_source.object_type() != FoundationObjectType::PublicSetupRecord
        || dealer_record_source.producer_sequence() != 0
        || board_payload.dealer_roster_position() != producer_roster_position
        || board_payload.public_setup_seed_prerequisite()
            != verified_public_randomness.public_setup_seed()
        || board_payload.ordered_recipient_envelope_hashes().len() != participant_count
        || verified_public_randomness
            .ordered_participant_identities()
            .get(usize::from(producer_roster_position))
            != Some(&producer_identity)
    {
        return Err(VssShareLinkageRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    let ordered_coefficient_material_roots = board_payload
        .coefficient_material_roots()
        .iter()
        .map(|root| root.into_bytes())
        .collect::<Vec<_>>();
    let ordered_recipient_share_material_roots = board_payload
        .recipient_share_material_roots()
        .iter()
        .map(|root| root.into_bytes())
        .collect::<Vec<_>>();
    let context = verified_public_randomness.context();
    let canonical_application_statement_bytes = canonical_selected_vss_share_linkage_statement(
        context.protocol_version(),
        context.suite_identifier().into_bytes(),
        context.ceremony_context_hash().into_bytes(),
        context.action_context_hash().into_bytes(),
        context.roster_hash().into_bytes(),
        verified_public_randomness.public_setup_seed().into_bytes(),
        producer_identity.into_bytes(),
        producer_roster_position,
        &ordered_coefficient_material_roots,
        &ordered_recipient_share_material_roots,
    )
    .map_err(|_| VssShareLinkageRuntimeError::Refusal(RefusalReason::WrongTypeOrLength))?;
    Ok(ExactVssBoardAuthority {
        verified_public_randomness,
        dealer_record_source,
        canonical_application_statement_bytes,
    })
}

fn require_selected_suite_matches_board_authority(
    selected_suite_handle: u32,
    authority: &ExactVssBoardAuthority,
) -> Result<(), VssShareLinkageRuntimeError> {
    let context = authority.verified_public_randomness.context();
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != context.protocol_version()
            || selected_suite.suite_identifier() != context.suite_identifier().into_bytes()
        {
            return Err(VssShareLinkageRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(VssShareLinkageRuntimeError::Runtime)??;
    Ok(())
}

fn bind_generated_vss_proof_to_board(
    generated_common_proof_handle: u32,
    board_binding_source_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ordered_object_handles: &[u32],
) -> Result<(), VssShareLinkageRuntimeError> {
    let board_authority = resolve_exact_vss_board_authority(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ordered_object_handles,
    )?;
    let board_binding_source = VSS_GENERATION_BOARD_BINDING_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow()
            .source(board_binding_source_handle)
            .cloned()
    })?;
    let preparation_source = &board_binding_source.preparation_source;
    let public_randomness_context = board_authority.verified_public_randomness.context();
    let roster_position = usize::from(preparation_source.roster_position());
    if board_authority.canonical_application_statement_bytes
        != preparation_source.canonical_application_statement_bytes()
        || public_randomness_context.protocol_version() != preparation_source.protocol_version()
        || public_randomness_context.suite_identifier().into_bytes()
            != preparation_source.suite_identifier()
        || public_randomness_context.manifest_hash().into_bytes()
            != preparation_source.manifest_hash()
        || public_randomness_context
            .ceremony_context_hash()
            .into_bytes()
            != preparation_source.ceremony_context_hash()
        || public_randomness_context.action_context_hash().into_bytes()
            != preparation_source.action_context_hash()
        || public_randomness_context.roster_hash().into_bytes() != preparation_source.roster_hash()
        || board_authority
            .verified_public_randomness
            .public_setup_seed()
            .into_bytes()
            != preparation_source.public_setup_seed()
        || board_authority
            .verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes()
            != preparation_source.setup_proof_context_hash()
        || board_authority
            .verified_public_randomness
            .ordered_setup_intent_object_hashes()
            .get(roster_position)
            .map(|hash| hash.into_bytes())
            != Some(preparation_source.source_setup_intent_object_hash())
    {
        return Err(VssShareLinkageRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    let board_payload = board_authority
        .dealer_record_source
        .dealer_public_record_payload()?;
    bind_generated_common_proof_to_verified_board_source(
        generated_common_proof_handle,
        &board_authority.dealer_record_source,
        board_payload.share_linkage_proof(),
        preparation_source.canonical_application_statement_bytes(),
    )?;
    VSS_GENERATION_BOARD_BINDING_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(board_binding_source_handle))?;
    Ok(())
}

fn prepare_vss_verification(
    selected_suite_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ordered_object_handles: &[u32],
) -> Result<(u32, u32), VssShareLinkageRuntimeError> {
    let board_authority = resolve_exact_vss_board_authority(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ordered_object_handles,
    )?;
    require_selected_suite_matches_board_authority(selected_suite_handle, &board_authority)?;
    let context = board_authority.verified_public_randomness.context();
    let producer_roster_position = board_authority
        .dealer_record_source
        .producer_roster_position()
        .ok_or(VssShareLinkageRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ))?;
    let application_slot = ProofApplicationSlot::new(
        context.suite_identifier(),
        context.ceremony_context_hash(),
        context.action_context_hash(),
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(producer_roster_position),
        None,
        None,
    )?;
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        board_authority
            .canonical_application_statement_bytes
            .clone(),
        &CanonicalDecodeLimits::default(),
    )?;
    let proof_header_hash = proof_header.proof_header_hash()?;
    let board_payload = board_authority
        .dealer_record_source
        .dealer_public_record_payload()?;
    let proof_application_binding = ProofApplicationBinding::new(
        application_slot,
        proof_header_hash,
        board_payload.share_linkage_proof().clone(),
    )?;
    let runtime_plan =
        selected_vss_proof_runtime_plan(&board_authority.canonical_application_statement_bytes)?;
    let statement_source =
        super::VerifiedCommonProofStatementSource::from_exact_family_verified_board_source(
            board_authority.dealer_record_source.clone(),
            context.protocol_version(),
            board_authority
                .canonical_application_statement_bytes
                .clone(),
            proof_application_binding,
            runtime_plan.relation_plan,
            runtime_plan.limits,
        )?;
    let statement_trees =
        super::VerifiedStatementOwnedTree::from_verified_committed_material_statement_source(
            &statement_source,
            &board_authority.verified_public_randomness,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let terminal_source_handle = VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().retain(VssVerificationTerminalSource {
            canonical_application_statement_bytes: board_authority
                .canonical_application_statement_bytes,
            board_source: board_authority.dealer_record_source,
            verified_public_randomness: board_authority.verified_public_randomness,
        })
    })?;
    let selected_suite_handle =
        CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
    let adapter_result =
        retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
            upstream_inputs.prepare_statement_tree_family_verification_without_evaluator(
                &selected_suite_handle,
                statement_source,
                statement_trees,
            )
        });
    match adapter_result {
        Ok(adapter_handle) => Ok((adapter_handle, terminal_source_handle)),
        Err(error) => {
            VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
            Err(VssShareLinkageRuntimeError::Runtime(error))
        }
    }
}

fn finish_vss_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<u32, CommonProofRuntimeError> {
    let terminal_source = VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
    let reserved_terminal_handle = match VERIFIED_VSS_SHARE_LINKAGE_TERMINAL_REGISTRY
        .with(|registry| registry.borrow_mut().reserve())
    {
        Ok(handle) => handle,
        Err(error) => {
            VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .restore(terminal_source_handle, terminal_source)
            })?;
            return Err(error);
        }
    };
    let terminal_source_cell = RefCell::new(Some(terminal_source));
    let result = super::preflight_and_consume_verified_common_proof_with_family_terminal(
        &super::VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_common_proof| {
            let terminal_source = terminal_source_cell.borrow();
            let terminal_source = terminal_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            VerifiedVssShareLinkageTerminal::preflight_from_borrowed_common_proof(
                verified_common_proof,
                &terminal_source.canonical_application_statement_bytes,
                &terminal_source.board_source,
                &terminal_source.verified_public_randomness,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        },
        |verified_common_proof, terminal_preflight| {
            let _terminal_source = terminal_source_cell
                .borrow_mut()
                .take()
                .expect("VSS terminal preflight retained the exact source");
            let terminal = terminal_preflight.complete(verified_common_proof);
            VERIFIED_VSS_SHARE_LINKAGE_TERMINAL_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .commit_preflighted(reserved_terminal_handle, terminal)
            })
        },
    );
    if result.is_err() {
        let reservation_release_result =
            VERIFIED_VSS_SHARE_LINKAGE_TERMINAL_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .release_reservation(reserved_terminal_handle)
            });
        let source_restore_result = if let Some(terminal_source) = terminal_source_cell.into_inner()
        {
            VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .restore(terminal_source_handle, terminal_source)
            })
        } else {
            Ok(())
        };
        reservation_release_result?;
        source_restore_result?;
    }
    result
}

fn finish_vss_low_degree_evidence(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<u32, CommonProofRuntimeError> {
    let terminal_source = VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
    let reserved_evidence_handle = match VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY
        .with(|registry| registry.borrow_mut().reserve())
    {
        Ok(handle) => handle,
        Err(error) => {
            VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .restore(terminal_source_handle, terminal_source)
            })?;
            return Err(error);
        }
    };
    let terminal_source_cell = RefCell::new(Some(terminal_source));
    let result = super::preflight_and_consume_verified_common_proof_with_family_terminal(
        &super::VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_common_proof| {
            let terminal_source = terminal_source_cell.borrow();
            let terminal_source = terminal_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight =
                VerifiedVssShareLinkageTerminal::preflight_from_borrowed_common_proof(
                    verified_common_proof,
                    &terminal_source.canonical_application_statement_bytes,
                    &terminal_source.board_source,
                    &terminal_source.verified_public_randomness,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let runtime_plan = selected_vss_proof_runtime_plan(
                &terminal_source.canonical_application_statement_bytes,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            VerifiedSameSecretLowDegreePrerequisite::from_positive_verified_vss_share_linkage(
                terminal_preflight.terminal(),
                verified_common_proof,
                &runtime_plan.relation_plan,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        },
        |_verified_common_proof, evidence| {
            let _terminal_source = terminal_source_cell
                .borrow_mut()
                .take()
                .expect("VSS low-degree evidence preflight retained the exact source");
            VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY.with(|registry| {
                registry.borrow_mut().commit_preflighted(
                    reserved_evidence_handle,
                    VerifiedVssLowDegreeEvidenceState::Available(evidence),
                )
            })
        },
    );
    if result.is_err() {
        let reservation_release_result =
            VERIFIED_VSS_LOW_DEGREE_EVIDENCE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .release_reservation(reserved_evidence_handle)
            });
        let source_restore_result = if let Some(terminal_source) = terminal_source_cell.into_inner()
        {
            VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .restore(terminal_source_handle, terminal_source)
            })
        } else {
            Ok(())
        };
        reservation_release_result?;
        source_restore_result?;
    }
    result
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn runtime_error_status(error: VssShareLinkageRuntimeError) -> u32 {
    match error {
        VssShareLinkageRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        VssShareLinkageRuntimeError::GenerationPreparation(error) => match error {
            SetupVssGenerationPreparationError::Refusal(refusal_reason) => {
                refusal_status(refusal_reason)
            }
            SetupVssGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            SetupVssGenerationPreparationError::Preparation(error) => match error {
                CommonProofGenerationPreparationError::Runtime(error) => {
                    super::runtime_ffi::runtime_error_status(error)
                }
                CommonProofGenerationPreparationError::Generation(error) => {
                    let _ = error;
                    refusal_status(RefusalReason::OutsideSupportedProfile)
                }
            },
            SetupVssGenerationPreparationError::Prover(error) => {
                let _ = error;
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
        },
        VssShareLinkageRuntimeError::Foundation(error) => refusal_status(error.refusal_reason),
        VssShareLinkageRuntimeError::ActionRandomnessRuntime(status)
        | VssShareLinkageRuntimeError::BoardRuntime(status)
        | VssShareLinkageRuntimeError::StateRuntime(status) => status,
        VssShareLinkageRuntimeError::Refusal(refusal_reason) => refusal_status(refusal_reason),
        VssShareLinkageRuntimeError::InvalidInput => {
            refusal_status(RefusalReason::WrongTypeOrLength)
        }
        VssShareLinkageRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        VssShareLinkageRuntimeError::Profile(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        VssShareLinkageRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        VssShareLinkageRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if pointer.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, byte_length) }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<[u8; BYTE_LENGTH], VssShareLinkageRuntimeError> {
    if pointer.is_null() || declared_byte_length != BYTE_LENGTH {
        return Err(VssShareLinkageRuntimeError::InvalidInput);
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) };
    bytes
        .try_into()
        .map_err(|_| VssShareLinkageRuntimeError::InvalidInput)
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi_inputs(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    board_binding_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: VssGenerationMode,
) -> u32 {
    let result = (|| {
        if board_binding_source_handle_output_pointer.is_null() {
            return Err(VssShareLinkageRuntimeError::InvalidInput);
        }
        let state_verifier_session_capability = unsafe {
            fixed_input::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let board_verifier_session_capability = unsafe {
            fixed_input::<BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        }?;
        let checkpoint_lineage_identifier = unsafe {
            fixed_input::<ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }?;
        prepare_vss_generation(
            selected_suite_handle,
            setup_generation_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            &state_verifier_session_capability,
            verified_reservation_handle,
            board_verifier_session_handle,
            &board_verifier_session_capability,
            setup_intent_object_handle,
            checkpoint_lineage_identifier,
            generation_mode,
        )
    })();
    match result {
        Ok((adapter_handle, board_binding_source_handle)) => {
            unsafe {
                board_binding_source_handle_output_pointer.write(board_binding_source_handle);
                write_status(status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Retains a fresh selected VSS share-linkage generation adapter. The
/// statement, committed-material roots, trace source, proof plan, and reset
/// binding are reconstructed from live Rust capabilities.
///
/// # Safety
///
/// Each capability pointer must name its declared readable range. The
/// checkpoint lineage pointer must name exactly 32 readable bytes. The board
/// binding output pointer must name one writable `u32`; a non-null status
/// pointer must do the same.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_vss_share_linkage_prepare_generation(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    board_binding_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            setup_generation_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            setup_intent_object_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            board_binding_source_handle_output_pointer,
            status_pointer,
            VssGenerationMode::Fresh,
        )
    }
}

/// Retains the selected VSS share-linkage resume adapter. The generic runtime
/// can activate it only after authenticating checkpoint bytes against the
/// exact fresh attempt description, lineage, and compiled checkpoint schedule.
///
/// # Safety
///
/// Each capability pointer must name its declared readable range. The
/// checkpoint lineage pointer must name exactly 32 readable bytes. The board
/// binding output pointer must name one writable `u32`; a non-null status
/// pointer must do the same.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_vss_share_linkage_prepare_resumed_generation(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    board_binding_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            setup_generation_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            setup_intent_object_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            board_binding_source_handle_output_pointer,
            status_pointer,
            VssGenerationMode::Resume,
        )
    }
}

/// Returns the exact byte length of the roster-ordered setup-intent,
/// commitment, reveal, and dealer-record handle catalog required by the
/// selected VSS verifier. The count is derived from the selected foundation
/// profile.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_vss_share_linkage_board_object_handle_catalog_byte_length() -> u32
{
    expected_vss_board_object_handle_count()
        .and_then(|count| {
            count
                .checked_mul(HANDLE_BYTE_LENGTH)
                .and_then(|byte_length| u32::try_from(byte_length).ok())
                .ok_or(VssShareLinkageRuntimeError::InvalidInput)
        })
        .unwrap_or(0)
}

/// Consumes a generated VSS common proof and its retained generation source
/// only after the exact authenticated public-randomness transcript and dealer
/// record reproduce every statement and setup binding.
///
/// # Safety
///
/// The board capability and object-handle pointers must name their declared
/// readable ranges. Object handles are little-endian `u32` values in exact
/// roster order: all setup intents, all commitments, all reveals, then the
/// dealer record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_vss_share_linkage_bind_generated_proof_to_board(
    generated_common_proof_handle: u32,
    board_binding_source_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    ordered_object_handle_bytes_pointer: *const u8,
    ordered_object_handle_bytes_byte_length: usize,
) -> u32 {
    let board_verifier_session_capability = unsafe {
        input_bytes(
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
        )
    };
    let ordered_object_handle_bytes = unsafe {
        input_bytes(
            ordered_object_handle_bytes_pointer,
            ordered_object_handle_bytes_byte_length,
        )
    };
    let result = decode_vss_board_object_handles(ordered_object_handle_bytes).and_then(
        |ordered_object_handles| {
            bind_generated_vss_proof_to_board(
                generated_common_proof_handle,
                board_binding_source_handle,
                board_verifier_session_handle,
                board_verifier_session_capability,
                &ordered_object_handles,
            )
        },
    );
    result.map_or_else(runtime_error_status, |()| 0)
}

/// Permanently discards a retained producer-side board-binding source after a
/// cancelled generation attempt.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_vss_share_linkage_discard_generation_board_binding_source(
    board_binding_source_handle: u32,
) -> u32 {
    VSS_GENERATION_BOARD_BINDING_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(board_binding_source_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
    })
}

/// Opens selected VSS common-proof verification from the complete exact
/// authenticated public-randomness transcript and one dealer record. The
/// returned generic family adapter owns no caller-authored statement facts;
/// the terminal-source output must later consume its positive proof result.
///
/// # Safety
///
/// The board capability and object-handle pointers must name their declared
/// readable ranges. Object handles are little-endian `u32` values in exact
/// roster order. The terminal-source output pointer must name one writable
/// `u32`; a non-null status pointer must do the same.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_vss_share_linkage_prepare_verification(
    selected_suite_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    ordered_object_handle_bytes_pointer: *const u8,
    ordered_object_handle_bytes_byte_length: usize,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if terminal_source_handle_output_pointer.is_null() {
            return Err(VssShareLinkageRuntimeError::InvalidInput);
        }
        let board_verifier_session_capability = unsafe {
            input_bytes(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        };
        let ordered_object_handle_bytes = unsafe {
            input_bytes(
                ordered_object_handle_bytes_pointer,
                ordered_object_handle_bytes_byte_length,
            )
        };
        let ordered_object_handles = decode_vss_board_object_handles(ordered_object_handle_bytes)?;
        prepare_vss_verification(
            selected_suite_handle,
            board_verifier_session_handle,
            board_verifier_session_capability,
            &ordered_object_handles,
        )
    })();
    match result {
        Ok((adapter_handle, terminal_source_handle)) => {
            unsafe {
                terminal_source_handle_output_pointer.write(terminal_source_handle);
                write_status(status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Consumes one positive generic VSS proof capability and its exact board
/// terminal source into a bounded, one-shot verified setup terminal.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_vss_share_linkage_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match finish_vss_verification(verified_common_proof_handle, terminal_source_handle) {
        Ok(output_handle) => {
            unsafe { write_status(status_pointer, 0) };
            output_handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// Consumes one positive generic VSS proof capability and its exact board
/// source into the opaque, one-shot low-degree evidence required by the
/// same-secret construction. This path does not retain a broad VSS terminal
/// and does not mint any accepted-setup authority.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_vss_share_linkage_finish_low_degree_evidence(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match finish_vss_low_degree_evidence(verified_common_proof_handle, terminal_source_handle) {
        Ok(output_handle) => {
            unsafe { write_status(status_pointer, 0) };
            output_handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// Discards a VSS terminal source after its generic verifier operation is
/// cancelled or reset.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_vss_share_linkage_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    VSS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
    })
}

/// Permanently drops a verified VSS terminal that will not be consumed by
/// accepted-setup construction.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_vss_share_linkage_discard_verified_terminal(
    terminal_handle: u32,
) -> u32 {
    consume_verified_vss_share_linkage_terminal(terminal_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
}

/// Permanently drops an unused one-shot VSS low-degree evidence token.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_vss_share_linkage_discard_low_degree_evidence(
    evidence_handle: u32,
) -> u32 {
    consume_verified_vss_low_degree_evidence(evidence_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::proof_suite::{
            CommonProofVerifierError, ProofChallengeExtensionElement, RelationTreeDescriptor,
            VerifiedCommonProofStatementSource, VerifiedRelationColumnEvaluator,
            VerifiedRelationColumnEvaluatorMemoryAccounting, VerifiedStatementOwnedTree,
            row_code_whir::prepare_row_code_whir_verification,
        },
        foundation::StreamDescriptor,
    };

    struct RefusingTestColumnEvaluator;

    impl VerifiedRelationColumnEvaluator for RefusingTestColumnEvaluator {
        fn memory_accounting(
            &self,
        ) -> Result<VerifiedRelationColumnEvaluatorMemoryAccounting, CommonProofVerifierError>
        {
            VerifiedRelationColumnEvaluatorMemoryAccounting::new(0, 0, 0)
        }

        fn evaluate_at_extension_point(
            &mut self,
            _column_ordinal: u32,
            _point: ProofChallengeExtensionElement,
        ) -> Option<ProofChallengeExtensionElement> {
            None
        }
    }

    fn test_root(domain: u8, ordinal: usize) -> [u8; Hash512::BYTE_LENGTH] {
        let mut root = [domain; Hash512::BYTE_LENGTH];
        root[..size_of::<u64>()].copy_from_slice(
            &u64::try_from(ordinal)
                .expect("selected catalog ordinal fits u64")
                .to_le_bytes(),
        );
        root[Hash512::BYTE_LENGTH - 1] = domain;
        root
    }

    fn test_proof_stream_descriptor(proof_byte_length: usize) -> StreamDescriptor {
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let chunk_count = proof_byte_length
            .checked_add(chunk_byte_length - 1)
            .expect("selected proof byte length fits usize")
            / chunk_byte_length;
        StreamDescriptor {
            total_byte_length: u64::try_from(proof_byte_length)
                .expect("selected proof byte length fits u64"),
            ordered_chunk_digests: vec![Hash512::from_bytes([0xd1; 64]); chunk_count].into(),
            full_object_digest: Hash512::from_bytes([0xd2; 64]),
        }
    }

    #[test]
    fn selected_vss_statement_tree_catalog_is_complete_and_exactly_bound() {
        let suite_identifier = Hash512::from_bytes([0x11; 64]);
        let manifest_hash = Hash512::from_bytes([0x18; 64]);
        let ceremony_context_hash = Hash512::from_bytes([0x22; 64]);
        let action_context_hash = Hash512::from_bytes([0x33; 64]);
        let roster_hash = Hash512::from_bytes([0x44; 64]);
        let public_setup_seed = Hash512::from_bytes([0x55; 64]);
        let ordered_participant_identities = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                ParticipantIdentity::from_bytes(test_root(0x70, usize::from(roster_position)))
            })
            .collect::<Vec<_>>();
        let verified_public_randomness = VerifiedPublicRandomness::from_test_values(
            suite_identifier,
            manifest_hash,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            ordered_participant_identities,
            public_setup_seed,
        );
        let relation_input = selected_committed_material_relation_plan_input()
            .expect("selected committed-material relation input");
        let sharing_limb_count = relation_input.sharing_data_modulus_indices.len();
        let reconstruction_threshold = usize::from(relation_input.threshold);
        let participant_count = usize::from(relation_input.participant_count);
        let coefficient_root_count = sharing_limb_count
            .checked_mul(reconstruction_threshold)
            .expect("selected coefficient root count fits usize");
        let recipient_root_count = sharing_limb_count
            .checked_mul(participant_count)
            .expect("selected recipient root count fits usize");
        let ordered_coefficient_roots = (0..coefficient_root_count)
            .map(|root_ordinal| test_root(0xa1, root_ordinal))
            .collect::<Vec<_>>();
        let ordered_recipient_roots = (0..recipient_root_count)
            .map(|root_ordinal| test_root(0xb2, root_ordinal))
            .collect::<Vec<_>>();
        let dealer_roster_position = 3_u16;
        let dealer_identity = verified_public_randomness.ordered_participant_identities()
            [usize::from(dealer_roster_position)]
        .into_bytes();
        let canonical_application_statement_bytes = canonical_selected_vss_share_linkage_statement(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier.into_bytes(),
            ceremony_context_hash.into_bytes(),
            action_context_hash.into_bytes(),
            roster_hash.into_bytes(),
            public_setup_seed.into_bytes(),
            dealer_identity,
            dealer_roster_position,
            &ordered_coefficient_roots,
            &ordered_recipient_roots,
        )
        .expect("selected VSS statement is canonical");
        let runtime_plan = selected_vss_proof_runtime_plan(&canonical_application_statement_bytes)
            .expect("selected VSS runtime plan");
        let proof_byte_length = runtime_plan
            .limits
            .maximum_proof_byte_length()
            .checked_sub(1)
            .expect("the test proof is smaller than the absolute proof bound");
        let statement_source =
            VerifiedCommonProofStatementSource::from_test_verified_vss_statement_source(
                &verified_public_randomness,
                canonical_application_statement_bytes.clone(),
                test_proof_stream_descriptor(proof_byte_length),
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )
            .expect("exact selected VSS statement source");
        let statement_trees =
            VerifiedStatementOwnedTree::from_verified_committed_material_statement_source(
                &statement_source,
                &verified_public_randomness,
            )
            .expect("selected VSS statement tree catalog");

        let relation_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected VSS relation context");
        let compiled_relation_plan =
            compile_vss_share_linkage_relation_plan(&relation_input, &relation_context)
                .expect("selected VSS relation plan");
        let selected_variant = compiled_relation_plan
            .select_variant(None, None)
            .expect("selected VSS relation variant");
        let expected_statement_tree_count = selected_variant
            .ordered_trees()
            .iter()
            .filter(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
            .count();
        assert_eq!(statement_trees.len(), expected_statement_tree_count);

        let mut expected_roots = Vec::with_capacity(expected_statement_tree_count);
        for sharing_limb_ordinal in 0..sharing_limb_count {
            let coefficient_start = sharing_limb_ordinal * reconstruction_threshold;
            expected_roots.extend_from_slice(
                &ordered_coefficient_roots
                    [coefficient_start..coefficient_start + reconstruction_threshold],
            );
            let recipient_start = sharing_limb_ordinal * participant_count;
            expected_roots.extend_from_slice(
                &ordered_recipient_roots[recipient_start..recipient_start + participant_count],
            );
        }
        assert_eq!(
            statement_trees
                .iter()
                .map(VerifiedStatementOwnedTree::expected_root)
                .collect::<Vec<_>>(),
            expected_roots,
            "the selected tree order remains limb-major with coefficient roots before recipient roots",
        );
        prepare_row_code_whir_verification(
            FOUNDATION_PROFILE.protocol_version,
            statement_source
                .proof_application_binding()
                .application_slot(),
            &canonical_application_statement_bytes,
            statement_source
                .proof_application_binding()
                .proof_header_hash(),
            u64::try_from(proof_byte_length).expect("the test proof length fits u64"),
            statement_source.relation_plan_capability(),
            statement_trees.clone(),
            Vec::new(),
            Box::new(RefusingTestColumnEvaluator),
        )
        .expect("the exact selected VSS catalog initializes the row-code WHIR verifier");

        let mut wrong_root_trees = statement_trees.clone();
        wrong_root_trees[0] = wrong_root_trees[0].with_test_expected_root([0xee; 64]);
        assert!(
            prepare_row_code_whir_verification(
                FOUNDATION_PROFILE.protocol_version,
                statement_source
                    .proof_application_binding()
                    .application_slot(),
                &canonical_application_statement_bytes,
                statement_source
                    .proof_application_binding()
                    .proof_header_hash(),
                u64::try_from(proof_byte_length).expect("the test proof length fits u64"),
                statement_source.relation_plan_capability(),
                wrong_root_trees,
                Vec::new(),
                Box::new(RefusingTestColumnEvaluator),
            )
            .is_err(),
            "a tree root cannot diverge from the canonical statement root",
        );

        let wrong_context_statement_bytes = canonical_selected_vss_share_linkage_statement(
            FOUNDATION_PROFILE.protocol_version,
            suite_identifier.into_bytes(),
            [0x92; 64],
            action_context_hash.into_bytes(),
            roster_hash.into_bytes(),
            public_setup_seed.into_bytes(),
            dealer_identity,
            dealer_roster_position,
            &ordered_coefficient_roots,
            &ordered_recipient_roots,
        )
        .expect("context-tampered VSS statement is still canonically encoded");
        let wrong_context_runtime_plan =
            selected_vss_proof_runtime_plan(&wrong_context_statement_bytes)
                .expect("selected plan remains independent of the statement context value");
        assert!(matches!(
            VerifiedCommonProofStatementSource::from_test_verified_vss_statement_source(
                &verified_public_randomness,
                wrong_context_statement_bytes,
                test_proof_stream_descriptor(proof_byte_length),
                wrong_context_runtime_plan.relation_plan,
                wrong_context_runtime_plan.limits,
            ),
            Err(CommonProofRuntimeError::WrongVerificationBinding),
        ));
    }

    #[test]
    fn single_active_source_registry_is_one_shot_and_supports_failure_restore() {
        let mut registry = SingleActiveVssSourceRegistry::default();
        let handle = registry.retain(41_u32).expect("first source retained");
        assert!(matches!(
            registry.retain(42),
            Err(CommonProofRuntimeError::AllocationLimitExceeded)
        ));
        assert_eq!(*registry.source(handle).expect("source remains live"), 41);

        let source = registry.take(handle).expect("source consumed once");
        assert!(matches!(
            registry.take(handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        registry
            .restore(handle, source)
            .expect("failed downstream operation restores the same source");
        assert_eq!(registry.take(handle).expect("restored source consumed"), 41);
        assert!(matches!(
            registry.source(handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }

    #[test]
    fn verified_terminal_registry_enforces_selected_roster_bound_and_one_shot_consumption() {
        let mut registry = BoundedVssOutputRegistry::default();
        let mut handles = Vec::new();
        for output in 0..u32::from(FOUNDATION_PROFILE.participant_count) {
            let handle = registry.reserve().expect("selected-roster slot reserved");
            handles.push(registry.commit_preflighted(handle, output));
        }
        assert!(matches!(
            registry.reserve(),
            Err(CommonProofRuntimeError::AllocationLimitExceeded)
        ));

        let consumed_handle = handles[3];
        assert_eq!(
            *registry
                .source(consumed_handle)
                .expect("terminal can be borrowed before downstream use"),
            3
        );
        assert_eq!(
            *registry
                .source(consumed_handle)
                .expect("borrowing does not consume the terminal"),
            3
        );
        assert_eq!(
            registry
                .consume(consumed_handle)
                .expect("terminal consumed"),
            3
        );
        assert!(matches!(
            registry.consume(consumed_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        let replacement_handle = registry.reserve().expect("released capacity reused");
        assert_ne!(replacement_handle, consumed_handle);
        assert_eq!(
            registry.commit_preflighted(replacement_handle, 99),
            replacement_handle
        );
    }

    #[test]
    fn terminal_reservation_can_be_cancelled_without_retaining_output() {
        let mut registry = BoundedVssOutputRegistry::<u32>::default();
        let reserved_handle = registry.reserve().expect("slot reserved");
        registry
            .release_reservation(reserved_handle)
            .expect("reservation cancelled");
        assert!(matches!(
            registry.release_reservation(reserved_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        assert!(matches!(
            registry.consume(reserved_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }

    #[test]
    fn board_catalog_decoder_requires_the_complete_profile_derived_order() {
        let handle_count =
            expected_vss_board_object_handle_count().expect("selected catalog count");
        let handles = (0..handle_count)
            .map(|ordinal| u32::try_from(ordinal + 1).expect("catalog ordinal fits u32"))
            .collect::<Vec<_>>();
        let canonical_handle_bytes = handles
            .iter()
            .flat_map(|handle| handle.to_le_bytes())
            .collect::<Vec<_>>();
        assert_eq!(
            decode_vss_board_object_handles(&canonical_handle_bytes)
                .expect("complete ordered catalog decodes"),
            handles
        );

        assert!(matches!(
            decode_vss_board_object_handles(
                &canonical_handle_bytes[..canonical_handle_bytes.len() - 1]
            ),
            Err(VssShareLinkageRuntimeError::InvalidInput)
        ));
        let mut reordered_bytes = canonical_handle_bytes;
        reordered_bytes[..HANDLE_BYTE_LENGTH].copy_from_slice(&handles[1].to_le_bytes());
        reordered_bytes[HANDLE_BYTE_LENGTH..HANDLE_BYTE_LENGTH * 2]
            .copy_from_slice(&handles[0].to_le_bytes());
        let decoded_reordered = decode_vss_board_object_handles(&reordered_bytes)
            .expect("decoder preserves the caller's exact ordering for board validation");
        assert_eq!(decoded_reordered[0], handles[1]);
        assert_eq!(decoded_reordered[1], handles[0]);
    }
}
