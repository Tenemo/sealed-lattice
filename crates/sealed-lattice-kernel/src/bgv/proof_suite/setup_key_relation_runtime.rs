//! Browser/WASM generation lifecycle for the selected same-secret and public-
//! key-share relations.
//!
//! Canonical statements and every witness source are derived from retained
//! setup-generation authority. JavaScript receives only the generic prover
//! adapter and an opaque retained source for the canonical public statement.

use core::slice;
use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::setup::{
        SetupGenerationAuthorityHandle, SetupGenerationKeyRelationApplication,
        SetupGenerationKeyRelationPreparationSource, SetupKeyRelationGenerationPreparationError,
        SetupKeyRelationProofFamily, resolve_setup_generation_key_relation_preparation_source,
        with_setup_generation_key_relation,
    },
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, FoundationObjectType, FoundationSchemaError,
        Hash512, ParticipantIdentity, PreparedActionProofAttemptSource, ProofApplicationSlot,
        RefusalReason, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
        VerifiedBoardApplicationSource, VerifiedStateReservationRuntimeBinding,
        resolve_prepared_action_proof_attempt_source, resolve_verified_board_application_sources,
        verified_state_reservation_binding,
    },
};

use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    retain_common_proof_generation_family_adapter, with_common_proof_selected_suite,
};
use super::{
    CommonProofGenerationPreparationError, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    ProofProfileError, RelationPlanError, SelectedProofAccountingError,
    decode_selected_public_key_share_statement, decode_selected_same_secret_statement,
    selected_proof_runtime_limits, selected_relation_plan_check_context, selected_relation_plans,
    verified_application_statement_hash,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_RETAINED_GENERATION_STATEMENT_SOURCE_COUNT: usize = 16;

#[derive(Debug)]
enum SetupKeyRelationRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Runtime(CommonProofRuntimeError),
    GenerationPreparation(SetupKeyRelationGenerationPreparationError),
    Foundation(FoundationSchemaError),
    ActionRandomnessRuntime(u32),
    BoardRuntime(u32),
    StateRuntime(u32),
    Refusal(RefusalReason),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for SetupKeyRelationRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for SetupKeyRelationRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for SetupKeyRelationRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for SetupKeyRelationRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofRuntimeError> for SetupKeyRelationRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<SetupKeyRelationGenerationPreparationError> for SetupKeyRelationRuntimeError {
    fn from(error: SetupKeyRelationGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<FoundationSchemaError> for SetupKeyRelationRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<RefusalReason> for SetupKeyRelationRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

struct SelectedSetupKeyRelationProofRuntimePlan {
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
    proof_query_count: u32,
}

struct SetupKeyRelationGenerationStatementSource {
    family: SetupKeyRelationProofFamily,
    canonical_application_statement_bytes: Box<[u8]>,
}

struct SetupKeyRelationGenerationStatementSourceRegistry {
    next_handle: u32,
    sources: BTreeMap<u32, SetupKeyRelationGenerationStatementSource>,
}

impl Default for SetupKeyRelationGenerationStatementSourceRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            sources: BTreeMap::new(),
        }
    }
}

impl SetupKeyRelationGenerationStatementSourceRegistry {
    fn retain(
        &mut self,
        source: SetupKeyRelationGenerationStatementSource,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.sources.len() >= MAXIMUM_RETAINED_GENERATION_STATEMENT_SOURCE_COUNT
            || self.next_handle == 0
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next_handle| *next_handle != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if self.sources.insert(handle, source).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(handle)
    }

    fn source(
        &self,
        handle: u32,
    ) -> Result<&SetupKeyRelationGenerationStatementSource, CommonProofRuntimeError> {
        self.sources
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<SetupKeyRelationGenerationStatementSource, CommonProofRuntimeError> {
        self.sources
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }
}

thread_local! {
    static SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY:
        RefCell<SetupKeyRelationGenerationStatementSourceRegistry> =
            RefCell::new(SetupKeyRelationGenerationStatementSourceRegistry::default());
}

fn selected_setup_key_relation_proof_runtime_plan(
    family: SetupKeyRelationProofFamily,
    canonical_application_statement_bytes: &[u8],
) -> Result<SelectedSetupKeyRelationProofRuntimePlan, SetupKeyRelationRuntimeError> {
    let statement_schema_identifier = family.statement_schema_identifier();
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or(SetupKeyRelationRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let selected_plan = selected_relation_plans()?
        .into_iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier() == statement_schema_identifier
        })
        .ok_or(SetupKeyRelationRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let relation_plan_variant = selected_plan.compiled_plan().select_variant(None, None)?;
    let limits = selected_proof_runtime_limits(
        statement_schema_identifier,
        canonical_application_statement_bytes,
        relation_plan_variant,
    )?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        selected_plan.compiled_plan(),
        &relation_context,
        None,
        None,
    )?;
    let proof_query_count = relation_plan.proof_query_count()?;
    Ok(SelectedSetupKeyRelationProofRuntimePlan {
        relation_plan,
        limits,
        proof_query_count,
    })
}

fn require_selected_suite_matches_generation_source(
    selected_suite_handle: u32,
    source: &SetupGenerationKeyRelationPreparationSource,
) -> Result<(), SetupKeyRelationRuntimeError> {
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != source.protocol_version()
            || selected_suite.suite_identifier() != source.suite_identifier()
        {
            return Err(SetupKeyRelationRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(SetupKeyRelationRuntimeError::Runtime)??;
    Ok(())
}

fn resolve_single_setup_intent_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
) -> Result<VerifiedBoardApplicationSource, SetupKeyRelationRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[setup_intent_object_handle],
    )
    .map_err(SetupKeyRelationRuntimeError::BoardRuntime)?;
    let source = sources.pop().ok_or(SetupKeyRelationRuntimeError::Refusal(
        RefusalReason::MissingPrerequisite,
    ))?;
    if !sources.is_empty() {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    source.setup_intent_payload()?;
    Ok(source)
}

fn require_setup_intent_matches_generation_source(
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationKeyRelationPreparationSource,
) -> Result<(), SetupKeyRelationRuntimeError> {
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
        return Err(SetupKeyRelationRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_generation_reservation_binding(
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    source: &SetupGenerationKeyRelationPreparationSource,
) -> Result<VerifiedStateReservationRuntimeBinding, SetupKeyRelationRuntimeError> {
    if state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(SetupKeyRelationRuntimeError::StateRuntime)?;
    if binding.authorization_hash.into_bytes() != source.action_randomness_authorization_hash() {
        return Err(SetupKeyRelationRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    Ok(binding)
}

fn resolve_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationKeyRelationPreparationSource,
    runtime_plan: &SelectedSetupKeyRelationProofRuntimePlan,
    checkpoint_continuation: crate::foundation::AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, SetupKeyRelationRuntimeError> {
    let statement_schema_identifier = source.family().statement_schema_identifier();
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(source.suite_identifier()),
        Hash512::from_bytes(source.ceremony_context_hash()),
        Hash512::from_bytes(source.action_context_hash()),
        statement_schema_identifier,
        Some(source.roster_position()),
        None,
        None,
    )?;
    let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        source.protocol_version(),
        source.suite_identifier(),
        statement_schema_identifier,
        source.canonical_application_statement_bytes(),
    ));
    let proof_byte_length = u64::try_from(runtime_plan.limits.proof_byte_length())
        .map_err(|_| SetupKeyRelationRuntimeError::InvalidInput)?;
    resolve_prepared_action_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        board_source,
        application_slot,
        application_statement_hash,
        proof_byte_length,
        runtime_plan.proof_query_count,
        checkpoint_continuation,
    )
    .map_err(SetupKeyRelationRuntimeError::ActionRandomnessRuntime)
}

fn prepare_common_generation(
    setup_generation_authority_handle: u32,
    preparation_source: &SetupGenerationKeyRelationPreparationSource,
    prepared_attempt: PreparedActionProofAttemptSource,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
) -> Result<super::PreparedCommonProofGeneration, SetupKeyRelationRuntimeError> {
    let (setup_proof_context_hash, participant_identity, roster_position) =
        match preparation_source.family() {
            SetupKeyRelationProofFamily::SameSecret => {
                let statement = decode_selected_same_secret_statement(
                    preparation_source.canonical_application_statement_bytes(),
                    super::SelectedApplicationStatementContext::new(
                        preparation_source.protocol_version(),
                        preparation_source.suite_identifier(),
                        None,
                        None,
                    ),
                )
                .map_err(|_| SetupKeyRelationRuntimeError::Refusal(RefusalReason::WrongContext))?;
                (
                    statement.setup_proof_context_hash(),
                    statement.participant_identity(),
                    statement.roster_position(),
                )
            }
            SetupKeyRelationProofFamily::PublicKeyShare => {
                let statement = decode_selected_public_key_share_statement(
                    preparation_source.canonical_application_statement_bytes(),
                    super::SelectedApplicationStatementContext::new(
                        preparation_source.protocol_version(),
                        preparation_source.suite_identifier(),
                        None,
                        None,
                    ),
                )
                .map_err(|_| SetupKeyRelationRuntimeError::Refusal(RefusalReason::WrongContext))?;
                (
                    statement.setup_proof_context_hash(),
                    statement.participant_identity(),
                    statement.roster_position(),
                )
            }
        };
    let application = SetupGenerationKeyRelationApplication::from_runtime_binding(
        preparation_source.family(),
        prepared_attempt,
        preparation_source.canonical_application_statement_bytes(),
        setup_proof_context_hash,
        preparation_source.roster_hash(),
        participant_identity,
        roster_position,
    );
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    with_setup_generation_key_relation(&authority_handle, &application, |source| {
        source.prepare_common_generation(relation_plan, limits)
    })
    .map_err(SetupKeyRelationRuntimeError::GenerationPreparation)
}

fn resumed_generation_preparation_error(
    error: SetupKeyRelationRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        SetupKeyRelationRuntimeError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        SetupKeyRelationRuntimeError::GenerationPreparation(
            SetupKeyRelationGenerationPreparationError::Runtime(error),
        ) => CommonProofGenerationPreparationError::Runtime(error),
        SetupKeyRelationRuntimeError::GenerationPreparation(
            SetupKeyRelationGenerationPreparationError::Preparation(error),
        ) => error,
        SetupKeyRelationRuntimeError::GenerationPreparation(
            SetupKeyRelationGenerationPreparationError::Refusal(RefusalReason::ConsumedState),
        ) => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::UnknownOrStaleHandle,
        ),
        _ => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding,
        ),
    }
}

#[derive(Clone, Copy)]
enum GenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
fn prepare_generation(
    family: SetupKeyRelationProofFamily,
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
    generation_mode: GenerationMode,
) -> Result<(u32, u32), SetupKeyRelationRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    let preparation_source =
        resolve_setup_generation_key_relation_preparation_source(&authority_handle, family)?;
    if preparation_source.family() != family {
        return Err(SetupKeyRelationRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
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
    let runtime_plan = selected_setup_key_relation_proof_runtime_plan(
        family,
        preparation_source.canonical_application_statement_bytes(),
    )?;
    let checkpoint_schedule_digest = runtime_plan
        .relation_plan
        .checkpoint_schedule_digest(runtime_plan.limits)?;
    let fresh_continuation =
        crate::foundation::AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_prepared_attempt = resolve_prepared_attempt(
        action_randomness_handle,
        verified_reservation_binding,
        &board_source,
        &preparation_source,
        &runtime_plan,
        fresh_continuation,
    )?;
    let generation_family_adapter = match generation_mode {
        GenerationMode::Fresh => {
            CommonProofGenerationFamilyAdapter::fresh(prepare_common_generation(
                setup_generation_authority_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?)
        }
        GenerationMode::Resume => {
            let fresh_preparation = prepare_common_generation(
                setup_generation_authority_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
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
                    let resumed_runtime_plan = selected_setup_key_relation_proof_runtime_plan(
                        family,
                        resumed_preparation_source.canonical_application_statement_bytes(),
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    let prepared_attempt = resolve_prepared_attempt(
                        action_randomness_handle,
                        verified_reservation_binding,
                        &board_source,
                        &resumed_preparation_source,
                        &resumed_runtime_plan,
                        authenticated_continuation,
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    prepare_common_generation(
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
    let statement_source_handle =
        SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .retain(SetupKeyRelationGenerationStatementSource {
                    family,
                    canonical_application_statement_bytes: preparation_source
                        .canonical_application_statement_bytes()
                        .to_vec()
                        .into_boxed_slice(),
                })
        })?;
    match retain_common_proof_generation_family_adapter(generation_family_adapter) {
        Ok(adapter_handle) => Ok((adapter_handle, statement_source_handle)),
        Err(error) => {
            SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(statement_source_handle))?;
            Err(SetupKeyRelationRuntimeError::Runtime(error))
        }
    }
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn runtime_error_status(error: SetupKeyRelationRuntimeError) -> u32 {
    match error {
        SetupKeyRelationRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        SetupKeyRelationRuntimeError::GenerationPreparation(error) => match error {
            SetupKeyRelationGenerationPreparationError::Refusal(refusal_reason) => {
                refusal_status(refusal_reason)
            }
            SetupKeyRelationGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            SetupKeyRelationGenerationPreparationError::Preparation(error) => match error {
                CommonProofGenerationPreparationError::Runtime(error) => {
                    super::runtime_ffi::runtime_error_status(error)
                }
                CommonProofGenerationPreparationError::Generation(error) => {
                    let _ = error;
                    refusal_status(RefusalReason::OutsideSupportedProfile)
                }
            },
            SetupKeyRelationGenerationPreparationError::Prover(error) => {
                let _ = error;
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
        },
        SetupKeyRelationRuntimeError::Foundation(error) => refusal_status(error.refusal_reason),
        SetupKeyRelationRuntimeError::ActionRandomnessRuntime(status)
        | SetupKeyRelationRuntimeError::BoardRuntime(status)
        | SetupKeyRelationRuntimeError::StateRuntime(status) => status,
        SetupKeyRelationRuntimeError::Refusal(refusal_reason) => refusal_status(refusal_reason),
        SetupKeyRelationRuntimeError::InvalidInput => {
            refusal_status(RefusalReason::WrongTypeOrLength)
        }
        SetupKeyRelationRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        SetupKeyRelationRuntimeError::Profile(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        SetupKeyRelationRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        SetupKeyRelationRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<[u8; BYTE_LENGTH], SetupKeyRelationRuntimeError> {
    if pointer.is_null() || declared_byte_length != BYTE_LENGTH {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) };
    bytes
        .try_into()
        .map_err(|_| SetupKeyRelationRuntimeError::InvalidInput)
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi_inputs(
    family: SetupKeyRelationProofFamily,
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
    statement_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: GenerationMode,
) -> u32 {
    let result = (|| {
        if statement_source_handle_output_pointer.is_null() {
            return Err(SetupKeyRelationRuntimeError::InvalidInput);
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
        prepare_generation(
            family,
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
        Ok((adapter_handle, statement_source_handle)) => {
            unsafe {
                statement_source_handle_output_pointer.write(statement_source_handle);
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

macro_rules! generation_entry_point {
    ($name:ident, $family:expr, $mode:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
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
            statement_source_handle_output_pointer: *mut u32,
            status_pointer: *mut u32,
        ) -> u32 {
            unsafe {
                prepare_generation_from_ffi_inputs(
                    $family,
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
                    statement_source_handle_output_pointer,
                    status_pointer,
                    $mode,
                )
            }
        }
    };
}

generation_entry_point!(
    sealed_lattice_same_secret_prepare_generation,
    SetupKeyRelationProofFamily::SameSecret,
    GenerationMode::Fresh
);
generation_entry_point!(
    sealed_lattice_same_secret_prepare_resumed_generation,
    SetupKeyRelationProofFamily::SameSecret,
    GenerationMode::Resume
);
generation_entry_point!(
    sealed_lattice_public_key_share_prepare_generation,
    SetupKeyRelationProofFamily::PublicKeyShare,
    GenerationMode::Fresh
);
generation_entry_point!(
    sealed_lattice_public_key_share_prepare_resumed_generation,
    SetupKeyRelationProofFamily::PublicKeyShare,
    GenerationMode::Resume
);

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_setup_key_relation_generation_statement_discard(
    statement_source_handle: u32,
) -> u32 {
    SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY
        .with(|registry| {
            registry
                .borrow_mut()
                .take(statement_source_handle)
                .map(|_| ())
        })
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_source(
        family: SetupKeyRelationProofFamily,
        bytes: &[u8],
    ) -> SetupKeyRelationGenerationStatementSource {
        SetupKeyRelationGenerationStatementSource {
            family,
            canonical_application_statement_bytes: bytes.to_vec().into_boxed_slice(),
        }
    }

    #[test]
    fn statement_source_registry_never_reuses_released_handles() {
        let mut registry = SetupKeyRelationGenerationStatementSourceRegistry::default();
        let first_handle = registry
            .retain(statement_source(
                SetupKeyRelationProofFamily::SameSecret,
                &[1, 2, 3],
            ))
            .expect("first source retains");
        let released = registry.take(first_handle).expect("first source releases");
        assert_eq!(
            released.canonical_application_statement_bytes.as_ref(),
            [1, 2, 3]
        );
        assert!(matches!(
            registry.source(first_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        let second_handle = registry
            .retain(statement_source(
                SetupKeyRelationProofFamily::PublicKeyShare,
                &[4, 5, 6, 7],
            ))
            .expect("second source retains");
        assert_ne!(second_handle, first_handle);
        assert_eq!(
            registry.source(second_handle).unwrap().family,
            SetupKeyRelationProofFamily::PublicKeyShare
        );
    }

    #[test]
    fn statement_source_registry_rejects_stale_and_out_of_capacity_access() {
        let mut registry = SetupKeyRelationGenerationStatementSourceRegistry::default();
        assert!(matches!(
            registry.take(91),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        for source_ordinal in 0..MAXIMUM_RETAINED_GENERATION_STATEMENT_SOURCE_COUNT {
            registry
                .retain(statement_source(
                    SetupKeyRelationProofFamily::SameSecret,
                    &[u8::try_from(source_ordinal).unwrap()],
                ))
                .expect("source within the exact bound retains");
        }
        assert!(matches!(
            registry.retain(statement_source(
                SetupKeyRelationProofFamily::PublicKeyShare,
                &[99],
            )),
            Err(CommonProofRuntimeError::AllocationLimitExceeded)
        ));
    }
}
