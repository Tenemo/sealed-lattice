//! Browser/WASM lifecycle for the exact collective RKG round-one aggregate.
//!
//! Rust derives the ordered ten-source catalog from opaque prepackage
//! authorities, authenticates one transport chunk at a time, constructs the
//! two sums, and owns the reset-safe public-only proof attempt. The host sees
//! only exact authenticated read requests and canonical readback bytes.

use core::slice;
use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::setup::{
        SetupGeneratedKeySwitchComponent, SetupGeneratedRelinearizationAggregateSourceAuthority,
        SetupRelinearizationAggregateConstruction, SetupRelinearizationAggregateSourceReadRequest,
        add_generated_proof_source_to_accepted_setup_package_builder,
        commit_prepackage_generated_relinearization_aggregate,
        construct_generated_relinearization_aggregate,
        preflight_prepackage_generated_relinearization_aggregate_slot,
        with_prepackage_generated_relinearization_round_one_sources,
    },
    foundation::{
        AuthenticatedCheckpointContinuationSource, CanonicalStreamReadbackVerifier,
        FOUNDATION_PROFILE, FoundationSchemaError, Hash512, PreparedPublicOnlyProofAttemptSource,
        ProofApplicationSlot, ProofApplicationSlotCeilings, RefusalReason,
        STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, StreamDescriptor,
        VerifiedStateReservationRuntimeBinding, resolve_prepared_public_only_proof_attempt_source,
        verified_state_reservation_binding,
    },
};

use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    retain_common_proof_generation_family_adapter,
};
use super::{
    CommonProofGenerationAuthorization, CommonProofGenerationPreparationError,
    CommonProofGenerationSources, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    PreparedCommonProofGeneration, ProofProfileError, RelationPlanError,
    SelectedProofAccountingError, selected_proof_runtime_limits,
    selected_relation_plan_check_context, selected_relation_plans,
    verified_application_statement_hash,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_RETAINED_AGGREGATE_SESSION_COUNT: usize = 2;

#[derive(Debug)]
enum AggregateRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Runtime(CommonProofRuntimeError),
    ActionRandomnessRuntime(u32),
    StateRuntime(u32),
    Refusal(RefusalReason),
    Foundation(FoundationSchemaError),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for AggregateRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for AggregateRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for AggregateRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for AggregateRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofRuntimeError> for AggregateRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RefusalReason> for AggregateRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl From<FoundationSchemaError> for AggregateRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

struct AggregateComponentReadback {
    component: SetupGeneratedKeySwitchComponent,
    material_root: [u8; Hash512::BYTE_LENGTH],
    stream_descriptor: StreamDescriptor,
    encoded_stream_descriptor: Box<[u8]>,
    authenticated_readback: Option<CanonicalStreamReadbackVerifier>,
}

impl AggregateComponentReadback {
    fn begin(
        component: SetupGeneratedKeySwitchComponent,
        source: &crate::bgv::setup::SetupGeneratedRelinearizationComponentSource,
    ) -> Result<Self, AggregateRuntimeError> {
        if component.topology() != source.topology()
            || component.stream_descriptor() != source.stream_descriptor()
            || u64::try_from(component.canonical_bytes().len()).ok()
                != Some(source.stream_descriptor().total_byte_length)
        {
            return Err(AggregateRuntimeError::Refusal(
                RefusalReason::WrongHashOrRoot,
            ));
        }
        let stream_descriptor = source.stream_descriptor().clone();
        Ok(Self {
            component,
            material_root: source.material_root().into_bytes(),
            encoded_stream_descriptor: stream_descriptor.encode()?.into_boxed_slice(),
            authenticated_readback: Some(source.begin_authenticated_readback()?),
            stream_descriptor,
        })
    }
}

struct AggregateSession {
    prepackage_catalog_handle: u32,
    construction: Option<SetupRelinearizationAggregateConstruction>,
    source_authority: Option<SetupGeneratedRelinearizationAggregateSourceAuthority>,
    components: Vec<AggregateComponentReadback>,
    next_component_ordinal: usize,
    next_chunk_index: usize,
}

impl AggregateSession {
    fn constructing(
        prepackage_catalog_handle: u32,
        construction: SetupRelinearizationAggregateConstruction,
    ) -> Self {
        Self {
            prepackage_catalog_handle,
            construction: Some(construction),
            source_authority: None,
            components: Vec::new(),
            next_component_ordinal: 0,
            next_chunk_index: 0,
        }
    }

    fn next_construction_read_request(
        &self,
    ) -> Result<Option<SetupRelinearizationAggregateSourceReadRequest>, AggregateRuntimeError> {
        self.construction
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .next_read_request()
            .map_err(AggregateRuntimeError::from)
    }

    fn absorb_construction_chunk(
        &mut self,
        request: &SetupRelinearizationAggregateSourceReadRequest,
        bytes: &[u8],
    ) -> Result<(), AggregateRuntimeError> {
        self.construction
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .supply_authenticated_source_chunk(request, bytes)
            .map_err(AggregateRuntimeError::from)
    }

    fn finish_construction(&mut self) -> Result<(), AggregateRuntimeError> {
        if self.source_authority.is_some() || !self.components.is_empty() {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        }
        let generation = self
            .construction
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .finish()?;
        let (components, source_authority) = generation.into_parts();
        let source_components = source_authority.components();
        let [left_component, right_component] = components;
        self.components = vec![
            AggregateComponentReadback::begin(left_component, &source_components[0])?,
            AggregateComponentReadback::begin(right_component, &source_components[1])?,
        ];
        self.source_authority = Some(source_authority);
        Ok(())
    }

    fn source_authority(
        &self,
    ) -> Result<&SetupGeneratedRelinearizationAggregateSourceAuthority, CommonProofRuntimeError>
    {
        self.source_authority
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn canonical_statement(&self) -> Result<&[u8], CommonProofRuntimeError> {
        Ok(self
            .source_authority()?
            .canonical_application_statement_bytes())
    }

    fn current_component(
        &self,
        component_ordinal: usize,
    ) -> Result<&AggregateComponentReadback, CommonProofRuntimeError> {
        if component_ordinal != self.next_component_ordinal {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.components
            .get(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn read_component_chunk(
        &mut self,
        component_ordinal: usize,
        chunk_index: usize,
        output: &mut [u8],
    ) -> Result<(), AggregateRuntimeError> {
        if component_ordinal != self.next_component_ordinal || chunk_index != self.next_chunk_index
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let component = self
            .components
            .get_mut(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let byte_start = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(AggregateRuntimeError::InvalidInput)?;
        let byte_end = byte_start
            .checked_add(chunk_byte_length)
            .map(|end| end.min(component.component.canonical_bytes().len()))
            .ok_or(AggregateRuntimeError::InvalidInput)?;
        let source_chunk = component
            .component
            .canonical_bytes()
            .get(byte_start..byte_end)
            .filter(|chunk| {
                !chunk.is_empty()
                    && chunk_index < component.stream_descriptor.ordered_chunk_digests.len()
            })
            .ok_or(AggregateRuntimeError::InvalidInput)?;
        if output.len() != source_chunk.len() {
            return Err(AggregateRuntimeError::InvalidInput);
        }
        component
            .authenticated_readback
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .authenticate_chunk(chunk_index, source_chunk)?;
        output.copy_from_slice(source_chunk);
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(AggregateRuntimeError::InvalidInput)?;
        if self.next_chunk_index == component.stream_descriptor.ordered_chunk_digests.len() {
            component
                .authenticated_readback
                .take()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
                .finish()
                .into_result()?;
            self.next_component_ordinal = self
                .next_component_ordinal
                .checked_add(1)
                .ok_or(AggregateRuntimeError::InvalidInput)?;
            self.next_chunk_index = 0;
        }
        Ok(())
    }

    fn readback_complete(&self) -> bool {
        self.next_component_ordinal == self.components.len()
            && self.next_chunk_index == 0
            && self
                .components
                .iter()
                .all(|component| component.authenticated_readback.is_none())
    }

    fn ready_to_commit(&self) -> bool {
        self.readback_complete() && self.source_authority.is_some()
    }
}

struct AggregateSessionRegistry {
    next_handle: u32,
    sessions: BTreeMap<u32, AggregateSession>,
}

impl Default for AggregateSessionRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            sessions: BTreeMap::new(),
        }
    }
}

impl AggregateSessionRegistry {
    fn retain(&mut self, session: AggregateSession) -> Result<u32, CommonProofRuntimeError> {
        if self.sessions.len() >= MAXIMUM_RETAINED_AGGREGATE_SESSION_COUNT || self.next_handle == 0
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if self.sessions.insert(handle, session).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(handle)
    }

    fn get(&self, handle: u32) -> Result<&AggregateSession, CommonProofRuntimeError> {
        self.sessions
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn get_mut(&mut self, handle: u32) -> Result<&mut AggregateSession, CommonProofRuntimeError> {
        self.sessions
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take(&mut self, handle: u32) -> Result<AggregateSession, CommonProofRuntimeError> {
        self.sessions
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        session: AggregateSession,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.sessions.contains_key(&handle) {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.sessions.insert(handle, session);
        Ok(())
    }
}

thread_local! {
    static AGGREGATE_SESSION_REGISTRY: RefCell<AggregateSessionRegistry> =
        RefCell::new(AggregateSessionRegistry::default());
}

struct AggregateProofRuntimePlan {
    compiled_relation_plan: super::CompiledRelationPlan,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
}

fn selected_aggregate_compiled_relation_plan()
-> Result<super::CompiledRelationPlan, AggregateRuntimeError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    selected_relation_plans()?
        .into_iter()
        .find(|artifact| artifact.application_statement_schema_identifier() == schema_identifier)
        .map(|artifact| artifact.compiled_plan().clone())
        .ok_or(AggregateRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))
}

fn begin_aggregate_construction(
    prepackage_catalog_handle: u32,
) -> Result<u32, AggregateRuntimeError> {
    if prepackage_catalog_handle == 0 {
        return Err(AggregateRuntimeError::InvalidInput);
    }
    let compiled_plan = selected_aggregate_compiled_relation_plan()?;
    let construction = with_prepackage_generated_relinearization_round_one_sources(
        prepackage_catalog_handle,
        |ordered_sources, ordered_proof_descriptors| {
            let schedule_position = ordered_sources
                .first()
                .map(|source| source.schedule_position())
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let evaluation_domain_size = compiled_plan
                .select_variant(Some(schedule_position), None)
                .and_then(|variant| {
                    usize::try_from(variant.evaluation_domain_size())
                        .map_err(|_| RelationPlanError::CountOverflow)
                })
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            construct_generated_relinearization_aggregate(
                ordered_sources,
                ordered_proof_descriptors,
                evaluation_domain_size,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        },
    )?;
    AGGREGATE_SESSION_REGISTRY
        .with(|registry| {
            registry.borrow_mut().retain(AggregateSession::constructing(
                prepackage_catalog_handle,
                construction,
            ))
        })
        .map_err(AggregateRuntimeError::from)
}

fn selected_aggregate_runtime_plan(
    canonical_statement: &[u8],
    schedule_position: u32,
) -> Result<AggregateProofRuntimePlan, AggregateRuntimeError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(schema_identifier).ok_or(
        AggregateRuntimeError::Relation(RelationPlanError::InvalidDomain),
    )?;
    let compiled_relation_plan = selected_aggregate_compiled_relation_plan()?;
    let variant = compiled_relation_plan.select_variant(Some(schedule_position), None)?;
    let limits = selected_proof_runtime_limits(schema_identifier, canonical_statement, variant)?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_relation_plan,
        &relation_context,
        Some(schedule_position),
        None,
    )?;
    Ok(AggregateProofRuntimePlan {
        compiled_relation_plan,
        relation_plan,
        limits,
    })
}

fn resolve_relinearization_aggregate_attempt(
    action_randomness_handle: u32,
    reservation_binding: VerifiedStateReservationRuntimeBinding,
    session_handle: u32,
    continuation: AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedPublicOnlyProofAttemptSource, AggregateRuntimeError> {
    let (
        protocol_version,
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        roster_hash,
        schedule_position,
        statement,
    ) = AGGREGATE_SESSION_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let session = registry.get(session_handle)?;
        let source = session.source_authority()?;
        Ok::<_, CommonProofRuntimeError>((
            source.protocol_version(),
            source.suite_identifier(),
            source.ceremony_context_hash(),
            source.action_context_hash(),
            source.roster_hash(),
            source.schedule_position(),
            session.canonical_statement()?.to_vec(),
        ))
    })?;
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(suite_identifier),
        Hash512::from_bytes(ceremony_context_hash),
        Hash512::from_bytes(action_context_hash),
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        Some(schedule_position),
        None,
    )?;
    let statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        protocol_version,
        suite_identifier,
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        &statement,
    ));
    resolve_prepared_public_only_proof_attempt_source(
        action_randomness_handle,
        reservation_binding,
        Hash512::from_bytes(roster_hash),
        application_slot,
        statement_hash,
        continuation,
    )
    .map_err(AggregateRuntimeError::ActionRandomnessRuntime)
}

fn prepare_common_generation(
    session_handle: u32,
    prepared_attempt: PreparedPublicOnlyProofAttemptSource,
    runtime_plan: AggregateProofRuntimePlan,
) -> Result<PreparedCommonProofGeneration, AggregateRuntimeError> {
    let (protocol_version, canonical_statement, relation_trees, source_provider) =
        AGGREGATE_SESSION_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let session = registry.get(session_handle)?;
            let source_authority = session.source_authority()?;
            let canonical_statement = session.canonical_statement()?.to_vec();
            with_prepackage_generated_relinearization_round_one_sources(
                session.prepackage_catalog_handle,
                |ordered_sources, ordered_proof_descriptors| {
                    let (relation_trees, source_provider, _) =
                        super::relation_plan::prepare_relinearization_round_one_aggregate_source(
                            &runtime_plan.compiled_relation_plan,
                            ordered_sources,
                            ordered_proof_descriptors,
                            source_authority,
                        )
                        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                    Ok((
                        source_authority.protocol_version(),
                        canonical_statement,
                        relation_trees,
                        source_provider,
                    ))
                },
            )
        })?;
    let authorization = CommonProofGenerationAuthorization::from_public_only_authenticated_attempt(
        prepared_attempt,
        &runtime_plan.relation_plan,
        protocol_version,
        &canonical_statement,
    )?;
    let sources = CommonProofGenerationSources::public_only(
        prepared_attempt.application_statement_schema_identifier(),
        Hash512::from_bytes(authorization.binding_hash()),
        prepared_attempt.attempt_lineage_identifier(),
        source_provider,
    )
    .map_err(|_| AggregateRuntimeError::InvalidInput)?;
    PreparedCommonProofGeneration::from_exact_family_sources(
        authorization,
        runtime_plan.relation_plan,
        canonical_statement,
        relation_trees,
        runtime_plan.limits,
        sources,
    )
    .map_err(|error| match error {
        CommonProofGenerationPreparationError::Runtime(error) => error.into(),
        CommonProofGenerationPreparationError::Generation(_) => AggregateRuntimeError::InvalidInput,
    })
}

#[derive(Clone, Copy)]
enum GenerationMode {
    Fresh,
    Resume,
}

fn resumed_generation_error(error: AggregateRuntimeError) -> CommonProofGenerationPreparationError {
    match error {
        AggregateRuntimeError::Runtime(error) => error.into(),
        _ => CommonProofRuntimeError::WrongVerificationBinding.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: GenerationMode,
) -> Result<u32, AggregateRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]
        || state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
    {
        return Err(AggregateRuntimeError::InvalidInput);
    }
    let (canonical_statement, schedule_position) = AGGREGATE_SESSION_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let session = registry.get(session_handle)?;
        if !session.readback_complete() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        Ok((
            session.canonical_statement()?.to_vec(),
            session.source_authority()?.schedule_position(),
        ))
    })?;
    let reservation_binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(AggregateRuntimeError::StateRuntime)?;
    let runtime_plan = selected_aggregate_runtime_plan(&canonical_statement, schedule_position)?;
    let checkpoint_schedule_digest = runtime_plan.relation_plan.checkpoint_schedule_digest()?;
    let fresh_continuation =
        AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_attempt = resolve_relinearization_aggregate_attempt(
        action_randomness_handle,
        reservation_binding,
        session_handle,
        fresh_continuation,
    )?;
    let adapter = match generation_mode {
        GenerationMode::Fresh => CommonProofGenerationFamilyAdapter::fresh(
            prepare_common_generation(session_handle, fresh_attempt, runtime_plan)?,
        ),
        GenerationMode::Resume => {
            let fresh_preparation =
                prepare_common_generation(session_handle, fresh_attempt, runtime_plan)?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                fresh_preparation.application_statement_schema_identifier(),
                fresh_preparation.runtime_binding_hash(),
                fresh_preparation.generation_authorization_hash(),
                fresh_preparation.proof_attempt_lineage_identifier(),
            );
            drop(fresh_preparation);
            CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |continuation| {
                    let (canonical_statement, schedule_position) = AGGREGATE_SESSION_REGISTRY
                        .with(|registry| {
                            let registry = registry.borrow();
                            let session = registry.get(session_handle)?;
                            Ok::<_, CommonProofRuntimeError>((
                                session.canonical_statement()?.to_vec(),
                                session.source_authority()?.schedule_position(),
                            ))
                        })
                        .map_err(CommonProofGenerationPreparationError::Runtime)?;
                    let runtime_plan =
                        selected_aggregate_runtime_plan(&canonical_statement, schedule_position)
                            .map_err(resumed_generation_error)?;
                    let attempt = resolve_relinearization_aggregate_attempt(
                        action_randomness_handle,
                        reservation_binding,
                        session_handle,
                        continuation,
                    )
                    .map_err(resumed_generation_error)?;
                    prepare_common_generation(session_handle, attempt, runtime_plan)
                        .map_err(resumed_generation_error)
                }),
            )
        }
    };
    retain_common_proof_generation_family_adapter(adapter).map_err(AggregateRuntimeError::from)
}

fn commit_generated_aggregate(
    accepted_setup_package_builder_handle: u32,
    prepackage_catalog_handle: u32,
    generated_proof_handle: u32,
    session_handle: u32,
) -> Result<(), AggregateRuntimeError> {
    if accepted_setup_package_builder_handle == 0
        || prepackage_catalog_handle == 0
        || generated_proof_handle == 0
    {
        return Err(AggregateRuntimeError::InvalidInput);
    }
    AGGREGATE_SESSION_REGISTRY.with(|registry| {
        consume_aggregate_session_atomically(
            &mut registry.borrow_mut(),
            session_handle,
            |session| {
                if session.prepackage_catalog_handle != prepackage_catalog_handle {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
                }
                if !session.ready_to_commit() {
                    return Err(CommonProofRuntimeError::WrongOperationPhase.into());
                }
                let prepared_slot = preflight_prepackage_generated_relinearization_aggregate_slot(
                    prepackage_catalog_handle,
                    generated_proof_handle,
                    session.source_authority()?,
                )?;
                add_generated_proof_source_to_accepted_setup_package_builder(
                    accepted_setup_package_builder_handle,
                    generated_proof_handle,
                    session
                        .source_authority()?
                        .canonical_application_statement_bytes(),
                )?;
                let source_authority = session
                    .source_authority
                    .take()
                    .expect("aggregate preflight retained the generated source authority");
                commit_prepackage_generated_relinearization_aggregate(
                    prepared_slot,
                    source_authority,
                );
                Ok(())
            },
        )
    })
}

fn consume_aggregate_session_atomically(
    registry: &mut AggregateSessionRegistry,
    session_handle: u32,
    operation: impl FnOnce(&mut AggregateSession) -> Result<(), AggregateRuntimeError>,
) -> Result<(), AggregateRuntimeError> {
    let mut session = registry.take(session_handle)?;
    if let Err(error) = operation(&mut session) {
        registry.restore(session_handle, session)?;
        return Err(error);
    }
    Ok(())
}

fn runtime_error_status(error: AggregateRuntimeError) -> u32 {
    match error {
        AggregateRuntimeError::Runtime(error) => super::runtime_ffi::runtime_error_status(error),
        AggregateRuntimeError::ActionRandomnessRuntime(status)
        | AggregateRuntimeError::StateRuntime(status) => status,
        AggregateRuntimeError::Refusal(refusal_reason) => refusal_reason.canonical_code() as u32,
        AggregateRuntimeError::Foundation(error) => error.refusal_reason.canonical_code() as u32,
        AggregateRuntimeError::InvalidInput => {
            RefusalReason::WrongTypeOrLength.canonical_code() as u32
        }
        AggregateRuntimeError::Accounting(error) => {
            let _ = error;
            RefusalReason::OutsideSupportedProfile.canonical_code() as u32
        }
        AggregateRuntimeError::Profile(error) => {
            let _ = error;
            RefusalReason::OutsideSupportedProfile.canonical_code() as u32
        }
        AggregateRuntimeError::Relation(error) => {
            let _ = error;
            RefusalReason::OutsideSupportedProfile.canonical_code() as u32
        }
        AggregateRuntimeError::RelationCapability(error) => {
            let _ = error;
            RefusalReason::OutsideSupportedProfile.canonical_code() as u32
        }
    }
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<[u8; BYTE_LENGTH], AggregateRuntimeError> {
    if pointer.is_null() || declared_byte_length != BYTE_LENGTH {
        return Err(AggregateRuntimeError::InvalidInput);
    }
    unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) }
        .try_into()
        .map_err(|_| AggregateRuntimeError::InvalidInput)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_construction_begin(
    prepackage_catalog_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match begin_aggregate_construction(prepackage_catalog_handle) {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_construction_next_read(
    session_handle: u32,
    roster_position_pointer: *mut u32,
    component_ordinal_pointer: *mut u32,
    source_material_root_pointer: *mut u8,
    source_material_root_byte_length: usize,
    source_stream_digest_pointer: *mut u8,
    source_stream_digest_byte_length: usize,
    source_stream_total_byte_length_pointer: *mut u64,
    source_stream_byte_offset_pointer: *mut u64,
    source_corpus_byte_offset_pointer: *mut u64,
    chunk_index_pointer: *mut u32,
    source_byte_length_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if roster_position_pointer.is_null()
            || component_ordinal_pointer.is_null()
            || source_material_root_pointer.is_null()
            || source_material_root_byte_length != Hash512::BYTE_LENGTH
            || source_stream_digest_pointer.is_null()
            || source_stream_digest_byte_length != Hash512::BYTE_LENGTH
            || source_stream_total_byte_length_pointer.is_null()
            || source_stream_byte_offset_pointer.is_null()
            || source_corpus_byte_offset_pointer.is_null()
            || chunk_index_pointer.is_null()
            || source_byte_length_pointer.is_null()
        {
            return Err(AggregateRuntimeError::InvalidInput);
        }
        let request = AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry
                .borrow()
                .get(session_handle)?
                .next_construction_read_request()
        })?;
        let Some(request) = request else {
            return Ok(0);
        };
        unsafe {
            roster_position_pointer.write(u32::from(request.roster_position()));
            component_ordinal_pointer.write(u32::from(request.component_ordinal()));
            slice::from_raw_parts_mut(source_material_root_pointer, Hash512::BYTE_LENGTH)
                .copy_from_slice(&request.source_material_root());
            slice::from_raw_parts_mut(source_stream_digest_pointer, Hash512::BYTE_LENGTH)
                .copy_from_slice(&request.source_stream_full_object_digest());
            source_stream_total_byte_length_pointer
                .write(request.source_stream_total_byte_length());
            source_stream_byte_offset_pointer.write(request.source_stream_byte_offset());
            source_corpus_byte_offset_pointer.write(request.source_corpus_byte_offset());
            chunk_index_pointer.write(
                u32::try_from(request.chunk_index())
                    .map_err(|_| AggregateRuntimeError::InvalidInput)?,
            );
            source_byte_length_pointer.write(
                u32::try_from(request.byte_length())
                    .map_err(|_| AggregateRuntimeError::InvalidInput)?,
            );
        }
        Ok(1)
    })();
    match result {
        Ok(poll) => {
            unsafe { write_status(status_pointer, 0) };
            poll
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_construction_absorb(
    session_handle: u32,
    roster_position: u32,
    component_ordinal: u32,
    source_material_root_pointer: *const u8,
    source_material_root_byte_length: usize,
    source_stream_digest_pointer: *const u8,
    source_stream_digest_byte_length: usize,
    source_stream_total_byte_length: u64,
    source_stream_byte_offset: u64,
    source_corpus_byte_offset: u64,
    chunk_index: u32,
    source_bytes_pointer: *const u8,
    source_byte_length: usize,
) -> u32 {
    let result = (|| {
        if source_bytes_pointer.is_null() || source_byte_length == 0 {
            return Err(AggregateRuntimeError::InvalidInput);
        }
        let source_material_root = unsafe {
            fixed_input::<{ Hash512::BYTE_LENGTH }>(
                source_material_root_pointer,
                source_material_root_byte_length,
            )
        }?;
        let source_stream_digest = unsafe {
            fixed_input::<{ Hash512::BYTE_LENGTH }>(
                source_stream_digest_pointer,
                source_stream_digest_byte_length,
            )
        }?;
        let source_bytes =
            unsafe { slice::from_raw_parts(source_bytes_pointer, source_byte_length) };
        AGGREGATE_SESSION_REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let session = registry.get_mut(session_handle)?;
            let expected = session
                .next_construction_read_request()?
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            if u32::from(expected.roster_position()) != roster_position
                || u32::from(expected.component_ordinal()) != component_ordinal
                || expected.source_material_root() != source_material_root
                || expected.source_stream_full_object_digest() != source_stream_digest
                || expected.source_stream_total_byte_length() != source_stream_total_byte_length
                || expected.source_stream_byte_offset() != source_stream_byte_offset
                || expected.source_corpus_byte_offset() != source_corpus_byte_offset
                || u32::try_from(expected.chunk_index()).ok() != Some(chunk_index)
                || expected.byte_length() != source_byte_length
            {
                return Err(AggregateRuntimeError::Refusal(RefusalReason::WrongContext));
            }
            session.absorb_construction_chunk(&expected, source_bytes)
        })
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_aggregate_construction_finish(
    session_handle: u32,
) -> u32 {
    AGGREGATE_SESSION_REGISTRY
        .with(|registry| {
            registry
                .borrow_mut()
                .get_mut(session_handle)?
                .finish_construction()
        })
        .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_aggregate_component_count(
    session_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = AGGREGATE_SESSION_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let session = registry.get(session_handle)?;
        if session.source_authority.is_none() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        u32::try_from(session.components.len())
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    });
    match result {
        Ok(count) => {
            unsafe { write_status(status_pointer, 0) };
            count
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_component_descriptor_byte_length(
    session_handle: u32,
    component_ordinal: u32,
    status_pointer: *mut u32,
) -> usize {
    let result = (|| {
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        AGGREGATE_SESSION_REGISTRY.with(|registry| {
            Ok::<_, CommonProofRuntimeError>(
                registry
                    .borrow()
                    .get(session_handle)?
                    .current_component(component_ordinal)?
                    .encoded_stream_descriptor
                    .len(),
            )
        })
    })();
    match result {
        Ok(byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            byte_length
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_component_copy_descriptor(
    session_handle: u32,
    component_ordinal: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        AGGREGATE_SESSION_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let descriptor = &registry
                .get(session_handle)?
                .current_component(component_ordinal)?
                .encoded_stream_descriptor;
            if descriptor.len() != output_byte_length {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) }
                .copy_from_slice(descriptor);
            Ok(())
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_component_copy_material_root(
    session_handle: u32,
    component_ordinal: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() || output_byte_length != Hash512::BYTE_LENGTH {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let material_root = AGGREGATE_SESSION_REGISTRY.with(|registry| {
            Ok::<_, CommonProofRuntimeError>(
                registry
                    .borrow()
                    .get(session_handle)?
                    .current_component(component_ordinal)?
                    .material_root,
            )
        })?;
        unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) }
            .copy_from_slice(&material_root);
        Ok(())
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_component_total_byte_length(
    session_handle: u32,
    component_ordinal: u32,
    status_pointer: *mut u32,
) -> u64 {
    let result = (|| {
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        AGGREGATE_SESSION_REGISTRY.with(|registry| {
            Ok::<_, CommonProofRuntimeError>(
                registry
                    .borrow()
                    .get(session_handle)?
                    .current_component(component_ordinal)?
                    .stream_descriptor
                    .total_byte_length,
            )
        })
    })();
    match result {
        Ok(byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            byte_length
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_component_read_chunk(
    session_handle: u32,
    component_ordinal: u32,
    chunk_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() || output_byte_length == 0 {
            return Err(AggregateRuntimeError::InvalidInput);
        }
        let component_ordinal =
            usize::try_from(component_ordinal).map_err(|_| AggregateRuntimeError::InvalidInput)?;
        let chunk_index =
            usize::try_from(chunk_index).map_err(|_| AggregateRuntimeError::InvalidInput)?;
        let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
        AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .get_mut(session_handle)?
                .read_component_chunk(component_ordinal, chunk_index, output)
        })
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_ffi(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    status_pointer: *mut u32,
    mode: GenerationMode,
) -> u32 {
    let result = (|| {
        let state_capability = unsafe {
            fixed_input::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let checkpoint_lineage_identifier = unsafe {
            fixed_input::<ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }?;
        prepare_generation(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            &state_capability,
            verified_reservation_handle,
            checkpoint_lineage_identifier,
            mode,
        )
    })();
    match result {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_prepare_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_ffi(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            status_pointer,
            GenerationMode::Fresh,
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_one_aggregate_prepare_resumed_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_ffi(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            status_pointer,
            GenerationMode::Resume,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_aggregate_commit_generated_source(
    accepted_setup_package_builder_handle: u32,
    prepackage_catalog_handle: u32,
    generated_proof_handle: u32,
    session_handle: u32,
) -> u32 {
    commit_generated_aggregate(
        accepted_setup_package_builder_handle,
        prepackage_catalog_handle,
        generated_proof_handle,
        session_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_aggregate_discard(
    session_handle: u32,
) -> u32 {
    AGGREGATE_SESSION_REGISTRY
        .with(|registry| registry.borrow_mut().take(session_handle).map(|_| ()))
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregate_session_for_atomic_commit_test() -> AggregateSession {
        AggregateSession {
            prepackage_catalog_handle: 61,
            construction: None,
            source_authority: None,
            components: Vec::new(),
            next_component_ordinal: 2,
            next_chunk_index: 0,
        }
    }

    #[test]
    fn atomic_aggregate_commit_restores_the_exact_session_after_refusal_and_consumes_once() {
        let mut registry = AggregateSessionRegistry::default();
        let session_handle = registry
            .retain(aggregate_session_for_atomic_commit_test())
            .expect("aggregate session should be retained");

        let refusal =
            consume_aggregate_session_atomically(&mut registry, session_handle, |session| {
                assert_eq!(session.prepackage_catalog_handle, 61);
                assert_eq!(session.next_component_ordinal, 2);
                assert_eq!(session.next_chunk_index, 0);
                Err(AggregateRuntimeError::Runtime(
                    CommonProofRuntimeError::WrongVerificationBinding,
                ))
            });
        assert!(matches!(
            refusal,
            Err(AggregateRuntimeError::Runtime(
                CommonProofRuntimeError::WrongVerificationBinding
            ))
        ));

        consume_aggregate_session_atomically(&mut registry, session_handle, |session| {
            assert_eq!(session.prepackage_catalog_handle, 61);
            assert_eq!(session.next_component_ordinal, 2);
            assert_eq!(session.next_chunk_index, 0);
            Ok(())
        })
        .expect("the restored aggregate session should remain retryable");
        assert!(matches!(
            registry.get(session_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }
}
