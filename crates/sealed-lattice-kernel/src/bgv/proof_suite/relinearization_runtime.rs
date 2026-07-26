//! Browser/WASM lifecycle for the suite-fixed RKG participant relations.
//!
//! Both rounds derive their canonical statement and witness from the retained
//! setup-generation authority. Round two additionally reenters the exact
//! generated round-one aggregate and bound proof descriptor retained by the
//! prepackage source catalog. JavaScript receives only reset-safe common-prover handles and
//! authenticated component readbacks; canonical statements remain authority-owned in Rust.

use core::slice;
use std::{cell::RefCell, collections::BTreeMap};

use zeroize::Zeroizing;

use crate::{
    bgv::setup::{
        SetupGeneratedRelinearizationComponentSource, SetupGenerationAuthorityHandle,
        SetupGenerationRelinearizationRoundOneApplication,
        SetupGenerationRelinearizationRoundOnePreparationSource,
        SetupGenerationRelinearizationRoundTwoActivation,
        SetupGenerationRelinearizationRoundTwoApplication,
        SetupGenerationRelinearizationRoundTwoPreparationSource,
        SetupRelinearizationGenerationPreparationError,
        absorb_setup_generation_relinearization_round_two_activation_pair,
        add_generated_proof_source_to_accepted_setup_package_builder,
        begin_setup_generation_relinearization_round_two_activation,
        commit_prepackage_generated_relinearization_round_one_source,
        commit_prepackage_generated_relinearization_round_two_source,
        finish_setup_generation_relinearization_round_two_activation,
        preflight_prepackage_generated_relinearization_round_one_source_slot,
        preflight_prepackage_generated_relinearization_round_two_source_slot,
        resolve_setup_generated_relinearization_round_one_source_authority,
        resolve_setup_generated_relinearization_round_two_source_authority,
        resolve_setup_generation_relinearization_round_one_preparation_source,
        resolve_setup_generation_relinearization_round_two_preparation_source,
        with_prepackage_generated_relinearization_aggregate,
        with_setup_generation_relinearization_round_one,
        with_setup_generation_relinearization_round_one_component_chunk,
        with_setup_generation_relinearization_round_two,
        with_setup_generation_relinearization_round_two_component_chunk,
    },
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, CanonicalStreamReadbackVerifier,
        FOUNDATION_PROFILE, FoundationObjectType, FoundationSchemaError, Hash512,
        ParticipantIdentity, PreparedActionProofAttemptSource, ProofApplicationSlot,
        ProofApplicationSlotCeilings, RefusalReason, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
        StreamDescriptor, VerifiedBoardApplicationSource, VerifiedStateReservationRuntimeBinding,
        resolve_prepared_action_proof_attempt_source, resolve_verified_board_application_sources,
        verified_state_reservation_binding,
    },
};

use super::application_statement::decode_selected_relinearization_round_two_statement;
use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    retain_common_proof_generation_family_adapter, with_common_proof_selected_suite,
};
use super::{
    CommonProofGenerationPreparationError, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    ProofProfileError, RelationPlanError, RelinearizationRoundTwoAuthenticatedAggregateSourcePlan,
    SelectedApplicationStatementContext, SelectedProofAccountingError,
    decode_selected_relinearization_round_one_statement, selected_proof_runtime_limits,
    selected_relation_plan_check_context, selected_relation_plans,
    verified_application_statement_hash,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_RETAINED_RELINEARIZATION_STATEMENT_SOURCE_COUNT: usize = 32;
const MAXIMUM_RETAINED_RELINEARIZATION_ACTIVATION_COUNT: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelinearizationProofRound {
    RoundOne,
    RoundTwo,
}

impl RelinearizationProofRound {
    const fn statement_schema_identifier(self) -> u16 {
        match self {
            Self::RoundOne => {
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            }
            Self::RoundTwo => {
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
            }
        }
    }
}

#[derive(Clone)]
enum RelinearizationPreparationSource {
    RoundOne(SetupGenerationRelinearizationRoundOnePreparationSource),
    RoundTwo(SetupGenerationRelinearizationRoundTwoPreparationSource),
}

impl RelinearizationPreparationSource {
    const fn proof_round(&self) -> RelinearizationProofRound {
        match self {
            Self::RoundOne(_) => RelinearizationProofRound::RoundOne,
            Self::RoundTwo(_) => RelinearizationProofRound::RoundTwo,
        }
    }

    const fn protocol_version(&self) -> u16 {
        match self {
            Self::RoundOne(source) => source.protocol_version(),
            Self::RoundTwo(source) => source.protocol_version(),
        }
    }

    const fn suite_identifier(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.suite_identifier(),
            Self::RoundTwo(source) => source.suite_identifier(),
        }
    }

    const fn manifest_hash(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.manifest_hash(),
            Self::RoundTwo(source) => source.manifest_hash(),
        }
    }

    const fn ceremony_context_hash(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.ceremony_context_hash(),
            Self::RoundTwo(source) => source.ceremony_context_hash(),
        }
    }

    const fn action_context_hash(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.action_context_hash(),
            Self::RoundTwo(source) => source.action_context_hash(),
        }
    }

    const fn roster_hash(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.roster_hash(),
            Self::RoundTwo(source) => source.roster_hash(),
        }
    }

    const fn source_setup_intent_object_hash(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.source_setup_intent_object_hash(),
            Self::RoundTwo(source) => source.source_setup_intent_object_hash(),
        }
    }

    const fn participant_identity(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.participant_identity(),
            Self::RoundTwo(source) => source.participant_identity(),
        }
    }

    const fn roster_position(&self) -> u16 {
        match self {
            Self::RoundOne(source) => source.roster_position(),
            Self::RoundTwo(source) => source.roster_position(),
        }
    }

    const fn action_randomness_authorization_hash(&self) -> [u8; 64] {
        match self {
            Self::RoundOne(source) => source.action_randomness_authorization_hash(),
            Self::RoundTwo(source) => source.action_randomness_authorization_hash(),
        }
    }

    const fn schedule_position(&self) -> u32 {
        match self {
            Self::RoundOne(source) => source.schedule_position(),
            Self::RoundTwo(source) => source.schedule_position(),
        }
    }

    fn canonical_application_statement_bytes(&self) -> &[u8] {
        match self {
            Self::RoundOne(source) => source.canonical_application_statement_bytes(),
            Self::RoundTwo(source) => source.canonical_application_statement_bytes(),
        }
    }
}

#[derive(Debug)]
enum RelinearizationRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Runtime(CommonProofRuntimeError),
    GenerationPreparation(SetupRelinearizationGenerationPreparationError),
    Foundation(FoundationSchemaError),
    ActionRandomnessRuntime(u32),
    BoardRuntime(u32),
    StateRuntime(u32),
    Refusal(RefusalReason),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for RelinearizationRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for RelinearizationRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for RelinearizationRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for RelinearizationRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofRuntimeError> for RelinearizationRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<SetupRelinearizationGenerationPreparationError> for RelinearizationRuntimeError {
    fn from(error: SetupRelinearizationGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<FoundationSchemaError> for RelinearizationRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<RefusalReason> for RelinearizationRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

struct SelectedRelinearizationProofRuntimePlan {
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
    proof_query_count: u32,
}

struct GeneratedRelinearizationComponentReadback {
    material_root: [u8; 64],
    stream_descriptor: StreamDescriptor,
    encoded_stream_descriptor: Box<[u8]>,
    authenticated_readback: Option<CanonicalStreamReadbackVerifier>,
}

impl GeneratedRelinearizationComponentReadback {
    fn from_generated_source(
        source: &SetupGeneratedRelinearizationComponentSource,
    ) -> Result<Self, RelinearizationRuntimeError> {
        let stream_descriptor = source.stream_descriptor().clone();
        Ok(Self {
            material_root: source.material_root().into_bytes(),
            encoded_stream_descriptor: stream_descriptor.encode()?.into_boxed_slice(),
            authenticated_readback: Some(source.begin_authenticated_readback()?),
            stream_descriptor,
        })
    }
}

struct RelinearizationGenerationSource {
    proof_round: RelinearizationProofRound,
    setup_generation_authority_identifier: u32,
    ordered_components: Box<[GeneratedRelinearizationComponentReadback]>,
    next_component_ordinal: usize,
    next_chunk_index: usize,
}

impl RelinearizationGenerationSource {
    fn component_count(&self) -> usize {
        self.ordered_components.len()
    }

    fn current_component(
        &self,
        component_ordinal: usize,
    ) -> Result<&GeneratedRelinearizationComponentReadback, CommonProofRuntimeError> {
        if component_ordinal != self.next_component_ordinal {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.ordered_components
            .get(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn current_component_mut(
        &mut self,
        component_ordinal: usize,
    ) -> Result<&mut GeneratedRelinearizationComponentReadback, CommonProofRuntimeError> {
        if component_ordinal != self.next_component_ordinal {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.ordered_components
            .get_mut(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn expected_chunk_byte_length(
        &self,
        component_ordinal: usize,
        chunk_index: usize,
    ) -> Result<usize, RelinearizationRuntimeError> {
        if chunk_index != self.next_chunk_index {
            return Err(RelinearizationRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let component = self.current_component(component_ordinal)?;
        if chunk_index >= component.stream_descriptor.ordered_chunk_digests.len() {
            return Err(RelinearizationRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let byte_start = chunk_index
            .checked_mul(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .ok_or(RelinearizationRuntimeError::InvalidInput)?;
        let total_byte_length = usize::try_from(component.stream_descriptor.total_byte_length)
            .map_err(|_| RelinearizationRuntimeError::InvalidInput)?;
        Ok(total_byte_length
            .checked_sub(byte_start)
            .ok_or(RelinearizationRuntimeError::InvalidInput)?
            .min(FOUNDATION_PROFILE.stream_chunk_byte_length))
    }

    fn authenticate_and_copy_chunk(
        &mut self,
        component_ordinal: usize,
        chunk_index: usize,
        source_chunk: &[u8],
        output: &mut [u8],
    ) -> Result<(), RelinearizationRuntimeError> {
        let expected_byte_length =
            self.expected_chunk_byte_length(component_ordinal, chunk_index)?;
        if source_chunk.len() != expected_byte_length || output.len() != expected_byte_length {
            return Err(RelinearizationRuntimeError::InvalidInput);
        }
        let is_final_component_chunk = {
            let component = self.current_component_mut(component_ordinal)?;
            let readback = component.authenticated_readback.as_mut().ok_or(
                RelinearizationRuntimeError::Runtime(CommonProofRuntimeError::WrongOperationPhase),
            )?;
            readback.authenticate_chunk(chunk_index, source_chunk)?;
            output.copy_from_slice(source_chunk);
            chunk_index + 1 == component.stream_descriptor.ordered_chunk_digests.len()
        };
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(RelinearizationRuntimeError::InvalidInput)?;
        if is_final_component_chunk {
            let readback = self
                .current_component_mut(component_ordinal)?
                .authenticated_readback
                .take()
                .ok_or(RelinearizationRuntimeError::Runtime(
                    CommonProofRuntimeError::WrongOperationPhase,
                ))?;
            readback.finish().into_result()?;
            self.next_component_ordinal = self
                .next_component_ordinal
                .checked_add(1)
                .ok_or(RelinearizationRuntimeError::InvalidInput)?;
            self.next_chunk_index = 0;
        }
        Ok(())
    }

    fn is_component_readback_complete(&self) -> bool {
        self.next_component_ordinal == self.ordered_components.len()
            && self.next_chunk_index == 0
            && self
                .ordered_components
                .iter()
                .all(|component| component.authenticated_readback.is_none())
    }

    fn can_release(&self) -> bool {
        self.is_component_readback_complete()
    }
}

struct RelinearizationGenerationSourceRegistry {
    next_handle: u32,
    sources: BTreeMap<u32, RelinearizationGenerationSource>,
}

impl Default for RelinearizationGenerationSourceRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            sources: BTreeMap::new(),
        }
    }
}

impl RelinearizationGenerationSourceRegistry {
    fn retain(
        &mut self,
        source: RelinearizationGenerationSource,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.sources.len() >= MAXIMUM_RETAINED_RELINEARIZATION_STATEMENT_SOURCE_COUNT
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
    ) -> Result<&RelinearizationGenerationSource, CommonProofRuntimeError> {
        self.sources
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn source_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut RelinearizationGenerationSource, CommonProofRuntimeError> {
        self.sources
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<RelinearizationGenerationSource, CommonProofRuntimeError> {
        self.sources
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        source: RelinearizationGenerationSource,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.sources.contains_key(&handle) {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.sources.insert(handle, source);
        Ok(())
    }
}

thread_local! {
    static RELINEARIZATION_GENERATION_SOURCE_REGISTRY:
        RefCell<RelinearizationGenerationSourceRegistry> =
        RefCell::new(RelinearizationGenerationSourceRegistry::default());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelinearizationRoundTwoActivationReadRequest {
    component_ordinal: usize,
    material_root: [u8; Hash512::BYTE_LENGTH],
    stream_digest: [u8; Hash512::BYTE_LENGTH],
    total_byte_length: u64,
    stream_byte_offset: u64,
    chunk_index: usize,
    source_byte_length: usize,
}

struct RelinearizationRoundTwoActivationSource {
    material_root: [u8; Hash512::BYTE_LENGTH],
    stream_digest: [u8; Hash512::BYTE_LENGTH],
    total_byte_length: u64,
    chunk_count: usize,
    readback: Option<CanonicalStreamReadbackVerifier>,
}

impl RelinearizationRoundTwoActivationSource {
    fn from_generated_source(
        source: &SetupGeneratedRelinearizationComponentSource,
    ) -> Result<Self, RelinearizationRuntimeError> {
        let stream_descriptor = source.stream_descriptor();
        if stream_descriptor.total_byte_length == 0
            || stream_descriptor.ordered_chunk_digests.is_empty()
        {
            return Err(RelinearizationRuntimeError::InvalidInput);
        }
        Ok(Self {
            material_root: source.material_root().into_bytes(),
            stream_digest: stream_descriptor.full_object_digest.into_bytes(),
            total_byte_length: stream_descriptor.total_byte_length,
            chunk_count: stream_descriptor.ordered_chunk_digests.len(),
            readback: Some(source.begin_authenticated_readback()?),
        })
    }
}

struct RelinearizationRoundTwoActivationSession {
    setup_generation_authority_identifier: u32,
    prepackage_catalog_identifier: u32,
    authority_activation: SetupGenerationRelinearizationRoundTwoActivation,
    sources: [RelinearizationRoundTwoActivationSource; 2],
    next_component_ordinal: usize,
    next_chunk_index: usize,
    pending_left_chunk: Option<Zeroizing<Box<[u8]>>>,
    readbacks_complete: bool,
    poisoned: bool,
}

impl RelinearizationRoundTwoActivationSession {
    fn new(
        setup_generation_authority_identifier: u32,
        prepackage_catalog_identifier: u32,
        authority_activation: SetupGenerationRelinearizationRoundTwoActivation,
        generated_aggregate: &crate::bgv::setup::SetupGeneratedRelinearizationAggregateSourceAuthority,
    ) -> Result<Self, RelinearizationRuntimeError> {
        let sources = [
            RelinearizationRoundTwoActivationSource::from_generated_source(
                &generated_aggregate.components()[0],
            )?,
            RelinearizationRoundTwoActivationSource::from_generated_source(
                &generated_aggregate.components()[1],
            )?,
        ];
        if setup_generation_authority_identifier == 0
            || prepackage_catalog_identifier == 0
            || sources[0].total_byte_length != sources[1].total_byte_length
            || sources[0].chunk_count != sources[1].chunk_count
            || sources[0].total_byte_length
                != authority_activation.topology().expected_byte_length()
        {
            return Err(RelinearizationRuntimeError::InvalidInput);
        }
        Ok(Self {
            setup_generation_authority_identifier,
            prepackage_catalog_identifier,
            authority_activation,
            sources,
            next_component_ordinal: 0,
            next_chunk_index: 0,
            pending_left_chunk: None,
            readbacks_complete: false,
            poisoned: false,
        })
    }

    fn next_read_request(
        &self,
    ) -> Result<Option<RelinearizationRoundTwoActivationReadRequest>, RelinearizationRuntimeError>
    {
        if self.poisoned {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        }
        if self.readbacks_complete {
            return Ok(None);
        }
        let source = self
            .sources
            .get(self.next_component_ordinal)
            .ok_or(RelinearizationRuntimeError::InvalidInput)?;
        if self.next_chunk_index >= source.chunk_count {
            return Err(CommonProofRuntimeError::WrongOperationPhase.into());
        }
        let stream_byte_offset = self
            .next_chunk_index
            .checked_mul(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(RelinearizationRuntimeError::InvalidInput)?;
        let source_byte_length = source
            .total_byte_length
            .checked_sub(stream_byte_offset)
            .map(|remaining| remaining.min(FOUNDATION_PROFILE.stream_chunk_byte_length as u64))
            .and_then(|length| usize::try_from(length).ok())
            .filter(|length| *length > 0)
            .ok_or(RelinearizationRuntimeError::InvalidInput)?;
        Ok(Some(RelinearizationRoundTwoActivationReadRequest {
            component_ordinal: self.next_component_ordinal,
            material_root: source.material_root,
            stream_digest: source.stream_digest,
            total_byte_length: source.total_byte_length,
            stream_byte_offset,
            chunk_index: self.next_chunk_index,
            source_byte_length,
        }))
    }

    fn absorb_source(
        &mut self,
        supplied_request: RelinearizationRoundTwoActivationReadRequest,
        source_bytes: &[u8],
    ) -> Result<(), RelinearizationRuntimeError> {
        let result = self.absorb_source_inner(supplied_request, source_bytes);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn absorb_source_inner(
        &mut self,
        supplied_request: RelinearizationRoundTwoActivationReadRequest,
        source_bytes: &[u8],
    ) -> Result<(), RelinearizationRuntimeError> {
        let expected_request = self
            .next_read_request()?
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if supplied_request != expected_request
            || source_bytes.len() != expected_request.source_byte_length
        {
            return Err(RelinearizationRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        self.sources[expected_request.component_ordinal]
            .readback
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .authenticate_chunk(expected_request.chunk_index, source_bytes)?;
        if expected_request.component_ordinal == 0 {
            if self.pending_left_chunk.is_some() {
                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
            }
            self.pending_left_chunk = Some(Zeroizing::new(source_bytes.into()));
            self.next_component_ordinal = 1;
            return Ok(());
        }
        let aggregate_left_bytes = self
            .pending_left_chunk
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let authority_handle = SetupGenerationAuthorityHandle::from_identifier(
            self.setup_generation_authority_identifier,
        );
        absorb_setup_generation_relinearization_round_two_activation_pair(
            &authority_handle,
            &mut self.authority_activation,
            &aggregate_left_bytes,
            source_bytes,
        )?;
        self.next_component_ordinal = 0;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(RelinearizationRuntimeError::InvalidInput)?;
        if self.next_chunk_index == self.sources[0].chunk_count {
            for source in &mut self.sources {
                source
                    .readback
                    .take()
                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
                    .finish()
                    .into_result()?;
            }
            self.readbacks_complete = true;
        }
        Ok(())
    }

    fn can_finish(&self) -> bool {
        !self.poisoned
            && self.readbacks_complete
            && self.pending_left_chunk.is_none()
            && self.next_component_ordinal == 0
            && self.next_chunk_index == self.sources[0].chunk_count
            && self.sources.iter().all(|source| source.readback.is_none())
    }
}

struct RelinearizationRoundTwoActivationRegistry {
    next_handle: u32,
    sessions: BTreeMap<u32, RelinearizationRoundTwoActivationSession>,
}

impl Default for RelinearizationRoundTwoActivationRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            sessions: BTreeMap::new(),
        }
    }
}

impl RelinearizationRoundTwoActivationRegistry {
    fn retain(
        &mut self,
        session: RelinearizationRoundTwoActivationSession,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.sessions.len() >= MAXIMUM_RETAINED_RELINEARIZATION_ACTIVATION_COUNT
            || self.next_handle == 0
            || self.sessions.values().any(|retained| {
                retained.setup_generation_authority_identifier
                    == session.setup_generation_authority_identifier
            })
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

    fn get(
        &self,
        handle: u32,
    ) -> Result<&RelinearizationRoundTwoActivationSession, CommonProofRuntimeError> {
        self.sessions
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn get_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut RelinearizationRoundTwoActivationSession, CommonProofRuntimeError> {
        self.sessions
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<RelinearizationRoundTwoActivationSession, CommonProofRuntimeError> {
        self.sessions
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        session: RelinearizationRoundTwoActivationSession,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.sessions.insert(handle, session).is_some() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        Ok(())
    }
}

thread_local! {
    static RELINEARIZATION_ROUND_TWO_ACTIVATION_REGISTRY:
        RefCell<RelinearizationRoundTwoActivationRegistry> =
        RefCell::new(RelinearizationRoundTwoActivationRegistry::default());
}

fn selected_relinearization_proof_runtime_plan(
    preparation_source: &RelinearizationPreparationSource,
) -> Result<SelectedRelinearizationProofRuntimePlan, RelinearizationRuntimeError> {
    let statement_schema_identifier = preparation_source
        .proof_round()
        .statement_schema_identifier();
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or(RelinearizationRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let selected_plan = selected_relation_plans()?
        .into_iter()
        .find(|artifact| {
            artifact.application_statement_schema_identifier() == statement_schema_identifier
        })
        .ok_or(RelinearizationRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let relation_plan_variant = selected_plan
        .compiled_plan()
        .select_variant(Some(preparation_source.schedule_position()), None)?;
    let limits = selected_proof_runtime_limits(
        statement_schema_identifier,
        preparation_source.canonical_application_statement_bytes(),
        relation_plan_variant,
    )?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        selected_plan.compiled_plan(),
        &relation_context,
        Some(preparation_source.schedule_position()),
        None,
    )?;
    let proof_query_count = relation_plan.proof_query_count()?;
    Ok(SelectedRelinearizationProofRuntimePlan {
        relation_plan,
        limits,
        proof_query_count,
    })
}

fn require_selected_suite_matches_generation_source(
    selected_suite_handle: u32,
    preparation_source: &RelinearizationPreparationSource,
) -> Result<(), RelinearizationRuntimeError> {
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != preparation_source.protocol_version()
            || selected_suite.suite_identifier() != preparation_source.suite_identifier()
        {
            return Err(RelinearizationRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(RelinearizationRuntimeError::Runtime)??;
    Ok(())
}

fn resolve_single_setup_intent_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
) -> Result<VerifiedBoardApplicationSource, RelinearizationRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(RelinearizationRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[setup_intent_object_handle],
    )
    .map_err(RelinearizationRuntimeError::BoardRuntime)?;
    let source = sources.pop().ok_or(RelinearizationRuntimeError::Refusal(
        RefusalReason::MissingPrerequisite,
    ))?;
    if !sources.is_empty() {
        return Err(RelinearizationRuntimeError::InvalidInput);
    }
    source.setup_intent_payload()?;
    Ok(source)
}

fn require_setup_intent_matches_generation_source(
    board_source: &VerifiedBoardApplicationSource,
    preparation_source: &RelinearizationPreparationSource,
) -> Result<(), RelinearizationRuntimeError> {
    if board_source.object_type() != FoundationObjectType::SetupIntent
        || board_source.suite_identifier().into_bytes() != preparation_source.suite_identifier()
        || board_source.manifest_hash().into_bytes() != preparation_source.manifest_hash()
        || board_source.ceremony_context_hash().into_bytes()
            != preparation_source.ceremony_context_hash()
        || board_source.action_context_hash().into_bytes()
            != preparation_source.action_context_hash()
        || board_source.roster_hash().into_bytes() != preparation_source.roster_hash()
        || board_source.object_hash().into_bytes()
            != preparation_source.source_setup_intent_object_hash()
        || board_source.producer_sequence() != 0
        || board_source.producer_roster_position() != Some(preparation_source.roster_position())
        || board_source
            .producer_participant_identity()
            .map(ParticipantIdentity::into_bytes)
            != Some(preparation_source.participant_identity())
    {
        return Err(RelinearizationRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_generation_reservation_binding(
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    preparation_source: &RelinearizationPreparationSource,
) -> Result<VerifiedStateReservationRuntimeBinding, RelinearizationRuntimeError> {
    if state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(RelinearizationRuntimeError::InvalidInput);
    }
    let binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(RelinearizationRuntimeError::StateRuntime)?;
    if binding.authorization_hash.into_bytes()
        != preparation_source.action_randomness_authorization_hash()
    {
        return Err(RelinearizationRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    Ok(binding)
}

fn resolve_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    board_source: &VerifiedBoardApplicationSource,
    preparation_source: &RelinearizationPreparationSource,
    runtime_plan: &SelectedRelinearizationProofRuntimePlan,
    checkpoint_continuation: crate::foundation::AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, RelinearizationRuntimeError> {
    let statement_schema_identifier = preparation_source
        .proof_round()
        .statement_schema_identifier();
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(preparation_source.suite_identifier()),
        Hash512::from_bytes(preparation_source.ceremony_context_hash()),
        Hash512::from_bytes(preparation_source.action_context_hash()),
        statement_schema_identifier,
        Some(preparation_source.roster_position()),
        Some(preparation_source.schedule_position()),
        None,
    )?;
    let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        preparation_source.protocol_version(),
        preparation_source.suite_identifier(),
        statement_schema_identifier,
        preparation_source.canonical_application_statement_bytes(),
    ));
    let proof_byte_length = u64::try_from(runtime_plan.limits.proof_byte_length())
        .map_err(|_| RelinearizationRuntimeError::InvalidInput)?;
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
    .map_err(RelinearizationRuntimeError::ActionRandomnessRuntime)
}

fn prepare_common_generation(
    setup_generation_authority_handle: u32,
    prepackage_catalog_handle: u32,
    preparation_source: &RelinearizationPreparationSource,
    prepared_attempt: PreparedActionProofAttemptSource,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
) -> Result<
    (
        super::PreparedCommonProofGeneration,
        Box<[GeneratedRelinearizationComponentReadback]>,
    ),
    RelinearizationRuntimeError,
> {
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    match preparation_source {
        RelinearizationPreparationSource::RoundOne(preparation_source) => {
            if prepackage_catalog_handle != 0 {
                return Err(RelinearizationRuntimeError::InvalidInput);
            }
            let statement = decode_selected_relinearization_round_one_statement(
                preparation_source.canonical_application_statement_bytes(),
                SelectedApplicationStatementContext::new(
                    preparation_source.protocol_version(),
                    preparation_source.suite_identifier(),
                    Some(preparation_source.schedule_position()),
                    None,
                ),
            )
            .map_err(|_| RelinearizationRuntimeError::Refusal(RefusalReason::WrongContext))?;
            let application =
                SetupGenerationRelinearizationRoundOneApplication::from_decoded_statement(
                    prepared_attempt,
                    preparation_source.canonical_application_statement_bytes(),
                    statement.setup_proof_context_hash(),
                    statement.participant_identity(),
                    statement.roster_position(),
                    statement.schedule_position(),
                );
            with_setup_generation_relinearization_round_one(
                &authority_handle,
                &application,
                |source| {
                    let generated_source = source.generated_source_authority()?;
                    let ordered_components = generated_source
                        .components()
                        .iter()
                        .map(GeneratedRelinearizationComponentReadback::from_generated_source)
                        .collect::<Result<Vec<_>, _>>()?
                        .into_boxed_slice();
                    let prepared_generation =
                        source.prepare_common_generation(relation_plan, limits)?;
                    Ok((prepared_generation, ordered_components))
                },
            )
        }
        RelinearizationPreparationSource::RoundTwo(preparation_source) => {
            if prepackage_catalog_handle == 0 {
                return Err(RelinearizationRuntimeError::InvalidInput);
            }
            let statement = decode_selected_relinearization_round_two_statement(
                preparation_source.canonical_application_statement_bytes(),
                SelectedApplicationStatementContext::new(
                    preparation_source.protocol_version(),
                    preparation_source.suite_identifier(),
                    Some(preparation_source.schedule_position()),
                    None,
                ),
            )
            .map_err(|_| RelinearizationRuntimeError::Refusal(RefusalReason::WrongContext))?;
            let application =
                SetupGenerationRelinearizationRoundTwoApplication::from_decoded_statement(
                    prepared_attempt,
                    preparation_source.canonical_application_statement_bytes(),
                    statement.setup_proof_context_hash(),
                    statement.participant_identity(),
                    statement.roster_position(),
                    statement.schedule_position(),
                    statement.anchor_commitment_roots(),
                    [
                        statement.round_one_left_root(),
                        statement.round_one_right_root(),
                    ],
                    [
                        statement.aggregate_round_one_left_root(),
                        statement.aggregate_round_one_right_root(),
                    ],
                    statement.contribution_root(),
                );
            with_prepackage_generated_relinearization_aggregate::<_, RelinearizationRuntimeError>(
                prepackage_catalog_handle,
                |generated_aggregate, aggregate_proof_stream_descriptor| {
                    let aggregate_source_plan =
                        RelinearizationRoundTwoAuthenticatedAggregateSourcePlan::from_catalog_source(
                            generated_aggregate,
                            aggregate_proof_stream_descriptor,
                        )
                        .map_err(SetupRelinearizationGenerationPreparationError::from)?;
                    with_setup_generation_relinearization_round_two(
                        &authority_handle,
                        &application,
                        generated_aggregate,
                        aggregate_proof_stream_descriptor,
                        |source| {
                            let ordered_components = [source
                                .generated_source_authority()
                                .component()]
                            .into_iter()
                            .map(GeneratedRelinearizationComponentReadback::from_generated_source)
                            .collect::<Result<Vec<_>, _>>()?
                            .into_boxed_slice();
                            let prepared_generation = source.prepare_common_generation(
                                relation_plan,
                                limits,
                                aggregate_source_plan,
                            )?;
                            Ok((prepared_generation, ordered_components))
                        },
                    )
                },
            )
        }
    }
}

fn resumed_generation_preparation_error(
    error: RelinearizationRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        RelinearizationRuntimeError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        RelinearizationRuntimeError::GenerationPreparation(
            SetupRelinearizationGenerationPreparationError::Runtime(error),
        ) => CommonProofGenerationPreparationError::Runtime(error),
        RelinearizationRuntimeError::GenerationPreparation(
            SetupRelinearizationGenerationPreparationError::Preparation(error),
        ) => error,
        RelinearizationRuntimeError::GenerationPreparation(
            SetupRelinearizationGenerationPreparationError::Refusal(RefusalReason::ConsumedState),
        ) => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::UnknownOrStaleHandle,
        ),
        _ => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding,
        ),
    }
}

#[derive(Clone, Copy)]
enum RelinearizationGenerationMode {
    Fresh,
    Resume,
}

fn resolve_preparation_source(
    proof_round: RelinearizationProofRound,
    authority_handle: &SetupGenerationAuthorityHandle,
) -> Result<RelinearizationPreparationSource, RelinearizationRuntimeError> {
    match proof_round {
        RelinearizationProofRound::RoundOne => {
            resolve_setup_generation_relinearization_round_one_preparation_source(authority_handle)
                .map(RelinearizationPreparationSource::RoundOne)
                .map_err(RelinearizationRuntimeError::from)
        }
        RelinearizationProofRound::RoundTwo => {
            resolve_setup_generation_relinearization_round_two_preparation_source(authority_handle)
                .map(RelinearizationPreparationSource::RoundTwo)
                .map_err(RelinearizationRuntimeError::from)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_generation(
    proof_round: RelinearizationProofRound,
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    prepackage_catalog_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: RelinearizationGenerationMode,
) -> Result<(u32, u32), RelinearizationRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]
        || (proof_round == RelinearizationProofRound::RoundOne && prepackage_catalog_handle != 0)
        || (proof_round == RelinearizationProofRound::RoundTwo && prepackage_catalog_handle == 0)
    {
        return Err(RelinearizationRuntimeError::InvalidInput);
    }
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    let preparation_source = resolve_preparation_source(proof_round, &authority_handle)?;
    if preparation_source.proof_round() != proof_round {
        return Err(RelinearizationRuntimeError::Refusal(
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
    let runtime_plan = selected_relinearization_proof_runtime_plan(&preparation_source)?;
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
    let (generation_family_adapter, ordered_components) = match generation_mode {
        RelinearizationGenerationMode::Fresh => {
            let (prepared_generation, ordered_components) = prepare_common_generation(
                setup_generation_authority_handle,
                prepackage_catalog_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            (
                CommonProofGenerationFamilyAdapter::fresh(prepared_generation),
                ordered_components,
            )
        }
        RelinearizationGenerationMode::Resume => {
            let (fresh_preparation, ordered_components) = prepare_common_generation(
                setup_generation_authority_handle,
                prepackage_catalog_handle,
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
            (
                CommonProofGenerationFamilyAdapter::resume(
                    description,
                    checkpoint_lineage_identifier,
                    checkpoint_schedule_digest,
                    Box::new(move |authenticated_continuation| {
                        let resumed_runtime_plan = selected_relinearization_proof_runtime_plan(
                            &resumed_preparation_source,
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
                            prepackage_catalog_handle,
                            &resumed_preparation_source,
                            prepared_attempt,
                            resumed_runtime_plan.relation_plan,
                            resumed_runtime_plan.limits,
                        )
                        .map(|(prepared_generation, _)| prepared_generation)
                        .map_err(resumed_generation_preparation_error)
                    }),
                ),
                ordered_components,
            )
        }
    };
    let generation_source_handle = RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain(RelinearizationGenerationSource {
                proof_round,
                setup_generation_authority_identifier: setup_generation_authority_handle,
                ordered_components,
                next_component_ordinal: 0,
                next_chunk_index: 0,
            })
    })?;
    match retain_common_proof_generation_family_adapter(generation_family_adapter) {
        Ok(adapter_handle) => Ok((adapter_handle, generation_source_handle)),
        Err(error) => {
            RELINEARIZATION_GENERATION_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(generation_source_handle))?;
            Err(RelinearizationRuntimeError::Runtime(error))
        }
    }
}

fn read_generated_relinearization_component_chunk(
    generation_source_handle: u32,
    component_ordinal: usize,
    chunk_index: usize,
    output: &mut [u8],
) -> Result<(), RelinearizationRuntimeError> {
    RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let source = registry.source_mut(generation_source_handle)?;
        let expected_byte_length =
            source.expected_chunk_byte_length(component_ordinal, chunk_index)?;
        if output.len() != expected_byte_length {
            return Err(RelinearizationRuntimeError::InvalidInput);
        }
        let authority_handle = SetupGenerationAuthorityHandle::from_identifier(
            source.setup_generation_authority_identifier,
        );
        let descriptor = source
            .current_component(component_ordinal)?
            .stream_descriptor
            .clone();
        match source.proof_round {
            RelinearizationProofRound::RoundOne => {
                with_setup_generation_relinearization_round_one_component_chunk(
                    &authority_handle,
                    component_ordinal,
                    &descriptor,
                    chunk_index,
                    |source_chunk| {
                        source.authenticate_and_copy_chunk(
                            component_ordinal,
                            chunk_index,
                            source_chunk,
                            output,
                        )
                    },
                )??;
            }
            RelinearizationProofRound::RoundTwo => {
                if component_ordinal != 0 {
                    return Err(RelinearizationRuntimeError::InvalidInput);
                }
                with_setup_generation_relinearization_round_two_component_chunk(
                    &authority_handle,
                    &descriptor,
                    chunk_index,
                    |source_chunk| {
                        source.authenticate_and_copy_chunk(
                            component_ordinal,
                            chunk_index,
                            source_chunk,
                            output,
                        )
                    },
                )??;
            }
        }
        Ok(())
    })
}

fn commit_relinearization_generation_source(
    accepted_setup_package_builder_handle: u32,
    prepackage_catalog_handle: u32,
    generated_proof_handle: u32,
    generation_source_handle: u32,
) -> Result<(), RelinearizationRuntimeError> {
    if accepted_setup_package_builder_handle == 0
        || prepackage_catalog_handle == 0
        || generated_proof_handle == 0
    {
        return Err(RelinearizationRuntimeError::InvalidInput);
    }
    RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
        consume_relinearization_generation_source_atomically(
            &mut registry.borrow_mut(),
            generation_source_handle,
            |pending_source| {
                let authority_handle = SetupGenerationAuthorityHandle::from_identifier(
                    pending_source.setup_generation_authority_identifier,
                );
                match pending_source.proof_round {
                    RelinearizationProofRound::RoundOne => {
                        let source =
                            resolve_setup_generated_relinearization_round_one_source_authority(
                                &authority_handle,
                            )?;
                        let prepared_slot =
                            preflight_prepackage_generated_relinearization_round_one_source_slot(
                                prepackage_catalog_handle,
                                generated_proof_handle,
                                &source,
                            )?;
                        add_generated_proof_source_to_accepted_setup_package_builder(
                            accepted_setup_package_builder_handle,
                            generated_proof_handle,
                            source.canonical_application_statement_bytes(),
                        )?;
                        commit_prepackage_generated_relinearization_round_one_source(
                            prepared_slot,
                            source,
                        );
                    }
                    RelinearizationProofRound::RoundTwo => {
                        let source =
                            resolve_setup_generated_relinearization_round_two_source_authority(
                                &authority_handle,
                            )?;
                        let prepared_slot =
                            preflight_prepackage_generated_relinearization_round_two_source_slot(
                                prepackage_catalog_handle,
                                generated_proof_handle,
                                &source,
                            )?;
                        add_generated_proof_source_to_accepted_setup_package_builder(
                            accepted_setup_package_builder_handle,
                            generated_proof_handle,
                            source.canonical_application_statement_bytes(),
                        )?;
                        commit_prepackage_generated_relinearization_round_two_source(
                            prepared_slot,
                            source,
                        );
                    }
                }
                Ok(())
            },
        )
    })
}

fn consume_relinearization_generation_source_atomically(
    registry: &mut RelinearizationGenerationSourceRegistry,
    generation_source_handle: u32,
    operation: impl FnOnce(&RelinearizationGenerationSource) -> Result<(), RelinearizationRuntimeError>,
) -> Result<(), RelinearizationRuntimeError> {
    let pending_source = registry.take(generation_source_handle)?;
    let result = if pending_source.can_release() {
        operation(&pending_source)
    } else {
        Err(CommonProofRuntimeError::WrongOperationPhase.into())
    };
    if let Err(error) = result {
        registry.restore(generation_source_handle, pending_source)?;
        return Err(error);
    }
    Ok(())
}

fn discard_relinearization_generation_source(
    generation_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(generation_source_handle)
            .map(|_| ())
    })
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn runtime_error_status(error: RelinearizationRuntimeError) -> u32 {
    match error {
        RelinearizationRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        RelinearizationRuntimeError::GenerationPreparation(error) => match error {
            SetupRelinearizationGenerationPreparationError::Refusal(refusal_reason) => {
                refusal_status(refusal_reason)
            }
            SetupRelinearizationGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            SetupRelinearizationGenerationPreparationError::Preparation(error) => match error {
                CommonProofGenerationPreparationError::Runtime(error) => {
                    super::runtime_ffi::runtime_error_status(error)
                }
                CommonProofGenerationPreparationError::Generation(error) => {
                    let _ = error;
                    refusal_status(RefusalReason::OutsideSupportedProfile)
                }
            },
            SetupRelinearizationGenerationPreparationError::Prover(error) => {
                let _ = error;
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
        },
        RelinearizationRuntimeError::Foundation(error) => refusal_status(error.refusal_reason),
        RelinearizationRuntimeError::ActionRandomnessRuntime(status)
        | RelinearizationRuntimeError::BoardRuntime(status)
        | RelinearizationRuntimeError::StateRuntime(status) => status,
        RelinearizationRuntimeError::Refusal(refusal_reason) => refusal_status(refusal_reason),
        RelinearizationRuntimeError::InvalidInput => {
            refusal_status(RefusalReason::WrongTypeOrLength)
        }
        RelinearizationRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        RelinearizationRuntimeError::Profile(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        RelinearizationRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        RelinearizationRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<[u8; BYTE_LENGTH], RelinearizationRuntimeError> {
    if pointer.is_null() || declared_byte_length != BYTE_LENGTH {
        return Err(RelinearizationRuntimeError::InvalidInput);
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) };
    bytes
        .try_into()
        .map_err(|_| RelinearizationRuntimeError::InvalidInput)
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_two_activation_begin(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    prepackage_catalog_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if selected_suite_handle == 0
            || setup_generation_authority_handle == 0
            || prepackage_catalog_handle == 0
        {
            return Err(RelinearizationRuntimeError::InvalidInput);
        }
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
        let session = with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
            with_prepackage_generated_relinearization_aggregate::<_, RelinearizationRuntimeError>(
                prepackage_catalog_handle,
                |generated_aggregate, aggregate_proof_stream_descriptor| {
                    let authority_activation =
                        begin_setup_generation_relinearization_round_two_activation(
                            &authority_handle,
                            selected_suite,
                            generated_aggregate,
                            aggregate_proof_stream_descriptor,
                        )?;
                    RelinearizationRoundTwoActivationSession::new(
                        setup_generation_authority_handle,
                        prepackage_catalog_handle,
                        authority_activation,
                        generated_aggregate,
                    )
                },
            )
        })
        .map_err(RelinearizationRuntimeError::Runtime)??;
        RELINEARIZATION_ROUND_TWO_ACTIVATION_REGISTRY
            .with(|registry| registry.borrow_mut().retain(session))
            .map_err(RelinearizationRuntimeError::Runtime)
    })();
    match result {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_two_activation_next_source_read(
    activation_handle: u32,
    component_ordinal_pointer: *mut u32,
    source_material_root_pointer: *mut u8,
    source_material_root_byte_length: usize,
    source_stream_digest_pointer: *mut u8,
    source_stream_digest_byte_length: usize,
    source_stream_total_byte_length_pointer: *mut u64,
    source_stream_byte_offset_pointer: *mut u64,
    chunk_index_pointer: *mut u32,
    source_byte_length_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if component_ordinal_pointer.is_null()
            || source_material_root_pointer.is_null()
            || source_material_root_byte_length != Hash512::BYTE_LENGTH
            || source_stream_digest_pointer.is_null()
            || source_stream_digest_byte_length != Hash512::BYTE_LENGTH
            || source_stream_total_byte_length_pointer.is_null()
            || source_stream_byte_offset_pointer.is_null()
            || chunk_index_pointer.is_null()
            || source_byte_length_pointer.is_null()
        {
            return Err(RelinearizationRuntimeError::InvalidInput);
        }
        let request = RELINEARIZATION_ROUND_TWO_ACTIVATION_REGISTRY.with(|registry| {
            registry
                .borrow()
                .get(activation_handle)?
                .next_read_request()
        })?;
        let Some(request) = request else {
            return Ok(0);
        };
        unsafe {
            component_ordinal_pointer.write(
                u32::try_from(request.component_ordinal)
                    .map_err(|_| RelinearizationRuntimeError::InvalidInput)?,
            );
            slice::from_raw_parts_mut(source_material_root_pointer, Hash512::BYTE_LENGTH)
                .copy_from_slice(&request.material_root);
            slice::from_raw_parts_mut(source_stream_digest_pointer, Hash512::BYTE_LENGTH)
                .copy_from_slice(&request.stream_digest);
            source_stream_total_byte_length_pointer.write(request.total_byte_length);
            source_stream_byte_offset_pointer.write(request.stream_byte_offset);
            chunk_index_pointer.write(
                u32::try_from(request.chunk_index)
                    .map_err(|_| RelinearizationRuntimeError::InvalidInput)?,
            );
            source_byte_length_pointer.write(
                u32::try_from(request.source_byte_length)
                    .map_err(|_| RelinearizationRuntimeError::InvalidInput)?,
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
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_round_two_activation_absorb_source(
    activation_handle: u32,
    component_ordinal: u32,
    source_material_root_pointer: *const u8,
    source_material_root_byte_length: usize,
    source_stream_digest_pointer: *const u8,
    source_stream_digest_byte_length: usize,
    source_stream_total_byte_length: u64,
    source_stream_byte_offset: u64,
    chunk_index: u32,
    source_bytes_pointer: *const u8,
    source_byte_length: usize,
) -> u32 {
    let result = (|| {
        if source_bytes_pointer.is_null() || source_byte_length == 0 {
            return Err(RelinearizationRuntimeError::InvalidInput);
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
        let supplied_request = RelinearizationRoundTwoActivationReadRequest {
            component_ordinal: usize::try_from(component_ordinal)
                .map_err(|_| RelinearizationRuntimeError::InvalidInput)?,
            material_root: source_material_root,
            stream_digest: source_stream_digest,
            total_byte_length: source_stream_total_byte_length,
            stream_byte_offset: source_stream_byte_offset,
            chunk_index: usize::try_from(chunk_index)
                .map_err(|_| RelinearizationRuntimeError::InvalidInput)?,
            source_byte_length,
        };
        let source_bytes =
            unsafe { slice::from_raw_parts(source_bytes_pointer, source_byte_length) };
        RELINEARIZATION_ROUND_TWO_ACTIVATION_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .get_mut(activation_handle)?
                .absorb_source(supplied_request, source_bytes)
        })
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_two_activation_finish(
    activation_handle: u32,
) -> u32 {
    let result = (|| {
        let mut session = RELINEARIZATION_ROUND_TWO_ACTIVATION_REGISTRY
            .with(|registry| registry.borrow_mut().take(activation_handle))?;
        let operation_result = (|| {
            if !session.can_finish() {
                return Err(CommonProofRuntimeError::WrongOperationPhase.into());
            }
            let authority_handle = SetupGenerationAuthorityHandle::from_identifier(
                session.setup_generation_authority_identifier,
            );
            with_prepackage_generated_relinearization_aggregate::<_, RelinearizationRuntimeError>(
                session.prepackage_catalog_identifier,
                |generated_aggregate, aggregate_proof_stream_descriptor| {
                    finish_setup_generation_relinearization_round_two_activation(
                        &authority_handle,
                        &mut session.authority_activation,
                        generated_aggregate,
                        aggregate_proof_stream_descriptor,
                    )
                    .map(|_| ())
                    .map_err(RelinearizationRuntimeError::from)
                },
            )
        })();
        if let Err(error) = operation_result {
            RELINEARIZATION_ROUND_TWO_ACTIVATION_REGISTRY
                .with(|registry| registry.borrow_mut().restore(activation_handle, session))?;
            return Err(error);
        }
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_two_activation_discard(
    activation_handle: u32,
) -> u32 {
    RELINEARIZATION_ROUND_TWO_ACTIVATION_REGISTRY
        .with(|registry| registry.borrow_mut().take(activation_handle))
        .map(|_| ())
        .map_err(RelinearizationRuntimeError::from)
        .map_or_else(runtime_error_status, |()| 0)
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi_inputs(
    proof_round: RelinearizationProofRound,
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    prepackage_catalog_handle: u32,
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
    generation_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: RelinearizationGenerationMode,
) -> u32 {
    let result = (|| {
        if generation_source_handle_output_pointer.is_null() {
            return Err(RelinearizationRuntimeError::InvalidInput);
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
            proof_round,
            selected_suite_handle,
            setup_generation_authority_handle,
            prepackage_catalog_handle,
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
        Ok((adapter_handle, generation_source_handle)) => {
            unsafe {
                generation_source_handle_output_pointer.write(generation_source_handle);
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

macro_rules! relinearization_generation_entry_point {
    ($name:ident, $proof_round:expr, $generation_mode:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            selected_suite_handle: u32,
            setup_generation_authority_handle: u32,
            prepackage_catalog_handle: u32,
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
            generation_source_handle_output_pointer: *mut u32,
            status_pointer: *mut u32,
        ) -> u32 {
            unsafe {
                prepare_generation_from_ffi_inputs(
                    $proof_round,
                    selected_suite_handle,
                    setup_generation_authority_handle,
                    prepackage_catalog_handle,
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
                    generation_source_handle_output_pointer,
                    status_pointer,
                    $generation_mode,
                )
            }
        }
    };
}

relinearization_generation_entry_point!(
    sealed_lattice_relinearization_round_one_prepare_generation,
    RelinearizationProofRound::RoundOne,
    RelinearizationGenerationMode::Fresh
);
relinearization_generation_entry_point!(
    sealed_lattice_relinearization_round_one_prepare_resumed_generation,
    RelinearizationProofRound::RoundOne,
    RelinearizationGenerationMode::Resume
);
relinearization_generation_entry_point!(
    sealed_lattice_relinearization_round_two_prepare_generation,
    RelinearizationProofRound::RoundTwo,
    RelinearizationGenerationMode::Fresh
);
relinearization_generation_entry_point!(
    sealed_lattice_relinearization_round_two_prepare_resumed_generation,
    RelinearizationProofRound::RoundTwo,
    RelinearizationGenerationMode::Resume
);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_component_count(
    generation_source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
        u32::try_from(
            registry
                .borrow()
                .source(generation_source_handle)?
                .component_count(),
        )
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
    });
    match result {
        Ok(component_count) => {
            unsafe { write_status(status_pointer, 0) };
            component_count
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
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_component_descriptor_byte_length(
    generation_source_handle: u32,
    component_ordinal: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
            u32::try_from(
                registry
                    .borrow()
                    .source(generation_source_handle)?
                    .current_component(component_ordinal)?
                    .encoded_stream_descriptor
                    .len(),
            )
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
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
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_component_copy_descriptor(
    generation_source_handle: u32,
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
        RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let descriptor = &registry
                .source(generation_source_handle)?
                .current_component(component_ordinal)?
                .encoded_stream_descriptor;
            if descriptor.len() != output_byte_length {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
            output.copy_from_slice(descriptor);
            Ok(())
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_component_copy_material_root(
    generation_source_handle: u32,
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
        RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let material_root = registry
                .source(generation_source_handle)?
                .current_component(component_ordinal)?
                .material_root;
            let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
            output.copy_from_slice(&material_root);
            Ok(())
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_component_total_byte_length(
    generation_source_handle: u32,
    component_ordinal: u32,
    status_pointer: *mut u32,
) -> u64 {
    let result = (|| {
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
            Ok::<u64, CommonProofRuntimeError>(
                registry
                    .borrow()
                    .source(generation_source_handle)?
                    .current_component(component_ordinal)?
                    .stream_descriptor
                    .total_byte_length,
            )
        })
    })();
    match result {
        Ok(total_byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            total_byte_length
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
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_component_read_chunk(
    generation_source_handle: u32,
    component_ordinal: u32,
    chunk_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() || output_byte_length == 0 {
            return Err(RelinearizationRuntimeError::InvalidInput);
        }
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| RelinearizationRuntimeError::InvalidInput)?;
        let chunk_index =
            usize::try_from(chunk_index).map_err(|_| RelinearizationRuntimeError::InvalidInput)?;
        let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
        read_generated_relinearization_component_chunk(
            generation_source_handle,
            component_ordinal,
            chunk_index,
            output,
        )
    })();
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            0
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            status
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_generation_source_commit(
    accepted_setup_package_builder_handle: u32,
    prepackage_catalog_handle: u32,
    generated_proof_handle: u32,
    generation_source_handle: u32,
) -> u32 {
    commit_relinearization_generation_source(
        accepted_setup_package_builder_handle,
        prepackage_catalog_handle,
        generated_proof_handle,
        generation_source_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_generation_source_discard(
    generation_source_handle: u32,
) -> u32 {
    discard_relinearization_generation_source(generation_source_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_generation_source(
        proof_round: RelinearizationProofRound,
        setup_generation_authority_identifier: u32,
    ) -> RelinearizationGenerationSource {
        RelinearizationGenerationSource {
            proof_round,
            setup_generation_authority_identifier,
            ordered_components: Vec::new().into_boxed_slice(),
            next_component_ordinal: 0,
            next_chunk_index: 0,
        }
    }

    #[test]
    fn atomic_generation_commit_restores_the_exact_source_after_refusal_and_consumes_once() {
        let mut registry = RelinearizationGenerationSourceRegistry::default();
        let generation_source_handle = registry
            .retain(ready_generation_source(
                RelinearizationProofRound::RoundTwo,
                47,
            ))
            .expect("generation source should be retained");

        let refusal = consume_relinearization_generation_source_atomically(
            &mut registry,
            generation_source_handle,
            |source| {
                assert_eq!(source.proof_round, RelinearizationProofRound::RoundTwo);
                assert_eq!(source.setup_generation_authority_identifier, 47);
                Err(RelinearizationRuntimeError::Refusal(
                    RefusalReason::WrongContext,
                ))
            },
        );
        assert!(matches!(
            refusal,
            Err(RelinearizationRuntimeError::Refusal(
                RefusalReason::WrongContext
            ))
        ));

        consume_relinearization_generation_source_atomically(
            &mut registry,
            generation_source_handle,
            |source| {
                assert_eq!(source.proof_round, RelinearizationProofRound::RoundTwo);
                assert_eq!(source.setup_generation_authority_identifier, 47);
                Ok(())
            },
        )
        .expect("the restored generation source should remain retryable");
        assert!(matches!(
            registry.source(generation_source_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }
}
