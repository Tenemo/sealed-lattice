//! Browser/WASM lifecycle for the suite-fixed RKG participant relations.
//!
//! Both rounds derive their canonical statement and witness from the retained
//! setup-generation authority. Round two additionally reenters the exact
//! positively verified round-one aggregate retained by the prepackage source
//! catalog. JavaScript receives only reset-safe common-prover handles and a
//! bounded read-once canonical statement source.

use core::slice;
use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::setup::{
        SetupGeneratedRelinearizationComponentSource,
        SetupGenerationAuthorityHandle, SetupGenerationRelinearizationRoundOneApplication,
        SetupGenerationRelinearizationRoundOnePreparationSource,
        SetupGenerationRelinearizationRoundTwoApplication,
        SetupGenerationRelinearizationRoundTwoPreparationSource,
        resolve_setup_generation_relinearization_round_one_preparation_source,
        resolve_setup_generation_relinearization_round_two_preparation_source,
        with_prepackage_relinearization_aggregate,
        with_setup_generation_relinearization_round_one,
        with_setup_generation_relinearization_round_one_component_chunk,
        with_setup_generation_relinearization_round_two,
        with_setup_generation_relinearization_round_two_component_chunk,
    },
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, CanonicalStreamReadbackVerifier,
        FOUNDATION_PROFILE, FoundationObjectType, FoundationSchemaError, Hash512,
        ParticipantIdentity, PreparedActionProofAttemptSource, ProofApplicationSlot,
        ProofApplicationSlotCeilings, RefusalReason, StreamDescriptor,
        STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VerifiedBoardApplicationSource,
        VerifiedStateReservationRuntimeBinding, resolve_prepared_action_proof_attempt_source,
        resolve_verified_board_application_sources, verified_state_reservation_binding,
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
    ProofProfileError, RelationPlanError, SelectedApplicationStatementContext,
    SelectedProofAccountingError, SetupRelinearizationGenerationPreparationError,
    decode_selected_relinearization_round_one_statement, selected_proof_runtime_limits,
    selected_relation_plan_check_context, selected_relation_plans,
    verified_application_statement_hash,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_RETAINED_RELINEARIZATION_STATEMENT_SOURCE_COUNT: usize = 32;

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
    public_polynomial_context_hash: [u8; 64],
    contribution_root: [u8; 64],
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
            public_polynomial_context_hash: source.public_polynomial_context_hash(),
            contribution_root: source.contribution_root(),
            encoded_stream_descriptor: stream_descriptor.encode()?.into_boxed_slice(),
            authenticated_readback: Some(source.begin_authenticated_readback()?),
            stream_descriptor,
        })
    }
}

struct RelinearizationGenerationSource {
    proof_round: RelinearizationProofRound,
    setup_generation_authority_identifier: u32,
    canonical_application_statement_bytes: Option<Box<[u8]>>,
    ordered_components: Box<[GeneratedRelinearizationComponentReadback]>,
    next_component_ordinal: usize,
    next_chunk_index: usize,
}

impl RelinearizationGenerationSource {
    fn is_component_readback_complete(&self) -> bool {
        self.next_component_ordinal == self.ordered_components.len()
            && self.next_chunk_index == 0
            && self
                .ordered_components
                .iter()
                .all(|component| component.authenticated_readback.is_none())
    }

    fn can_release(&self) -> bool {
        self.canonical_application_statement_bytes.is_none()
            && self.is_component_readback_complete()
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
}

thread_local! {
    static RELINEARIZATION_GENERATION_SOURCE_REGISTRY:
        RefCell<RelinearizationGenerationSourceRegistry> =
        RefCell::new(RelinearizationGenerationSourceRegistry::default());
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
    let relation_plan_variant = selected_plan.compiled_plan().select_variant(
        Some(preparation_source.schedule_position()),
        None,
    )?;
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
            let application = SetupGenerationRelinearizationRoundOneApplication::from_decoded_statement(
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
            let application = SetupGenerationRelinearizationRoundTwoApplication::from_decoded_statement(
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
            with_prepackage_relinearization_aggregate::<_, RelinearizationRuntimeError>(
                prepackage_catalog_handle,
                |verified_aggregate| {
                    with_setup_generation_relinearization_round_two(
                        &authority_handle,
                        &application,
                        verified_aggregate,
                        |source| {
                            let ordered_components = [source
                                .generated_source_authority()
                                .component()]
                            .into_iter()
                            .map(
                                GeneratedRelinearizationComponentReadback::from_generated_source,
                            )
                            .collect::<Result<Vec<_>, _>>()?
                            .into_boxed_slice();
                            let prepared_generation =
                                source.prepare_common_generation(relation_plan, limits)?;
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
        || (proof_round == RelinearizationProofRound::RoundOne
            && prepackage_catalog_handle != 0)
        || (proof_round == RelinearizationProofRound::RoundTwo
            && prepackage_catalog_handle == 0)
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
                    canonical_application_statement_bytes: Some(
                        preparation_source
                            .canonical_application_statement_bytes()
                            .to_vec()
                            .into_boxed_slice(),
                    ),
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
    statement_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: RelinearizationGenerationMode,
) -> u32 {
    let result = (|| {
        if statement_source_handle_output_pointer.is_null() {
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
            statement_source_handle_output_pointer: *mut u32,
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
                    statement_source_handle_output_pointer,
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
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_statement_byte_length(
    statement_source_handle: u32,
    status_pointer: *mut u32,
) -> usize {
    let result = RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
        Ok::<usize, CommonProofRuntimeError>(
            registry
                .borrow()
                .source(statement_source_handle)?
                .canonical_application_statement_bytes
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
                .len(),
        )
    });
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
pub unsafe extern "C" fn sealed_lattice_relinearization_generation_statement_copy_and_release(
    statement_source_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() || output_byte_length == 0 {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        RELINEARIZATION_GENERATION_SOURCE_REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let source = registry.source_mut(statement_source_handle)?;
            let statement = source
                .canonical_application_statement_bytes
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            if statement.len() != output_byte_length {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
            output.copy_from_slice(statement);
            source.canonical_application_statement_bytes = None;
            Ok(())
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_generation_statement_discard(
    statement_source_handle: u32,
) -> u32 {
    RELINEARIZATION_GENERATION_SOURCE_REGISTRY
        .with(|registry| {
            let mut registry = registry.borrow_mut();
            let source = registry.source_mut(statement_source_handle)?;
            source
                .canonical_application_statement_bytes
                .take()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            Ok(())
        })
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}
