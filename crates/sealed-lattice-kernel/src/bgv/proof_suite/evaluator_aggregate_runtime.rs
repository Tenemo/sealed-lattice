//! Browser/WASM lifecycle for the complete selected evaluator aggregate.
//!
//! The host owns the large source and evaluator-store byte arrays. Rust owns
//! every descriptor, authenticated readback, relation coordinate, runtime
//! tree, statement binding, and reset-safe public-only proof attempt.

use core::slice;
use std::cell::RefCell;

use crate::{
    bgv::setup::{
        CanonicalPackageStreamKind, commit_preflighted_verified_evaluator_key_store,
        commit_prepackage_generated_evaluator_proof,
        contribute_generated_canonical_package_proof_and_stream_source,
        preflight_prepackage_generated_evaluator_proof_slot,
        preflight_verified_evaluator_key_store_slot, restore_prepackage_evaluator_statement_source,
        take_prepackage_evaluator_statement_source,
        with_completed_prepackage_evaluator_source_catalog,
        with_prepackage_evaluator_generation_sources,
    },
    foundation::{
        AuthenticatedCheckpointContinuationSource, FOUNDATION_PROFILE, Hash512,
        PreparedPublicOnlyProofAttemptSource, ProofApplicationSlot, ProofApplicationSlotCeilings,
        RefusalReason, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, StreamDescriptor,
        VerifiedStateReservationRuntimeBinding, resolve_prepared_public_only_proof_attempt_source,
        verified_state_reservation_binding,
    },
};

use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    cancel_common_proof_verification_family_adapter_reservation,
    commit_reserved_common_proof_verification_family_adapter_from_upstream,
    preflight_and_consume_verified_common_proof_with_family_terminal,
    preflight_reserved_common_proof_verification_family_adapter_from_upstream,
    reserve_common_proof_verification_family_adapter,
    retain_common_proof_generation_family_adapter, with_common_proof_selected_suite,
};
use super::{
    CommonProofGenerationAuthorization, CommonProofGenerationPreparationError,
    CommonProofGenerationSources, CommonProofProverError, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofSelectedSuiteCapabilityHandle, ComponentMaterialOwnershipBinding,
    ComponentPublicPolynomialRuntimeError,
    DescriptorAuthenticatedKeySwitchComponentPublicPolynomialStream, EvaluatorKeyStorePhysicalRole,
    PreparedCommonProofGeneration, ProofProfileError, RelationPlanError,
    SelectedEvaluatorAggregatePlanError, SelectedEvaluatorAggregateSourcePolynomialProvider,
    SelectedEvaluatorEntryKind, SelectedEvaluatorStoreConstruction,
    SelectedEvaluatorStoreConstructionOutput, SelectedEvaluatorStoreOutputChunk,
    SelectedEvaluatorStoreSourceReadRequest, SelectedProofAccountingError,
    SetupPublicPolynomialContext, SetupPublicPolynomialRootRole, SetupPublicPolynomialTree,
    VerifiedCommonProofCapabilityHandle, VerifiedCommonProofStatementSource,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedEvaluatorKeyStore, VerifiedEvaluatorKeyStoreMaterial,
    VerifiedEvaluatorKeyStoreMaterialStream, VerifiedEvaluatorKeyStorePreflight,
    VerifiedEvaluatorRuntimeRoot, VerifiedStatementOwnedTree,
    selected_evaluator_aggregate_relation_plan, selected_evaluator_entry_positions,
    selected_proof_runtime_limits, selected_relation_plan_check_context,
    verified_application_statement_hash,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const STORE_SOURCE_READ_REQUEST_BYTE_LENGTH: usize = 160;
const STORE_DESCRIPTOR_DESCRIPTION_BYTE_LENGTH: usize = 72;
const STORE_POLL_SOURCE_READ_REQUIRED: u32 = 1;
const STORE_POLL_OUTPUT_CHUNK_READY: u32 = 2;
const STORE_POLL_CONSTRUCTION_COMPLETE: u32 = 3;

fn component_runtime_error(
    error: ComponentPublicPolynomialRuntimeError,
) -> CommonProofRuntimeError {
    match error {
        ComponentPublicPolynomialRuntimeError::Refusal(RefusalReason::ConsumedState) => {
            CommonProofRuntimeError::WrongOperationPhase
        }
        ComponentPublicPolynomialRuntimeError::Refusal(RefusalReason::OutsideSupportedProfile) => {
            CommonProofRuntimeError::AllocationLimitExceeded
        }
        ComponentPublicPolynomialRuntimeError::Refusal(_)
        | ComponentPublicPolynomialRuntimeError::PublicPolynomial(_) => {
            CommonProofRuntimeError::WrongVerificationBinding
        }
    }
}

#[derive(Debug)]
enum EvaluatorAggregateRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    AggregatePlan(SelectedEvaluatorAggregatePlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Prover(CommonProofProverError),
    Runtime(CommonProofRuntimeError),
    Refusal(RefusalReason),
    ActionRandomnessRuntime(u32),
    StateRuntime(u32),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for EvaluatorAggregateRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for EvaluatorAggregateRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for EvaluatorAggregateRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<SelectedEvaluatorAggregatePlanError> for EvaluatorAggregateRuntimeError {
    fn from(error: SelectedEvaluatorAggregatePlanError) -> Self {
        Self::AggregatePlan(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for EvaluatorAggregateRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofProverError> for EvaluatorAggregateRuntimeError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CommonProofRuntimeError> for EvaluatorAggregateRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RefusalReason> for EvaluatorAggregateRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

struct ActiveRuntimeTreeStream {
    logical_component_ordinal: usize,
    stream: DescriptorAuthenticatedKeySwitchComponentPublicPolynomialStream,
}

struct EvaluatorAggregateSession {
    prepackage_catalog_handle: u32,
    construction: Option<SelectedEvaluatorStoreConstruction>,
    pending_output_chunk: Option<SelectedEvaluatorStoreOutputChunk>,
    construction_output: Option<SelectedEvaluatorStoreConstructionOutput>,
    active_runtime_tree_stream: Option<ActiveRuntimeTreeStream>,
    ordered_runtime_component_trees: Vec<SetupPublicPolynomialTree>,
    ordered_runtime_roots: Vec<VerifiedEvaluatorRuntimeRoot>,
    ordered_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    canonical_application_statement_bytes: Option<Vec<u8>>,
    store_material_stream: Option<VerifiedEvaluatorKeyStoreMaterialStream>,
    verified_store_material: Option<VerifiedEvaluatorKeyStoreMaterial>,
    package_statement_source: Option<VerifiedCommonProofStatementSource>,
    statement_trees: Option<Vec<VerifiedStatementOwnedTree>>,
    verified_evaluator_key_store: Option<VerifiedEvaluatorKeyStore>,
    generated_proof_handle: Option<u32>,
}

impl EvaluatorAggregateSession {
    fn begin(prepackage_catalog_handle: u32) -> Result<Self, CommonProofRuntimeError> {
        let construction = with_prepackage_evaluator_generation_sources(
            prepackage_catalog_handle,
            |source_catalog, relinearization_aggregate, _| {
                SelectedEvaluatorStoreConstruction::begin(
                    source_catalog,
                    relinearization_aggregate,
                    FOUNDATION_PROFILE.option_count,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
            },
        )?;
        Ok(Self {
            prepackage_catalog_handle,
            construction: Some(construction),
            pending_output_chunk: None,
            construction_output: None,
            active_runtime_tree_stream: None,
            ordered_runtime_component_trees: Vec::new(),
            ordered_runtime_roots: Vec::new(),
            ordered_auxiliary_roots: Vec::new(),
            canonical_application_statement_bytes: None,
            store_material_stream: None,
            verified_store_material: None,
            package_statement_source: None,
            statement_trees: None,
            verified_evaluator_key_store: None,
            generated_proof_handle: None,
        })
    }

    fn require_construction(
        &self,
    ) -> Result<&SelectedEvaluatorStoreConstruction, CommonProofRuntimeError> {
        self.construction
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn require_construction_mut(
        &mut self,
    ) -> Result<&mut SelectedEvaluatorStoreConstruction, CommonProofRuntimeError> {
        self.construction
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn poll_construction(&mut self) -> Result<u32, CommonProofRuntimeError> {
        if self.pending_output_chunk.is_some() {
            return Ok(STORE_POLL_OUTPUT_CHUNK_READY);
        }
        if self
            .require_construction()?
            .next_source_read_request()
            .is_some()
        {
            return Ok(STORE_POLL_SOURCE_READ_REQUIRED);
        }
        if let Some(output_chunk) = self
            .require_construction_mut()?
            .take_next_output_chunk()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
        {
            self.pending_output_chunk = Some(output_chunk);
            return Ok(STORE_POLL_OUTPUT_CHUNK_READY);
        }
        if self
            .require_construction()?
            .next_source_read_request()
            .is_none()
        {
            return Ok(STORE_POLL_CONSTRUCTION_COMPLETE);
        }
        Err(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn copy_source_request(&self, output: &mut [u8]) -> Result<(), CommonProofRuntimeError> {
        let request = self
            .require_construction()?
            .next_source_read_request()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        encode_store_source_request(&request, output)
    }

    fn supply_source_range(
        &mut self,
        encoded_request: &[u8],
        source_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let expected = self
            .require_construction()?
            .next_source_read_request()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if encode_store_source_request_to_array(&expected)?.as_slice() != encoded_request
            || source_bytes.len() != expected.byte_length()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.require_construction_mut()?
            .absorb_source_chunk(&expected, source_bytes)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    }

    fn copy_output_chunk(
        &self,
        chunk_index: usize,
        output: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let pending = self
            .pending_output_chunk
            .as_ref()
            .filter(|chunk| chunk.chunk_index() == chunk_index)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if output.len() != pending.bytes().len() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        output.copy_from_slice(pending.bytes());
        Ok(())
    }

    fn pending_output_description(&self) -> Result<(usize, usize), CommonProofRuntimeError> {
        self.pending_output_chunk
            .as_ref()
            .map(|chunk| (chunk.chunk_index(), chunk.bytes().len()))
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn acknowledge_output_chunk(
        &mut self,
        chunk_index: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        if self
            .pending_output_chunk
            .as_ref()
            .is_none_or(|chunk| chunk.chunk_index() != chunk_index)
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.pending_output_chunk = None;
        Ok(())
    }

    fn finish_construction(&mut self) -> Result<(), CommonProofRuntimeError> {
        if self.pending_output_chunk.is_some() || self.construction_output.is_some() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let construction = self
            .construction
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        match construction.finish() {
            Ok(output) => {
                self.construction_output = Some(output);
                Ok(())
            }
            Err(_) => Err(CommonProofRuntimeError::WrongVerificationBinding),
        }
    }

    fn output(&self) -> Result<&SelectedEvaluatorStoreConstructionOutput, CommonProofRuntimeError> {
        self.construction_output
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn begin_runtime_tree(
        &mut self,
        selected_suite_handle: u32,
        logical_component_ordinal: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.active_runtime_tree_stream.is_some()
            || logical_component_ordinal != self.ordered_runtime_component_trees.len()
            || self.canonical_application_statement_bytes.is_some()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let output = self.output()?;
        let physical_component_ordinal = output
            .ordered_physical_roles()
            .iter()
            .enumerate()
            .filter(|(_, role)| **role == EvaluatorKeyStorePhysicalRole::Runtime)
            .nth(logical_component_ordinal)
            .map(|(ordinal, _)| ordinal)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let position = *output
            .ordered_positions()
            .get(physical_component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let descriptor = output
            .ordered_component_descriptors()
            .get(physical_component_ordinal)
            .cloned()
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let topology =
            with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
                let catalog_level = match position.key_kind() {
                    SelectedEvaluatorEntryKind::Relinearization { catalog_level }
                    | SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
                };
                super::KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                    selected_suite,
                    catalog_level,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
            })??;
        let stream = DescriptorAuthenticatedKeySwitchComponentPublicPolynomialStream::begin(
            topology, descriptor,
        )
        .map_err(component_runtime_error)?;
        self.active_runtime_tree_stream = Some(ActiveRuntimeTreeStream {
            logical_component_ordinal,
            stream,
        });
        Ok(())
    }

    fn absorb_runtime_tree_chunk(
        &mut self,
        logical_component_ordinal: usize,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let active = self
            .active_runtime_tree_stream
            .as_mut()
            .filter(|active| active.logical_component_ordinal == logical_component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        active
            .stream
            .absorb_chunk(chunk_index, chunk_bytes)
            .map_err(component_runtime_error)
    }

    fn finish_runtime_tree(
        &mut self,
        logical_component_ordinal: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        let active = self
            .active_runtime_tree_stream
            .take()
            .filter(|active| active.logical_component_ordinal == logical_component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let position = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
            .get(logical_component_ordinal)
            .copied()
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let setup_proof_context_hash = with_prepackage_evaluator_generation_sources(
            self.prepackage_catalog_handle,
            |source_catalog, _, _| Ok(source_catalog.setup_proof_context_hash()),
        )?;
        let context = SetupPublicPolynomialContext::new(
            setup_proof_context_hash,
            match position.key_kind() {
                SelectedEvaluatorEntryKind::Relinearization { .. } => {
                    SetupPublicPolynomialRootRole::RelinearizationRuntime
                }
                SelectedEvaluatorEntryKind::Galois { .. } => {
                    SetupPublicPolynomialRootRole::GaloisRuntime
                }
            },
            None,
            None,
            Some(position.schedule_position()),
            None,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let tree = active
            .stream
            .finish(context)
            .map_err(component_runtime_error)?
            .into_tree();
        let runtime_root = VerifiedEvaluatorRuntimeRoot::from_recomputed_public_polynomial_tree(
            &tree,
            FOUNDATION_PROFILE.option_count,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if runtime_root.position() != position {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.ordered_runtime_component_trees.push(tree);
        self.ordered_runtime_roots.push(runtime_root);
        Ok(())
    }

    fn finalize_statement_and_begin_material_pass(
        &mut self,
        selected_suite_handle: u32,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.active_runtime_tree_stream.is_some()
            || self.canonical_application_statement_bytes.is_some()
            || self.store_material_stream.is_some()
            || self.verified_store_material.is_some()
            || self.ordered_runtime_component_trees.len()
                != selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
                    .len()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let (canonical_statement, auxiliary_roots) = with_prepackage_evaluator_generation_sources(
            self.prepackage_catalog_handle,
            |source_catalog, _, auxiliary_roots| {
                let statement = self
                    .output()?
                    .canonical_application_statement(
                        source_catalog,
                        &self.ordered_runtime_roots,
                        auxiliary_roots,
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                Ok((statement, auxiliary_roots.to_vec()))
            },
        )?;
        let application_statement_hash = verified_application_statement_hash(
            FOUNDATION_PROFILE.protocol_version,
            with_prepackage_evaluator_generation_sources(
                self.prepackage_catalog_handle,
                |source_catalog, _, _| Ok(source_catalog.suite_identifier()),
            )?,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            &canonical_statement,
        );
        let ownership_binding = with_prepackage_evaluator_generation_sources(
            self.prepackage_catalog_handle,
            |source_catalog, _, _| {
                Ok(
                    ComponentMaterialOwnershipBinding::from_verified_application(
                        source_catalog.suite_identifier(),
                        source_catalog.action_context_hash(),
                        application_statement_hash,
                    ),
                )
            },
        )?;
        let material_stream =
            with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
                self.output()?
                    .begin_material_verification(selected_suite, ownership_binding)
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
            })??;
        self.ordered_auxiliary_roots = auxiliary_roots;
        self.canonical_application_statement_bytes = Some(canonical_statement);
        self.store_material_stream = Some(material_stream);
        Ok(())
    }

    fn absorb_store_material_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        self.store_material_stream
            .as_mut()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    }

    fn finish_store_material(&mut self) -> Result<(), CommonProofRuntimeError> {
        if self.verified_store_material.is_some() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let stream = self
            .store_material_stream
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        self.verified_store_material = Some(
            stream
                .finish()
                .into_result()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
        );
        Ok(())
    }

    fn canonical_statement(&self) -> Result<&[u8], CommonProofRuntimeError> {
        self.canonical_application_statement_bytes
            .as_deref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn verified_store_material(
        &self,
    ) -> Result<&VerifiedEvaluatorKeyStoreMaterial, CommonProofRuntimeError> {
        self.verified_store_material
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }
}

struct SingleEvaluatorAggregateSessionRegistry {
    active: Option<(u32, EvaluatorAggregateSession)>,
    next_handle: u32,
}

impl Default for SingleEvaluatorAggregateSessionRegistry {
    fn default() -> Self {
        Self {
            active: None,
            next_handle: 1,
        }
    }
}

impl SingleEvaluatorAggregateSessionRegistry {
    fn retain(
        &mut self,
        session: EvaluatorAggregateSession,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.active.is_some() || self.next_handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.active = Some((handle, session));
        Ok(handle)
    }

    fn with<Output>(
        &self,
        handle: u32,
        inspect: impl FnOnce(&EvaluatorAggregateSession) -> Result<Output, CommonProofRuntimeError>,
    ) -> Result<Output, CommonProofRuntimeError> {
        inspect(
            self.active
                .as_ref()
                .filter(|(active_handle, _)| *active_handle == handle)
                .map(|(_, session)| session)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?,
        )
    }

    fn with_mut<Output>(
        &mut self,
        handle: u32,
        inspect: impl FnOnce(&mut EvaluatorAggregateSession) -> Result<Output, CommonProofRuntimeError>,
    ) -> Result<Output, CommonProofRuntimeError> {
        inspect(
            self.active
                .as_mut()
                .filter(|(active_handle, _)| *active_handle == handle)
                .map(|(_, session)| session)
                .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?,
        )
    }

    fn take(&mut self, handle: u32) -> Result<EvaluatorAggregateSession, CommonProofRuntimeError> {
        self.with(handle, |_| Ok(()))?;
        self.active
            .take()
            .map(|(_, session)| session)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }
}

thread_local! {
    static EVALUATOR_AGGREGATE_SESSION_REGISTRY:
        RefCell<SingleEvaluatorAggregateSessionRegistry> =
        RefCell::new(SingleEvaluatorAggregateSessionRegistry::default());
}

struct SelectedEvaluatorProofRuntimePlan {
    compiled_relation_plan: super::CompiledRelationPlan,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
    proof_query_count: u32,
}

fn selected_evaluator_proof_runtime_plan(
    canonical_application_statement_bytes: &[u8],
) -> Result<SelectedEvaluatorProofRuntimePlan, EvaluatorAggregateRuntimeError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(schema_identifier).ok_or(
        EvaluatorAggregateRuntimeError::Relation(RelationPlanError::InvalidDomain),
    )?;
    let compiled_relation_plan = selected_evaluator_aggregate_relation_plan()?;
    let variant =
        compiled_relation_plan.select_variant(None, Some(FOUNDATION_PROFILE.option_count))?;
    let limits = selected_proof_runtime_limits(
        schema_identifier,
        canonical_application_statement_bytes,
        variant,
    )?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_relation_plan,
        &relation_context,
        None,
        Some(FOUNDATION_PROFILE.option_count),
    )?;
    let proof_query_count = relation_plan.proof_query_count()?;
    Ok(SelectedEvaluatorProofRuntimePlan {
        compiled_relation_plan,
        relation_plan,
        limits,
        proof_query_count,
    })
}

fn resolve_evaluator_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    session_handle: u32,
    runtime_plan: &SelectedEvaluatorProofRuntimePlan,
    checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedPublicOnlyProofAttemptSource, EvaluatorAggregateRuntimeError> {
    let (
        suite_identifier,
        ceremony_context_hash,
        action_context_hash,
        roster_hash,
        canonical_statement,
    ) = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            with_prepackage_evaluator_generation_sources(
                session.prepackage_catalog_handle,
                |source_catalog, _, _| {
                    Ok((
                        source_catalog.suite_identifier(),
                        source_catalog.ceremony_context_hash(),
                        source_catalog.action_context_hash(),
                        source_catalog.roster_hash(),
                        session.canonical_statement()?.to_vec(),
                    ))
                },
            )
        })
    })?;
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(suite_identifier),
        Hash512::from_bytes(ceremony_context_hash),
        Hash512::from_bytes(action_context_hash),
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        None,
        None,
    )
    .map_err(|_| EvaluatorAggregateRuntimeError::InvalidInput)?;
    let statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        FOUNDATION_PROFILE.protocol_version,
        suite_identifier,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        &canonical_statement,
    ));
    resolve_prepared_public_only_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        Hash512::from_bytes(roster_hash),
        application_slot,
        statement_hash,
        u64::try_from(runtime_plan.limits.proof_byte_length())
            .map_err(|_| EvaluatorAggregateRuntimeError::InvalidInput)?,
        runtime_plan.proof_query_count,
        checkpoint_continuation,
    )
    .map_err(EvaluatorAggregateRuntimeError::ActionRandomnessRuntime)
}

fn prepare_evaluator_common_generation(
    session_handle: u32,
    prepared_attempt: PreparedPublicOnlyProofAttemptSource,
    runtime_plan: SelectedEvaluatorProofRuntimePlan,
) -> Result<PreparedCommonProofGeneration, EvaluatorAggregateRuntimeError> {
    let (canonical_statement, relation_trees, source_provider) =
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                let canonical_statement = session.canonical_statement()?.to_vec();
                with_prepackage_evaluator_generation_sources(
                    session.prepackage_catalog_handle,
                    |source_catalog, _, _| {
                        let (trees, provider) =
                            SelectedEvaluatorAggregateSourcePolynomialProvider::prepare(
                                &runtime_plan.compiled_relation_plan,
                                source_catalog,
                                session.verified_store_material()?,
                                &session.ordered_runtime_roots,
                                &canonical_statement,
                            )
                            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                        Ok((canonical_statement, trees, provider))
                    },
                )
            })
        })?;
    let authorization = CommonProofGenerationAuthorization::from_public_only_authenticated_attempt(
        prepared_attempt,
        &runtime_plan.relation_plan,
        FOUNDATION_PROFILE.protocol_version,
        &canonical_statement,
        runtime_plan.limits,
    )?;
    let sources = CommonProofGenerationSources::public_only(
        prepared_attempt.application_statement_schema_identifier(),
        Hash512::from_bytes(authorization.binding_hash()),
        prepared_attempt.attempt_lineage_identifier(),
        source_provider,
    )
    .map_err(|_| EvaluatorAggregateRuntimeError::InvalidInput)?;
    PreparedCommonProofGeneration::from_exact_family_sources(
        authorization,
        runtime_plan.relation_plan,
        canonical_statement,
        relation_trees,
        runtime_plan.limits,
        sources,
    )
    .map_err(|error| match error {
        CommonProofGenerationPreparationError::Runtime(error) => {
            EvaluatorAggregateRuntimeError::Runtime(error)
        }
        CommonProofGenerationPreparationError::Generation(error) => {
            let _ = error;
            EvaluatorAggregateRuntimeError::InvalidInput
        }
    })
}

#[derive(Clone, Copy)]
enum EvaluatorGenerationMode {
    Fresh,
    Resume,
}

fn resumed_generation_error(
    error: EvaluatorAggregateRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        EvaluatorAggregateRuntimeError::Runtime(error) => error.into(),
        _ => CommonProofRuntimeError::WrongVerificationBinding.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_evaluator_generation(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: EvaluatorGenerationMode,
) -> Result<u32, EvaluatorAggregateRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]
        || state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
    {
        return Err(EvaluatorAggregateRuntimeError::InvalidInput);
    }
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            session.verified_store_material()?;
            if session.generated_proof_handle.is_some() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            Ok(())
        })
    })?;
    let verified_reservation_binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(EvaluatorAggregateRuntimeError::StateRuntime)?;
    let canonical_statement = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            Ok(session.canonical_statement()?.to_vec())
        })
    })?;
    let runtime_plan = selected_evaluator_proof_runtime_plan(&canonical_statement)?;
    let checkpoint_schedule_digest = runtime_plan
        .relation_plan
        .checkpoint_schedule_digest(runtime_plan.limits)?;
    let fresh_continuation =
        AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_prepared_attempt = resolve_evaluator_prepared_attempt(
        action_randomness_handle,
        verified_reservation_binding,
        session_handle,
        &runtime_plan,
        fresh_continuation,
    )?;
    let adapter = match generation_mode {
        EvaluatorGenerationMode::Fresh => {
            CommonProofGenerationFamilyAdapter::fresh(prepare_evaluator_common_generation(
                session_handle,
                fresh_prepared_attempt,
                runtime_plan,
            )?)
        }
        EvaluatorGenerationMode::Resume => {
            let fresh_preparation = prepare_evaluator_common_generation(
                session_handle,
                fresh_prepared_attempt,
                runtime_plan,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
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
                    let canonical_statement = EVALUATOR_AGGREGATE_SESSION_REGISTRY
                        .with(|registry| {
                            registry.borrow().with(session_handle, |session| {
                                Ok(session.canonical_statement()?.to_vec())
                            })
                        })
                        .map_err(CommonProofGenerationPreparationError::Runtime)?;
                    let runtime_plan = selected_evaluator_proof_runtime_plan(&canonical_statement)
                        .map_err(resumed_generation_error)?;
                    let attempt = resolve_evaluator_prepared_attempt(
                        action_randomness_handle,
                        verified_reservation_binding,
                        session_handle,
                        &runtime_plan,
                        continuation,
                    )
                    .map_err(resumed_generation_error)?;
                    prepare_evaluator_common_generation(session_handle, attempt, runtime_plan)
                        .map_err(resumed_generation_error)
                }),
            )
        }
    };
    retain_common_proof_generation_family_adapter(adapter)
        .map_err(EvaluatorAggregateRuntimeError::Runtime)
}

fn commit_generated_evaluator_proof(
    session_handle: u32,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let preflight = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle.is_some() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            preflight_prepackage_generated_evaluator_proof_slot(
                session.prepackage_catalog_handle,
                generated_common_proof_handle,
                session.verified_store_material()?.store_descriptor(),
                session.canonical_statement()?,
                &session.ordered_runtime_roots,
                &session.ordered_auxiliary_roots,
            )
        })
    })?;
    commit_prepackage_generated_evaluator_proof(preflight);
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow_mut().with_mut(session_handle, |session| {
            session.generated_proof_handle = Some(generated_common_proof_handle);
            Ok(())
        })
    })
}

fn evaluator_package_stream_descriptor(
    session_handle: u32,
) -> Result<StreamDescriptor, CommonProofRuntimeError> {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle.is_none() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            Ok(session
                .verified_store_material()?
                .store_descriptor()
                .clone())
        })
    })
}

fn contribute_evaluator_package(
    session_handle: u32,
    package_builder_handle: u32,
    generated_common_proof_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<(), CommonProofRuntimeError> {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle != Some(generated_common_proof_handle)
                || session.canonical_statement()? != canonical_application_statement_bytes
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            Ok(())
        })
    })?;
    contribute_generated_canonical_package_proof_and_stream_source(
        package_builder_handle,
        CanonicalPackageStreamKind::EvaluatorKeyStore,
        session_handle,
        evaluator_package_stream_descriptor,
        generated_common_proof_handle,
        canonical_application_statement_bytes,
    )
}

fn take_package_statement_source(session_handle: u32) -> Result<(), CommonProofRuntimeError> {
    let prepackage_catalog_handle = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle.is_none()
                || session.package_statement_source.is_some()
            {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            Ok(session.prepackage_catalog_handle)
        })
    })?;
    let mut source = Some(take_prepackage_evaluator_statement_source(
        prepackage_catalog_handle,
    )?);
    let retain_result = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow_mut().with_mut(session_handle, |session| {
            let retained_source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            if session.package_statement_source.is_some()
                || retained_source.canonical_application_statement_bytes()
                    != session.canonical_statement()?
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            session.package_statement_source = source.take();
            Ok(())
        })
    });
    if let Err(error) = retain_result {
        restore_prepackage_evaluator_statement_source(
            prepackage_catalog_handle,
            source.expect("failed evaluator statement retention preserves the package source"),
        )?;
        return Err(error);
    }
    Ok(())
}

fn prepare_evaluator_verification_adapter(
    selected_suite_handle: u32,
    session_handle: u32,
) -> Result<u32, CommonProofRuntimeError> {
    let adapter_reservation_handle = reserve_common_proof_verification_family_adapter()?;
    let borrowed_preflight = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            if session.generated_proof_handle.is_none()
                || session.statement_trees.is_some()
                || session.verified_evaluator_key_store.is_some()
            {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            let statement_source = session
                .package_statement_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            with_completed_prepackage_evaluator_source_catalog(
                session.prepackage_catalog_handle,
                |source_catalog, _| {
                    let statement_trees =
                        VerifiedStatementOwnedTree::from_verified_evaluator_aggregate_statement_sources(
                            statement_source,
                            source_catalog,
                            &session.ordered_runtime_component_trees,
                        )
                        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                    preflight_reserved_common_proof_verification_family_adapter_from_upstream(
                        adapter_reservation_handle,
                        |upstream_inputs| {
                            let selected_suite_handle =
                                CommonProofSelectedSuiteCapabilityHandle::from_identifier(
                                    selected_suite_handle,
                                );
                            upstream_inputs
                                .preflight_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
                                    &selected_suite_handle,
                                    statement_source,
                                    &statement_trees,
                                    &session.ordered_auxiliary_roots,
                                )
                        },
                    )?;
                    Ok(statement_trees)
                },
            )
        })
    });
    let statement_trees = match borrowed_preflight {
        Ok(statement_trees) => statement_trees,
        Err(error) => {
            cancel_common_proof_verification_family_adapter_reservation(adapter_reservation_handle)
                .expect("failed evaluator preflight retains its common-proof reservation");
            return Err(error);
        }
    };
    let adapter_statement_trees = statement_trees.clone();
    let (statement_source, auxiliary_roots) = EVALUATOR_AGGREGATE_SESSION_REGISTRY
        .with(|registry| {
            registry.borrow_mut().with_mut(session_handle, |session| {
                let statement_source = session
                    .package_statement_source
                    .take()
                    .expect("preflighted evaluator statement source remains live");
                session.statement_trees = Some(statement_trees);
                Ok((statement_source, session.ordered_auxiliary_roots.clone()))
            })
        })
        .expect("preflighted evaluator session remains live during commit");
    Ok(
        commit_reserved_common_proof_verification_family_adapter_from_upstream(
            adapter_reservation_handle,
            move |upstream_inputs| {
                let selected_suite_handle =
                    CommonProofSelectedSuiteCapabilityHandle::from_identifier(
                        selected_suite_handle,
                    );
                upstream_inputs
                    .prepare_preflighted_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
                        &selected_suite_handle,
                        statement_source,
                        adapter_statement_trees,
                        auxiliary_roots,
                    )
            },
        ),
    )
}

fn finish_evaluator_verification(
    session_handle: u32,
    verified_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |borrowed_proof| {
            EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
                registry.borrow().with(session_handle, |session| {
                    let statement_trees = session
                        .statement_trees
                        .as_deref()
                        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                    with_completed_prepackage_evaluator_source_catalog(
                        session.prepackage_catalog_handle,
                        |source_catalog, _| {
                            VerifiedEvaluatorKeyStorePreflight::from_borrowed_common_proof(
                                borrowed_proof,
                                session.canonical_statement()?,
                                source_catalog,
                                session.verified_store_material()?,
                                statement_trees,
                                &session.ordered_runtime_component_trees,
                                &session.ordered_auxiliary_roots,
                            )
                            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                        },
                    )
                })
            })
        },
        |verified_proof, terminal_preflight| {
            EVALUATOR_AGGREGATE_SESSION_REGISTRY
                .with(|registry| {
                    registry.borrow_mut().with_mut(session_handle, |session| {
                        let canonical_statement = session.canonical_statement()?.to_vec();
                        let store_material = session
                            .verified_store_material
                            .take()
                            .expect("evaluator terminal preflight retains its store material");
                        let runtime_component_trees =
                            core::mem::take(&mut session.ordered_runtime_component_trees);
                        let auxiliary_roots = core::mem::take(&mut session.ordered_auxiliary_roots);
                        session.statement_trees = None;
                        let verified_store = terminal_preflight.complete(
                            verified_proof,
                            &canonical_statement,
                            store_material,
                            runtime_component_trees,
                            auxiliary_roots,
                        );
                        assert!(
                            session
                                .verified_evaluator_key_store
                                .replace(verified_store)
                                .is_none(),
                        );
                        Ok(())
                    })
                })
                .expect("evaluator terminal commit uses the exact preflighted session");
        },
    )
}

fn commit_verified_evaluator_store(
    session_handle: u32,
    accepted_setup_assembly_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let prepared_slot =
        preflight_verified_evaluator_key_store_slot(accepted_setup_assembly_handle)?;
    let store = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow_mut().with_mut(session_handle, |session| {
            session
                .verified_evaluator_key_store
                .take()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)
        })
    })?;
    commit_preflighted_verified_evaluator_key_store(prepared_slot, store);
    Ok(())
}

fn encode_store_source_request_to_array(
    request: &SelectedEvaluatorStoreSourceReadRequest,
) -> Result<[u8; STORE_SOURCE_READ_REQUEST_BYTE_LENGTH], CommonProofRuntimeError> {
    let mut encoded = [0_u8; STORE_SOURCE_READ_REQUEST_BYTE_LENGTH];
    encode_store_source_request(request, &mut encoded)?;
    Ok(encoded)
}

fn encode_store_source_request(
    request: &SelectedEvaluatorStoreSourceReadRequest,
    output: &mut [u8],
) -> Result<(), CommonProofRuntimeError> {
    if output.len() != STORE_SOURCE_READ_REQUEST_BYTE_LENGTH {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let physical_component_ordinal = u32::try_from(request.physical_component_ordinal())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let source_ordinal = u32::try_from(request.source_ordinal())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let chunk_index = u32::try_from(request.chunk_index())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    let byte_length = u32::try_from(request.byte_length())
        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
    output[0..4].copy_from_slice(&physical_component_ordinal.to_le_bytes());
    output[4..8].copy_from_slice(&source_ordinal.to_le_bytes());
    output[8..72].copy_from_slice(&request.source_material_root());
    output[72..136].copy_from_slice(&request.source_stream_digest());
    output[136..144].copy_from_slice(&request.source_stream_total_byte_length().to_le_bytes());
    output[144..152].copy_from_slice(&request.source_stream_byte_offset().to_le_bytes());
    output[152..156].copy_from_slice(&chunk_index.to_le_bytes());
    output[156..160].copy_from_slice(&byte_length.to_le_bytes());
    Ok(())
}

fn refusal_status(reason: RefusalReason) -> u32 {
    reason.canonical_code() as u32
}

fn runtime_error_status(error: EvaluatorAggregateRuntimeError) -> u32 {
    match error {
        EvaluatorAggregateRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        EvaluatorAggregateRuntimeError::Refusal(reason) => refusal_status(reason),
        EvaluatorAggregateRuntimeError::ActionRandomnessRuntime(status)
        | EvaluatorAggregateRuntimeError::StateRuntime(status) => status,
        EvaluatorAggregateRuntimeError::InvalidInput => {
            refusal_status(RefusalReason::WrongTypeOrLength)
        }
        EvaluatorAggregateRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        EvaluatorAggregateRuntimeError::Profile(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        EvaluatorAggregateRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        EvaluatorAggregateRuntimeError::AggregatePlan(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        EvaluatorAggregateRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        EvaluatorAggregateRuntimeError::Prover(error) => {
            let _ = error;
            refusal_status(RefusalReason::InvalidArithmeticRelation)
        }
    }
}

unsafe fn exact_input<'input>(
    pointer: *const u8,
    byte_length: usize,
) -> Result<&'input [u8], EvaluatorAggregateRuntimeError> {
    if pointer.is_null() || byte_length == 0 {
        return Err(EvaluatorAggregateRuntimeError::InvalidInput);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, byte_length) })
}

unsafe fn exact_output<'output>(
    pointer: *mut u8,
    byte_length: usize,
) -> Result<&'output mut [u8], EvaluatorAggregateRuntimeError> {
    if pointer.is_null() || byte_length == 0 {
        return Err(EvaluatorAggregateRuntimeError::InvalidInput);
    }
    Ok(unsafe { slice::from_raw_parts_mut(pointer, byte_length) })
}

unsafe fn write_status(pointer: *mut u32, status: u32) {
    if !pointer.is_null() {
        unsafe { pointer.write(status) };
    }
}

#[unsafe(no_mangle)]
pub const extern "C" fn sealed_lattice_evaluator_aggregate_store_source_request_byte_length() -> u32
{
    STORE_SOURCE_READ_REQUEST_BYTE_LENGTH as u32
}

/// # Safety
///
/// A non-null `status_pointer` must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_begin_store_construction(
    prepackage_catalog_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = EvaluatorAggregateSession::begin(prepackage_catalog_handle).and_then(|session| {
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| registry.borrow_mut().retain(session))
    });
    match result {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
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

/// # Safety
///
/// Every non-null output pointer must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_store_construction_poll(
    session_handle: u32,
    first_value_pointer: *mut u32,
    second_value_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow_mut().with_mut(session_handle, |session| {
            let poll = session.poll_construction()?;
            let (first, second) = if poll == STORE_POLL_OUTPUT_CHUNK_READY {
                let (chunk_index, byte_length) = session.pending_output_description()?;
                (
                    u32::try_from(chunk_index)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    u32::try_from(byte_length)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                )
            } else {
                (0, 0)
            };
            Ok((poll, first, second))
        })
    });
    match result {
        Ok((poll, first, second)) => {
            if !first_value_pointer.is_null() {
                unsafe { first_value_pointer.write(first) };
            }
            if !second_value_pointer.is_null() {
                unsafe { second_value_pointer.write(second) };
            }
            unsafe { write_status(status_pointer, 0) };
            poll
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

/// # Safety
///
/// `output_pointer` must point to its declared non-empty writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_copy_store_source_request(
    session_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                session.copy_source_request(output)
            })
        })?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

/// # Safety
///
/// Each input pointer must point to its declared non-empty readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_supply_store_source_range(
    session_handle: u32,
    request_pointer: *const u8,
    request_byte_length: usize,
    source_pointer: *const u8,
    source_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        let request = unsafe { exact_input(request_pointer, request_byte_length) }?;
        let source = unsafe { exact_input(source_pointer, source_byte_length) }?;
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(session_handle, |session| {
                session.supply_source_range(request, source)
            })
        })?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

/// # Safety
///
/// `output_pointer` must point to its declared non-empty writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_copy_store_output_chunk(
    session_handle: u32,
    chunk_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                session.copy_output_chunk(
                    usize::try_from(chunk_index)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    output,
                )
            })
        })?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_acknowledge_store_output_chunk(
    session_handle: u32,
    chunk_index: u32,
) -> u32 {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(session_handle, |session| {
                session.acknowledge_output_chunk(
                    usize::try_from(chunk_index)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                )
            })
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_finish_store_construction(
    session_handle: u32,
) -> u32 {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(
                session_handle,
                EvaluatorAggregateSession::finish_construction,
            )
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

/// # Safety
///
/// `output_pointer` must point to its declared non-empty writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_describe_store(
    session_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        if output.len() != STORE_DESCRIPTOR_DESCRIPTION_BYTE_LENGTH {
            return Err(EvaluatorAggregateRuntimeError::InvalidInput);
        }
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                let descriptor = session.output()?.store_descriptor();
                output[..8].copy_from_slice(&descriptor.total_byte_length.to_le_bytes());
                output[8..].copy_from_slice(descriptor.full_object_digest.as_bytes());
                Ok(())
            })
        })?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_begin_runtime_component_tree(
    session_handle: u32,
    selected_suite_handle: u32,
    logical_component_ordinal: u32,
) -> u32 {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(session_handle, |session| {
                session.begin_runtime_tree(
                    selected_suite_handle,
                    usize::try_from(logical_component_ordinal)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                )
            })
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

/// # Safety
///
/// `chunk_pointer` must point to its declared non-empty readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_absorb_runtime_component_chunk(
    session_handle: u32,
    logical_component_ordinal: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        let chunk = unsafe { exact_input(chunk_pointer, chunk_byte_length) }?;
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(session_handle, |session| {
                session.absorb_runtime_tree_chunk(
                    usize::try_from(logical_component_ordinal)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    usize::try_from(chunk_index)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    chunk,
                )
            })
        })?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_finish_runtime_component_tree(
    session_handle: u32,
    logical_component_ordinal: u32,
) -> u32 {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(session_handle, |session| {
                session.finish_runtime_tree(
                    usize::try_from(logical_component_ordinal)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                )
            })
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_finalize_statement(
    session_handle: u32,
    selected_suite_handle: u32,
) -> u32 {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(session_handle, |session| {
                session.finalize_statement_and_begin_material_pass(selected_suite_handle)
            })
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

/// # Safety
///
/// A non-null `status_pointer` must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_application_statement_byte_length(
    session_handle: u32,
    status_pointer: *mut u32,
) -> u64 {
    let result = EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry.borrow().with(session_handle, |session| {
            u64::try_from(session.canonical_statement()?.len())
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)
        })
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

/// # Safety
///
/// `output_pointer` must point to its declared non-empty writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_copy_application_statement(
    session_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        let output = unsafe { exact_output(output_pointer, output_byte_length) }?;
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow().with(session_handle, |session| {
                let statement = session.canonical_statement()?;
                if output.len() != statement.len() {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding);
                }
                output.copy_from_slice(statement);
                Ok(())
            })
        })?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

/// # Safety
///
/// `chunk_pointer` must point to its declared non-empty readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_absorb_store_material_chunk(
    session_handle: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        let chunk = unsafe { exact_input(chunk_pointer, chunk_byte_length) }?;
        EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(session_handle, |session| {
                session.absorb_store_material_chunk(
                    usize::try_from(chunk_index)
                        .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?,
                    chunk,
                )
            })
        })?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_finish_store_material(
    session_handle: u32,
) -> u32 {
    EVALUATOR_AGGREGATE_SESSION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .with_mut(
                session_handle,
                EvaluatorAggregateSession::finish_store_material,
            )
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi(
    session_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    status_pointer: *mut u32,
    generation_mode: EvaluatorGenerationMode,
) -> u32 {
    let result: Result<u32, EvaluatorAggregateRuntimeError> = (|| {
        let state_capability = unsafe {
            exact_input(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let checkpoint_lineage = unsafe {
            exact_input(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }?;
        let checkpoint_lineage: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] = checkpoint_lineage
            .try_into()
            .map_err(|_| EvaluatorAggregateRuntimeError::InvalidInput)?;
        prepare_evaluator_generation(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_capability,
            verified_reservation_handle,
            checkpoint_lineage,
            generation_mode,
        )
    })();
    match result {
        Ok(adapter_handle) => {
            unsafe { write_status(status_pointer, 0) };
            adapter_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// # Safety
///
/// The capability and checkpoint pointers must point to their declared
/// non-empty readable ranges. A non-null `status_pointer` must point to one
/// writable `u32` in WASM memory.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_prepare_generation(
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
        prepare_generation_from_ffi(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            status_pointer,
            EvaluatorGenerationMode::Fresh,
        )
    }
}

/// # Safety
///
/// The capability and checkpoint pointers must point to their declared
/// non-empty readable ranges. A non-null `status_pointer` must point to one
/// writable `u32` in WASM memory.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_prepare_resumed_generation(
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
        prepare_generation_from_ffi(
            session_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            status_pointer,
            EvaluatorGenerationMode::Resume,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_commit_generated_proof(
    session_handle: u32,
    generated_common_proof_handle: u32,
) -> u32 {
    commit_generated_evaluator_proof(session_handle, generated_common_proof_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_contribute_package(
    session_handle: u32,
    package_builder_handle: u32,
    generated_common_proof_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
) -> u32 {
    let result: Result<(), EvaluatorAggregateRuntimeError> = (|| {
        if canonical_application_statement_byte_length
            > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
        {
            return Err(EvaluatorAggregateRuntimeError::InvalidInput);
        }
        let statement = unsafe {
            exact_input(
                canonical_application_statement_pointer,
                canonical_application_statement_byte_length,
            )
        }?;
        contribute_evaluator_package(
            session_handle,
            package_builder_handle,
            generated_common_proof_handle,
            statement,
        )?;
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_take_package_statement_source(
    session_handle: u32,
) -> u32 {
    take_package_statement_source(session_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// # Safety
///
/// A non-null `status_pointer` must point to one writable `u32` in WASM memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_evaluator_aggregate_prepare_verification(
    selected_suite_handle: u32,
    session_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match prepare_evaluator_verification_adapter(selected_suite_handle, session_handle) {
        Ok(adapter_handle) => {
            unsafe { write_status(status_pointer, 0) };
            adapter_handle
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
pub extern "C" fn sealed_lattice_evaluator_aggregate_finish_verification(
    session_handle: u32,
    verified_common_proof_handle: u32,
) -> u32 {
    finish_evaluator_verification(session_handle, verified_common_proof_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_commit_verified_store(
    session_handle: u32,
    accepted_setup_assembly_handle: u32,
) -> u32 {
    commit_verified_evaluator_store(session_handle, accepted_setup_assembly_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_evaluator_aggregate_discard_session(session_handle: u32) -> u32 {
    let result = EVALUATOR_AGGREGATE_SESSION_REGISTRY
        .with(|registry| registry.borrow_mut().take(session_handle));
    match result {
        Ok(mut session) => {
            if let Some(statement_source) = session.package_statement_source.take()
                && let Err(error) = restore_prepackage_evaluator_statement_source(
                    session.prepackage_catalog_handle,
                    statement_source,
                )
            {
                return super::runtime_ffi::runtime_error_status(error);
            }
            0
        }
        Err(error) => super::runtime_ffi::runtime_error_status(error),
    }
}
