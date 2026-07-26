//! Browser/WASM positive verification ingress for the selected RKG phases.
//!
//! The accepted setup package supplies the exact proof slot and statement.
//! Component bytes are then streamed through the canonical component decoder,
//! so only recomputed trees and authenticated material can reach the existing
//! typed round-one, aggregate, and round-two terminals.

use core::slice;
use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::setup::{
        retain_relinearization_round_one_aggregate_verification_terminal_source,
        retain_relinearization_round_one_verification_terminal_source,
        retain_relinearization_round_two_verification_terminal_source,
        with_accepted_setup_verification_sources,
    },
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, ProofApplicationBinding, ProofApplicationSlot,
        ProofApplicationSlotCeilings, ProofObjectHeader, StreamDescriptor,
    },
};

use super::application_statement::decode_selected_relinearization_round_two_statement;
use super::runtime_ffi::{
    retain_common_proof_verification_family_adapter_from_upstream, with_common_proof_selected_suite,
};
use super::{
    CommonProofRelationPlanCapability, CommonProofRuntimeError,
    CommonProofSelectedSuiteCapabilityHandle, ComponentMaterialOwnershipBinding,
    KeySwitchComponentMaterialTopology, KeySwitchComponentPublicPolynomialStream,
    RecomputedKeySwitchComponentTree, SelectedApplicationStatementContext,
    SelectedEvaluatorEntryKind, SetupPublicPolynomialContext, SetupPublicPolynomialRootRole,
    VerifiedCommonProofStatementSource, VerifiedKeyRelationColumnEvaluator,
    VerifiedStatementOwnedTree, decode_selected_relinearization_round_one_aggregate_statement,
    decode_selected_relinearization_round_one_statement, selected_evaluator_entry_positions,
    selected_proof_runtime_limits, selected_relation_plan_check_context, selected_relation_plans,
};

const MAXIMUM_ACTIVE_RELINEARIZATION_VERIFICATION_INGRESSES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelinearizationVerificationFamily {
    One,
    OneAggregate,
    Two,
}

impl RelinearizationVerificationFamily {
    const fn schema_identifier(self) -> u16 {
        match self {
            Self::One => {
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            }
            Self::OneAggregate => {
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            }
            Self::Two => {
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
            }
        }
    }

    const fn component_count(self) -> usize {
        match self {
            Self::One | Self::OneAggregate => 2,
            Self::Two => 1,
        }
    }

    const fn uses_verifier_columns(self) -> bool {
        !matches!(self, Self::OneAggregate)
    }
}

struct RelinearizationVerificationComponentIngress {
    topology: KeySwitchComponentMaterialTopology,
    context: SetupPublicPolynomialContext,
    expected_contribution_root: [u8; 64],
    recomputed: Option<RecomputedKeySwitchComponentTree>,
}

struct ActiveRelinearizationComponentIngress {
    component_ordinal: usize,
    stream: KeySwitchComponentPublicPolynomialStream,
}

struct RelinearizationVerificationIngress {
    family: RelinearizationVerificationFamily,
    selected_suite_handle: u32,
    verification_assembly_handle: u32,
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: Vec<u8>,
    roster_hash: [u8; 64],
    statement_source: Option<VerifiedCommonProofStatementSource>,
    statement_trees: Option<Vec<VerifiedStatementOwnedTree>>,
    verified_column_evaluator: Option<VerifiedKeyRelationColumnEvaluator>,
    ordered_components: Vec<RelinearizationVerificationComponentIngress>,
    next_component_ordinal: usize,
    active_component: Option<ActiveRelinearizationComponentIngress>,
}

impl RelinearizationVerificationIngress {
    fn begin_component(
        &mut self,
        component_ordinal: usize,
        stream_descriptor: StreamDescriptor,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.active_component.is_some() || component_ordinal != self.next_component_ordinal {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let component = self
            .ordered_components
            .get(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        if component.recomputed.is_some() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let statement_source = self
            .statement_source
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let application_slot = statement_source
            .proof_application_binding()
            .application_slot();
        let ownership_binding = ComponentMaterialOwnershipBinding::from_verified_application(
            application_slot.suite_identifier().into_bytes(),
            application_slot.action_context_hash().into_bytes(),
            statement_source.application_statement_hash().into_bytes(),
        );
        let stream = KeySwitchComponentPublicPolynomialStream::begin(
            component.topology.clone(),
            ownership_binding,
            stream_descriptor,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        self.active_component = Some(ActiveRelinearizationComponentIngress {
            component_ordinal,
            stream,
        });
        Ok(())
    }

    fn absorb_component_chunk(
        &mut self,
        component_ordinal: usize,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let active = self
            .active_component
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if active.component_ordinal != component_ordinal {
            self.active_component = Some(active);
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let ActiveRelinearizationComponentIngress {
            component_ordinal,
            mut stream,
        } = active;
        match stream.absorb_chunk(chunk_index, chunk_bytes) {
            Ok(()) => {
                self.active_component = Some(ActiveRelinearizationComponentIngress {
                    component_ordinal,
                    stream,
                });
                Ok(())
            }
            Err(_) => Err(CommonProofRuntimeError::WrongVerificationBinding),
        }
    }

    fn finish_component(
        &mut self,
        component_ordinal: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        let active = self
            .active_component
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if active.component_ordinal != component_ordinal
            || component_ordinal != self.next_component_ordinal
        {
            self.active_component = Some(active);
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let component = self
            .ordered_components
            .get_mut(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let recomputed = active
            .stream
            .finish(component.context.clone())
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if recomputed.tree().root() != component.expected_contribution_root {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        component.recomputed = Some(recomputed);
        self.next_component_ordinal = self
            .next_component_ordinal
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.active_component.is_none()
            && self.next_component_ordinal == self.family.component_count()
            && self.next_component_ordinal == self.ordered_components.len()
            && self
                .ordered_components
                .iter()
                .all(|component| component.recomputed.is_some())
    }
}

struct RelinearizationVerificationIngressRegistry {
    next_handle: u32,
    ingresses: BTreeMap<u32, RelinearizationVerificationIngress>,
}

impl Default for RelinearizationVerificationIngressRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            ingresses: BTreeMap::new(),
        }
    }
}

impl RelinearizationVerificationIngressRegistry {
    fn retain(
        &mut self,
        ingress: RelinearizationVerificationIngress,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.ingresses.len() >= MAXIMUM_ACTIVE_RELINEARIZATION_VERIFICATION_INGRESSES
            || self.next_handle == 0
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if self.ingresses.insert(handle, ingress).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(handle)
    }

    fn with_mut<Output>(
        &mut self,
        handle: u32,
        inspect: impl FnOnce(
            &mut RelinearizationVerificationIngress,
        ) -> Result<Output, CommonProofRuntimeError>,
    ) -> Result<Output, CommonProofRuntimeError> {
        let ingress = self
            .ingresses
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        inspect(ingress)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<RelinearizationVerificationIngress, CommonProofRuntimeError> {
        self.ingresses
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }
}

thread_local! {
    static RELINEARIZATION_VERIFICATION_INGRESS_REGISTRY:
        RefCell<RelinearizationVerificationIngressRegistry> =
            RefCell::new(RelinearizationVerificationIngressRegistry::default());
}

struct DecodedRelinearizationVerificationStatement {
    roster_position: Option<u16>,
    schedule_position: u32,
    ordered_components: Vec<([u8; 64], SetupPublicPolynomialContext)>,
}

fn selected_relinearization_catalog_level_and_schedule()
-> Result<(usize, u32), CommonProofRuntimeError> {
    let mut selected = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
        .into_iter()
        .filter_map(|position| match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { catalog_level } => {
                Some((catalog_level, position.schedule_position()))
            }
            SelectedEvaluatorEntryKind::Galois { .. } => None,
        });
    let selected_position = selected
        .next()
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
    if selected.next().is_some() {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(selected_position)
}

fn decode_relinearization_verification_statement(
    family: RelinearizationVerificationFamily,
    canonical_application_statement_bytes: &[u8],
    protocol_version: u16,
    suite_identifier: [u8; 64],
    expected_schedule_position: u32,
) -> Result<DecodedRelinearizationVerificationStatement, CommonProofRuntimeError> {
    let context = SelectedApplicationStatementContext::new(
        protocol_version,
        suite_identifier,
        Some(expected_schedule_position),
        None,
    );
    match family {
        RelinearizationVerificationFamily::One => {
            let statement = decode_selected_relinearization_round_one_statement(
                canonical_application_statement_bytes,
                context,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let schedule_position = statement.schedule_position();
            if schedule_position != expected_schedule_position {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let ordered_components = [
                (
                    statement.round_one_left_root(),
                    SetupPublicPolynomialContext::new(
                        statement.setup_proof_context_hash(),
                        SetupPublicPolynomialRootRole::RelinearizationRoundOneLeft,
                        Some(statement.participant_identity()),
                        Some(statement.roster_position()),
                        Some(schedule_position),
                        None,
                    ),
                ),
                (
                    statement.round_one_right_root(),
                    SetupPublicPolynomialContext::new(
                        statement.setup_proof_context_hash(),
                        SetupPublicPolynomialRootRole::RelinearizationRoundOneRight,
                        Some(statement.participant_identity()),
                        Some(statement.roster_position()),
                        Some(schedule_position),
                        None,
                    ),
                ),
            ]
            .into_iter()
            .map(|(root, context)| {
                context
                    .map(|context| (root, context))
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
            })
            .collect::<Result<Vec<_>, _>>()?;
            Ok(DecodedRelinearizationVerificationStatement {
                roster_position: Some(statement.roster_position()),
                schedule_position,
                ordered_components,
            })
        }
        RelinearizationVerificationFamily::OneAggregate => {
            let statement = decode_selected_relinearization_round_one_aggregate_statement(
                canonical_application_statement_bytes,
                context,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let schedule_position = statement.schedule_position();
            if schedule_position != expected_schedule_position {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let ordered_components = [
                (
                    statement.aggregate_left_root(),
                    SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneLeft,
                ),
                (
                    statement.aggregate_right_root(),
                    SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight,
                ),
            ]
            .into_iter()
            .map(|(root, role)| {
                SetupPublicPolynomialContext::new(
                    statement.setup_proof_context_hash(),
                    role,
                    None,
                    None,
                    Some(schedule_position),
                    None,
                )
                .map(|context| (root, context))
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
            })
            .collect::<Result<Vec<_>, _>>()?;
            Ok(DecodedRelinearizationVerificationStatement {
                roster_position: None,
                schedule_position,
                ordered_components,
            })
        }
        RelinearizationVerificationFamily::Two => {
            let statement = decode_selected_relinearization_round_two_statement(
                canonical_application_statement_bytes,
                context,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let schedule_position = statement.schedule_position();
            if schedule_position != expected_schedule_position {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let component_context = SetupPublicPolynomialContext::new(
                statement.setup_proof_context_hash(),
                SetupPublicPolynomialRootRole::RelinearizationRoundTwo,
                Some(statement.participant_identity()),
                Some(statement.roster_position()),
                Some(schedule_position),
                None,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            Ok(DecodedRelinearizationVerificationStatement {
                roster_position: Some(statement.roster_position()),
                schedule_position,
                ordered_components: vec![(statement.contribution_root(), component_context)],
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn begin_relinearization_verification_ingress(
    family: RelinearizationVerificationFamily,
    selected_suite_handle: u32,
    verification_assembly_handle: u32,
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<u32, CommonProofRuntimeError> {
    if selected_suite_handle == 0
        || verification_assembly_handle == 0
        || prepackage_catalog_handle == 0
        || canonical_application_statement_bytes.is_empty()
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let (catalog_level, expected_schedule_position) =
        selected_relinearization_catalog_level_and_schedule()?;
    let topology = with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
            selected_suite,
            catalog_level,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
    })??;
    let canonical_application_statement_bytes = canonical_application_statement_bytes.to_vec();
    let ingress = with_accepted_setup_verification_sources(
        verification_assembly_handle,
        |package, verified_public_randomness| {
            let verified_context = verified_public_randomness.context();
            let decoded = decode_relinearization_verification_statement(
                family,
                &canonical_application_statement_bytes,
                verified_context.protocol_version(),
                verified_context.suite_identifier().into_bytes(),
                expected_schedule_position,
            )?;
            let schema_identifier = family.schema_identifier();
            let selected_slots = package
                .selected_public_proof_slots()
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let mut matching_descriptor_indices = selected_slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| {
                    slot.application_statement_schema_identifier() == schema_identifier
                        && slot.roster_position() == decoded.roster_position
                        && slot.schedule_position() == Some(decoded.schedule_position)
                })
                .map(|(descriptor_index, _)| descriptor_index);
            let proof_descriptor_index = matching_descriptor_indices
                .next()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            if matching_descriptor_indices.next().is_some() {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let proof_stream_descriptor = package
                .ordered_proof_descriptors()
                .get(proof_descriptor_index)
                .cloned()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let application_slot = ProofApplicationSlot::new(
                verified_context.suite_identifier(),
                verified_context.ceremony_context_hash(),
                verified_context.action_context_hash(),
                schema_identifier,
                decoded.roster_position,
                Some(decoded.schedule_position),
                None,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let proof_header = ProofObjectHeader::from_canonical_application_statement(
                canonical_application_statement_bytes.clone(),
                &CanonicalDecodeLimits::default(),
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let proof_application_binding = ProofApplicationBinding::new(
                application_slot,
                proof_header
                    .proof_header_hash()
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
                proof_stream_descriptor,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let relation_plan_artifact = selected_relation_plans()
                .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?
                .into_iter()
                .find(|artifact| {
                    artifact.application_statement_schema_identifier() == schema_identifier
                })
                .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
            let relation_plan = relation_plan_artifact.compiled_plan();
            let relation_plan_variant = relation_plan
                .select_variant(Some(decoded.schedule_position), None)
                .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
            let runtime_limits = selected_proof_runtime_limits(
                schema_identifier,
                &canonical_application_statement_bytes,
                relation_plan_variant,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
            let relation_context = selected_relation_plan_check_context(schema_identifier)
                .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
            let verified_column_evaluator = if family.uses_verifier_columns() {
                Some(
                    VerifiedKeyRelationColumnEvaluator::from_verified_public_randomness(
                        verified_public_randomness,
                        &relation_plan_artifact,
                        relation_plan_variant,
                    )
                    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?,
                )
            } else {
                None
            };
            let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
                relation_plan,
                &relation_context,
                Some(decoded.schedule_position),
                None,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
            let statement_source =
                VerifiedCommonProofStatementSource::from_exact_family_verified_accepted_setup_package(
                    package,
                    verified_public_randomness,
                    proof_descriptor_index,
                    canonical_application_statement_bytes.clone(),
                    proof_application_binding,
                    relation_plan_capability,
                    runtime_limits,
                )?;
            let statement_trees =
                VerifiedStatementOwnedTree::from_verified_accepted_setup_statement_source(
                    &statement_source,
                    verified_public_randomness,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let ordered_components = decoded
                .ordered_components
                .into_iter()
                .map(|(expected_contribution_root, context)| {
                    RelinearizationVerificationComponentIngress {
                        topology: topology.clone(),
                        context,
                        expected_contribution_root,
                        recomputed: None,
                    }
                })
                .collect::<Vec<_>>();
            if ordered_components.len() != family.component_count() {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            Ok(RelinearizationVerificationIngress {
                family,
                selected_suite_handle,
                verification_assembly_handle,
                prepackage_catalog_handle,
                canonical_application_statement_bytes: canonical_application_statement_bytes
                    .clone(),
                roster_hash: verified_context.roster_hash().into_bytes(),
                statement_source: Some(statement_source),
                statement_trees: Some(statement_trees),
                verified_column_evaluator,
                ordered_components,
                next_component_ordinal: 0,
                active_component: None,
            })
        },
    )?;
    RELINEARIZATION_VERIFICATION_INGRESS_REGISTRY
        .with(|registry| registry.borrow_mut().retain(ingress))
}

fn prepare_relinearization_verification(
    ingress_handle: u32,
) -> Result<(u32, u32), CommonProofRuntimeError> {
    let mut ingress = RELINEARIZATION_VERIFICATION_INGRESS_REGISTRY
        .with(|registry| registry.borrow_mut().take(ingress_handle))?;
    if !ingress.is_complete() {
        return Err(CommonProofRuntimeError::WrongOperationPhase);
    }
    let statement_source = ingress
        .statement_source
        .take()
        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
    let statement_trees = ingress
        .statement_trees
        .take()
        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
    let terminal_statement_trees = statement_trees.clone();
    let selected_suite_handle =
        CommonProofSelectedSuiteCapabilityHandle::from_identifier(ingress.selected_suite_handle);
    let adapter_handle = match ingress.family {
        RelinearizationVerificationFamily::One | RelinearizationVerificationFamily::Two => {
            let verified_column_evaluator = ingress
                .verified_column_evaluator
                .take()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
                upstream_inputs.prepare_statement_tree_family_verification(
                    &selected_suite_handle,
                    statement_source,
                    statement_trees,
                    Box::new(verified_column_evaluator),
                )
            })?
        }
        RelinearizationVerificationFamily::OneAggregate => {
            if ingress.verified_column_evaluator.is_some() {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
                upstream_inputs.prepare_statement_tree_family_verification_without_evaluator(
                    &selected_suite_handle,
                    statement_source,
                    statement_trees,
                )
            })?
        }
    };

    let mut recomputed_components = ingress
        .ordered_components
        .into_iter()
        .map(|component| {
            component
                .recomputed
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let terminal_result = match ingress.family {
        RelinearizationVerificationFamily::One => {
            let right = recomputed_components
                .pop()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            let left = recomputed_components
                .pop()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            if !recomputed_components.is_empty() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            let (left_material, left_tree) = left.into_parts();
            let (right_material, right_tree) = right.into_parts();
            retain_relinearization_round_one_verification_terminal_source(
                ingress.verification_assembly_handle,
                ingress.prepackage_catalog_handle,
                ingress.canonical_application_statement_bytes,
                ingress.roster_hash,
                terminal_statement_trees,
                [left_tree, right_tree],
                [left_material, right_material],
            )
        }
        RelinearizationVerificationFamily::OneAggregate => {
            let right = recomputed_components
                .pop()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            let left = recomputed_components
                .pop()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            if !recomputed_components.is_empty() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            let (left_material, left_tree) = left.into_parts();
            let (right_material, right_tree) = right.into_parts();
            retain_relinearization_round_one_aggregate_verification_terminal_source(
                ingress.prepackage_catalog_handle,
                ingress.canonical_application_statement_bytes,
                ingress.roster_hash,
                terminal_statement_trees,
                [left_tree, right_tree],
                [left_material, right_material],
            )
        }
        RelinearizationVerificationFamily::Two => {
            let component = recomputed_components
                .pop()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            if !recomputed_components.is_empty() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            let (material, tree) = component.into_parts();
            retain_relinearization_round_two_verification_terminal_source(
                ingress.prepackage_catalog_handle,
                ingress.canonical_application_statement_bytes,
                ingress.roster_hash,
                terminal_statement_trees,
                tree,
                material,
            )
        }
    };
    match terminal_result {
        Ok(terminal_source_handle) => Ok((adapter_handle, terminal_source_handle)),
        Err(error) => {
            let cleanup_status =
                super::runtime_ffi::sealed_lattice_common_proof_discard_verification_family_adapter(
                    adapter_handle,
                );
            assert_eq!(
                cleanup_status, 0,
                "unpublished RKG verifier adapter remains live"
            );
            Err(error)
        }
    }
}

unsafe fn variable_input<'input>(
    pointer: *const u8,
    byte_length: usize,
) -> Result<&'input [u8], CommonProofRuntimeError> {
    if pointer.is_null() || byte_length == 0 {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, byte_length) })
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

macro_rules! relinearization_verification_ingress_entry_point {
    ($name:ident, $family:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            selected_suite_handle: u32,
            verification_assembly_handle: u32,
            prepackage_catalog_handle: u32,
            canonical_application_statement_pointer: *const u8,
            canonical_application_statement_byte_length: usize,
            status_pointer: *mut u32,
        ) -> u32 {
            let result = (|| {
                let canonical_application_statement_bytes = unsafe {
                    variable_input(
                        canonical_application_statement_pointer,
                        canonical_application_statement_byte_length,
                    )
                }?;
                begin_relinearization_verification_ingress(
                    $family,
                    selected_suite_handle,
                    verification_assembly_handle,
                    prepackage_catalog_handle,
                    canonical_application_statement_bytes,
                )
            })();
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
    };
}

relinearization_verification_ingress_entry_point!(
    sealed_lattice_relinearization_round_one_verification_ingress_begin,
    RelinearizationVerificationFamily::One
);
relinearization_verification_ingress_entry_point!(
    sealed_lattice_relinearization_round_one_aggregate_verification_ingress_begin,
    RelinearizationVerificationFamily::OneAggregate
);
relinearization_verification_ingress_entry_point!(
    sealed_lattice_relinearization_round_two_verification_ingress_begin,
    RelinearizationVerificationFamily::Two
);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_verification_component_begin(
    ingress_handle: u32,
    component_ordinal: u32,
    stream_descriptor_pointer: *const u8,
    stream_descriptor_byte_length: usize,
) -> u32 {
    let result = (|| {
        let descriptor_bytes =
            unsafe { variable_input(stream_descriptor_pointer, stream_descriptor_byte_length) }?;
        let stream_descriptor =
            StreamDescriptor::decode(descriptor_bytes, &CanonicalDecodeLimits::default())
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        RELINEARIZATION_VERIFICATION_INGRESS_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(ingress_handle, |ingress| {
                ingress.begin_component(component_ordinal, stream_descriptor)
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_verification_component_absorb_chunk(
    ingress_handle: u32,
    component_ordinal: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let result = (|| {
        let chunk_bytes = unsafe { variable_input(chunk_pointer, chunk_byte_length) }?;
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let chunk_index = usize::try_from(chunk_index)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        RELINEARIZATION_VERIFICATION_INGRESS_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(ingress_handle, |ingress| {
                ingress.absorb_component_chunk(component_ordinal, chunk_index, chunk_bytes)
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_verification_component_finish(
    ingress_handle: u32,
    component_ordinal: u32,
) -> u32 {
    usize::try_from(component_ordinal)
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        .and_then(|component_ordinal| {
            RELINEARIZATION_VERIFICATION_INGRESS_REGISTRY.with(|registry| {
                registry.borrow_mut().with_mut(ingress_handle, |ingress| {
                    ingress.finish_component(component_ordinal)
                })
            })
        })
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_relinearization_prepare_verification(
    ingress_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    if terminal_source_handle_output_pointer.is_null() {
        unsafe {
            write_status(
                status_pointer,
                super::runtime_ffi::runtime_error_status(
                    CommonProofRuntimeError::WrongVerificationBinding,
                ),
            )
        };
        return 0;
    }
    match prepare_relinearization_verification(ingress_handle) {
        Ok((adapter_handle, terminal_source_handle)) => {
            unsafe {
                terminal_source_handle_output_pointer.write(terminal_source_handle);
                write_status(status_pointer, 0);
            }
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
pub extern "C" fn sealed_lattice_relinearization_discard_verification_ingress(
    ingress_handle: u32,
) -> u32 {
    RELINEARIZATION_VERIFICATION_INGRESS_REGISTRY
        .with(|registry| registry.borrow_mut().take(ingress_handle).map(|_| ()))
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}
