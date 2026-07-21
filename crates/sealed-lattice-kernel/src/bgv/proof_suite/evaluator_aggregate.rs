//! Exact selected-suite construction for the complete evaluator aggregate
//! proof family.

use std::collections::VecDeque;

#[cfg(test)]
use crate::{
    bgv::evaluator::top_k::{
        SELECTED_RELINEARIZATION_KEY_LEVEL, TRACE_GALOIS_PATHS, TRACE_KEY_LEVEL,
    },
    foundation::{derive_canonical_stream_descriptor, selected_suite_capability_for_tests},
};

use crate::{
    bgv::{
        key_switch_topology::{KEY_SWITCH_DATA_PRIMES_PER_BLOCK, canonical_residue_byte_length},
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
    },
    foundation::{
        CanonicalStreamDomain, CanonicalStreamReadbackVerifier, CanonicalStreamVerifier,
        CanonicalStreamWriter, FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings,
        RefusalReason, SelectedSuiteCapability, StreamDescriptor, VerificationResult,
        VerifiedCanonicalStreamSummary,
    },
};

use super::{
    CompiledRelationPlan, EvaluatorKeyAggregateEntryPlanInput, EvaluatorKeyAggregatePlanInput,
    EvaluatorKeyAggregateVariantInput, PublicAggregateRelationGeometry, RelationPlanError,
    SelectedEvaluatorEntryKind, SelectedEvaluatorEntryPosition, SuiteModulusReference,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedEvaluatorRuntimeRoot,
    VerifiedRelinearizationAggregateMaterial,
    application_statement::{
        SelectedApplicationStatementError, SelectedEvaluatorAggregateEntryInput,
        canonical_selected_evaluator_aggregate_statement,
    },
    compile_evaluator_key_aggregate_relation_plan,
    component_material_stream::{
        ComponentMaterialOwnershipBinding, KeySwitchComponentMaterialTopology,
        VerifiedKeySwitchComponentMaterial, VerifiedKeySwitchComponentMaterialStream,
    },
    selected_evaluator_entry_positions,
    selected_profile::{
        SELECTED_EVALUATION_DOMAIN_SIZE, SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        selected_relation_plan_check_context,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedEvaluatorAggregatePlanError {
    WrongSelectedSuite,
    ApplicationStatement(SelectedApplicationStatementError),
    RelationPlan(RelationPlanError),
    CountOverflow,
}

impl From<SelectedApplicationStatementError> for SelectedEvaluatorAggregatePlanError {
    fn from(error: SelectedApplicationStatementError) -> Self {
        Self::ApplicationStatement(error)
    }
}

impl From<RelationPlanError> for SelectedEvaluatorAggregatePlanError {
    fn from(error: RelationPlanError) -> Self {
        Self::RelationPlan(error)
    }
}

/// Constructs the selected `0x1218` plan used in production. Each of its
/// twenty variants covers the complete ordered evaluator-key list selected by
/// that action's top count; one action authorizes one aggregate proof object.
pub(crate) fn selected_evaluator_aggregate_relation_plan()
-> Result<CompiledRelationPlan, SelectedEvaluatorAggregatePlanError> {
    if KEY_SWITCH_DATA_PRIMES_PER_BLOCK == 0
        || POLYNOMIAL_DEGREE < 2
        || POLYNOMIAL_DEGREE / 2
            != usize::try_from(SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE)
                .map_err(|_| SelectedEvaluatorAggregatePlanError::CountOverflow)?
    {
        return Err(SelectedEvaluatorAggregatePlanError::WrongSelectedSuite);
    }

    let ordered_variants = (1..=FOUNDATION_PROFILE.option_count)
        .map(|top_count| {
            let ordered_entries = selected_evaluator_entry_positions(top_count)?
                .into_iter()
                .map(|position| {
                    Ok(EvaluatorKeyAggregateEntryPlanInput {
                        schedule_position: position.schedule_position(),
                        ordered_runtime_component_moduli: ordered_runtime_component_moduli(
                            position,
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, SelectedEvaluatorAggregatePlanError>>()?;
            Ok(EvaluatorKeyAggregateVariantInput {
                top_count,
                ordered_entries,
            })
        })
        .collect::<Result<Vec<_>, SelectedEvaluatorAggregatePlanError>>()?;
    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(SelectedEvaluatorAggregatePlanError::WrongSelectedSuite)?;

    compile_evaluator_key_aggregate_relation_plan(
        &EvaluatorKeyAggregatePlanInput {
            geometry: PublicAggregateRelationGeometry {
                ring_degree: u64::try_from(POLYNOMIAL_DEGREE)
                    .map_err(|_| SelectedEvaluatorAggregatePlanError::CountOverflow)?,
                evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
                public_polynomial_column_degree_bound_exclusive:
                    SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
                participant_count: FOUNDATION_PROFILE.participant_count,
            },
            ordered_variants,
        },
        &relation_context,
    )
    .map_err(Into::into)
}

fn selected_entry_catalog_level(position: SelectedEvaluatorEntryPosition) -> usize {
    match position.key_kind() {
        SelectedEvaluatorEntryKind::Relinearization { catalog_level }
        | SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
    }
}

fn ordered_runtime_component_moduli(
    position: SelectedEvaluatorEntryPosition,
) -> Result<Vec<SuiteModulusReference>, SelectedEvaluatorAggregatePlanError> {
    let active_data_modulus_count = selected_entry_catalog_level(position)
        .checked_add(1)
        .filter(|count| *count <= DATA_PRIMES.len())
        .ok_or(SelectedEvaluatorAggregatePlanError::WrongSelectedSuite)?;
    let data_block_count = active_data_modulus_count
        .checked_add(KEY_SWITCH_DATA_PRIMES_PER_BLOCK - 1)
        .ok_or(SelectedEvaluatorAggregatePlanError::CountOverflow)?
        / KEY_SWITCH_DATA_PRIMES_PER_BLOCK;
    let extended_moduli = (0..active_data_modulus_count)
        .map(|modulus_index| {
            u16::try_from(modulus_index)
                .map(SuiteModulusReference::data)
                .map_err(|_| SelectedEvaluatorAggregatePlanError::CountOverflow)
        })
        .chain((0..SPECIAL_PRIMES.len()).map(|modulus_index| {
            u16::try_from(modulus_index)
                .map(SuiteModulusReference::special)
                .map_err(|_| SelectedEvaluatorAggregatePlanError::CountOverflow)
        }))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((0..data_block_count)
        .flat_map(|_| {
            extended_moduli
                .iter()
                .copied()
                .flat_map(|modulus_reference| [modulus_reference; 2])
        })
        .collect())
}

/// One exact selected-catalog entry in the verifier-authenticated evaluator
/// store. The stream range names bytes in the complete store transport; the
/// nested component capability authenticates its exact local descriptor for
/// restartable column replay.
#[derive(Debug)]
pub(crate) struct VerifiedEvaluatorKeyStoreComponentMaterial {
    position: SelectedEvaluatorEntryPosition,
    store_byte_offset: u64,
    material: VerifiedKeySwitchComponentMaterial,
    linked_relinearization_auxiliary: Option<VerifiedEvaluatorKeyStoreAuxiliaryMaterial>,
}

impl VerifiedEvaluatorKeyStoreComponentMaterial {
    pub(crate) const fn position(&self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) const fn store_byte_offset(&self) -> u64 {
        self.store_byte_offset
    }

    pub(crate) const fn material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.material
    }

    pub(crate) const fn linked_relinearization_auxiliary(
        &self,
    ) -> Option<&VerifiedEvaluatorKeyStoreAuxiliaryMaterial> {
        self.linked_relinearization_auxiliary.as_ref()
    }
}

/// The round-one aggregate polynomial paired with the runtime round-two
/// relinearization polynomial. Unlike a Galois common component, this value is
/// not a deterministic public sample and therefore remains an independently
/// authenticated range in the physical evaluator store.
#[derive(Debug)]
pub(crate) struct VerifiedEvaluatorKeyStoreAuxiliaryMaterial {
    store_byte_offset: u64,
    material: VerifiedKeySwitchComponentMaterial,
}

impl VerifiedEvaluatorKeyStoreAuxiliaryMaterial {
    pub(crate) const fn store_byte_offset(&self) -> u64 {
        self.store_byte_offset
    }

    pub(crate) const fn material(&self) -> &VerifiedKeySwitchComponentMaterial {
        &self.material
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvaluatorKeyStorePhysicalRole {
    Runtime,
    RelinearizationAuxiliary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorStoreSourceReadRequest {
    physical_component_ordinal: usize,
    source_ordinal: usize,
    source_material_root: [u8; Hash512::BYTE_LENGTH],
    source_stream_digest: [u8; Hash512::BYTE_LENGTH],
    source_stream_total_byte_length: u64,
    source_stream_byte_offset: u64,
    chunk_index: usize,
    byte_length: usize,
}

/// One bounded, authenticated source opened from either a generation-only
/// Galois authority or the corresponding positively verified catalog. The
/// construction runtime owns the fresh readback verifier and therefore never
/// accepts a detached root or descriptor from its worker caller.
pub(crate) struct SelectedEvaluatorStoreSource {
    topology: KeySwitchComponentMaterialTopology,
    material_root: [u8; Hash512::BYTE_LENGTH],
    descriptor: StreamDescriptor,
    readback: CanonicalStreamReadbackVerifier,
}

impl SelectedEvaluatorStoreSource {
    pub(crate) fn from_authenticated_authority(
        topology: KeySwitchComponentMaterialTopology,
        material_root: [u8; Hash512::BYTE_LENGTH],
        descriptor: StreamDescriptor,
        readback: CanonicalStreamReadbackVerifier,
    ) -> Self {
        Self {
            topology,
            material_root,
            descriptor,
            readback,
        }
    }

    pub(crate) const fn topology(&self) -> &KeySwitchComponentMaterialTopology {
        &self.topology
    }

    pub(crate) fn into_authenticated_parts(
        self,
    ) -> (
        KeySwitchComponentMaterialTopology,
        [u8; Hash512::BYTE_LENGTH],
        StreamDescriptor,
        CanonicalStreamReadbackVerifier,
    ) {
        (
            self.topology,
            self.material_root,
            self.descriptor,
            self.readback,
        )
    }
}

/// Exact source interface shared by prepackage generation and final positive
/// verification. Implementations are non-serializable authorities; host data
/// cannot implement or cross this crate-private boundary.
pub(crate) trait SelectedEvaluatorStoreSourceCatalog {
    fn protocol_version(&self) -> u16;

    fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH];

    fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH];

    fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH];

    fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH];

    fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH];

    fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH];

    fn component_source(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Result<Option<SelectedEvaluatorStoreSource>, RefusalReason>;

    fn component_root(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]>;

    fn component_public_polynomial_context_hash(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]>;
}

impl SelectedEvaluatorStoreSourceReadRequest {
    pub(crate) const fn physical_component_ordinal(&self) -> usize {
        self.physical_component_ordinal
    }

    pub(crate) const fn source_ordinal(&self) -> usize {
        self.source_ordinal
    }

    pub(crate) const fn source_material_root(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.source_material_root
    }

    pub(crate) const fn source_stream_digest(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.source_stream_digest
    }

    pub(crate) const fn source_stream_total_byte_length(&self) -> u64 {
        self.source_stream_total_byte_length
    }

    pub(crate) const fn source_stream_byte_offset(&self) -> u64 {
        self.source_stream_byte_offset
    }

    pub(crate) const fn chunk_index(&self) -> usize {
        self.chunk_index
    }

    pub(crate) const fn byte_length(&self) -> usize {
        self.byte_length
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorStoreOutputChunk {
    chunk_index: usize,
    bytes: Vec<u8>,
}

impl SelectedEvaluatorStoreOutputChunk {
    pub(crate) const fn chunk_index(&self) -> usize {
        self.chunk_index
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
pub(crate) struct SelectedEvaluatorStoreConstructionOutput {
    top_count: u16,
    store_descriptor: StreamDescriptor,
    ordered_component_descriptors: Box<[StreamDescriptor]>,
    ordered_positions: Box<[SelectedEvaluatorEntryPosition]>,
    ordered_physical_roles: Box<[EvaluatorKeyStorePhysicalRole]>,
}

impl SelectedEvaluatorStoreConstructionOutput {
    pub(crate) const fn store_descriptor(&self) -> &StreamDescriptor {
        &self.store_descriptor
    }

    pub(crate) fn ordered_component_descriptors(&self) -> &[StreamDescriptor] {
        &self.ordered_component_descriptors
    }

    pub(crate) fn ordered_positions(&self) -> &[SelectedEvaluatorEntryPosition] {
        &self.ordered_positions
    }

    pub(crate) fn ordered_physical_roles(&self) -> &[EvaluatorKeyStorePhysicalRole] {
        &self.ordered_physical_roles
    }

    /// Derives the exact complete-list statement only from the accepted source
    /// catalog, recomputed typed roots, and this generator-owned store digest.
    /// No caller-supplied source-root list or detached store digest enters the
    /// application binding.
    pub(crate) fn canonical_application_statement<SourceCatalog>(
        &self,
        source_catalog: &SourceCatalog,
        ordered_runtime_roots: &[VerifiedEvaluatorRuntimeRoot],
        ordered_auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
    ) -> Result<Vec<u8>, SelectedApplicationStatementError>
    where
        SourceCatalog: SelectedEvaluatorStoreSourceCatalog + ?Sized,
    {
        let logical_positions = selected_evaluator_entry_positions(self.top_count)?;
        let expected_physical_component_count = logical_positions.len()
            + logical_positions
                .iter()
                .filter(|position| {
                    matches!(
                        position.key_kind(),
                        SelectedEvaluatorEntryKind::Relinearization { .. }
                    )
                })
                .count();
        if source_catalog.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || ordered_runtime_roots.len() != logical_positions.len()
            || ordered_auxiliary_roots.len() != logical_positions.len()
            || self.ordered_component_descriptors.len() != expected_physical_component_count
            || self.ordered_positions.len() != expected_physical_component_count
            || self.ordered_physical_roles.len() != expected_physical_component_count
        {
            return Err(SelectedApplicationStatementError::InvalidProfile);
        }
        validate_physical_layout(&self.ordered_positions, &self.ordered_physical_roles)
            .map_err(|_| SelectedApplicationStatementError::InvalidProfile)?;

        let ordered_source_roots = logical_positions
            .iter()
            .map(|position| {
                (0..FOUNDATION_PROFILE.participant_count)
                    .map(|roster_position| {
                        source_catalog
                            .component_root(roster_position, *position)
                            .ok_or(SelectedApplicationStatementError::InvalidProfile)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ordered_entries = logical_positions
            .iter()
            .enumerate()
            .map(|(entry_ordinal, position)| {
                let runtime_root = ordered_runtime_roots
                    .get(entry_ordinal)
                    .ok_or(SelectedApplicationStatementError::InvalidProfile)?;
                let auxiliary_root = ordered_auxiliary_roots
                    .get(entry_ordinal)
                    .ok_or(SelectedApplicationStatementError::InvalidProfile)?;
                if runtime_root.position() != *position || auxiliary_root.position() != *position {
                    return Err(SelectedApplicationStatementError::InvalidProfile);
                }
                Ok(SelectedEvaluatorAggregateEntryInput::new(
                    &ordered_source_roots[entry_ordinal],
                    runtime_root.runtime_component_root(),
                    auxiliary_root.auxiliary_component_root(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        canonical_selected_evaluator_aggregate_statement(
            source_catalog.setup_proof_context_hash(),
            self.top_count,
            &ordered_entries,
            self.store_descriptor.full_object_digest.into_bytes(),
        )
    }

    /// Starts the second, authenticated readback pass that mints the verified
    /// physical store carrier after the final statement hash is available.
    pub(crate) fn begin_material_verification(
        &self,
        selected_suite: &SelectedSuiteCapability,
        ownership_binding: ComponentMaterialOwnershipBinding,
    ) -> Result<VerifiedEvaluatorKeyStoreMaterialStream, RefusalReason> {
        VerifiedEvaluatorKeyStoreMaterialStream::begin(
            selected_suite,
            ownership_binding,
            self.top_count,
            self.store_descriptor.clone(),
            self.ordered_component_descriptors.to_vec(),
        )
    }
}

struct SelectedEvaluatorStoreSourceReadback {
    material_root: [u8; Hash512::BYTE_LENGTH],
    descriptor: StreamDescriptor,
    readback: Option<CanonicalStreamReadbackVerifier>,
}

struct SelectedEvaluatorPhysicalComponentConstruction {
    position: SelectedEvaluatorEntryPosition,
    role: EvaluatorKeyStorePhysicalRole,
    topology: KeySwitchComponentMaterialTopology,
    sources: Box<[SelectedEvaluatorStoreSourceReadback]>,
}

/// Restartable, bounded-frontier construction of the exact selected evaluator
/// store. Runtime components are reduced coefficient-wise from all ten
/// authenticated participant sources; the sole relinearization auxiliary
/// range is copied through the same authenticated path from the frozen 0x1215
/// aggregate. At most one transport chunk per source and one output chunk are
/// retained, independent of the complete store size.
pub(crate) struct SelectedEvaluatorStoreConstruction {
    top_count: u16,
    physical_components: Box<[SelectedEvaluatorPhysicalComponentConstruction]>,
    physical_component_ordinal: usize,
    source_chunk_index: usize,
    next_source_ordinal: usize,
    pending_source_chunks: Vec<Vec<u8>>,
    pending_source_residue_bytes: Vec<[u8; core::mem::size_of::<u64>()]>,
    pending_residue_byte_count: usize,
    next_block_index: usize,
    next_limb_index: usize,
    next_coefficient_index: usize,
    component_writer: Option<CanonicalStreamWriter>,
    component_pending_chunk: Vec<u8>,
    component_next_chunk_index: usize,
    ordered_component_descriptors: Vec<StreamDescriptor>,
    store_writer: Option<CanonicalStreamWriter>,
    store_pending_chunk: Vec<u8>,
    store_next_chunk_index: usize,
    ready_output_chunks: VecDeque<SelectedEvaluatorStoreOutputChunk>,
    store_finish_pending: bool,
    finished_store_descriptor: Option<StreamDescriptor>,
    refusal_reason: Option<RefusalReason>,
}

impl SelectedEvaluatorStoreConstruction {
    pub(crate) fn begin<SourceCatalog>(
        source_catalog: &SourceCatalog,
        relinearization_aggregate: &VerifiedRelinearizationAggregateMaterial,
        top_count: u16,
    ) -> Result<Self, RefusalReason>
    where
        SourceCatalog: SelectedEvaluatorStoreSourceCatalog + ?Sized,
    {
        if source_catalog.protocol_version() != relinearization_aggregate.protocol_version()
            || source_catalog.suite_identifier() != relinearization_aggregate.suite_identifier()
            || source_catalog.ceremony_context_hash()
                != relinearization_aggregate.ceremony_context_hash()
            || source_catalog.action_context_hash()
                != relinearization_aggregate.action_context_hash()
            || source_catalog.roster_hash() != relinearization_aggregate.roster_hash()
            || source_catalog.setup_proof_context_hash()
                != relinearization_aggregate.setup_proof_context_hash()
        {
            return Err(RefusalReason::WrongContext);
        }
        let ordered_positions = selected_evaluator_entry_positions(top_count)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let mut physical_components = Vec::new();
        for position in ordered_positions {
            let mut sources = Vec::new();
            for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                sources.push(
                    source_catalog
                        .component_source(roster_position, position)?
                        .ok_or(RefusalReason::MissingPrerequisite)?,
                );
            }
            let topology = sources
                .first()
                .map(|source| source.topology.clone())
                .ok_or(RefusalReason::MissingPrerequisite)?;
            if sources.iter().any(|source| source.topology != topology) {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            physical_components.push(SelectedEvaluatorPhysicalComponentConstruction {
                position,
                role: EvaluatorKeyStorePhysicalRole::Runtime,
                topology: topology.clone(),
                sources: selected_evaluator_source_readbacks_from_sources(sources),
            });
            if matches!(
                position.key_kind(),
                SelectedEvaluatorEntryKind::Relinearization { .. }
            ) {
                if relinearization_aggregate.evaluator_position() != position
                    || relinearization_aggregate.material().topology() != &topology
                {
                    return Err(RefusalReason::WrongContext);
                }
                physical_components.push(SelectedEvaluatorPhysicalComponentConstruction {
                    position,
                    role: EvaluatorKeyStorePhysicalRole::RelinearizationAuxiliary,
                    topology,
                    sources: selected_evaluator_source_readbacks(&[
                        relinearization_aggregate.material()
                    ])?,
                });
            }
        }
        if physical_components.is_empty() {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        let total_store_byte_length =
            physical_components
                .iter()
                .try_fold(0_u64, |total, component| {
                    total
                        .checked_add(component.topology.expected_byte_length())
                        .ok_or(RefusalReason::OutsideSupportedProfile)
                })?;
        let first_component = physical_components
            .first()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let component_writer = CanonicalStreamWriter::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            first_component.topology.expected_byte_length(),
        )?;
        let pending_source_residue_bytes =
            vec![[0_u8; core::mem::size_of::<u64>()]; first_component.sources.len()];
        let physical_component_count = physical_components.len();
        Ok(Self {
            top_count,
            pending_source_chunks: Vec::with_capacity(first_component.sources.len()),
            physical_components: physical_components.into_boxed_slice(),
            physical_component_ordinal: 0,
            source_chunk_index: 0,
            next_source_ordinal: 0,
            pending_source_residue_bytes,
            pending_residue_byte_count: 0,
            next_block_index: 0,
            next_limb_index: 0,
            next_coefficient_index: 0,
            component_writer: Some(component_writer),
            component_pending_chunk: Vec::with_capacity(
                FOUNDATION_PROFILE.stream_chunk_byte_length,
            ),
            component_next_chunk_index: 0,
            ordered_component_descriptors: Vec::with_capacity(physical_component_count),
            store_writer: Some(CanonicalStreamWriter::new(
                CanonicalStreamDomain::EvaluatorKeyStore,
                total_store_byte_length,
            )?),
            store_pending_chunk: Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length),
            store_next_chunk_index: 0,
            ready_output_chunks: VecDeque::new(),
            store_finish_pending: false,
            finished_store_descriptor: None,
            refusal_reason: None,
        })
    }

    pub(crate) fn next_source_read_request(
        &self,
    ) -> Option<SelectedEvaluatorStoreSourceReadRequest> {
        if self.refusal_reason.is_some()
            || self.finished_store_descriptor.is_some()
            || !self.ready_output_chunks.is_empty()
        {
            return None;
        }
        let component = self
            .physical_components
            .get(self.physical_component_ordinal)?;
        let source = component.sources.get(self.next_source_ordinal)?;
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let local_byte_offset = self.source_chunk_index.checked_mul(chunk_byte_length)?;
        let local_byte_offset = u64::try_from(local_byte_offset).ok()?;
        let remaining = source
            .descriptor
            .total_byte_length
            .checked_sub(local_byte_offset)?;
        let byte_length =
            usize::try_from(remaining.min(u64::try_from(chunk_byte_length).ok()?)).ok()?;
        Some(SelectedEvaluatorStoreSourceReadRequest {
            physical_component_ordinal: self.physical_component_ordinal,
            source_ordinal: self.next_source_ordinal,
            source_material_root: source.material_root,
            source_stream_digest: source.descriptor.full_object_digest.into_bytes(),
            source_stream_total_byte_length: source.descriptor.total_byte_length,
            source_stream_byte_offset: local_byte_offset,
            chunk_index: self.source_chunk_index,
            byte_length,
        })
    }

    pub(crate) fn take_next_output_chunk(
        &mut self,
    ) -> Result<Option<SelectedEvaluatorStoreOutputChunk>, RefusalReason> {
        if let Some(reason) = self.refusal_reason {
            return Err(reason);
        }
        let output_chunk = self.ready_output_chunks.pop_front();
        if output_chunk.is_some()
            && self.ready_output_chunks.is_empty()
            && self.store_finish_pending
            && let Err(reason) = self.finish_store_writer()
        {
            self.refusal_reason = Some(reason);
            self.store_pending_chunk.clear();
            self.ready_output_chunks.clear();
            return Err(reason);
        }
        Ok(output_chunk)
    }

    pub(crate) fn absorb_source_chunk(
        &mut self,
        request: &SelectedEvaluatorStoreSourceReadRequest,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if let Some(reason) = self.refusal_reason {
            return Err(reason);
        }
        let result = self.absorb_source_chunk_inner(request, chunk_bytes);
        if let Err(reason) = result {
            self.refusal_reason = Some(reason);
            self.pending_source_chunks.clear();
            self.component_pending_chunk.clear();
            self.store_pending_chunk.clear();
        }
        result
    }

    fn absorb_source_chunk_inner(
        &mut self,
        request: &SelectedEvaluatorStoreSourceReadRequest,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        let expected_request = self
            .next_source_read_request()
            .ok_or(RefusalReason::ConsumedState)?;
        if request != &expected_request || chunk_bytes.len() != request.byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let (source_count, component_total_byte_length) = {
            let component = self
                .physical_components
                .get_mut(self.physical_component_ordinal)
                .ok_or(RefusalReason::ConsumedState)?;
            let source = component
                .sources
                .get_mut(self.next_source_ordinal)
                .ok_or(RefusalReason::ConsumedState)?;
            source
                .readback
                .as_mut()
                .ok_or(RefusalReason::ConsumedState)?
                .authenticate_chunk(self.source_chunk_index, chunk_bytes)?;
            (
                component.sources.len(),
                component.topology.expected_byte_length(),
            )
        };
        self.pending_source_chunks.push(chunk_bytes.to_vec());
        self.next_source_ordinal = self
            .next_source_ordinal
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.next_source_ordinal == source_count {
            self.process_aligned_source_chunks()?;
            self.next_source_ordinal = 0;
            self.source_chunk_index = self
                .source_chunk_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if component_stream_is_complete(component_total_byte_length, self.source_chunk_index) {
                self.finish_current_component()?;
            }
        }
        Ok(())
    }

    fn process_aligned_source_chunks(&mut self) -> Result<(), RefusalReason> {
        let (source_count, topology) = {
            let component = self
                .physical_components
                .get(self.physical_component_ordinal)
                .ok_or(RefusalReason::ConsumedState)?;
            (component.sources.len(), component.topology.clone())
        };
        if self.pending_source_chunks.len() != source_count || self.pending_source_chunks.is_empty()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let chunk_byte_length = self.pending_source_chunks[0].len();
        if self
            .pending_source_chunks
            .iter()
            .any(|chunk| chunk.len() != chunk_byte_length)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let source_chunks = core::mem::take(&mut self.pending_source_chunks);
        for byte_ordinal in 0..chunk_byte_length {
            let modulus = *topology
                .ordered_moduli()
                .get(self.next_limb_index)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let residue_byte_length = canonical_residue_byte_length(modulus)
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
            if residue_byte_length == 0
                || residue_byte_length > core::mem::size_of::<u64>()
                || self.pending_residue_byte_count >= residue_byte_length
            {
                return Err(RefusalReason::UnsupportedVersionOrSuite);
            }
            for (source_ordinal, source_chunk) in source_chunks.iter().enumerate() {
                self.pending_source_residue_bytes[source_ordinal]
                    [self.pending_residue_byte_count] = source_chunk[byte_ordinal];
            }
            self.pending_residue_byte_count += 1;
            if self.pending_residue_byte_count == residue_byte_length {
                let mut aggregate_residue = 0_u128;
                for source_residue_bytes in &mut self.pending_source_residue_bytes {
                    let residue = u64::from_le_bytes(*source_residue_bytes);
                    if residue >= modulus {
                        return Err(RefusalReason::MalformedEncoding);
                    }
                    aggregate_residue += u128::from(residue);
                    source_residue_bytes.fill(0);
                }
                let aggregate_residue = u64::try_from(aggregate_residue % u128::from(modulus))
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                self.append_generated_bytes(
                    &aggregate_residue.to_le_bytes()[..residue_byte_length],
                )?;
                self.pending_residue_byte_count = 0;
                self.advance_residue_coordinate(&topology)?;
            }
        }
        self.pending_source_chunks = Vec::with_capacity(source_count);
        Ok(())
    }

    fn advance_residue_coordinate(
        &mut self,
        topology: &KeySwitchComponentMaterialTopology,
    ) -> Result<(), RefusalReason> {
        self.next_coefficient_index = self
            .next_coefficient_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.next_coefficient_index == topology.polynomial_degree() {
            self.next_coefficient_index = 0;
            self.next_limb_index = self
                .next_limb_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            if self.next_limb_index == topology.extended_limb_count() {
                self.next_limb_index = 0;
                self.next_block_index = self
                    .next_block_index
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
        }
        if self.next_block_index > topology.data_block_count() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(())
    }

    fn append_generated_bytes(&mut self, mut bytes: &[u8]) -> Result<(), RefusalReason> {
        while !bytes.is_empty() {
            let component_remaining = FOUNDATION_PROFILE
                .stream_chunk_byte_length
                .checked_sub(self.component_pending_chunk.len())
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let take = component_remaining.min(bytes.len());
            self.component_pending_chunk
                .extend_from_slice(&bytes[..take]);
            if self.component_pending_chunk.len() == FOUNDATION_PROFILE.stream_chunk_byte_length {
                self.flush_component_chunk()?;
            }
            let store_remaining = FOUNDATION_PROFILE
                .stream_chunk_byte_length
                .checked_sub(self.store_pending_chunk.len())
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let store_take = store_remaining.min(take);
            self.store_pending_chunk
                .extend_from_slice(&bytes[..store_take]);
            if self.store_pending_chunk.len() == FOUNDATION_PROFILE.stream_chunk_byte_length {
                self.flush_store_chunk()?;
            }
            if store_take != take {
                self.store_pending_chunk
                    .extend_from_slice(&bytes[store_take..take]);
            }
            bytes = &bytes[take..];
        }
        Ok(())
    }

    fn flush_component_chunk(&mut self) -> Result<(), RefusalReason> {
        if self.component_pending_chunk.is_empty() {
            return Ok(());
        }
        self.component_writer
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .absorb_chunk(
                self.component_next_chunk_index,
                &self.component_pending_chunk,
            )?;
        self.component_next_chunk_index = self
            .component_next_chunk_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.component_pending_chunk.clear();
        Ok(())
    }

    fn flush_store_chunk(&mut self) -> Result<(), RefusalReason> {
        if self.store_pending_chunk.is_empty() {
            return Ok(());
        }
        self.store_writer
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .absorb_chunk(self.store_next_chunk_index, &self.store_pending_chunk)?;
        let bytes = core::mem::take(&mut self.store_pending_chunk);
        self.ready_output_chunks
            .push_back(SelectedEvaluatorStoreOutputChunk {
                chunk_index: self.store_next_chunk_index,
                bytes,
            });
        self.store_next_chunk_index = self
            .store_next_chunk_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        self.store_pending_chunk = Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length);
        Ok(())
    }

    fn finish_current_component(&mut self) -> Result<(), RefusalReason> {
        {
            let component = self
                .physical_components
                .get_mut(self.physical_component_ordinal)
                .ok_or(RefusalReason::ConsumedState)?;
            if self.pending_residue_byte_count != 0
                || self.next_block_index != component.topology.data_block_count()
                || self.next_limb_index != 0
                || self.next_coefficient_index != 0
            {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            for source in &mut component.sources {
                source
                    .readback
                    .take()
                    .ok_or(RefusalReason::ConsumedState)?
                    .finish()
                    .into_result()?;
            }
        }
        self.flush_component_chunk()?;
        let component_descriptor = self
            .component_writer
            .take()
            .ok_or(RefusalReason::ConsumedState)?
            .finish()?;
        self.ordered_component_descriptors
            .push(component_descriptor);
        self.physical_component_ordinal = self
            .physical_component_ordinal
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.physical_component_ordinal == self.physical_components.len() {
            if self.ready_output_chunks.is_empty() || self.store_pending_chunk.is_empty() {
                self.finish_store_writer()?;
            } else {
                self.store_finish_pending = true;
            }
            return Ok(());
        }
        let next_component = self
            .physical_components
            .get(self.physical_component_ordinal)
            .ok_or(RefusalReason::ConsumedState)?;
        self.source_chunk_index = 0;
        self.next_source_ordinal = 0;
        self.pending_source_chunks = Vec::with_capacity(next_component.sources.len());
        self.pending_source_residue_bytes =
            vec![[0_u8; core::mem::size_of::<u64>()]; next_component.sources.len()];
        self.pending_residue_byte_count = 0;
        self.next_block_index = 0;
        self.next_limb_index = 0;
        self.next_coefficient_index = 0;
        self.component_writer = Some(CanonicalStreamWriter::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            next_component.topology.expected_byte_length(),
        )?);
        self.component_pending_chunk.clear();
        self.component_next_chunk_index = 0;
        Ok(())
    }

    fn finish_store_writer(&mut self) -> Result<(), RefusalReason> {
        self.flush_store_chunk()?;
        self.finished_store_descriptor = Some(
            self.store_writer
                .take()
                .ok_or(RefusalReason::ConsumedState)?
                .finish()?,
        );
        self.store_finish_pending = false;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<SelectedEvaluatorStoreConstructionOutput, RefusalReason> {
        if let Some(reason) = self.refusal_reason {
            return Err(reason);
        }
        if !self.ready_output_chunks.is_empty()
            || self.store_finish_pending
            || self.physical_component_ordinal != self.physical_components.len()
            || self.ordered_component_descriptors.len() != self.physical_components.len()
            || self.component_writer.is_some()
            || self.store_writer.is_some()
        {
            return Err(RefusalReason::ConsumedState);
        }
        let store_descriptor = self
            .finished_store_descriptor
            .ok_or(RefusalReason::ConsumedState)?;
        let ordered_positions = self
            .physical_components
            .iter()
            .map(|component| component.position)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let ordered_physical_roles = self
            .physical_components
            .iter()
            .map(|component| component.role)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(SelectedEvaluatorStoreConstructionOutput {
            top_count: self.top_count,
            store_descriptor,
            ordered_component_descriptors: self.ordered_component_descriptors.into_boxed_slice(),
            ordered_positions,
            ordered_physical_roles,
        })
    }
}

fn selected_evaluator_source_readbacks_from_sources(
    sources: Vec<SelectedEvaluatorStoreSource>,
) -> Box<[SelectedEvaluatorStoreSourceReadback]> {
    sources
        .into_iter()
        .map(|source| SelectedEvaluatorStoreSourceReadback {
            material_root: source.material_root,
            descriptor: source.descriptor,
            readback: Some(source.readback),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn selected_evaluator_source_readbacks(
    materials: &[&VerifiedKeySwitchComponentMaterial],
) -> Result<Box<[SelectedEvaluatorStoreSourceReadback]>, RefusalReason> {
    materials
        .iter()
        .map(|material| {
            Ok(SelectedEvaluatorStoreSourceReadback {
                material_root: material.material_root().into_bytes(),
                descriptor: material.stream_descriptor().clone(),
                readback: Some(material.begin_authenticated_readback()?),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn component_stream_is_complete(total_byte_length: u64, chunk_count: usize) -> bool {
    chunk_count
        .checked_mul(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .and_then(|observed| u64::try_from(observed).ok())
        .is_some_and(|observed| observed >= total_byte_length)
}

/// Opaque, replayable authority for the exact complete evaluator store bytes.
/// It is minted only after the whole canonical store and every ordered local
/// component stream have both authenticated successfully.
#[derive(Debug)]
pub(crate) struct VerifiedEvaluatorKeyStoreMaterial {
    top_count: u16,
    canonical_store_summary: VerifiedCanonicalStreamSummary,
    ordered_components: Box<[VerifiedEvaluatorKeyStoreComponentMaterial]>,
}

impl VerifiedEvaluatorKeyStoreMaterial {
    /// Authenticates the smallest exact selected-store catalog needed by the
    /// aggregation/evaluator seam tests. The physical bytes remain ordered as
    /// L22 relinearization B, linked L22 A, then L18 Galois-257 B.
    #[cfg(test)]
    pub(crate) fn from_test_authenticated_minimal_physical_material(
        ownership_binding: ComponentMaterialOwnershipBinding,
        store_bytes: Vec<u8>,
    ) -> Result<(Self, Vec<u8>), RefusalReason> {
        let selected_suite = selected_suite_capability_for_tests();
        let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let relinearization_position = positions
            .iter()
            .copied()
            .find(|position| {
                matches!(
                    position.key_kind(),
                    SelectedEvaluatorEntryKind::Relinearization { catalog_level }
                        if catalog_level == SELECTED_RELINEARIZATION_KEY_LEVEL
                )
            })
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let first_trace_galois_element = TRACE_GALOIS_PATHS
            .first()
            .and_then(|path| path.first())
            .copied()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let trace_galois_position = positions
            .iter()
            .copied()
            .find(|position| {
                matches!(
                    position.key_kind(),
                    SelectedEvaluatorEntryKind::Galois {
                        galois_element,
                        catalog_level,
                    } if galois_element == first_trace_galois_element
                        && catalog_level == TRACE_KEY_LEVEL
                )
            })
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let relinearization_topology =
            KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                &selected_suite,
                SELECTED_RELINEARIZATION_KEY_LEVEL,
            )?;
        let trace_galois_topology =
            KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                &selected_suite,
                TRACE_KEY_LEVEL,
            )?;
        let relinearization_byte_length =
            usize::try_from(relinearization_topology.expected_byte_length())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let trace_galois_byte_length =
            usize::try_from(trace_galois_topology.expected_byte_length())
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let expected_store_byte_length = relinearization_byte_length
            .checked_mul(2)
            .and_then(|length| length.checked_add(trace_galois_byte_length))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if store_bytes.len() != expected_store_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let auxiliary_start = relinearization_byte_length;
        let trace_start = relinearization_byte_length
            .checked_mul(2)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let component_descriptors = vec![
            derive_canonical_stream_descriptor(
                CanonicalStreamDomain::EvaluatorKeyStore,
                &store_bytes[..auxiliary_start],
            )?,
            derive_canonical_stream_descriptor(
                CanonicalStreamDomain::EvaluatorKeyStore,
                &store_bytes[auxiliary_start..trace_start],
            )?,
            derive_canonical_stream_descriptor(
                CanonicalStreamDomain::EvaluatorKeyStore,
                &store_bytes[trace_start..],
            )?,
        ];
        let store_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyStore,
            &store_bytes,
        )?;
        let mut stream = VerifiedEvaluatorKeyStoreMaterialStream::begin_with_physical_layout(
            FOUNDATION_PROFILE.option_count,
            vec![
                relinearization_topology.clone(),
                relinearization_topology,
                trace_galois_topology,
            ],
            ownership_binding,
            vec![
                relinearization_position,
                relinearization_position,
                trace_galois_position,
            ],
            vec![
                EvaluatorKeyStorePhysicalRole::Runtime,
                EvaluatorKeyStorePhysicalRole::RelinearizationAuxiliary,
                EvaluatorKeyStorePhysicalRole::Runtime,
            ],
            store_descriptor,
            component_descriptors,
        )?;
        for (chunk_index, chunk) in store_bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            stream.absorb_chunk(chunk_index, chunk).into_result()?;
        }
        let material = stream.finish().into_result()?;
        Ok((material, store_bytes))
    }

    pub(crate) const fn top_count(&self) -> u16 {
        self.top_count
    }

    pub(crate) const fn store_descriptor(&self) -> &StreamDescriptor {
        self.canonical_store_summary.stream_descriptor()
    }

    pub(crate) const fn canonical_store_summary(&self) -> &VerifiedCanonicalStreamSummary {
        &self.canonical_store_summary
    }

    pub(crate) fn ordered_components(&self) -> &[VerifiedEvaluatorKeyStoreComponentMaterial] {
        &self.ordered_components
    }

    pub(crate) fn component(
        &self,
        position: SelectedEvaluatorEntryPosition,
    ) -> Option<&VerifiedEvaluatorKeyStoreComponentMaterial> {
        self.ordered_components
            .iter()
            .find(|component| component.position() == position)
    }

    #[cfg(test)]
    pub(crate) fn begin_authenticated_readback(
        &self,
    ) -> Result<CanonicalStreamReadbackVerifier, RefusalReason> {
        CanonicalStreamReadbackVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            self.canonical_store_summary.clone(),
        )
    }
}

/// Incrementally authenticates the selected evaluator-store concatenation.
/// One component transport chunk is the only retained payload; component and
/// store chunk boundaries are deliberately independent.
pub(crate) struct VerifiedEvaluatorKeyStoreMaterialStream {
    top_count: u16,
    ordered_topologies: Box<[KeySwitchComponentMaterialTopology]>,
    ownership_binding: ComponentMaterialOwnershipBinding,
    ordered_positions: Box<[SelectedEvaluatorEntryPosition]>,
    ordered_physical_roles: Box<[EvaluatorKeyStorePhysicalRole]>,
    pending_component_descriptors: VecDeque<StreamDescriptor>,
    canonical_store_stream: Option<CanonicalStreamVerifier>,
    active_component_stream: Option<VerifiedKeySwitchComponentMaterialStream>,
    active_component_chunk: Vec<u8>,
    active_component_chunk_index: usize,
    active_component_observed_byte_length: u64,
    observed_store_byte_length: u64,
    next_component_store_byte_offset: u64,
    verified_components: Vec<VerifiedEvaluatorKeyStoreComponentMaterial>,
    refusal_reason: Option<RefusalReason>,
}

impl VerifiedEvaluatorKeyStoreMaterialStream {
    fn active_physical_component_ordinal(&self) -> Result<usize, RefusalReason> {
        self.ordered_topologies
            .len()
            .checked_sub(self.pending_component_descriptors.len())
            .and_then(|consumed_or_active| consumed_or_active.checked_sub(1))
            .ok_or(RefusalReason::WrongTypeOrLength)
    }

    pub(crate) fn begin(
        selected_suite: &SelectedSuiteCapability,
        ownership_binding: ComponentMaterialOwnershipBinding,
        top_count: u16,
        store_descriptor: StreamDescriptor,
        ordered_component_descriptors: Vec<StreamDescriptor>,
    ) -> Result<Self, RefusalReason> {
        let ordered_positions = selected_evaluator_entry_positions(top_count)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let mut ordered_topologies = Vec::new();
        let mut ordered_physical_positions = Vec::new();
        let mut ordered_physical_roles = Vec::new();
        for position in ordered_positions {
            let topology = KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                selected_suite,
                selected_entry_catalog_level(position),
            )?;
            ordered_topologies.push(topology.clone());
            ordered_physical_positions.push(position);
            ordered_physical_roles.push(EvaluatorKeyStorePhysicalRole::Runtime);
            if matches!(
                position.key_kind(),
                SelectedEvaluatorEntryKind::Relinearization { .. }
            ) {
                ordered_topologies.push(topology);
                ordered_physical_positions.push(position);
                ordered_physical_roles
                    .push(EvaluatorKeyStorePhysicalRole::RelinearizationAuxiliary);
            }
        }
        Self::begin_with_physical_layout(
            top_count,
            ordered_topologies,
            ownership_binding,
            ordered_physical_positions,
            ordered_physical_roles,
            store_descriptor,
            ordered_component_descriptors,
        )
    }

    #[cfg(test)]
    fn begin_with_topologies_and_positions(
        top_count: u16,
        ordered_topologies: Vec<KeySwitchComponentMaterialTopology>,
        ownership_binding: ComponentMaterialOwnershipBinding,
        ordered_positions: Vec<SelectedEvaluatorEntryPosition>,
        store_descriptor: StreamDescriptor,
        ordered_component_descriptors: Vec<StreamDescriptor>,
    ) -> Result<Self, RefusalReason> {
        let ordered_physical_roles =
            vec![EvaluatorKeyStorePhysicalRole::Runtime; ordered_positions.len()];
        Self::begin_with_physical_layout(
            top_count,
            ordered_topologies,
            ownership_binding,
            ordered_positions,
            ordered_physical_roles,
            store_descriptor,
            ordered_component_descriptors,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_with_physical_layout(
        top_count: u16,
        ordered_topologies: Vec<KeySwitchComponentMaterialTopology>,
        ownership_binding: ComponentMaterialOwnershipBinding,
        ordered_positions: Vec<SelectedEvaluatorEntryPosition>,
        ordered_physical_roles: Vec<EvaluatorKeyStorePhysicalRole>,
        store_descriptor: StreamDescriptor,
        ordered_component_descriptors: Vec<StreamDescriptor>,
    ) -> Result<Self, RefusalReason> {
        if ordered_positions.is_empty()
            || ordered_positions.len() != ordered_topologies.len()
            || ordered_positions.len() != ordered_physical_roles.len()
            || ordered_positions.len() != ordered_component_descriptors.len()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        validate_physical_layout(&ordered_positions, &ordered_physical_roles)?;
        let expected_store_byte_length =
            ordered_topologies
                .iter()
                .try_fold(0_u64, |total, topology| {
                    total
                        .checked_add(topology.expected_byte_length())
                        .ok_or(RefusalReason::OutsideSupportedProfile)
                })?;
        if store_descriptor.total_byte_length != expected_store_byte_length
            || ordered_component_descriptors
                .iter()
                .zip(&ordered_topologies)
                .any(|(descriptor, topology)| {
                    descriptor.total_byte_length != topology.expected_byte_length()
                })
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let canonical_store_stream = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            store_descriptor,
        )?;
        let mut pending_component_descriptors = VecDeque::from(ordered_component_descriptors);
        let first_component_descriptor = pending_component_descriptors
            .pop_front()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let active_component_stream = VerifiedKeySwitchComponentMaterialStream::begin(
            ordered_topologies[0].clone(),
            ownership_binding,
            first_component_descriptor,
        )?;

        Ok(Self {
            top_count,
            ordered_topologies: ordered_topologies.into_boxed_slice(),
            ownership_binding,
            ordered_positions: ordered_positions.into_boxed_slice(),
            ordered_physical_roles: ordered_physical_roles.into_boxed_slice(),
            pending_component_descriptors,
            canonical_store_stream: Some(canonical_store_stream),
            active_component_stream: Some(active_component_stream),
            active_component_chunk: Vec::new(),
            active_component_chunk_index: 0,
            active_component_observed_byte_length: 0,
            observed_store_byte_length: 0,
            next_component_store_byte_offset: 0,
            verified_components: Vec::new(),
            refusal_reason: None,
        })
    }

    pub(crate) fn absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> VerificationResult<()> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        let result = self.absorb_chunk_inner(chunk_index, chunk_bytes);
        match result {
            Ok(()) => VerificationResult::valid(()),
            Err(refusal_reason) => {
                self.cancel_inner(refusal_reason);
                VerificationResult::refused(refusal_reason)
            }
        }
    }

    fn absorb_chunk_inner(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        self.canonical_store_stream
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()?;
        self.observed_store_byte_length = self
            .observed_store_byte_length
            .checked_add(
                u64::try_from(chunk_bytes.len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .ok_or(RefusalReason::OutsideSupportedProfile)?;

        let mut unread_bytes = chunk_bytes;
        while !unread_bytes.is_empty() {
            let physical_component_ordinal = self.active_physical_component_ordinal()?;
            let active_component_byte_length = self
                .ordered_topologies
                .get(physical_component_ordinal)
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .expected_byte_length();
            let component_remaining = active_component_byte_length
                .checked_sub(self.active_component_observed_byte_length)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            if component_remaining == 0 {
                self.finish_active_component()?;
                continue;
            }
            let component_chunk_byte_length =
                u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let component_chunk_start = u64::try_from(self.active_component_chunk_index)
                .ok()
                .and_then(|index| index.checked_mul(component_chunk_byte_length))
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
            let component_chunk_target = usize::try_from(
                active_component_byte_length
                    .checked_sub(component_chunk_start)
                    .ok_or(RefusalReason::WrongTypeOrLength)?
                    .min(component_chunk_byte_length),
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let needed = component_chunk_target
                .checked_sub(self.active_component_chunk.len())
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let copied = needed.min(unread_bytes.len());
            self.active_component_chunk
                .extend_from_slice(&unread_bytes[..copied]);
            unread_bytes = &unread_bytes[copied..];
            self.active_component_observed_byte_length = self
                .active_component_observed_byte_length
                .checked_add(
                    u64::try_from(copied).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                )
                .ok_or(RefusalReason::OutsideSupportedProfile)?;

            if self.active_component_chunk.len() == component_chunk_target {
                self.active_component_stream
                    .as_mut()
                    .ok_or(RefusalReason::WrongTypeOrLength)?
                    .absorb_chunk(
                        self.active_component_chunk_index,
                        &self.active_component_chunk,
                    )
                    .into_result()?;
                self.active_component_chunk.clear();
                self.active_component_chunk_index = self
                    .active_component_chunk_index
                    .checked_add(1)
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
            }
            if self.active_component_observed_byte_length == active_component_byte_length {
                self.finish_active_component()?;
            }
        }
        Ok(())
    }

    fn finish_active_component(&mut self) -> Result<(), RefusalReason> {
        let physical_component_ordinal = self.active_physical_component_ordinal()?;
        let component_byte_length = self
            .ordered_topologies
            .get(physical_component_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .expected_byte_length();
        if !self.active_component_chunk.is_empty()
            || self.active_component_observed_byte_length != component_byte_length
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let position = *self
            .ordered_positions
            .get(physical_component_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let physical_role = *self
            .ordered_physical_roles
            .get(physical_component_ordinal)
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        let material = self
            .active_component_stream
            .take()
            .ok_or(RefusalReason::WrongTypeOrLength)?
            .finish()
            .into_result()?;
        let store_byte_offset = self.next_component_store_byte_offset;
        self.next_component_store_byte_offset = self
            .next_component_store_byte_offset
            .checked_add(component_byte_length)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        match physical_role {
            EvaluatorKeyStorePhysicalRole::Runtime => {
                self.verified_components
                    .push(VerifiedEvaluatorKeyStoreComponentMaterial {
                        position,
                        store_byte_offset,
                        material,
                        linked_relinearization_auxiliary: None,
                    });
            }
            EvaluatorKeyStorePhysicalRole::RelinearizationAuxiliary => {
                let runtime_component = self
                    .verified_components
                    .last_mut()
                    .filter(|component| {
                        component.position == position
                            && component.linked_relinearization_auxiliary.is_none()
                            && matches!(
                                position.key_kind(),
                                SelectedEvaluatorEntryKind::Relinearization { .. }
                            )
                    })
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                runtime_component.linked_relinearization_auxiliary =
                    Some(VerifiedEvaluatorKeyStoreAuxiliaryMaterial {
                        store_byte_offset,
                        material,
                    });
            }
        }
        self.active_component_chunk_index = 0;
        self.active_component_observed_byte_length = 0;

        if physical_component_ordinal + 1 < self.ordered_positions.len() {
            let next_topology = self
                .ordered_topologies
                .get(physical_component_ordinal + 1)
                .ok_or(RefusalReason::WrongTypeOrLength)?
                .clone();
            let descriptor = self
                .pending_component_descriptors
                .pop_front()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            self.active_component_stream = Some(VerifiedKeySwitchComponentMaterialStream::begin(
                next_topology,
                self.ownership_binding,
                descriptor,
            )?);
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> VerificationResult<VerifiedEvaluatorKeyStoreMaterial> {
        let result = self.finish_inner();
        self.active_component_chunk.fill(0);
        match result {
            Ok(material) => VerificationResult::valid(material),
            Err(refusal_reason) => VerificationResult::refused(refusal_reason),
        }
    }

    fn finish_inner(&mut self) -> Result<VerifiedEvaluatorKeyStoreMaterial, RefusalReason> {
        if let Some(refusal_reason) = self.refusal_reason {
            return Err(refusal_reason);
        }
        if self.active_component_stream.is_some()
            || !self.active_component_chunk.is_empty()
            || !self.pending_component_descriptors.is_empty()
            || self.next_component_store_byte_offset
                != self
                    .canonical_store_stream
                    .as_ref()
                    .ok_or(RefusalReason::ConsumedState)?
                    .stream_descriptor()
                    .total_byte_length
            || !verified_components_match_physical_layout(
                &self.verified_components,
                &self.ordered_positions,
                &self.ordered_physical_roles,
            )
            || self.observed_store_byte_length
                != self
                    .canonical_store_stream
                    .as_ref()
                    .ok_or(RefusalReason::ConsumedState)?
                    .stream_descriptor()
                    .total_byte_length
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let canonical_store_summary = self
            .canonical_store_stream
            .take()
            .ok_or(RefusalReason::ConsumedState)?
            .finish_with_summary()
            .into_result()?;
        Ok(VerifiedEvaluatorKeyStoreMaterial {
            top_count: self.top_count,
            canonical_store_summary,
            ordered_components: core::mem::take(&mut self.verified_components).into_boxed_slice(),
        })
    }

    fn cancel_inner(&mut self, refusal_reason: RefusalReason) {
        if let Some(active_component_stream) = self.active_component_stream.as_mut() {
            active_component_stream.cancel();
        }
        self.active_component_stream = None;
        self.active_component_chunk.fill(0);
        self.active_component_chunk.clear();
        self.pending_component_descriptors.clear();
        self.canonical_store_stream = None;
        self.refusal_reason = Some(refusal_reason);
    }

    #[cfg(test)]
    const fn retained_payload_byte_length(&self) -> usize {
        self.active_component_chunk.len()
    }
}

fn validate_physical_layout(
    ordered_positions: &[SelectedEvaluatorEntryPosition],
    ordered_roles: &[EvaluatorKeyStorePhysicalRole],
) -> Result<(), RefusalReason> {
    if ordered_positions.len() != ordered_roles.len() || ordered_positions.is_empty() {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let mut seen_runtime_positions = Vec::new();
    for physical_ordinal in 0..ordered_positions.len() {
        let position = ordered_positions[physical_ordinal];
        match ordered_roles[physical_ordinal] {
            EvaluatorKeyStorePhysicalRole::Runtime => {
                if seen_runtime_positions.contains(&position) {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                seen_runtime_positions.push(position);
                let has_linked_auxiliary = ordered_roles.get(physical_ordinal + 1)
                    == Some(&EvaluatorKeyStorePhysicalRole::RelinearizationAuxiliary)
                    && ordered_positions.get(physical_ordinal + 1) == Some(&position);
                if has_linked_auxiliary
                    != matches!(
                        position.key_kind(),
                        SelectedEvaluatorEntryKind::Relinearization { .. }
                    )
                {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
            EvaluatorKeyStorePhysicalRole::RelinearizationAuxiliary => {
                if physical_ordinal == 0
                    || ordered_roles[physical_ordinal - 1] != EvaluatorKeyStorePhysicalRole::Runtime
                    || ordered_positions[physical_ordinal - 1] != position
                    || !matches!(
                        position.key_kind(),
                        SelectedEvaluatorEntryKind::Relinearization { .. }
                    )
                {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
        }
    }
    Ok(())
}

fn verified_components_match_physical_layout(
    verified_components: &[VerifiedEvaluatorKeyStoreComponentMaterial],
    ordered_positions: &[SelectedEvaluatorEntryPosition],
    ordered_roles: &[EvaluatorKeyStorePhysicalRole],
) -> bool {
    let expected_runtime_positions = ordered_positions
        .iter()
        .zip(ordered_roles)
        .filter_map(|(position, role)| {
            (*role == EvaluatorKeyStorePhysicalRole::Runtime).then_some(*position)
        })
        .collect::<Vec<_>>();
    verified_components.len() == expected_runtime_positions.len()
        && verified_components
            .iter()
            .zip(expected_runtime_positions)
            .all(|(component, position)| {
                component.position == position
                    && component.linked_relinearization_auxiliary.is_some()
                        == matches!(
                            position.key_kind(),
                            SelectedEvaluatorEntryKind::Relinearization { .. }
                        )
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::derive_canonical_stream_descriptor;

    const TEST_MATERIAL_OWNERSHIP: ComponentMaterialOwnershipBinding =
        ComponentMaterialOwnershipBinding::from_verified_application(
            [0x11; 64], [0x22; 64], [0x33; 64],
        );

    #[test]
    fn minimal_test_store_material_refuses_a_truncated_physical_catalog() {
        assert!(matches!(
            VerifiedEvaluatorKeyStoreMaterial::from_test_authenticated_minimal_physical_material(
                TEST_MATERIAL_OWNERSHIP,
                vec![0],
            ),
            Err(RefusalReason::WrongTypeOrLength),
        ));
    }

    fn test_store_topology() -> KeySwitchComponentMaterialTopology {
        KeySwitchComponentMaterialTopology::for_test_suite(&[257, 769], &[12_289], 1, 8)
            .expect("test evaluator-store topology")
    }

    fn test_short_store_topology() -> KeySwitchComponentMaterialTopology {
        KeySwitchComponentMaterialTopology::for_test_suite(&[257], &[12_289], 1, 8)
            .expect("short test evaluator-store topology")
    }

    fn test_component_bytes(component_ordinal: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        let moduli = [257_u64, 769, 12_289];
        for block_index in 0..2_u64 {
            for modulus in moduli {
                let residue_byte_length = 2;
                for coefficient_index in 0..8_u64 {
                    let residue =
                        (component_ordinal * 43 + block_index * 17 + coefficient_index) % modulus;
                    bytes.extend_from_slice(&residue.to_le_bytes()[..residue_byte_length]);
                }
            }
        }
        assert_eq!(bytes.len(), 96);
        bytes
    }

    fn test_short_component_bytes(component_ordinal: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        for modulus in [257_u64, 12_289] {
            for coefficient_index in 0..8_u64 {
                let residue = (component_ordinal * 43 + coefficient_index) % modulus;
                bytes.extend_from_slice(&residue.to_le_bytes()[..2]);
            }
        }
        assert_eq!(bytes.len(), 32);
        bytes
    }

    fn test_descriptor(bytes: &[u8]) -> StreamDescriptor {
        derive_canonical_stream_descriptor(CanonicalStreamDomain::EvaluatorKeyStore, bytes)
            .expect("test evaluator-store descriptor")
    }

    fn test_verified_component_material(
        topology: KeySwitchComponentMaterialTopology,
        bytes: &[u8],
    ) -> VerifiedKeySwitchComponentMaterial {
        let descriptor = test_descriptor(bytes);
        let mut stream = VerifiedKeySwitchComponentMaterialStream::begin(
            topology,
            TEST_MATERIAL_OWNERSHIP,
            descriptor,
        )
        .expect("test component stream begins");
        for (chunk_index, chunk) in bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            stream
                .absorb_chunk(chunk_index, chunk)
                .into_result()
                .expect("test component chunk authenticates");
        }
        stream
            .finish()
            .into_result()
            .expect("test component material verifies")
    }

    fn test_construction(
        components: Vec<(
            SelectedEvaluatorEntryPosition,
            KeySwitchComponentMaterialTopology,
            Vec<VerifiedKeySwitchComponentMaterial>,
        )>,
    ) -> SelectedEvaluatorStoreConstruction {
        let total_store_byte_length = components
            .iter()
            .map(|(_, topology, _)| topology.expected_byte_length())
            .sum::<u64>();
        let physical_components = components
            .into_iter()
            .map(|(position, topology, materials)| {
                let material_references = materials.iter().collect::<Vec<_>>();
                let sources = selected_evaluator_source_readbacks(&material_references)
                    .expect("test source readbacks begin");
                SelectedEvaluatorPhysicalComponentConstruction {
                    position,
                    role: EvaluatorKeyStorePhysicalRole::Runtime,
                    topology,
                    sources,
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let first_component = physical_components
            .first()
            .expect("test construction has a component");
        SelectedEvaluatorStoreConstruction {
            top_count: FOUNDATION_PROFILE.option_count,
            pending_source_chunks: Vec::with_capacity(first_component.sources.len()),
            pending_source_residue_bytes: vec![
                [0_u8; core::mem::size_of::<u64>()];
                first_component.sources.len()
            ],
            component_writer: Some(
                CanonicalStreamWriter::new(
                    CanonicalStreamDomain::EvaluatorKeyStore,
                    first_component.topology.expected_byte_length(),
                )
                .expect("test component writer begins"),
            ),
            physical_components,
            physical_component_ordinal: 0,
            source_chunk_index: 0,
            next_source_ordinal: 0,
            pending_residue_byte_count: 0,
            next_block_index: 0,
            next_limb_index: 0,
            next_coefficient_index: 0,
            component_pending_chunk: Vec::with_capacity(
                FOUNDATION_PROFILE.stream_chunk_byte_length,
            ),
            component_next_chunk_index: 0,
            ordered_component_descriptors: Vec::new(),
            store_writer: Some(
                CanonicalStreamWriter::new(
                    CanonicalStreamDomain::EvaluatorKeyStore,
                    total_store_byte_length,
                )
                .expect("test store writer begins"),
            ),
            store_pending_chunk: Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length),
            store_next_chunk_index: 0,
            ready_output_chunks: VecDeque::new(),
            store_finish_pending: false,
            finished_store_descriptor: None,
            refusal_reason: None,
        }
    }

    fn component_bytes_from_residues(
        topology: &KeySwitchComponentMaterialTopology,
        mut residue_at: impl FnMut(usize, usize, usize, u64) -> u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            usize::try_from(topology.expected_byte_length()).expect("test length fits usize"),
        );
        for block_index in 0..topology.data_block_count() {
            for (limb_index, modulus) in topology.ordered_moduli().iter().copied().enumerate() {
                let residue_byte_length =
                    canonical_residue_byte_length(modulus).expect("test residue width");
                for coefficient_index in 0..topology.polynomial_degree() {
                    let residue = residue_at(block_index, limb_index, coefficient_index, modulus);
                    assert!(residue < modulus);
                    bytes.extend_from_slice(&residue.to_le_bytes()[..residue_byte_length]);
                }
            }
        }
        bytes
    }

    fn test_store_stream(
        store_descriptor: StreamDescriptor,
        component_descriptors: Vec<StreamDescriptor>,
    ) -> VerifiedEvaluatorKeyStoreMaterialStream {
        VerifiedEvaluatorKeyStoreMaterialStream::begin_with_topologies_and_positions(
            FOUNDATION_PROFILE.option_count,
            vec![test_store_topology(), test_store_topology()],
            ComponentMaterialOwnershipBinding::from_verified_application(
                [0x11; 64], [0x22; 64], [0x33; 64],
            ),
            selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
                .expect("selected evaluator positions")[1..3]
                .to_vec(),
            store_descriptor,
            component_descriptors,
        )
        .expect("test evaluator-store stream begins")
    }

    #[test]
    fn selected_complete_list_plan_has_every_action_variant_and_exact_full_shape() {
        let plan = selected_evaluator_aggregate_relation_plan()
            .expect("selected evaluator aggregate relation plan");
        let trees_per_entry = usize::from(FOUNDATION_PROFILE.participant_count) + 1;
        assert_eq!(plan.variants().len(), 20);
        for (variant, top_count) in plan
            .variants()
            .iter()
            .zip(1..=FOUNDATION_PROFILE.option_count)
        {
            let selected_positions = selected_evaluator_entry_positions(top_count)
                .expect("action-selected evaluator entry list");
            let expected_column_count = selected_positions
                .iter()
                .copied()
                .map(|position| {
                    ordered_runtime_component_moduli(position)
                        .expect("selected entry columns")
                        .len()
                        * trees_per_entry
                })
                .sum::<usize>();
            assert_eq!(variant.schedule_position(), None);
            assert_eq!(variant.top_count(), Some(top_count));
            assert_eq!(
                variant.ordered_trees().len(),
                selected_positions.len() * trees_per_entry
            );
            assert_eq!(variant.ordered_columns().len(), expected_column_count);
        }
    }

    #[test]
    fn bounded_store_construction_reduces_ten_sources_modulo_each_selected_limb() {
        let topology = test_store_topology();
        let source_bytes = (0..usize::from(FOUNDATION_PROFILE.participant_count))
            .map(|source_ordinal| {
                component_bytes_from_residues(
                    &topology,
                    |block_index, limb_index, coefficient_index, modulus| match source_ordinal {
                        0 => 0,
                        1 => modulus - 1,
                        2 => 1,
                        3 => modulus - 1,
                        _ => {
                            u64::try_from(
                                block_index * 17
                                    + limb_index * 11
                                    + coefficient_index
                                    + source_ordinal,
                            )
                            .expect("test coordinate fits u64")
                                % modulus
                        }
                    },
                )
            })
            .collect::<Vec<_>>();
        let materials = source_bytes
            .iter()
            .map(|bytes| test_verified_component_material(topology.clone(), bytes))
            .collect::<Vec<_>>();
        let position = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .expect("selected positions")[1];
        let mut construction = test_construction(vec![(position, topology.clone(), materials)]);
        while let Some(request) = construction.next_source_read_request() {
            assert_eq!(request.physical_component_ordinal(), 0);
            assert_eq!(request.chunk_index(), 0);
            let bytes = &source_bytes[request.source_ordinal()];
            assert_eq!(request.byte_length(), bytes.len());
            construction
                .absorb_source_chunk(&request, bytes)
                .expect("authenticated source is reduced");
        }
        let output_chunk = construction
            .take_next_output_chunk()
            .expect("output retrieval succeeds")
            .expect("one output chunk is ready");
        assert_eq!(output_chunk.chunk_index(), 0);
        let expected = component_bytes_from_residues(
            &topology,
            |block_index, limb_index, coefficient_index, modulus| {
                let reduced = source_bytes
                    .iter()
                    .map(|bytes| {
                        let residues_before = block_index
                            * topology.extended_limb_count()
                            * topology.polynomial_degree()
                            + limb_index * topology.polynomial_degree()
                            + coefficient_index;
                        let residue_byte_length =
                            canonical_residue_byte_length(modulus).expect("test residue width");
                        let byte_offset = residues_before * residue_byte_length;
                        let mut encoded = [0_u8; core::mem::size_of::<u64>()];
                        encoded[..residue_byte_length].copy_from_slice(
                            &bytes[byte_offset..byte_offset + residue_byte_length],
                        );
                        u128::from(u64::from_le_bytes(encoded))
                    })
                    .sum::<u128>()
                    .rem_euclid(u128::from(modulus));
                u64::try_from(reduced).expect("reduced residue fits u64")
            },
        );
        assert_eq!(output_chunk.bytes(), expected);
        assert!(
            construction
                .take_next_output_chunk()
                .expect("empty output retrieval succeeds")
                .is_none()
        );
        let terminal = construction.finish().expect("construction finishes");
        assert_eq!(terminal.ordered_component_descriptors().len(), 1);
        assert_eq!(
            terminal.store_descriptor().full_object_digest,
            test_descriptor(&expected).full_object_digest
        );
    }

    #[test]
    fn store_construction_retains_only_one_output_chunk_at_a_component_boundary() {
        let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .expect("selected positions");
        let short_topology = test_short_store_topology();
        let aligned_topology = KeySwitchComponentMaterialTopology::for_test_suite(
            &[257],
            &[12_289],
            1,
            FOUNDATION_PROFILE.stream_chunk_byte_length / 4,
        )
        .expect("aligned test topology");
        assert_eq!(
            aligned_topology.expected_byte_length(),
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .expect("stream chunk length fits u64")
        );
        let short_bytes =
            component_bytes_from_residues(&short_topology, |_, _, coefficient_index, modulus| {
                u64::try_from(coefficient_index).expect("coefficient fits u64") % modulus
            });
        let aligned_bytes = component_bytes_from_residues(
            &aligned_topology,
            |_, limb_index, coefficient_index, modulus| {
                u64::try_from(limb_index + coefficient_index).expect("coordinate fits u64")
                    % modulus
            },
        );
        let short_material = test_verified_component_material(short_topology.clone(), &short_bytes);
        let aligned_material =
            test_verified_component_material(aligned_topology.clone(), &aligned_bytes);
        let mut construction = test_construction(vec![
            (positions[1], short_topology, vec![short_material]),
            (positions[2], aligned_topology, vec![aligned_material]),
        ]);

        let short_request = construction
            .next_source_read_request()
            .expect("short component request");
        construction
            .absorb_source_chunk(&short_request, &short_bytes)
            .expect("short component copies");
        let aligned_request = construction
            .next_source_read_request()
            .expect("aligned component request");
        construction
            .absorb_source_chunk(&aligned_request, &aligned_bytes)
            .expect("aligned component copies");
        assert!(construction.next_source_read_request().is_none());

        let first_output = construction
            .take_next_output_chunk()
            .expect("first output retrieval succeeds")
            .expect("first output is ready");
        assert_eq!(
            first_output.bytes().len(),
            FOUNDATION_PROFILE.stream_chunk_byte_length
        );
        let second_output = construction
            .take_next_output_chunk()
            .expect("second output retrieval succeeds")
            .expect("deferred final output is ready");
        assert_eq!(second_output.bytes().len(), short_bytes.len());
        assert!(
            construction
                .take_next_output_chunk()
                .expect("empty output retrieval succeeds")
                .is_none()
        );
        let terminal = construction.finish().expect("construction finishes");
        assert_eq!(terminal.ordered_component_descriptors().len(), 2);
        assert_eq!(
            terminal.store_descriptor().total_byte_length,
            u64::try_from(short_bytes.len() + aligned_bytes.len())
                .expect("test store length fits u64")
        );
    }

    #[test]
    fn complete_store_stream_authenticates_whole_bytes_and_ordered_component_ranges() {
        let first_component = test_component_bytes(0);
        let second_component = test_component_bytes(1);
        let mut store_bytes = first_component.clone();
        store_bytes.extend_from_slice(&second_component);
        let mut stream = test_store_stream(
            test_descriptor(&store_bytes),
            vec![
                test_descriptor(&first_component),
                test_descriptor(&second_component),
            ],
        );
        stream
            .absorb_chunk(0, &store_bytes)
            .into_result()
            .expect("whole store and both component ranges authenticate");
        assert_eq!(stream.retained_payload_byte_length(), 0);
        let verified = stream
            .finish()
            .into_result()
            .expect("complete evaluator-store material verifies");

        assert_eq!(verified.top_count(), FOUNDATION_PROFILE.option_count);
        assert_eq!(verified.ordered_components().len(), 2);
        assert_eq!(verified.ordered_components()[0].store_byte_offset(), 0);
        assert_eq!(verified.ordered_components()[1].store_byte_offset(), 96);
        assert_eq!(
            verified.ordered_components()[0].position(),
            selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count).unwrap()[1]
        );
        assert_eq!(
            verified
                .component(verified.ordered_components()[1].position())
                .map(VerifiedEvaluatorKeyStoreComponentMaterial::store_byte_offset),
            Some(96)
        );
        let mut whole_readback = verified
            .begin_authenticated_readback()
            .expect("verified store begins whole-stream replay");
        assert_eq!(whole_readback.authenticate_chunk(0, &store_bytes), Ok(()));
        assert!(whole_readback.finish().is_valid());

        for (component, bytes) in verified
            .ordered_components()
            .iter()
            .zip([first_component.as_slice(), second_component.as_slice()])
        {
            let mut component_readback = component
                .material()
                .begin_authenticated_readback()
                .expect("verified component begins local replay");
            assert_eq!(component_readback.authenticate_chunk(0, bytes), Ok(()));
            assert!(component_readback.finish().is_valid());
        }
    }

    #[test]
    fn store_stream_uses_each_selected_entry_length_for_boundaries_and_offsets() {
        let first_component = test_short_component_bytes(0);
        let second_component = test_component_bytes(1);
        let mut store_bytes = first_component.clone();
        store_bytes.extend_from_slice(&second_component);
        let positions = selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .expect("selected evaluator positions")[1..3]
            .to_vec();
        let mut stream =
            VerifiedEvaluatorKeyStoreMaterialStream::begin_with_topologies_and_positions(
                FOUNDATION_PROFILE.option_count,
                vec![test_short_store_topology(), test_store_topology()],
                ComponentMaterialOwnershipBinding::from_verified_application(
                    [0x11; 64], [0x22; 64], [0x33; 64],
                ),
                positions,
                test_descriptor(&store_bytes),
                vec![
                    test_descriptor(&first_component),
                    test_descriptor(&second_component),
                ],
            )
            .expect("variable-length evaluator store begins");

        stream
            .absorb_chunk(0, &store_bytes)
            .into_result()
            .expect("variable-length evaluator store authenticates");
        let verified = stream
            .finish()
            .into_result()
            .expect("variable-length evaluator store finishes");
        assert_eq!(verified.ordered_components()[0].store_byte_offset(), 0);
        assert_eq!(verified.ordered_components()[1].store_byte_offset(), 32);
        assert_eq!(
            verified.ordered_components()[0]
                .material()
                .total_byte_length(),
            32
        );
        assert_eq!(
            verified.ordered_components()[1]
                .material()
                .total_byte_length(),
            96
        );
    }

    #[test]
    fn store_stream_refuses_wrong_whole_hash_component_hash_and_length() {
        let first_component = test_component_bytes(0);
        let second_component = test_component_bytes(1);
        let mut store_bytes = first_component.clone();
        store_bytes.extend_from_slice(&second_component);

        let mut substituted_store_bytes = store_bytes.clone();
        substituted_store_bytes[0] ^= 1;
        let mut wrong_whole_hash = test_store_stream(
            test_descriptor(&store_bytes),
            vec![
                test_descriptor(&first_component),
                test_descriptor(&second_component),
            ],
        );
        assert_eq!(
            wrong_whole_hash.absorb_chunk(0, &substituted_store_bytes),
            VerificationResult::refused(RefusalReason::WrongHashOrRoot)
        );

        let mut wrong_component_hash = test_store_stream(
            test_descriptor(&store_bytes),
            vec![
                test_descriptor(&second_component),
                test_descriptor(&first_component),
            ],
        );
        assert_eq!(
            wrong_component_hash.absorb_chunk(0, &store_bytes),
            VerificationResult::refused(RefusalReason::WrongHashOrRoot)
        );

        let truncated_store = &store_bytes[..store_bytes.len() - 1];
        assert_eq!(
            VerifiedEvaluatorKeyStoreMaterialStream::begin_with_topologies_and_positions(
                FOUNDATION_PROFILE.option_count,
                vec![test_store_topology(), test_store_topology()],
                ComponentMaterialOwnershipBinding::from_verified_application(
                    [0x11; 64], [0x22; 64], [0x33; 64],
                ),
                selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count).unwrap()[1..3]
                    .to_vec(),
                test_descriptor(truncated_store),
                vec![
                    test_descriptor(&first_component),
                    test_descriptor(&second_component),
                ],
            )
            .err(),
            Some(RefusalReason::WrongTypeOrLength)
        );
    }
}
