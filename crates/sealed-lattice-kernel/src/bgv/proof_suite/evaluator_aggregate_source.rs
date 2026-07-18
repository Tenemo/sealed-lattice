//! Authenticated, restart-safe source replay for the complete evaluator
//! aggregate relation.

use core::mem::size_of;

use zeroize::Zeroizing;

use crate::{
    foundation::{
        CanonicalItemType, CanonicalStreamReadbackVerifier, FOUNDATION_PROFILE, Hash512,
        ProofApplicationSlotCeilings,
    },
    hashing::hash_framed_parts_512,
};

use super::relation_plan::{RelationColumnDescriptor, RelationColumnValueType};
use super::{
    BoundTreeConstructionKind, CommonProofAuthenticatedSourceReadRequest, CommonProofProverError,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialReplayIdentity,
    CommonProofSourcePolynomialRequest, CommonProofSourcePolynomialRequestContext,
    CompiledRelationPlan, KeySwitchComponentMaterialTopology, KeySwitchComponentTraceColumn,
    ProofBaseFieldElement, ProvidedCommonProofSourcePolynomial, RelationPlanCheckContext,
    RelationPlanVariant, RelationProofTreeInput, RelationTreeDescriptor,
    SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SelectedEvaluatorStoreSource,
    SelectedEvaluatorStoreSourceCatalog, SetupPublicPolynomialContext,
    SetupPublicPolynomialRootRole, StatementOwnedProofTreeInput, VerifiedEvaluatorKeyStoreMaterial,
    VerifiedEvaluatorRuntimeRoot, VerifiedKeySwitchComponentMaterial,
    decode_selected_application_statement, selected_evaluator_aggregate_entry_roots_in_order,
    selected_evaluator_entry_positions, verified_application_statement_hash,
};

const EVALUATOR_SOURCE_CATALOG_BINDING_DOMAIN: &str =
    "sealed-lattice/evaluator-aggregate/source-catalog-binding/v1";
const EVALUATOR_SOURCE_DESCRIPTOR_BINDING_DOMAIN: &str =
    "sealed-lattice/evaluator-aggregate/source-descriptor-binding/v1";
const COMPLETE_LIST_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/complete-list-setup-polynomial/source-replay-identity/v1";
const COMPLETE_LIST_SOURCE_DESCRIPTOR_BINDING_DOMAIN: &str =
    "sealed-lattice/complete-list-setup-polynomial/source-descriptor-binding/v1";
const RELINEARIZATION_ENTRY_KIND_BINDING: u16 = 1;
const GALOIS_ENTRY_KIND_BINDING: u16 = 2;
const EVALUATOR_RUNTIME_SOURCE_ROLE: u16 = u16::MAX;

/// Source-derived resident memory for the authenticated complete-list
/// evaluator provider. Fixed owners include every in-place `Option`, catalog
/// handle, and pending-buffer handle. Boxed catalog payloads, topology arrays,
/// readback digests, readback flags, and loading transients are separate so
/// their release at `finish` remains visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedEvaluatorAggregateSourceProviderMemoryAccounting {
    provider_fixed_owner_byte_length: u64,
    authenticated_source_catalog_byte_length: u64,
    ordered_source_column_catalog_byte_length: u64,
    topology_catalog_byte_length: u64,
    readback_chunk_digest_byte_length: u64,
    readback_authentication_flag_byte_length: u64,
    loading_persistent_resident_byte_length: u64,
    post_source_polynomial_finish_persistent_resident_byte_length: u64,
    maximum_pending_column_byte_length: u64,
    maximum_cached_authenticated_chunk_byte_length: u64,
    additional_loading_source_polynomials_transient_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
}

impl SelectedEvaluatorAggregateSourceProviderMemoryAccounting {
    pub(crate) const fn provider_fixed_owner_byte_length(self) -> u64 {
        self.provider_fixed_owner_byte_length
    }

    pub(crate) const fn authenticated_source_catalog_byte_length(self) -> u64 {
        self.authenticated_source_catalog_byte_length
    }

    pub(crate) const fn ordered_source_column_catalog_byte_length(self) -> u64 {
        self.ordered_source_column_catalog_byte_length
    }

    pub(crate) const fn topology_catalog_byte_length(self) -> u64 {
        self.topology_catalog_byte_length
    }

    pub(crate) const fn readback_chunk_digest_byte_length(self) -> u64 {
        self.readback_chunk_digest_byte_length
    }

    pub(crate) const fn readback_authentication_flag_byte_length(self) -> u64 {
        self.readback_authentication_flag_byte_length
    }

    pub(crate) const fn loading_persistent_resident_byte_length(self) -> u64 {
        self.loading_persistent_resident_byte_length
    }

    pub(crate) const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
        self.post_source_polynomial_finish_persistent_resident_byte_length
    }

    pub(crate) const fn maximum_pending_column_byte_length(self) -> u64 {
        self.maximum_pending_column_byte_length
    }

    pub(crate) const fn maximum_cached_authenticated_chunk_byte_length(self) -> u64 {
        self.maximum_cached_authenticated_chunk_byte_length
    }

    pub(crate) const fn additional_loading_source_polynomials_transient_byte_length(self) -> u64 {
        self.additional_loading_source_polynomials_transient_byte_length
    }

    pub(crate) const fn maximum_returned_source_polynomial_byte_length(self) -> u64 {
        self.maximum_returned_source_polynomial_byte_length
    }
}

fn checked_provider_add(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_add(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn checked_provider_multiply(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_mul(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn finish_evaluator_source_provider_memory_accounting(
    authenticated_source_count: usize,
    source_column_count: usize,
    topology_catalog_byte_length: u64,
    readback_chunk_count: u64,
    maximum_pending_column_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
) -> Result<SelectedEvaluatorAggregateSourceProviderMemoryAccounting, CommonProofProverError> {
    if authenticated_source_count == 0
        || source_column_count == 0
        || maximum_pending_column_byte_length == 0
        || maximum_returned_source_polynomial_byte_length == 0
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let provider_fixed_owner_byte_length =
        u64::try_from(size_of::<SelectedEvaluatorAggregateSourcePolynomialProvider>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let authenticated_source_catalog_byte_length = checked_provider_multiply(
        u64::try_from(authenticated_source_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(size_of::<EvaluatorAggregateAuthenticatedSource>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let ordered_source_column_catalog_byte_length = checked_provider_multiply(
        u64::try_from(source_column_count).map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(size_of::<EvaluatorAggregateSourceColumn>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let readback_chunk_digest_byte_length = checked_provider_multiply(
        readback_chunk_count,
        u64::try_from(size_of::<Hash512>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let readback_authentication_flag_byte_length = checked_provider_multiply(
        readback_chunk_count,
        u64::try_from(size_of::<bool>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let post_source_polynomial_finish_persistent_resident_byte_length = [
        provider_fixed_owner_byte_length,
        authenticated_source_catalog_byte_length,
        ordered_source_column_catalog_byte_length,
        topology_catalog_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_provider_add)?;
    let loading_persistent_resident_byte_length = [
        post_source_polynomial_finish_persistent_resident_byte_length,
        readback_chunk_digest_byte_length,
        readback_authentication_flag_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_provider_add)?;
    let maximum_cached_authenticated_chunk_byte_length =
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let additional_loading_source_polynomials_transient_byte_length = checked_provider_add(
        maximum_pending_column_byte_length,
        maximum_cached_authenticated_chunk_byte_length,
    )?;
    Ok(SelectedEvaluatorAggregateSourceProviderMemoryAccounting {
        provider_fixed_owner_byte_length,
        authenticated_source_catalog_byte_length,
        ordered_source_column_catalog_byte_length,
        topology_catalog_byte_length,
        readback_chunk_digest_byte_length,
        readback_authentication_flag_byte_length,
        loading_persistent_resident_byte_length,
        post_source_polynomial_finish_persistent_resident_byte_length,
        maximum_pending_column_byte_length,
        maximum_cached_authenticated_chunk_byte_length,
        additional_loading_source_polynomials_transient_byte_length,
        maximum_returned_source_polynomial_byte_length,
    })
}

/// Derives the complete-list provider allocation from the checked relation
/// descriptors and verifier-owned suite moduli, without constructing setup
/// material or hand-entering a selected-profile estimate.
pub(crate) fn evaluator_aggregate_source_provider_memory_accounting(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<SelectedEvaluatorAggregateSourceProviderMemoryAccounting, CommonProofProverError> {
    let mut visited_columns = vec![false; variant.ordered_columns().len()];
    let mut topology_catalog_byte_length = 0_u64;
    let mut readback_chunk_count = 0_u64;
    let mut maximum_pending_column_byte_length = 0_u64;
    let mut maximum_returned_source_polynomial_byte_length = 0_u64;
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            ordered_column_ordinals,
            ..
        } = tree
        else {
            return Err(CommonProofProverError::InvalidTree);
        };
        let mut distinct_modulus_references = Vec::new();
        let mut stream_total_byte_length = 0_u64;
        for column_ordinal in ordered_column_ordinals {
            let column_index = usize::try_from(*column_ordinal)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
            let visited = visited_columns
                .get_mut(column_index)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let column = variant
                .ordered_columns()
                .get(column_index)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let modulus_reference = column
                .canonical_residue_modulus()
                .filter(|_| column.value_type() == RelationColumnValueType::BaseField)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            if *visited {
                return Err(CommonProofProverError::InvalidColumn);
            }
            *visited = true;
            if !distinct_modulus_references.contains(&modulus_reference) {
                distinct_modulus_references.push(modulus_reference);
            }
            let modulus = relation_context
                .resolved_modulus(modulus_reference)
                .map_err(|_| CommonProofProverError::InvalidColumn)?;
            let residue_byte_length = u64::try_from(
                crate::bgv::coefficient_codec::canonical_modulus_byte_length(modulus),
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?;
            let pending_column_byte_length = checked_provider_multiply(
                column.source_degree_bound_exclusive(),
                residue_byte_length,
            )?;
            let returned_source_polynomial_byte_length = checked_provider_multiply(
                column.source_degree_bound_exclusive(),
                u64::try_from(size_of::<ProofBaseFieldElement>())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )?;
            stream_total_byte_length =
                checked_provider_add(stream_total_byte_length, pending_column_byte_length)?;
            maximum_pending_column_byte_length =
                maximum_pending_column_byte_length.max(pending_column_byte_length);
            maximum_returned_source_polynomial_byte_length =
                maximum_returned_source_polynomial_byte_length
                    .max(returned_source_polynomial_byte_length);
        }
        if distinct_modulus_references.is_empty() || stream_total_byte_length == 0 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        topology_catalog_byte_length = checked_provider_add(
            topology_catalog_byte_length,
            checked_provider_multiply(
                u64::try_from(distinct_modulus_references.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                u64::try_from(size_of::<u64>() + size_of::<u8>())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )?,
        )?;
        readback_chunk_count = checked_provider_add(
            readback_chunk_count,
            stream_total_byte_length.div_ceil(stream_chunk_byte_length),
        )?;
    }
    if visited_columns.iter().any(|visited| !visited) {
        return Err(CommonProofProverError::InvalidColumn);
    }
    finish_evaluator_source_provider_memory_accounting(
        variant.ordered_trees().len(),
        variant.ordered_columns().len(),
        topology_catalog_byte_length,
        readback_chunk_count,
        maximum_pending_column_byte_length,
        maximum_returned_source_polynomial_byte_length,
    )
}

fn prepared_evaluator_source_provider_memory_accounting(
    ordered_sources: &[EvaluatorAggregateAuthenticatedSource],
    ordered_source_columns: &[EvaluatorAggregateSourceColumn],
) -> Result<SelectedEvaluatorAggregateSourceProviderMemoryAccounting, CommonProofProverError> {
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut topology_catalog_byte_length = 0_u64;
    let mut readback_chunk_count = 0_u64;
    for source in ordered_sources {
        if source.readback.is_none() || source.stream_total_byte_length == 0 {
            return Err(CommonProofProverError::InvalidInput);
        }
        topology_catalog_byte_length = checked_provider_add(
            topology_catalog_byte_length,
            checked_provider_multiply(
                u64::try_from(source.topology.extended_limb_count())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                u64::try_from(size_of::<u64>() + size_of::<u8>())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )?,
        )?;
        readback_chunk_count = checked_provider_add(
            readback_chunk_count,
            source
                .stream_total_byte_length
                .div_ceil(stream_chunk_byte_length),
        )?;
    }
    let maximum_pending_column_byte_length = ordered_source_columns
        .iter()
        .map(|source| source.trace_column.byte_length())
        .max()
        .ok_or(CommonProofProverError::InvalidColumn)?;
    let maximum_returned_source_polynomial_byte_length =
        ordered_source_columns
            .iter()
            .try_fold(0_u64, |maximum, source| {
                checked_provider_multiply(
                    u64::try_from(source.trace_column.coefficient_count())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    u64::try_from(size_of::<ProofBaseFieldElement>())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .map(|length| maximum.max(length))
            })?;
    finish_evaluator_source_provider_memory_accounting(
        ordered_sources.len(),
        ordered_source_columns.len(),
        topology_catalog_byte_length,
        readback_chunk_count,
        maximum_pending_column_byte_length,
        maximum_returned_source_polynomial_byte_length,
    )
}

struct EvaluatorAggregateAuthenticatedSource {
    material_root: [u8; Hash512::BYTE_LENGTH],
    topology: KeySwitchComponentMaterialTopology,
    stream_total_byte_length: u64,
    stream_full_object_digest: [u8; Hash512::BYTE_LENGTH],
    storage_byte_offset: u64,
    descriptor_binding: [u8; Hash512::BYTE_LENGTH],
    readback: Option<CanonicalStreamReadbackVerifier>,
}

#[derive(Clone)]
struct EvaluatorAggregateSourceColumn {
    column_ordinal: u32,
    source_index: usize,
    trace_column: KeySwitchComponentTraceColumn,
    descriptor: RelationColumnDescriptor,
}

struct PendingEvaluatorAggregateSourceColumn {
    source_column: EvaluatorAggregateSourceColumn,
    coefficients_bytes: Zeroizing<Box<[u8]>>,
    filled_byte_length: usize,
}

struct CachedEvaluatorAggregateSourceChunk {
    source_index: usize,
    stream_byte_offset: u64,
    bytes: Zeroizing<Box<[u8]>>,
}

/// One verifier- or generation-authority-owned source in the exact tree order
/// of a public complete-list relation. Storage coordinates are assigned by
/// the Rust runtime that owns the authenticated input corpus; JavaScript never
/// supplies a detached topology, root, context, or stream descriptor.
pub(crate) struct CompleteListSetupPolynomialSourceInput {
    source: SelectedEvaluatorStoreSource,
    storage_byte_offset: u64,
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    expected_root: [u8; Hash512::BYTE_LENGTH],
}

impl CompleteListSetupPolynomialSourceInput {
    pub(crate) fn from_authenticated_source(
        source: SelectedEvaluatorStoreSource,
        storage_byte_offset: u64,
        public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
        expected_root: [u8; Hash512::BYTE_LENGTH],
    ) -> Self {
        Self {
            source,
            storage_byte_offset,
            public_polynomial_context_hash,
            expected_root,
        }
    }
}

/// Closed, plan-addressed provider for one action-selected `0x1218` variant.
/// The provider traverses the checked tree and column descriptors themselves;
/// no arithmetic global-column convention or host ordinal map is accepted.
pub(crate) struct SelectedEvaluatorAggregateSourcePolynomialProvider {
    expected_request_context: CommonProofSourcePolynomialRequestContext,
    source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
    memory_accounting: SelectedEvaluatorAggregateSourceProviderMemoryAccounting,
    ordered_sources: Box<[EvaluatorAggregateAuthenticatedSource]>,
    ordered_source_columns: Box<[EvaluatorAggregateSourceColumn]>,
    next_source_column_position: usize,
    pending_column: Option<PendingEvaluatorAggregateSourceColumn>,
    cached_chunk: Option<CachedEvaluatorAggregateSourceChunk>,
    finished: bool,
}

impl SelectedEvaluatorAggregateSourcePolynomialProvider {
    /// Prepares any checked public complete-list relation whose bound trees
    /// are exact key-switch setup-polynomial streams. This is the shared
    /// compact frontier used by the evaluator aggregate and RKG round-one
    /// aggregate families; it retains only descriptors, readback state, one
    /// source column, and one authenticated transport chunk.
    pub(crate) fn prepare_complete_list(
        relation_plan: &CompiledRelationPlan,
        relation_plan_variant: RelationPlanVariant,
        expected_request_context: CommonProofSourcePolynomialRequestContext,
        source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
        ordered_source_inputs: Vec<CompleteListSetupPolynomialSourceInput>,
    ) -> Result<(Vec<RelationProofTreeInput>, Self), CommonProofProverError> {
        if source_catalog_binding == [0_u8; Hash512::BYTE_LENGTH]
            || expected_request_context.relation_plan_hash() != relation_plan.canonical_hash()?
            || expected_request_context.relation_plan_variant_hash()
                != relation_plan_variant.canonical_hash()?
            || relation_plan_variant.schedule_position()
                != expected_request_context.schedule_position()
            || relation_plan_variant.top_count() != expected_request_context.top_count()
            || ordered_source_inputs.len() != relation_plan_variant.ordered_trees().len()
        {
            return Err(CommonProofProverError::InvalidInput);
        }

        let mut ordered_sources = Vec::new();
        ordered_sources
            .try_reserve_exact(ordered_source_inputs.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut relation_trees = Vec::new();
        relation_trees
            .try_reserve_exact(ordered_source_inputs.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut ordered_source_columns = Vec::new();

        for (source_index, (tree, source_input)) in relation_plan_variant
            .ordered_trees()
            .iter()
            .zip(ordered_source_inputs)
            .enumerate()
        {
            let RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } = tree
            else {
                return Err(CommonProofProverError::InvalidTree);
            };
            let (topology, material_root, stream_descriptor, readback) =
                source_input.source.into_authenticated_parts();
            if ordered_column_ordinals.len()
                != topology
                    .trace_column_count()
                    .map_err(|_| CommonProofProverError::InvalidColumn)?
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            relation_trees.push(setup_polynomial_tree_input(
                source_input.public_polynomial_context_hash,
                source_input.expected_root,
                &topology,
            )?);
            let stream_full_object_digest = stream_descriptor.full_object_digest.into_bytes();
            let source_ordinal =
                u64::try_from(source_index).map_err(|_| CommonProofProverError::CountOverflow)?;
            let descriptor_binding = hash_framed_parts_512(
                COMPLETE_LIST_SOURCE_DESCRIPTOR_BINDING_DOMAIN,
                &[
                    &source_catalog_binding,
                    &source_ordinal.to_le_bytes(),
                    &source_input.storage_byte_offset.to_le_bytes(),
                    &source_input.public_polynomial_context_hash,
                    &source_input.expected_root,
                    &material_root,
                    &stream_full_object_digest,
                    &stream_descriptor.total_byte_length.to_le_bytes(),
                ],
            );
            for (trace_column_index, column_ordinal) in
                ordered_column_ordinals.iter().copied().enumerate()
            {
                let descriptor = relation_plan_variant
                    .ordered_columns()
                    .get(
                        usize::try_from(column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .cloned()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                if ordered_source_columns.last().is_some_and(
                    |prior: &EvaluatorAggregateSourceColumn| prior.column_ordinal >= column_ordinal,
                ) {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                ordered_source_columns.push(EvaluatorAggregateSourceColumn {
                    column_ordinal,
                    source_index,
                    trace_column: topology
                        .trace_column(trace_column_index)
                        .map_err(|_| CommonProofProverError::InvalidColumn)?,
                    descriptor,
                });
            }
            ordered_sources.push(EvaluatorAggregateAuthenticatedSource {
                material_root,
                topology,
                stream_total_byte_length: stream_descriptor.total_byte_length,
                stream_full_object_digest,
                storage_byte_offset: source_input.storage_byte_offset,
                descriptor_binding,
                readback: Some(readback),
            });
        }
        if ordered_source_columns.len() != relation_plan_variant.ordered_columns().len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let memory_accounting = prepared_evaluator_source_provider_memory_accounting(
            &ordered_sources,
            &ordered_source_columns,
        )?;
        Ok((
            relation_trees,
            Self {
                expected_request_context,
                source_catalog_binding,
                memory_accounting,
                ordered_sources: ordered_sources.into_boxed_slice(),
                ordered_source_columns: ordered_source_columns.into_boxed_slice(),
                next_source_column_position: 0,
                pending_column: None,
                cached_chunk: None,
                finished: false,
            },
        ))
    }

    /// Prepares the exact bound-public tree list and its authenticated source
    /// provider from verifier-owned source and store material. The statement
    /// roots, selected plan variant, physical store layout, and every source
    /// material capability must agree before any byte request can be emitted.
    pub(crate) fn prepare<SourceCatalog>(
        relation_plan: &CompiledRelationPlan,
        source_catalog: &SourceCatalog,
        store_material: &VerifiedEvaluatorKeyStoreMaterial,
        ordered_runtime_roots: &[VerifiedEvaluatorRuntimeRoot],
        canonical_application_statement_bytes: &[u8],
    ) -> Result<(Vec<RelationProofTreeInput>, Self), CommonProofProverError>
    where
        SourceCatalog: SelectedEvaluatorStoreSourceCatalog + ?Sized,
    {
        let top_count = store_material.top_count();
        let positions = selected_evaluator_entry_positions(top_count)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        if source_catalog.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || relation_plan.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            || positions.is_empty()
            || store_material.ordered_components().len() != positions.len()
            || ordered_runtime_roots.len() != positions.len()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let relation_plan_hash = relation_plan.canonical_hash()?;
        let variant = relation_plan.select_variant(None, Some(top_count))?.clone();
        let relation_plan_variant_hash = variant.canonical_hash()?;
        let application_statement_hash = verified_application_statement_hash(
            source_catalog.protocol_version(),
            source_catalog.suite_identifier(),
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            canonical_application_statement_bytes,
        );
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            SelectedApplicationStatementContext::new(
                source_catalog.protocol_version(),
                source_catalog.suite_identifier(),
                None,
                Some(top_count),
            ),
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let statement_entries =
            selected_evaluator_aggregate_entry_roots_in_order(&statement, top_count)
                .map_err(|_| CommonProofProverError::InvalidInput)?;
        if !statement.items.first().is_some_and(|item| {
            item.item_type() == CanonicalItemType::Hash512
                && item.canonical_bytes() == source_catalog.setup_proof_context_hash()
        }) || !statement.items.get(2).is_some_and(|item| {
            item.item_type() == CanonicalItemType::Hash512
                && item.canonical_bytes()
                    == store_material
                        .store_descriptor()
                        .full_object_digest
                        .as_bytes()
        }) {
            return Err(CommonProofProverError::InvalidInput);
        }

        let source_catalog_binding = hash_framed_parts_512(
            EVALUATOR_SOURCE_CATALOG_BINDING_DOMAIN,
            &[
                &source_catalog.protocol_version().to_le_bytes(),
                &source_catalog.suite_identifier(),
                &source_catalog.ceremony_context_hash(),
                &source_catalog.action_context_hash(),
                &source_catalog.manifest_hash(),
                &source_catalog.roster_hash(),
                &source_catalog.setup_proof_context_hash(),
                &top_count.to_le_bytes(),
                &application_statement_hash,
                &relation_plan_hash,
                &relation_plan_variant_hash,
                store_material
                    .store_descriptor()
                    .full_object_digest
                    .as_bytes(),
            ],
        );

        let mut source_descriptions = Vec::new();
        let mut relation_trees = Vec::new();
        for (entry_ordinal, position) in positions.iter().copied().enumerate() {
            let statement_entry = statement_entries
                .get(entry_ordinal)
                .filter(|entry| entry.position() == position)
                .ok_or(CommonProofProverError::InvalidInput)?;
            for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                let source = source_catalog
                    .component_source(roster_position, position)
                    .map_err(|_| CommonProofProverError::InvalidInput)?
                    .ok_or(CommonProofProverError::InvalidInput)?;
                let expected_root = source_catalog
                    .component_root(roster_position, position)
                    .filter(|root| {
                        statement_entry
                            .source_component_roots()
                            .get(usize::from(roster_position))
                            == Some(root)
                    })
                    .ok_or(CommonProofProverError::InvalidInput)?;
                let public_polynomial_context_hash = source_catalog
                    .component_public_polynomial_context_hash(roster_position, position)
                    .ok_or(CommonProofProverError::InvalidInput)?;
                let topology = source.topology().clone();
                source_descriptions.push(prepare_authenticated_catalog_source(
                    source_catalog_binding,
                    position,
                    roster_position,
                    0,
                    source,
                )?);
                relation_trees.push(setup_polynomial_tree_input(
                    public_polynomial_context_hash,
                    expected_root,
                    &topology,
                )?);
            }

            let component = store_material
                .ordered_components()
                .get(entry_ordinal)
                .filter(|component| component.position() == position)
                .ok_or(CommonProofProverError::InvalidInput)?;
            let runtime_root = ordered_runtime_roots
                .get(entry_ordinal)
                .copied()
                .filter(|root| {
                    root.position() == position
                        && root.runtime_component_root() == statement_entry.runtime_component_root()
                })
                .ok_or(CommonProofProverError::InvalidInput)?;
            let runtime_context = SetupPublicPolynomialContext::new(
                source_catalog.setup_proof_context_hash(),
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
            .and_then(|context| context.context_hash())
            .map_err(|_| CommonProofProverError::InvalidInput)?;
            source_descriptions.push(prepare_authenticated_source(
                source_catalog_binding,
                position,
                EVALUATOR_RUNTIME_SOURCE_ROLE,
                component.store_byte_offset(),
                component.material(),
            )?);
            relation_trees.push(setup_polynomial_tree_input(
                runtime_context,
                runtime_root.runtime_component_root(),
                component.material().topology(),
            )?);
        }

        if source_descriptions.len() != variant.ordered_trees().len()
            || relation_trees.len() != variant.ordered_trees().len()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let mut ordered_source_columns = Vec::new();
        for (source_index, (tree, source)) in variant
            .ordered_trees()
            .iter()
            .zip(&source_descriptions)
            .enumerate()
        {
            let RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } = tree
            else {
                return Err(CommonProofProverError::InvalidTree);
            };
            if ordered_column_ordinals.len()
                != source
                    .topology
                    .trace_column_count()
                    .map_err(|_| CommonProofProverError::InvalidColumn)?
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            for (trace_column_index, column_ordinal) in
                ordered_column_ordinals.iter().copied().enumerate()
            {
                if variant
                    .ordered_columns()
                    .get(
                        usize::try_from(column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .is_none()
                    || ordered_source_columns.last().is_some_and(
                        |prior: &EvaluatorAggregateSourceColumn| {
                            prior.column_ordinal >= column_ordinal
                        },
                    )
                {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                ordered_source_columns.push(EvaluatorAggregateSourceColumn {
                    column_ordinal,
                    source_index,
                    trace_column: source
                        .topology
                        .trace_column(trace_column_index)
                        .map_err(|_| CommonProofProverError::InvalidColumn)?,
                    descriptor: variant
                        .ordered_columns()
                        .get(
                            usize::try_from(column_ordinal)
                                .map_err(|_| CommonProofProverError::CountOverflow)?,
                        )
                        .cloned()
                        .ok_or(CommonProofProverError::InvalidColumn)?,
                });
            }
        }
        if ordered_source_columns.len() != variant.ordered_columns().len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let expected_request_context = CommonProofSourcePolynomialRequestContext::new(
            source_catalog.protocol_version(),
            source_catalog.suite_identifier(),
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            application_statement_hash,
            relation_plan_hash,
            relation_plan_variant_hash,
            None,
            Some(top_count),
        );
        let memory_accounting = prepared_evaluator_source_provider_memory_accounting(
            &source_descriptions,
            &ordered_source_columns,
        )?;
        Ok((
            relation_trees,
            Self {
                expected_request_context,
                source_catalog_binding,
                memory_accounting,
                ordered_sources: source_descriptions.into_boxed_slice(),
                ordered_source_columns: ordered_source_columns.into_boxed_slice(),
                next_source_column_position: 0,
                pending_column: None,
                cached_chunk: None,
                finished: false,
            },
        ))
    }

    fn expected_source_column(
        &self,
    ) -> Result<EvaluatorAggregateSourceColumn, CommonProofProverError> {
        self.ordered_source_columns
            .get(self.next_source_column_position)
            .cloned()
            .ok_or(CommonProofProverError::InvalidColumn)
    }

    fn next_read_request(
        &self,
    ) -> Result<CommonProofAuthenticatedSourceReadRequest, CommonProofProverError> {
        let pending = self
            .pending_column
            .as_ref()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let source = self
            .ordered_sources
            .get(pending.source_column.source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let accumulated_byte_length = u64::try_from(pending.filled_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let next_column_byte_offset = pending
            .source_column
            .trace_column
            .byte_offset()
            .checked_add(accumulated_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let column_end = pending
            .source_column
            .trace_column
            .byte_offset()
            .checked_add(pending.source_column.trace_column.byte_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if next_column_byte_offset >= column_end {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let chunk_index = next_column_byte_offset / chunk_byte_length;
        let stream_byte_offset = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let requested_byte_length = source
            .stream_total_byte_length
            .checked_sub(stream_byte_offset)
            .map(|remaining| remaining.min(chunk_byte_length))
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(CommonProofProverError::CountOverflow)?;
        CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
            self.expected_request_context.request(
                pending.source_column.column_ordinal,
                &pending.source_column.descriptor,
            ),
            self.source_catalog_binding,
            source.descriptor_binding,
            source.material_root,
            source.stream_full_object_digest,
            source.stream_total_byte_length,
            stream_byte_offset,
            source
                .storage_byte_offset
                .checked_add(stream_byte_offset)
                .ok_or(CommonProofProverError::CountOverflow)?,
            requested_byte_length,
            u32::try_from(chunk_index).map_err(|_| CommonProofProverError::CountOverflow)?,
        )
    }

    fn absorb_cached_chunk(&mut self) -> Result<(), CommonProofProverError> {
        let Some(cache) = self.cached_chunk.as_ref() else {
            return Ok(());
        };
        let pending = self
            .pending_column
            .as_mut()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if cache.source_index != pending.source_column.source_index {
            return Ok(());
        }
        let column = pending.source_column.trace_column;
        let next_byte_offset = column
            .byte_offset()
            .checked_add(
                u64::try_from(pending.filled_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let cache_end = cache
            .stream_byte_offset
            .checked_add(
                u64::try_from(cache.bytes.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if next_byte_offset < cache.stream_byte_offset || next_byte_offset >= cache_end {
            return Ok(());
        }
        let column_end = column
            .byte_offset()
            .checked_add(column.byte_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        let copy_end = column_end.min(cache_end);
        let cache_start = usize::try_from(next_byte_offset - cache.stream_byte_offset)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let cache_copy_end = usize::try_from(copy_end - cache.stream_byte_offset)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let copied_byte_length = cache_copy_end
            .checked_sub(cache_start)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let filled_end = pending
            .filled_byte_length
            .checked_add(copied_byte_length)
            .filter(|end| *end <= pending.coefficients_bytes.len())
            .ok_or(CommonProofProverError::CountOverflow)?;
        pending.coefficients_bytes[pending.filled_byte_length..filled_end]
            .copy_from_slice(&cache.bytes[cache_start..cache_copy_end]);
        pending.filled_byte_length = filled_end;
        Ok(())
    }

    fn pending_column_is_complete(&self) -> bool {
        self.pending_column.as_ref().is_some_and(|pending| {
            u64::try_from(pending.filled_byte_length).ok()
                == Some(pending.source_column.trace_column.byte_length())
        })
    }

    fn finish_pending_column(
        &mut self,
    ) -> Result<ProvidedCommonProofSourcePolynomial, CommonProofProverError> {
        if !self.pending_column_is_complete() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let pending = self
            .pending_column
            .take()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let source = self
            .ordered_sources
            .get(pending.source_column.source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let coefficients = pending
            .source_column
            .trace_column
            .decode_authenticated_bytes(&pending.coefficients_bytes[..pending.filled_byte_length])
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let replay_identity = CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
            hash_framed_parts_512(
                COMPLETE_LIST_SOURCE_REPLAY_IDENTITY_DOMAIN,
                &[
                    &self
                        .expected_request_context
                        .stable_generation_binding_hash(),
                    &self.source_catalog_binding,
                    &source.descriptor_binding,
                    &source.material_root,
                    &source.stream_full_object_digest,
                    &pending.source_column.column_ordinal.to_le_bytes(),
                    &pending
                        .source_column
                        .trace_column
                        .byte_offset()
                        .to_le_bytes(),
                    &pending
                        .source_column
                        .trace_column
                        .byte_length()
                        .to_le_bytes(),
                ],
            ),
        )?;
        self.next_source_column_position = self
            .next_source_column_position
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(ProvidedCommonProofSourcePolynomial::new(
            CommonProofSourcePolynomial::from_base_coefficients(coefficients),
            replay_identity,
        ))
    }
}

impl CommonProofSourcePolynomialProvider for SelectedEvaluatorAggregateSourcePolynomialProvider {
    fn persistent_resident_memory_byte_length(&self) -> Result<u64, CommonProofProverError> {
        Ok(self
            .memory_accounting
            .loading_persistent_resident_byte_length())
    }

    fn post_source_polynomial_finish_persistent_resident_memory_byte_length(
        &self,
    ) -> Result<u64, CommonProofProverError> {
        Ok(self
            .memory_accounting
            .post_source_polynomial_finish_persistent_resident_byte_length())
    }

    fn loading_source_polynomials_transient_byte_length(
        &self,
    ) -> Result<u64, CommonProofProverError> {
        Ok(self
            .memory_accounting
            .additional_loading_source_polynomials_transient_byte_length())
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if self.finished {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let expected = self.expected_source_column()?;
        if request.request_context() != self.expected_request_context
            || request.column_ordinal() != expected.column_ordinal
            || request.descriptor() != &expected.descriptor
            || self.pending_column.as_ref().is_some_and(|pending| {
                pending.source_column.column_ordinal != expected.column_ordinal
            })
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if self.pending_column.is_none() {
            let capacity = usize::try_from(expected.trace_column.byte_length())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
            self.pending_column = Some(PendingEvaluatorAggregateSourceColumn {
                source_column: expected,
                coefficients_bytes: Zeroizing::new(vec![0_u8; capacity].into_boxed_slice()),
                filled_byte_length: 0,
            });
        }
        self.absorb_cached_chunk()?;
        if self.pending_column_is_complete() {
            return self
                .finish_pending_column()
                .map(CommonProofSourcePolynomialProviderPoll::Ready);
        }
        let request = self.next_read_request()?;
        // The retained chunk has already contributed every byte it can to the
        // pending column. Release it before the caller allocates the next
        // authenticated chunk so two full source chunks never overlap here.
        self.cached_chunk = None;
        Ok(CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(request))
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        let expected_request = self.next_read_request()?;
        if request != expected_request
            || authenticated_bytes.len()
                != usize::try_from(request.source_byte_length())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_index = self
            .pending_column
            .as_ref()
            .map(|pending| pending.source_column.source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        self.ordered_sources
            .get_mut(source_index)
            .and_then(|source| source.readback.as_mut())
            .ok_or(CommonProofProverError::InvalidColumn)?
            .authenticate_chunk(
                usize::try_from(request.authentication_chunk_index())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                &authenticated_bytes,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        self.cached_chunk = Some(CachedEvaluatorAggregateSourceChunk {
            source_index,
            stream_byte_offset: request.source_stream_byte_offset(),
            bytes: authenticated_bytes,
        });
        self.absorb_cached_chunk()
    }

    fn cancel_pending_authenticated_source_read(&mut self) {
        self.pending_column = None;
        self.cached_chunk = None;
        self.finished = true;
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.finished
            || self.pending_column.is_some()
            || self.next_source_column_position != self.ordered_source_columns.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_chunk = None;
        for source in &mut self.ordered_sources {
            source
                .readback
                .take()
                .ok_or(CommonProofProverError::InvalidColumn)?
                .finish()
                .into_result()
                .map_err(|_| CommonProofProverError::InvalidColumn)?;
        }
        self.finished = true;
        Ok(())
    }
}

fn setup_polynomial_tree_input(
    public_polynomial_context_hash: [u8; Hash512::BYTE_LENGTH],
    expected_root: [u8; Hash512::BYTE_LENGTH],
    topology: &KeySwitchComponentMaterialTopology,
) -> Result<RelationProofTreeInput, CommonProofProverError> {
    Ok(RelationProofTreeInput::BoundPublic(
        StatementOwnedProofTreeInput::SetupPolynomial {
            public_polynomial_context_hash,
            row_width: u32::try_from(
                topology
                    .trace_column_count()
                    .map_err(|_| CommonProofProverError::InvalidColumn)?,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?,
            expected_root,
        },
    ))
}

fn prepare_authenticated_source(
    source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
    position: SelectedEvaluatorEntryPosition,
    source_role: u16,
    storage_byte_offset: u64,
    material: &VerifiedKeySwitchComponentMaterial,
) -> Result<EvaluatorAggregateAuthenticatedSource, CommonProofProverError> {
    prepare_authenticated_source_parts(
        source_catalog_binding,
        position,
        source_role,
        storage_byte_offset,
        material.topology().clone(),
        material.material_root().into_bytes(),
        material.stream_descriptor().clone(),
        material
            .begin_authenticated_readback()
            .map_err(|_| CommonProofProverError::InvalidInput)?,
    )
}

fn prepare_authenticated_catalog_source(
    source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
    position: SelectedEvaluatorEntryPosition,
    source_role: u16,
    storage_byte_offset: u64,
    source: SelectedEvaluatorStoreSource,
) -> Result<EvaluatorAggregateAuthenticatedSource, CommonProofProverError> {
    let (topology, material_root, stream_descriptor, readback) = source.into_authenticated_parts();
    prepare_authenticated_source_parts(
        source_catalog_binding,
        position,
        source_role,
        storage_byte_offset,
        topology,
        material_root,
        stream_descriptor,
        readback,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_authenticated_source_parts(
    source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
    position: SelectedEvaluatorEntryPosition,
    source_role: u16,
    storage_byte_offset: u64,
    topology: KeySwitchComponentMaterialTopology,
    material_root: [u8; Hash512::BYTE_LENGTH],
    stream_descriptor: crate::foundation::StreamDescriptor,
    readback: CanonicalStreamReadbackVerifier,
) -> Result<EvaluatorAggregateAuthenticatedSource, CommonProofProverError> {
    let (entry_kind, galois_element, catalog_level) = match position.key_kind() {
        SelectedEvaluatorEntryKind::Relinearization { catalog_level } => {
            (RELINEARIZATION_ENTRY_KIND_BINDING, 0_u64, catalog_level)
        }
        SelectedEvaluatorEntryKind::Galois {
            galois_element,
            catalog_level,
        } => (
            GALOIS_ENTRY_KIND_BINDING,
            u64::try_from(galois_element).map_err(|_| CommonProofProverError::CountOverflow)?,
            catalog_level,
        ),
    };
    let catalog_level =
        u64::try_from(catalog_level).map_err(|_| CommonProofProverError::CountOverflow)?;
    let stream_full_object_digest = stream_descriptor.full_object_digest.into_bytes();
    let descriptor_binding = hash_framed_parts_512(
        EVALUATOR_SOURCE_DESCRIPTOR_BINDING_DOMAIN,
        &[
            &source_catalog_binding,
            &position.schedule_position().to_le_bytes(),
            &entry_kind.to_le_bytes(),
            &galois_element.to_le_bytes(),
            &catalog_level.to_le_bytes(),
            &source_role.to_le_bytes(),
            &storage_byte_offset.to_le_bytes(),
            &material_root,
            &stream_full_object_digest,
            &stream_descriptor.total_byte_length.to_le_bytes(),
        ],
    );
    Ok(EvaluatorAggregateAuthenticatedSource {
        material_root,
        topology,
        stream_total_byte_length: stream_descriptor.total_byte_length,
        stream_full_object_digest,
        storage_byte_offset,
        descriptor_binding,
        readback: Some(readback),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter,
    };

    fn test_provider() -> (
        SelectedEvaluatorAggregateSourcePolynomialProvider,
        super::super::RelationPlanVariant,
        Vec<u8>,
    ) {
        let topology = KeySwitchComponentMaterialTopology::for_test_suite(&[97], &[193], 1, 16)
            .expect("test topology");
        let bytes = vec![0_u8; usize::try_from(topology.expected_byte_length()).unwrap()];
        let mut writer = CanonicalStreamWriter::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            topology.expected_byte_length(),
        )
        .expect("stream writer");
        writer.absorb_chunk(0, &bytes).expect("stream bytes");
        let descriptor = writer.finish().expect("stream descriptor");
        let mut verifier = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            descriptor.clone(),
        )
        .expect("stream verifier");
        verifier
            .absorb_chunk(0, &bytes)
            .into_result()
            .expect("verified stream bytes");
        let summary = verifier
            .finish_with_summary()
            .into_result()
            .expect("verified stream summary");
        let readback =
            CanonicalStreamReadbackVerifier::new(CanonicalStreamDomain::EvaluatorKeyStore, summary)
                .expect("authenticated readback");
        let plan = super::super::selected_evaluator_aggregate_relation_plan()
            .expect("selected evaluator plan");
        let variant = plan
            .select_variant(None, Some(1))
            .expect("first action variant")
            .clone();
        let first_column_ordinal = *variant.ordered_trees()[0]
            .ordered_column_ordinals()
            .first()
            .expect("first source column");
        let trace_column = topology.trace_column(0).expect("first trace column");
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x21; 64],
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            [0x22; 64],
            plan.canonical_hash().expect("plan hash"),
            variant.canonical_hash().expect("variant hash"),
            None,
            Some(1),
        );
        let ordered_sources = vec![EvaluatorAggregateAuthenticatedSource {
            material_root: [0x24; 64],
            topology,
            stream_total_byte_length: descriptor.total_byte_length,
            stream_full_object_digest: descriptor.full_object_digest.into_bytes(),
            storage_byte_offset: 2_048,
            descriptor_binding: [0x25; 64],
            readback: Some(readback),
        }]
        .into_boxed_slice();
        let ordered_source_columns = vec![EvaluatorAggregateSourceColumn {
            column_ordinal: first_column_ordinal,
            source_index: 0,
            trace_column,
            descriptor: variant.ordered_columns()
                [usize::try_from(first_column_ordinal).expect("column ordinal")]
            .clone(),
        }]
        .into_boxed_slice();
        let memory_accounting = prepared_evaluator_source_provider_memory_accounting(
            &ordered_sources,
            &ordered_source_columns,
        )
        .expect("provider accounting");
        (
            SelectedEvaluatorAggregateSourcePolynomialProvider {
                expected_request_context: request_context,
                source_catalog_binding: [0x23; 64],
                memory_accounting,
                ordered_sources,
                ordered_source_columns,
                next_source_column_position: 0,
                pending_column: None,
                cached_chunk: None,
                finished: false,
            },
            variant,
            bytes,
        )
    }

    fn poll_first_column(
        provider: &mut SelectedEvaluatorAggregateSourcePolynomialProvider,
        request_variant: &super::super::RelationPlanVariant,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let column_ordinal = provider.ordered_source_columns[0].column_ordinal;
        let request_context = provider.expected_request_context;
        provider.poll_source_polynomial(request_context.request(
            column_ordinal,
            &request_variant.ordered_columns()
                [usize::try_from(column_ordinal).expect("column ordinal")],
        ))
    }

    #[test]
    fn provider_memory_accounting_covers_exact_owned_catalogs_and_loading_buffers() {
        let (provider, _, _) = test_provider();
        let accounting = provider.memory_accounting;
        assert_eq!(
            accounting.loading_persistent_resident_byte_length(),
            accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                + accounting.readback_chunk_digest_byte_length()
                + accounting.readback_authentication_flag_byte_length()
        );
        assert_eq!(
            accounting.post_source_polynomial_finish_persistent_resident_byte_length(),
            accounting.provider_fixed_owner_byte_length()
                + accounting.authenticated_source_catalog_byte_length()
                + accounting.ordered_source_column_catalog_byte_length()
                + accounting.topology_catalog_byte_length()
        );
        assert_eq!(
            accounting.additional_loading_source_polynomials_transient_byte_length(),
            accounting.maximum_pending_column_byte_length()
                + accounting.maximum_cached_authenticated_chunk_byte_length()
        );
        assert!(accounting.maximum_returned_source_polynomial_byte_length() > 0);
    }

    #[test]
    fn authenticated_source_read_accepts_one_canonical_chunk_and_rejects_larger_ranges() {
        let (provider, request_variant, _) = test_provider();
        let column_ordinal = provider.ordered_source_columns[0].column_ordinal;
        let request_context = provider.expected_request_context;
        let descriptor = &request_variant.ordered_columns()
            [usize::try_from(column_ordinal).expect("column ordinal")];
        let canonical_chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let canonical_chunk_byte_length_u32 =
            u32::try_from(canonical_chunk_byte_length).expect("canonical chunk byte length");
        let total_byte_length = u64::try_from(canonical_chunk_byte_length)
            .expect("canonical chunk byte length")
            .checked_add(1)
            .expect("test stream byte length");

        let exact_chunk_request =
            CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
                request_context.request(column_ordinal, descriptor),
                [0x31; 64],
                [0x32; 64],
                [0x33; 64],
                [0x34; 64],
                total_byte_length,
                0,
                4_096,
                canonical_chunk_byte_length_u32,
                0,
            )
            .expect("one canonical source chunk");
        assert_eq!(
            exact_chunk_request.source_byte_length(),
            canonical_chunk_byte_length_u32
        );

        let oversized_byte_length = canonical_chunk_byte_length_u32
            .checked_add(1)
            .expect("oversized byte length");
        assert!(matches!(
            CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
                request_context.request(column_ordinal, descriptor),
                [0x31; 64],
                [0x32; 64],
                [0x33; 64],
                [0x34; 64],
                total_byte_length,
                0,
                4_096,
                oversized_byte_length,
                0,
            ),
            Err(CommonProofProverError::InvalidColumn)
        ));
        assert!(matches!(
            CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
                request_context.request(column_ordinal, descriptor),
                [0x31; 64],
                [0x32; 64],
                [0x33; 64],
                [0x34; 64],
                total_byte_length,
                0,
                u64::MAX,
                1,
                0,
            ),
            Err(CommonProofProverError::InvalidColumn)
        ));
    }

    #[test]
    fn authenticated_source_request_is_stable_and_rejects_wrong_range_or_replay() {
        let (mut provider, request_variant, bytes) = test_provider();
        let first_request = match poll_first_column(&mut provider, &request_variant)
            .expect("first provider poll")
        {
            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(request) => {
                request
            }
            CommonProofSourcePolynomialProviderPoll::Ready(_) => panic!("read was not requested"),
        };
        let repeated_request = match poll_first_column(&mut provider, &request_variant)
            .expect("repeated provider poll")
        {
            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(request) => {
                request
            }
            CommonProofSourcePolynomialProviderPoll::Ready(_) => panic!("read was not requested"),
        };
        assert_eq!(first_request, repeated_request);
        assert_eq!(first_request.storage_byte_offset(), 2_048);
        assert_eq!(first_request.source_stream_byte_offset(), 0);
        assert_eq!(
            usize::try_from(first_request.source_byte_length()).unwrap(),
            bytes.len()
        );

        let column_ordinal = provider.ordered_source_columns[0].column_ordinal;
        let wrong_storage_request =
            CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
                provider.expected_request_context.request(
                    column_ordinal,
                    &request_variant.ordered_columns()[usize::try_from(column_ordinal).unwrap()],
                ),
                first_request.source_catalog_binding(),
                first_request.source_descriptor_binding(),
                first_request.source_material_root(),
                first_request.source_stream_digest(),
                first_request.source_stream_total_byte_length(),
                first_request.source_stream_byte_offset(),
                first_request.storage_byte_offset() + 1,
                first_request.source_byte_length(),
                first_request.authentication_chunk_index(),
            )
            .expect("well-formed wrong storage request");
        assert_ne!(
            first_request.request_identity(),
            wrong_storage_request.request_identity()
        );
        assert_eq!(
            provider.supply_authenticated_source_range(
                wrong_storage_request,
                Zeroizing::new(bytes.clone().into_boxed_slice()),
            ),
            Err(CommonProofProverError::InvalidColumn)
        );
        assert_eq!(
            provider.supply_authenticated_source_range(
                first_request,
                Zeroizing::new(bytes[..bytes.len() - 1].to_vec().into_boxed_slice()),
            ),
            Err(CommonProofProverError::InvalidColumn)
        );

        provider
            .supply_authenticated_source_range(
                first_request,
                Zeroizing::new(bytes.clone().into_boxed_slice()),
            )
            .expect("exact authenticated source range");
        assert!(matches!(
            poll_first_column(&mut provider, &request_variant),
            Ok(CommonProofSourcePolynomialProviderPoll::Ready(_))
        ));
        assert_eq!(
            provider.supply_authenticated_source_range(
                first_request,
                Zeroizing::new(bytes.into_boxed_slice()),
            ),
            Err(CommonProofProverError::InvalidColumn)
        );
    }

    #[test]
    fn fresh_provider_reissues_the_same_request_and_cancellation_clears_payloads() {
        let (mut first_provider, first_variant, _) = test_provider();
        let (mut resumed_provider, resumed_variant, _) = test_provider();
        let first_request = match poll_first_column(&mut first_provider, &first_variant).unwrap() {
            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(request) => {
                request
            }
            CommonProofSourcePolynomialProviderPoll::Ready(_) => panic!("read was not requested"),
        };
        let resumed_request = match poll_first_column(&mut resumed_provider, &resumed_variant)
            .unwrap()
        {
            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(request) => {
                request
            }
            CommonProofSourcePolynomialProviderPoll::Ready(_) => panic!("read was not requested"),
        };
        assert_eq!(first_request, resumed_request);
        first_provider.cancel_pending_authenticated_source_read();
        assert!(first_provider.pending_column.is_none());
        assert!(first_provider.cached_chunk.is_none());
        assert!(first_provider.finished);
        assert!(matches!(
            poll_first_column(&mut first_provider, &first_variant),
            Err(CommonProofProverError::InvalidColumn)
        ));
    }
}
