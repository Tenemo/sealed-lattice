use std::mem::size_of;

use crate::{
    bgv::proof_suite::{
        AuthenticatedCompactCommittedMaterialSource, COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
        CommonProofBoundTreeLeafSaltRequest, CommonProofProverError,
        CommonProofRelationPlanCapability, CommonProofSourcePolynomial,
        CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
        CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
        CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
        CompactCommittedMaterialSource, ProofBaseFieldElement, ProofEvaluationDomain,
        ProofLeafVisibility, ProofTreeRole, ProvidedCommonProofSourcePolynomial,
        RelationProofTreeInput, StatementOwnedProofTreeInput,
    },
    foundation::PersistentProofWitnessCoinBinding,
    hashing::hash_framed_parts_512,
};

use super::{
    BoundTreeConstructionKind, CommittedMaterialRelationPlanInput,
    CommittedMaterialTraceWitnessProvider, CommittedMaterialTraceWitnessStructureMemoryAccounting,
    CompiledRelationPlan, RelationColumnDescriptor, RelationColumnOrigin, RelationPlanCheckContext,
    RelationTreeDescriptor, compile_aggregate_threshold_share_relation_plan,
    compile_vss_share_linkage_relation_plan,
    derive_aggregate_threshold_share_trace_witness_provider,
    derive_vss_share_linkage_trace_witness_provider,
};

const VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
const AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
const VSS_SOURCE_RESTART_BINDING_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/source-restart-binding/v1";
const VSS_SOURCE_POLYNOMIAL_REPLAY_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/source-polynomial-replay/v1";
const AGGREGATE_SOURCE_RESTART_BINDING_DOMAIN: &str =
    "sealed-lattice/setup/aggregate-threshold-share/source-restart-binding/v1";
const AGGREGATE_SOURCE_POLYNOMIAL_REPLAY_DOMAIN: &str =
    "sealed-lattice/setup/aggregate-threshold-share/source-polynomial-replay/v1";
const COMMITTED_MATERIAL_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/common-proof/committed-material-canonical-semantic-witness/v2";
const CANONICAL_WITNESS_U64_FRAMING_BUFFER_BYTE_LENGTH: u64 = 4_096;

#[derive(Clone, Copy)]
enum SelectedCommittedMaterialRelationKind {
    VssShareLinkage,
    AggregateThresholdShare,
}

impl SelectedCommittedMaterialRelationKind {
    const fn statement_schema_identifier(self) -> u16 {
        match self {
            Self::VssShareLinkage => VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            Self::AggregateThresholdShare => AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        }
    }

    const fn restart_binding_domain(self) -> &'static str {
        match self {
            Self::VssShareLinkage => VSS_SOURCE_RESTART_BINDING_DOMAIN,
            Self::AggregateThresholdShare => AGGREGATE_SOURCE_RESTART_BINDING_DOMAIN,
        }
    }

    const fn polynomial_replay_domain(self) -> &'static str {
        match self {
            Self::VssShareLinkage => VSS_SOURCE_POLYNOMIAL_REPLAY_DOMAIN,
            Self::AggregateThresholdShare => AGGREGATE_SOURCE_POLYNOMIAL_REPLAY_DOMAIN,
        }
    }
}

struct BoundMaterialColumn {
    logical_root_ordinal: usize,
    physical_column_ordinal: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialSourceProviderMemoryAccounting {
    logical_root_count: u64,
    adapter_fixed_byte_length: u64,
    authenticated_coefficient_byte_length: u64,
    compact_source_byte_length: u64,
    adapter_source_wrapper_catalog_byte_length: u64,
    trace_provider_source_wrapper_catalog_byte_length: u64,
    bound_material_column_lookup_catalog_byte_length: u64,
    ordered_column_catalog_byte_length: u64,
    resolved_modulus_catalog_byte_length: u64,
    recipe_catalog_byte_length: u64,
    nested_recipe_catalog_byte_length: u64,
    relation_tree_input_catalog_byte_length: u64,
    canonical_witness_framing_transient_byte_length: u64,
    construction_transient_peak_byte_length: u64,
    construction_peak_resident_byte_length: u64,
    preparation_transient_byte_length: u64,
    preparation_peak_resident_byte_length: u64,
    loading_persistent_resident_byte_length: u64,
    post_source_polynomial_finish_persistent_resident_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
}

impl CommittedMaterialSourceProviderMemoryAccounting {
    pub(crate) const fn logical_root_count(self) -> u64 {
        self.logical_root_count
    }

    #[cfg(test)]
    pub(crate) const fn adapter_fixed_byte_length(self) -> u64 {
        self.adapter_fixed_byte_length
    }

    pub(crate) const fn authenticated_coefficient_byte_length(self) -> u64 {
        self.authenticated_coefficient_byte_length
    }

    pub(crate) const fn compact_source_byte_length(self) -> u64 {
        self.compact_source_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn adapter_source_wrapper_catalog_byte_length(self) -> u64 {
        self.adapter_source_wrapper_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn trace_provider_source_wrapper_catalog_byte_length(self) -> u64 {
        self.trace_provider_source_wrapper_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn bound_material_column_lookup_catalog_byte_length(self) -> u64 {
        self.bound_material_column_lookup_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn ordered_column_catalog_byte_length(self) -> u64 {
        self.ordered_column_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn resolved_modulus_catalog_byte_length(self) -> u64 {
        self.resolved_modulus_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn recipe_catalog_byte_length(self) -> u64 {
        self.recipe_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn nested_recipe_catalog_byte_length(self) -> u64 {
        self.nested_recipe_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn relation_tree_input_catalog_byte_length(self) -> u64 {
        self.relation_tree_input_catalog_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn canonical_witness_framing_transient_byte_length(self) -> u64 {
        self.canonical_witness_framing_transient_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn construction_transient_peak_byte_length(self) -> u64 {
        self.construction_transient_peak_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn construction_peak_resident_byte_length(self) -> u64 {
        self.construction_peak_resident_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn preparation_transient_byte_length(self) -> u64 {
        self.preparation_transient_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn preparation_peak_resident_byte_length(self) -> u64 {
        self.preparation_peak_resident_byte_length
    }

    pub(crate) const fn loading_persistent_resident_byte_length(self) -> u64 {
        self.loading_persistent_resident_byte_length
    }

    pub(crate) const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
        self.post_source_polynomial_finish_persistent_resident_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn persistent_resident_byte_length(self) -> u64 {
        self.loading_persistent_resident_byte_length
    }

    pub(crate) const fn maximum_returned_source_polynomial_byte_length(self) -> u64 {
        self.maximum_returned_source_polynomial_byte_length
    }

    /// The returned source polynomial is already owned by the common prover's
    /// loading-phase working set. Regeneration and interpolation occur in
    /// place, so the provider contributes no second trace-sized allocation.
    pub(crate) const fn additional_loading_source_polynomials_transient_byte_length(self) -> u64 {
        0
    }

    /// The 128-byte secret leaf salt is returned by value into the common
    /// tree-materialization working set. No provider-owned salt catalog or
    /// second salt buffer survives the call.
    #[cfg(test)]
    pub(crate) const fn additional_materializing_base_trees_transient_byte_length(self) -> u64 {
        0
    }

    fn from_dimensions(
        logical_root_count: usize,
        canonical_coefficient_count_per_root: usize,
        bound_material_column_lookup_count: usize,
        ordered_column_count: usize,
        relation_tree_input_count: usize,
        maximum_returned_source_polynomial_value_count: usize,
        trace_witness_structure: CommittedMaterialTraceWitnessStructureMemoryAccounting,
    ) -> Result<Self, CommonProofProverError> {
        let logical_root_count =
            u64::try_from(logical_root_count).map_err(|_| CommonProofProverError::CountOverflow)?;
        let canonical_coefficient_count_per_root =
            u64::try_from(canonical_coefficient_count_per_root)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let bound_material_column_lookup_count = u64::try_from(bound_material_column_lookup_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let ordered_column_count = u64::try_from(ordered_column_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let relation_tree_input_count = u64::try_from(relation_tree_input_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let maximum_returned_source_polynomial_value_count =
            u64::try_from(maximum_returned_source_polynomial_value_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let canonical_coefficient_byte_length =
            u64::try_from(size_of::<u64>()).map_err(|_| CommonProofProverError::CountOverflow)?;
        let compact_source_struct_byte_length =
            u64::try_from(size_of::<CompactCommittedMaterialSource>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let adapter_source_wrapper_byte_length =
            u64::try_from(size_of::<(u16, AuthenticatedCompactCommittedMaterialSource)>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_provider_source_wrapper_byte_length =
            u64::try_from(size_of::<AuthenticatedCompactCommittedMaterialSource>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let bound_material_column_lookup_byte_length =
            u64::try_from(size_of::<Option<BoundMaterialColumn>>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let proof_base_field_element_byte_length =
            u64::try_from(size_of::<ProofBaseFieldElement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let adapter_fixed_byte_length =
            u64::try_from(size_of::<CommittedMaterialSourcePolynomialAdapter>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let ordered_column_byte_length = u64::try_from(size_of::<RelationColumnDescriptor>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let relation_tree_input_byte_length = u64::try_from(size_of::<RelationProofTreeInput>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let framed_part_reference_byte_length =
            u64::try_from(size_of::<&[u8]>()).map_err(|_| CommonProofProverError::CountOverflow)?;
        let root_part_byte_length = u64::try_from(size_of::<[u8; 64]>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let authenticated_coefficient_byte_length = logical_root_count
            .checked_mul(canonical_coefficient_count_per_root)
            .and_then(|count| count.checked_mul(canonical_coefficient_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let compact_source_byte_length = logical_root_count
            .checked_mul(compact_source_struct_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let adapter_source_wrapper_catalog_byte_length = logical_root_count
            .checked_mul(adapter_source_wrapper_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let trace_provider_source_wrapper_catalog_byte_length = logical_root_count
            .checked_mul(trace_provider_source_wrapper_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let bound_material_column_lookup_catalog_byte_length = bound_material_column_lookup_count
            .checked_mul(bound_material_column_lookup_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let ordered_column_catalog_byte_length = ordered_column_count
            .checked_mul(ordered_column_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let relation_tree_input_catalog_byte_length = relation_tree_input_count
            .checked_mul(relation_tree_input_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let resolved_modulus_catalog_byte_length =
            trace_witness_structure.resolved_modulus_catalog_byte_length();
        let recipe_catalog_byte_length = trace_witness_structure.recipe_catalog_byte_length();
        let nested_recipe_catalog_byte_length =
            trace_witness_structure.nested_recipe_catalog_byte_length();
        if resolved_modulus_catalog_byte_length
            .checked_add(recipe_catalog_byte_length)
            .and_then(|total| total.checked_add(nested_recipe_catalog_byte_length))
            != Some(trace_witness_structure.total_byte_length())
        {
            return Err(CommonProofProverError::CountOverflow);
        }
        let loading_persistent_resident_byte_length = adapter_fixed_byte_length
            .checked_add(authenticated_coefficient_byte_length)
            .and_then(|total| total.checked_add(compact_source_byte_length))
            .and_then(|total| total.checked_add(adapter_source_wrapper_catalog_byte_length))
            .and_then(|total| total.checked_add(trace_provider_source_wrapper_catalog_byte_length))
            .and_then(|total| total.checked_add(bound_material_column_lookup_catalog_byte_length))
            .and_then(|total| total.checked_add(ordered_column_catalog_byte_length))
            .and_then(|total| total.checked_add(resolved_modulus_catalog_byte_length))
            .and_then(|total| total.checked_add(recipe_catalog_byte_length))
            .and_then(|total| total.checked_add(nested_recipe_catalog_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let post_source_polynomial_finish_persistent_resident_byte_length =
            adapter_fixed_byte_length
                .checked_add(authenticated_coefficient_byte_length)
                .and_then(|total| total.checked_add(compact_source_byte_length))
                .and_then(|total| total.checked_add(adapter_source_wrapper_catalog_byte_length))
                .ok_or(CommonProofProverError::CountOverflow)?;
        let restart_reference_catalog_byte_length = logical_root_count
            .checked_add(4)
            .and_then(|count| count.checked_mul(framed_part_reference_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let restart_root_catalog_byte_length = logical_root_count
            .checked_mul(root_part_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let construction_transient_peak_byte_length = restart_root_catalog_byte_length
            .checked_add(
                trace_provider_source_wrapper_catalog_byte_length
                    .max(restart_reference_catalog_byte_length),
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let construction_peak_resident_byte_length = loading_persistent_resident_byte_length
            .checked_add(relation_tree_input_catalog_byte_length)
            .and_then(|total| total.checked_add(construction_transient_peak_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let canonical_witness_framing_transient_byte_length =
            CANONICAL_WITNESS_U64_FRAMING_BUFFER_BYTE_LENGTH;
        let preparation_transient_byte_length = relation_tree_input_catalog_byte_length
            .checked_add(canonical_witness_framing_transient_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let preparation_peak_resident_byte_length = loading_persistent_resident_byte_length
            .checked_add(preparation_transient_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let maximum_returned_source_polynomial_byte_length =
            maximum_returned_source_polynomial_value_count
                .checked_mul(proof_base_field_element_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(Self {
            logical_root_count,
            adapter_fixed_byte_length,
            authenticated_coefficient_byte_length,
            compact_source_byte_length,
            adapter_source_wrapper_catalog_byte_length,
            trace_provider_source_wrapper_catalog_byte_length,
            bound_material_column_lookup_catalog_byte_length,
            ordered_column_catalog_byte_length,
            resolved_modulus_catalog_byte_length,
            recipe_catalog_byte_length,
            nested_recipe_catalog_byte_length,
            relation_tree_input_catalog_byte_length,
            canonical_witness_framing_transient_byte_length,
            construction_transient_peak_byte_length,
            construction_peak_resident_byte_length,
            preparation_transient_byte_length,
            preparation_peak_resident_byte_length,
            loading_persistent_resident_byte_length,
            post_source_polynomial_finish_persistent_resident_byte_length,
            maximum_returned_source_polynomial_byte_length,
        })
    }
}

#[derive(Clone, Copy)]
struct CommittedMaterialCanonicalWitnessBindingContext {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    statement_schema_identifier: u16,
    application_statement_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    restart_binding_hash: [u8; 64],
}

#[derive(Clone, Copy)]
struct CommittedMaterialCanonicalWitnessSource<'source> {
    logical_root_ordinal: usize,
    tree_catalog_index: u16,
    trace_domain_size: usize,
    evaluation_domain_size: usize,
    evaluation_coset_offset: u64,
    masking_polynomial_maximum_degree: usize,
    committed_polynomial_degree_bound_exclusive: usize,
    material_column_degree_bound_exclusive: usize,
    material_context_hash: [u8; 64],
    root: [u8; 64],
    canonical_modulus: u64,
    canonical_message: &'source [u64],
}

fn absorb_committed_material_canonical_semantic_witness<'source>(
    binding: &mut PersistentProofWitnessCoinBinding,
    context: CommittedMaterialCanonicalWitnessBindingContext,
    ordered_sources: impl ExactSizeIterator<Item = CommittedMaterialCanonicalWitnessSource<'source>>,
) -> Result<(), CommonProofProverError> {
    let map_binding_error = |_| CommonProofProverError::InvalidColumn;
    let source_count =
        u64::try_from(ordered_sources.len()).map_err(|_| CommonProofProverError::CountOverflow)?;
    binding
        .absorb_canonical_bytes(COMMITTED_MATERIAL_CANONICAL_SEMANTIC_WITNESS_DOMAIN)
        .map_err(map_binding_error)?;
    for bytes in [
        context.protocol_version.to_le_bytes().as_slice(),
        context.suite_identifier.as_slice(),
        context.statement_schema_identifier.to_le_bytes().as_slice(),
        context.application_statement_hash.as_slice(),
        context.relation_plan_hash.as_slice(),
        context.relation_plan_variant_hash.as_slice(),
        context.restart_binding_hash.as_slice(),
        source_count.to_le_bytes().as_slice(),
    ] {
        binding
            .absorb_canonical_bytes(bytes)
            .map_err(map_binding_error)?;
    }
    for source in ordered_sources {
        let logical_root_ordinal = u64::try_from(source.logical_root_ordinal)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let trace_domain_size = u64::try_from(source.trace_domain_size)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let evaluation_domain_size = u64::try_from(source.evaluation_domain_size)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let masking_polynomial_maximum_degree =
            u64::try_from(source.masking_polynomial_maximum_degree)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let committed_polynomial_degree_bound_exclusive =
            u64::try_from(source.committed_polynomial_degree_bound_exclusive)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let material_column_degree_bound_exclusive =
            u64::try_from(source.material_column_degree_bound_exclusive)
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        for bytes in [
            logical_root_ordinal.to_le_bytes().as_slice(),
            source.tree_catalog_index.to_le_bytes().as_slice(),
            trace_domain_size.to_le_bytes().as_slice(),
            evaluation_domain_size.to_le_bytes().as_slice(),
            source.evaluation_coset_offset.to_le_bytes().as_slice(),
            masking_polynomial_maximum_degree.to_le_bytes().as_slice(),
            committed_polynomial_degree_bound_exclusive
                .to_le_bytes()
                .as_slice(),
            material_column_degree_bound_exclusive
                .to_le_bytes()
                .as_slice(),
            source.material_context_hash.as_slice(),
            source.root.as_slice(),
            source.canonical_modulus.to_le_bytes().as_slice(),
        ] {
            binding
                .absorb_canonical_bytes(bytes)
                .map_err(map_binding_error)?;
        }
        binding
            .absorb_canonical_u64_values(source.canonical_message)
            .map_err(map_binding_error)?;
    }
    Ok(())
}

fn committed_material_source_provider_memory_accounting(
    relation_kind: SelectedCommittedMaterialRelationKind,
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
    compiled_relation_plan: &CompiledRelationPlan,
    trace_witness_structure: CommittedMaterialTraceWitnessStructureMemoryAccounting,
) -> Result<CommittedMaterialSourceProviderMemoryAccounting, CommonProofProverError> {
    let expected_relation_plan = match relation_kind {
        SelectedCommittedMaterialRelationKind::VssShareLinkage => {
            compile_vss_share_linkage_relation_plan(input, context)
        }
        SelectedCommittedMaterialRelationKind::AggregateThresholdShare => {
            compile_aggregate_threshold_share_relation_plan(input, context)
        }
    }
    .map_err(CommonProofProverError::Relation)?;
    if compiled_relation_plan
        .canonical_hash()
        .map_err(CommonProofProverError::Relation)?
        != expected_relation_plan
            .canonical_hash()
            .map_err(CommonProofProverError::Relation)?
        || compiled_relation_plan.application_statement_schema_identifier()
            != relation_kind.statement_schema_identifier()
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    compiled_relation_plan
        .check(context)
        .map_err(CommonProofProverError::Relation)?;
    let variant = compiled_relation_plan
        .select_variant(None, None)
        .map_err(CommonProofProverError::Relation)?;
    if variant.schedule_position().is_some()
        || variant.top_count().is_some()
        || variant.trace_domain_size()
            != input
                .relation_trace_domain_size()
                .map_err(CommonProofProverError::Relation)?
    {
        return Err(CommonProofProverError::InvalidColumn);
    }

    let expected_roots_per_limb = match relation_kind {
        SelectedCommittedMaterialRelationKind::VssShareLinkage => {
            usize::from(input.threshold).checked_add(usize::from(input.participant_count))
        }
        SelectedCommittedMaterialRelationKind::AggregateThresholdShare => {
            usize::from(input.participant_count).checked_add(1)
        }
    }
    .ok_or(CommonProofProverError::CountOverflow)?;
    let expected_logical_root_count = input
        .sharing_data_modulus_indices
        .len()
        .checked_mul(expected_roots_per_limb)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let mut logical_root_count = 0_usize;
    for descriptor in variant.ordered_trees() {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            ordered_column_ordinals,
            ..
        } = descriptor
        else {
            continue;
        };
        if *construction_kind != BoundTreeConstructionKind::CommittedMaterial
            || ordered_column_ordinals.len() != 4
            || ordered_column_ordinals.iter().any(|column_ordinal| {
                usize::try_from(*column_ordinal)
                    .ok()
                    .and_then(|column_index| variant.ordered_columns().get(column_index))
                    .is_none_or(|column| {
                        !matches!(column.origin(), RelationColumnOrigin::BoundTree { .. })
                    })
            })
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        logical_root_count = logical_root_count
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    if logical_root_count != expected_logical_root_count {
        return Err(CommonProofProverError::InvalidTree);
    }
    let canonical_coefficient_count_per_root =
        usize::try_from(input.ring_degree).map_err(|_| CommonProofProverError::CountOverflow)?;
    let maximum_returned_source_polynomial_value_count = usize::try_from(
        variant
            .trace_domain_size()
            .max(input.material_column_degree_bound_exclusive),
    )
    .map_err(|_| CommonProofProverError::CountOverflow)?;
    CommittedMaterialSourceProviderMemoryAccounting::from_dimensions(
        logical_root_count,
        canonical_coefficient_count_per_root,
        variant.ordered_columns().len(),
        variant.ordered_columns().len(),
        variant.ordered_trees().len(),
        maximum_returned_source_polynomial_value_count,
        trace_witness_structure,
    )
}

/// One-column-at-a-time source adapter for selected committed-material relations.
///
/// Canonical coefficients and compact root authorities are owner-held `Arc`s.
/// The adapter materializes only the requested polynomial, consumes the
/// checked variant in exact column order, and binds every replay identity to
/// the application, checked plan, exact descriptor, and persistent root.
pub(crate) struct CommittedMaterialSourcePolynomialAdapter {
    relation_kind: SelectedCommittedMaterialRelationKind,
    ordered_columns: Option<Box<[RelationColumnDescriptor]>>,
    relation_tree_inputs: Option<Box<[RelationProofTreeInput]>>,
    trace_domain: ProofEvaluationDomain,
    trace_witness: Option<CommittedMaterialTraceWitnessProvider>,
    bound_material_by_column: Option<Box<[Option<BoundMaterialColumn>]>>,
    bound_sources_by_catalog_index: Box<[(u16, AuthenticatedCompactCommittedMaterialSource)]>,
    memory_accounting: CommittedMaterialSourceProviderMemoryAccounting,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    restart_binding_hash: [u8; 64],
    next_column_ordinal: u32,
    source_polynomials_finished: bool,
    next_leaf_salt_source_ordinal: usize,
    next_leaf_salt_index: usize,
    leaf_salts_finished: bool,
}

impl CommittedMaterialSourcePolynomialAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_vss_share_linkage(
        input: CommittedMaterialRelationPlanInput,
        context: &RelationPlanCheckContext,
        compiled_relation_plan: &CompiledRelationPlan,
        protocol_version: u16,
        suite_identifier: [u8; 64],
        application_statement_hash: [u8; 64],
        relation_plan_capability: &CommonProofRelationPlanCapability,
        ordered_sources: Vec<AuthenticatedCompactCommittedMaterialSource>,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            SelectedCommittedMaterialRelationKind::VssShareLinkage,
            input,
            context,
            compiled_relation_plan,
            protocol_version,
            suite_identifier,
            application_statement_hash,
            relation_plan_capability,
            ordered_sources,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_aggregate_threshold_share(
        input: CommittedMaterialRelationPlanInput,
        context: &RelationPlanCheckContext,
        compiled_relation_plan: &CompiledRelationPlan,
        protocol_version: u16,
        suite_identifier: [u8; 64],
        application_statement_hash: [u8; 64],
        relation_plan_capability: &CommonProofRelationPlanCapability,
        ordered_sources: Vec<AuthenticatedCompactCommittedMaterialSource>,
    ) -> Result<Self, CommonProofProverError> {
        Self::new(
            SelectedCommittedMaterialRelationKind::AggregateThresholdShare,
            input,
            context,
            compiled_relation_plan,
            protocol_version,
            suite_identifier,
            application_statement_hash,
            relation_plan_capability,
            ordered_sources,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        relation_kind: SelectedCommittedMaterialRelationKind,
        input: CommittedMaterialRelationPlanInput,
        context: &RelationPlanCheckContext,
        compiled_relation_plan: &CompiledRelationPlan,
        protocol_version: u16,
        suite_identifier: [u8; 64],
        application_statement_hash: [u8; 64],
        relation_plan_capability: &CommonProofRelationPlanCapability,
        ordered_sources: Vec<AuthenticatedCompactCommittedMaterialSource>,
    ) -> Result<Self, CommonProofProverError> {
        let variant = compiled_relation_plan
            .select_variant(None, None)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let relation_plan_variant_hash = variant
            .canonical_hash()
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let compiled_relation_plan_hash = compiled_relation_plan
            .canonical_hash()
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let relation_plan_hash = relation_plan_capability.relation_plan_hash();
        if protocol_version == 0
            || suite_identifier == [0_u8; 64]
            || application_statement_hash == [0_u8; 64]
            || relation_plan_hash != compiled_relation_plan_hash
            || relation_plan_capability.relation_plan_variant_hash() != relation_plan_variant_hash
            || relation_plan_variant_hash == [0_u8; 64]
            || compiled_relation_plan.application_statement_schema_identifier()
                != relation_kind.statement_schema_identifier()
            || variant.schedule_position().is_some()
            || variant.top_count().is_some()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let ordered_sources = ordered_sources.into_boxed_slice();
        let actual_authenticated_coefficient_byte_length =
            ordered_sources.iter().try_fold(0_u64, |total, source| {
                let source_byte_length =
                    u64::try_from(source.retained_canonical_coefficient_byte_length())
                        .map_err(|_| CommonProofProverError::CountOverflow)?;
                total
                    .checked_add(source_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)
            })?;
        let actual_compact_source_byte_length =
            ordered_sources.iter().try_fold(0_u64, |total, source| {
                let source_byte_length =
                    u64::try_from(source.compact_source().retained_byte_length())
                        .map_err(|_| CommonProofProverError::CountOverflow)?;
                total
                    .checked_add(source_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)
            })?;
        let actual_maximum_returned_source_polynomial_byte_length = ordered_sources
            .iter()
            .try_fold(0_u64, |maximum, source| {
                let source_byte_length = u64::try_from(
                    source
                        .compact_source()
                        .maximum_regenerated_column_byte_length(),
                )
                .map_err(|_| CommonProofProverError::CountOverflow)?;
                Ok::<_, CommonProofProverError>(maximum.max(source_byte_length))
            })?
            .max(
                variant
                    .trace_domain_size()
                    .checked_mul(
                        u64::try_from(size_of::<ProofBaseFieldElement>())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::CountOverflow)?,
            );
        let trace_witness = match relation_kind {
            SelectedCommittedMaterialRelationKind::VssShareLinkage => {
                derive_vss_share_linkage_trace_witness_provider(
                    &input,
                    context,
                    ordered_sources.to_vec(),
                )
            }
            SelectedCommittedMaterialRelationKind::AggregateThresholdShare => {
                derive_aggregate_threshold_share_trace_witness_provider(
                    &input,
                    context,
                    ordered_sources.to_vec(),
                )
            }
        }
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        if trace_witness.relation_plan_hash() != compiled_relation_plan_hash
            || trace_witness.logical_root_count() != ordered_sources.len()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let memory_accounting = committed_material_source_provider_memory_accounting(
            relation_kind,
            &input,
            context,
            compiled_relation_plan,
            trace_witness
                .structure_memory_accounting()
                .map_err(CommonProofProverError::Relation)?,
        )?;
        if actual_authenticated_coefficient_byte_length
            != memory_accounting.authenticated_coefficient_byte_length()
            || actual_compact_source_byte_length != memory_accounting.compact_source_byte_length()
            || actual_maximum_returned_source_polynomial_byte_length
                != memory_accounting.maximum_returned_source_polynomial_byte_length()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
        let ordered_columns = variant.ordered_columns().to_vec().into_boxed_slice();
        let mut bound_material_by_column = Vec::new();
        bound_material_by_column
            .try_reserve_exact(variant.ordered_columns().len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        bound_material_by_column.resize_with(variant.ordered_columns().len(), || None);
        let mut bound_sources_by_catalog_index = Vec::new();
        bound_sources_by_catalog_index
            .try_reserve_exact(ordered_sources.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut relation_tree_inputs = Vec::new();
        relation_tree_inputs
            .try_reserve_exact(variant.ordered_trees().len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut next_source = ordered_sources.into_vec().into_iter();
        let mut ordered_root_parts = Vec::new();
        ordered_root_parts
            .try_reserve_exact(
                usize::try_from(memory_accounting.logical_root_count())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        for (tree_catalog_index, descriptor) in variant.ordered_trees().iter().enumerate() {
            match descriptor {
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    ordered_column_ordinals,
                    ..
                } => {
                    if *construction_kind != BoundTreeConstructionKind::CommittedMaterial
                        || ordered_column_ordinals.len() != 4
                    {
                        return Err(CommonProofProverError::InvalidTree);
                    }
                    let source = next_source
                        .next()
                        .ok_or(CommonProofProverError::InvalidTree)?;
                    let logical_root_ordinal = bound_sources_by_catalog_index.len();
                    let material_context_hash = source.compact_source().material_context_hash();
                    let root = source.compact_source().root();
                    bound_sources_by_catalog_index.push((
                        u16::try_from(tree_catalog_index)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                        source,
                    ));
                    ordered_root_parts.push(root);
                    relation_tree_inputs.push(RelationProofTreeInput::BoundPublic(
                        StatementOwnedProofTreeInput::CommittedMaterial {
                            material_context_hash,
                            expected_root: root,
                        },
                    ));
                    for (physical_column_ordinal, column_ordinal) in
                        ordered_column_ordinals.iter().copied().enumerate()
                    {
                        let Some(descriptor) = variant.ordered_columns().get(
                            usize::try_from(column_ordinal)
                                .map_err(|_| CommonProofProverError::CountOverflow)?,
                        ) else {
                            return Err(CommonProofProverError::InvalidColumn);
                        };
                        if !matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. })
                            || bound_material_by_column
                                .get_mut(
                                    usize::try_from(column_ordinal)
                                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                                )
                                .ok_or(CommonProofProverError::InvalidColumn)?
                                .replace(BoundMaterialColumn {
                                    logical_root_ordinal,
                                    physical_column_ordinal,
                                })
                                .is_some()
                        {
                            return Err(CommonProofProverError::InvalidColumn);
                        }
                    }
                }
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } => relation_tree_inputs.push(RelationProofTreeInput::ProofCreated {
                    tree_role: match *proof_tree_role {
                        value if value == ProofTreeRole::BaseOracle as u16 => {
                            ProofTreeRole::BaseOracle
                        }
                        value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                            ProofTreeRole::AuxiliaryOracle
                        }
                        _ => return Err(CommonProofProverError::InvalidTree),
                    },
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    leaf_visibility: ProofLeafVisibility::SecretBearing,
                }),
            }
        }
        if next_source.next().is_some()
            || bound_sources_by_catalog_index.is_empty()
            || ordered_root_parts.len() != trace_witness.logical_root_count()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        drop(next_source);
        let mut restart_parts = Vec::with_capacity(4 + ordered_root_parts.len());
        restart_parts.push(application_statement_hash.as_slice());
        restart_parts.push(relation_plan_hash.as_slice());
        restart_parts.push(relation_plan_variant_hash.as_slice());
        restart_parts.push(suite_identifier.as_slice());
        restart_parts.extend(ordered_root_parts.iter().map(<[u8; 64]>::as_slice));
        let restart_binding_hash =
            hash_framed_parts_512(relation_kind.restart_binding_domain(), &restart_parts);
        drop(restart_parts);
        drop(ordered_root_parts);
        let bound_material_by_column = bound_material_by_column.into_boxed_slice();
        let bound_sources_by_catalog_index = bound_sources_by_catalog_index.into_boxed_slice();
        Ok(Self {
            relation_kind,
            ordered_columns: Some(ordered_columns),
            relation_tree_inputs: Some(relation_tree_inputs.into_boxed_slice()),
            trace_domain,
            trace_witness: Some(trace_witness),
            bound_material_by_column: Some(bound_material_by_column),
            bound_sources_by_catalog_index,
            memory_accounting,
            protocol_version,
            suite_identifier,
            application_statement_hash,
            relation_plan_hash,
            relation_plan_variant_hash,
            restart_binding_hash,
            next_column_ordinal: 0,
            source_polynomials_finished: false,
            next_leaf_salt_source_ordinal: 0,
            next_leaf_salt_index: 0,
            leaf_salts_finished: false,
        })
    }

    pub(crate) fn absorb_canonical_semantic_witness(
        &self,
        binding: &mut PersistentProofWitnessCoinBinding,
    ) -> Result<(), CommonProofProverError> {
        let context = CommittedMaterialCanonicalWitnessBindingContext {
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            statement_schema_identifier: self.relation_kind.statement_schema_identifier(),
            application_statement_hash: self.application_statement_hash,
            relation_plan_hash: self.relation_plan_hash,
            relation_plan_variant_hash: self.relation_plan_variant_hash,
            restart_binding_hash: self.restart_binding_hash,
        };
        let ordered_sources = self.bound_sources_by_catalog_index.iter().enumerate().map(
            |(logical_root_ordinal, (tree_catalog_index, source))| {
                let profile = source.compact_source().profile();
                CommittedMaterialCanonicalWitnessSource {
                    logical_root_ordinal,
                    tree_catalog_index: *tree_catalog_index,
                    trace_domain_size: profile.trace_domain_size(),
                    evaluation_domain_size: profile.evaluation_domain_size(),
                    evaluation_coset_offset: profile.evaluation_coset_offset(),
                    masking_polynomial_maximum_degree: profile.masking_polynomial_maximum_degree(),
                    committed_polynomial_degree_bound_exclusive: profile
                        .committed_polynomial_degree_bound_exclusive(),
                    material_column_degree_bound_exclusive: profile
                        .material_column_degree_bound_exclusive(),
                    material_context_hash: source.compact_source().material_context_hash(),
                    root: source.compact_source().root(),
                    canonical_modulus: source.canonical_modulus(),
                    canonical_message: source.canonical_message(),
                }
            },
        );
        absorb_committed_material_canonical_semantic_witness(binding, context, ordered_sources)
    }

    pub(crate) fn relation_tree_inputs(
        &mut self,
    ) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
        self.relation_tree_inputs
            .take()
            .map(Vec::from)
            .ok_or(CommonProofProverError::InvalidTree)
    }

    fn replay_identity(
        &self,
        column_ordinal: u32,
        root: Option<[u8; 64]>,
    ) -> Result<[u8; 64], CommonProofProverError> {
        let descriptor = self
            .ordered_columns
            .as_deref()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let descriptor_bytes = descriptor
            .canonical_tuple()
            .and_then(|tuple| {
                tuple
                    .encode()
                    .map_err(|_| super::RelationPlanError::CanonicalEncoding)
            })
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        Ok(hash_framed_parts_512(
            self.relation_kind.polynomial_replay_domain(),
            &[
                &self.restart_binding_hash,
                &column_ordinal.to_le_bytes(),
                &descriptor_bytes,
                &root.unwrap_or([0_u8; 64]),
            ],
        ))
    }

    const fn expected_request_context(&self) -> CommonProofSourcePolynomialRequestContext {
        CommonProofSourcePolynomialRequestContext::new(
            self.protocol_version,
            self.suite_identifier,
            self.relation_kind.statement_schema_identifier(),
            self.application_statement_hash,
            self.relation_plan_hash,
            self.relation_plan_variant_hash,
            None,
            None,
        )
    }
}

impl CommonProofSourcePolynomialProvider for CommittedMaterialSourcePolynomialAdapter {
    fn memory_accounting(
        &self,
    ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
        Ok(CommonProofSourceProviderMemoryAccounting::new(
            self.memory_accounting
                .loading_persistent_resident_byte_length(),
            self.memory_accounting
                .post_source_polynomial_finish_persistent_resident_byte_length(),
            self.memory_accounting
                .additional_loading_source_polynomials_transient_byte_length(),
            self.memory_accounting
                .maximum_returned_source_polynomial_byte_length(),
        ))
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        if self.source_polynomials_finished {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let expected_column_ordinal = self.next_column_ordinal;
        let expected_descriptor = self
            .ordered_columns
            .as_deref()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .get(
                usize::try_from(expected_column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if request.protocol_version() != self.protocol_version
            || request.suite_identifier() != self.suite_identifier
            || request.application_statement_schema_identifier()
                != self.relation_kind.statement_schema_identifier()
            || request.application_statement_hash() != self.application_statement_hash
            || request.relation_plan_hash() != self.relation_plan_hash
            || request.relation_plan_variant_hash() != self.relation_plan_variant_hash
            || request.schedule_position().is_some()
            || request.top_count().is_some()
            || request.column_ordinal() != expected_column_ordinal
            || request.descriptor() != expected_descriptor
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let (polynomial, root) = match expected_descriptor.origin() {
            RelationColumnOrigin::BoundTree { .. } => {
                let source = self
                    .bound_material_by_column
                    .as_deref()
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .get(
                        usize::try_from(expected_column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .and_then(Option::as_ref)
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let authenticated_source = self
                    .bound_sources_by_catalog_index
                    .get(source.logical_root_ordinal)
                    .map(|(_, authenticated_source)| authenticated_source)
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let polynomial = authenticated_source
                    .regenerate_masked_coefficients(source.physical_column_ordinal)
                    .map_err(|_| CommonProofProverError::InvalidColumn)?;
                (
                    CommonProofSourcePolynomial::from_protected_base_coefficients(polynomial),
                    Some(authenticated_source.compact_source().root()),
                )
            }
            RelationColumnOrigin::Prover => {
                let mut rows = self
                    .trace_witness
                    .as_ref()
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .column_trace_field_values(expected_column_ordinal)
                    .map_err(|_| CommonProofProverError::InvalidColumn)?;
                self.trace_domain
                    .interpolate_base_polynomial_in_place(&mut rows)?;
                (
                    CommonProofSourcePolynomial::from_base_coefficients(rows),
                    None,
                )
            }
            RelationColumnOrigin::VerifierSequence { .. } => {
                return Err(CommonProofProverError::InvalidColumn);
            }
        };
        let replay_identity = CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
            self.replay_identity(expected_column_ordinal, root)?,
        )?;
        self.next_column_ordinal = self
            .next_column_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(CommonProofSourcePolynomialProviderPoll::Ready(
            ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
        ))
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if !self.source_polynomials_finished
            && usize::try_from(self.next_column_ordinal).ok()
                == self.ordered_columns.as_deref().map(|columns| columns.len())
            && self.relation_tree_inputs.is_none()
        {
            self.source_polynomials_finished = true;
            self.ordered_columns = None;
            self.trace_witness = None;
            self.bound_material_by_column = None;
            Ok(())
        } else {
            Err(CommonProofProverError::InvalidColumn)
        }
    }

    fn provide_bound_tree_leaf_salt(
        &mut self,
        request: CommonProofBoundTreeLeafSaltRequest,
    ) -> Result<Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>, CommonProofProverError>
    {
        if !self.source_polynomials_finished || self.leaf_salts_finished {
            return Err(CommonProofProverError::InvalidTree);
        }
        let (expected_catalog_index, authenticated_source) = self
            .bound_sources_by_catalog_index
            .get(self.next_leaf_salt_source_ordinal)
            .ok_or(CommonProofProverError::InvalidTree)?;
        let compact_source = authenticated_source.compact_source();
        let expected_leaf_count = compact_source.profile().evaluation_domain_size() / 2;
        if request.request_context() != self.expected_request_context()
            || request.tree_catalog_index() != *expected_catalog_index
            || request.expected_root() != compact_source.root()
            || usize::try_from(request.leaf_index()).ok() != Some(self.next_leaf_salt_index)
            || self.next_leaf_salt_index >= expected_leaf_count
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let salt = compact_source
            .persistent_leaf_salt(self.next_leaf_salt_index)
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        self.next_leaf_salt_index = self
            .next_leaf_salt_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.next_leaf_salt_index == expected_leaf_count {
            self.next_leaf_salt_source_ordinal = self
                .next_leaf_salt_source_ordinal
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            self.next_leaf_salt_index = 0;
        }
        Ok(Some(salt))
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            && !self.leaf_salts_finished
            && self.next_leaf_salt_source_ordinal == self.bound_sources_by_catalog_index.len()
            && self.next_leaf_salt_index == 0
        {
            self.leaf_salts_finished = true;
            Ok(())
        } else {
            Err(CommonProofProverError::InvalidTree)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionPrivateRandomness,
        ActionRandomnessDerivationInput, ActionRandomnessRoot, Hash512, ParticipantIdentity,
        PersistentProofCoinInput, PrivateRandomnessAttemptIdentifier, ProofApplicationSlot,
    };
    use zeroize::Zeroizing;

    fn test_hash(fill: u8) -> Hash512 {
        Hash512::from_bytes([fill; Hash512::BYTE_LENGTH])
    }

    fn test_action_randomness() -> ActionPrivateRandomness {
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(ActionRandomnessDerivationInput::new(
            test_hash(0x11),
            test_hash(0x22),
            test_hash(0x33),
            ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
        ))
        .expect("fixed action randomness derives")
    }

    fn test_persistent_proof_coin_input() -> PersistentProofCoinInput {
        let application_slot = ProofApplicationSlot::new(
            test_hash(0x11),
            test_hash(0x22),
            test_hash(0x33),
            VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(0),
            None,
            None,
        )
        .expect("VSS proof application slot");
        PersistentProofCoinInput::new(application_slot, test_hash(0x55))
            .expect("persistent proof coin input")
    }

    fn canonical_witness_attempt_identifier<'source>(
        context: CommittedMaterialCanonicalWitnessBindingContext,
        ordered_sources: &[CommittedMaterialCanonicalWitnessSource<'source>],
    ) -> PrivateRandomnessAttemptIdentifier {
        let action_randomness = test_action_randomness();
        let persistent_input = test_persistent_proof_coin_input();
        let mut binding = action_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_input)
            .expect("witness binding begins");
        absorb_committed_material_canonical_semantic_witness(
            &mut binding,
            context,
            ordered_sources.iter().copied(),
        )
        .expect("canonical committed-material witness binds");
        binding.finish().expect("witness-bound attempt derives")
    }

    fn test_trace_witness_structure_memory_accounting()
    -> CommittedMaterialTraceWitnessStructureMemoryAccounting {
        CommittedMaterialTraceWitnessStructureMemoryAccounting::
            from_exact_component_byte_lengths_for_test(11, 13, 17)
            .expect("synthetic trace-witness structure fits")
    }

    #[test]
    fn source_provider_memory_accounting_counts_each_retained_allocation_once() {
        let logical_root_count = 3_usize;
        let coefficient_count_per_root = 17_usize;
        let column_lookup_count = 29_usize;
        let ordered_column_count = 31_usize;
        let relation_tree_input_count = 7_usize;
        let maximum_returned_value_count = 64_usize;
        let accounting = CommittedMaterialSourceProviderMemoryAccounting::from_dimensions(
            logical_root_count,
            coefficient_count_per_root,
            column_lookup_count,
            ordered_column_count,
            relation_tree_input_count,
            maximum_returned_value_count,
            test_trace_witness_structure_memory_accounting(),
        )
        .expect("the synthetic dimensions fit");

        assert_eq!(accounting.logical_root_count(), 3);
        assert_eq!(
            accounting.authenticated_coefficient_byte_length(),
            u64::try_from(logical_root_count * coefficient_count_per_root * size_of::<u64>())
                .expect("coefficient allocation fits")
        );
        assert_eq!(
            accounting.compact_source_byte_length(),
            u64::try_from(logical_root_count * size_of::<CompactCommittedMaterialSource>())
                .expect("compact-source allocation fits")
        );
        assert_eq!(
            accounting.adapter_source_wrapper_catalog_byte_length(),
            u64::try_from(
                logical_root_count
                    * size_of::<(u16, AuthenticatedCompactCommittedMaterialSource)>(),
            )
            .expect("adapter wrapper catalog fits")
        );
        assert_eq!(
            accounting.trace_provider_source_wrapper_catalog_byte_length(),
            u64::try_from(
                logical_root_count * size_of::<AuthenticatedCompactCommittedMaterialSource>(),
            )
            .expect("trace-provider wrapper catalog fits")
        );
        assert_eq!(
            accounting.bound_material_column_lookup_catalog_byte_length(),
            u64::try_from(column_lookup_count * size_of::<Option<BoundMaterialColumn>>())
                .expect("column lookup catalog fits")
        );
        assert_eq!(
            accounting.persistent_resident_byte_length(),
            accounting.adapter_fixed_byte_length()
                + accounting.authenticated_coefficient_byte_length()
                + accounting.compact_source_byte_length()
                + accounting.adapter_source_wrapper_catalog_byte_length()
                + accounting.trace_provider_source_wrapper_catalog_byte_length()
                + accounting.bound_material_column_lookup_catalog_byte_length()
                + accounting.ordered_column_catalog_byte_length()
                + accounting.resolved_modulus_catalog_byte_length()
                + accounting.recipe_catalog_byte_length()
                + accounting.nested_recipe_catalog_byte_length()
        );
        assert_eq!(
            accounting.post_source_polynomial_finish_persistent_resident_byte_length(),
            accounting.adapter_fixed_byte_length()
                + accounting.authenticated_coefficient_byte_length()
                + accounting.compact_source_byte_length()
                + accounting.adapter_source_wrapper_catalog_byte_length()
        );
        assert_eq!(
            accounting.preparation_transient_byte_length(),
            accounting.relation_tree_input_catalog_byte_length()
                + accounting.canonical_witness_framing_transient_byte_length()
        );
        assert_eq!(
            accounting.preparation_peak_resident_byte_length(),
            accounting.loading_persistent_resident_byte_length()
                + accounting.preparation_transient_byte_length()
        );
        assert_eq!(
            accounting.construction_peak_resident_byte_length(),
            accounting.loading_persistent_resident_byte_length()
                + accounting.relation_tree_input_catalog_byte_length()
                + accounting.construction_transient_peak_byte_length()
        );
        assert_eq!(
            accounting.maximum_returned_source_polynomial_byte_length(),
            u64::try_from(maximum_returned_value_count * size_of::<ProofBaseFieldElement>())
                .expect("returned polynomial allocation fits")
        );
        assert_eq!(
            accounting.additional_loading_source_polynomials_transient_byte_length(),
            0
        );
        assert_eq!(
            accounting.additional_materializing_base_trees_transient_byte_length(),
            0
        );
    }

    #[test]
    fn source_provider_memory_accounting_rejects_overflowing_dimension_products() {
        assert_eq!(
            CommittedMaterialSourceProviderMemoryAccounting::from_dimensions(
                usize::MAX,
                usize::MAX,
                1,
                1,
                1,
                1,
                test_trace_witness_structure_memory_accounting(),
            ),
            Err(CommonProofProverError::CountOverflow)
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(
                CommittedMaterialSourceProviderMemoryAccounting::from_dimensions(
                    1,
                    1,
                    usize::MAX,
                    1,
                    1,
                    1,
                    test_trace_witness_structure_memory_accounting(),
                ),
                Err(CommonProofProverError::CountOverflow)
            );
            assert_eq!(
                CommittedMaterialSourceProviderMemoryAccounting::from_dimensions(
                    1,
                    1,
                    1,
                    usize::MAX,
                    1,
                    usize::MAX,
                    test_trace_witness_structure_memory_accounting(),
                ),
                Err(CommonProofProverError::CountOverflow)
            );
        }
    }

    #[test]
    fn canonical_source_binding_separates_every_load_bearing_witness_coordinate() {
        let first_message = [1_u64, 2, 3, 4, 5, 6, 7, 8];
        let second_message = [9_u64, 10, 11, 12, 13, 14, 15, 16];
        let changed_first_message = [1_u64, 2, 3, 4, 5, 6, 7, 17];
        let baseline_context = CommittedMaterialCanonicalWitnessBindingContext {
            protocol_version: 1,
            suite_identifier: [0x11; 64],
            statement_schema_identifier: VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
            application_statement_hash: [0x22; 64],
            relation_plan_hash: [0x33; 64],
            relation_plan_variant_hash: [0x44; 64],
            restart_binding_hash: [0x55; 64],
        };
        let first_source = CommittedMaterialCanonicalWitnessSource {
            logical_root_ordinal: 0,
            tree_catalog_index: 1,
            trace_domain_size: 4,
            evaluation_domain_size: 32,
            evaluation_coset_offset: 7,
            masking_polynomial_maximum_degree: 3,
            committed_polynomial_degree_bound_exclusive: 16,
            material_column_degree_bound_exclusive: 8,
            material_context_hash: [0x61; 64],
            root: [0x71; 64],
            canonical_modulus: 257,
            canonical_message: &first_message,
        };
        let second_source = CommittedMaterialCanonicalWitnessSource {
            logical_root_ordinal: 1,
            tree_catalog_index: 2,
            material_context_hash: [0x62; 64],
            root: [0x72; 64],
            canonical_message: &second_message,
            ..first_source
        };
        let baseline_sources = [first_source, second_source];
        let baseline = canonical_witness_attempt_identifier(baseline_context, &baseline_sources);

        let mut changed_variant_context = baseline_context;
        changed_variant_context.relation_plan_variant_hash[0] ^= 1;
        assert_ne!(
            canonical_witness_attempt_identifier(changed_variant_context, &baseline_sources),
            baseline
        );

        let mut changed_coefficient_source = first_source;
        changed_coefficient_source.canonical_message = &changed_first_message;
        let mut changed_root_source = first_source;
        changed_root_source.root[0] ^= 1;
        let mut changed_material_context_source = first_source;
        changed_material_context_source.material_context_hash[0] ^= 1;
        let mut changed_modulus_source = first_source;
        changed_modulus_source.canonical_modulus += 2;
        for changed_first_source in [
            changed_coefficient_source,
            changed_root_source,
            changed_material_context_source,
            changed_modulus_source,
        ] {
            assert_ne!(
                canonical_witness_attempt_identifier(
                    baseline_context,
                    &[changed_first_source, second_source],
                ),
                baseline
            );
        }
        assert_ne!(
            canonical_witness_attempt_identifier(baseline_context, &[second_source, first_source],),
            baseline
        );
    }
}
