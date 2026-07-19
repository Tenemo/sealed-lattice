use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::{
    bgv::{
        parameters::PLAINTEXT_MODULUS,
        setup::{
            SetupGeneratedRelinearizationAggregateSourceAuthority, SetupGenerationAuthorityHandle,
            SetupGenerationRelinearizationRoundTwoApplication,
            SetupGenerationRelinearizationRoundTwoSource,
            with_setup_generation_relinearization_round_two_witness,
        },
    },
    foundation::{
        CanonicalStreamReadbackVerifier, FOUNDATION_PROFILE, Hash512,
        PreparedActionProofAttemptSource, ProofApplicationSlotCeilings, RefusalReason,
        StreamDescriptor,
    },
    hashing::{StreamingHash512, hash_framed_parts_512},
};

use super::super::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofProverError,
    CommonProofRelationPlanCapability, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    KeySwitchComponentMaterialTopology, KeySwitchComponentTraceColumn, ProofEvaluationDomain,
    ProofLeafVisibility, ProofTreeRole, ProvidedCommonProofSourcePolynomial,
    RelationProofTreeInput, SetupPublicPolynomialContext, SetupPublicPolynomialRootRole,
    StatementOwnedProofTreeInput,
};
use super::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor, RelationVerifierSource, SuiteModulusReference,
    galois_key_share_adapter::{
        centered_residue, exact_modular_quotient, exact_negacyclic_product_radix, half_position,
        requested_source_column_ordinals, signed_integer_to_base_field, split_balanced_quotient,
        split_rows_match, split_signed_i8_polynomial,
    },
    relinearization_round_one_adapter::{
        CachedQuotient, CachedQuotientKey, RelinearizationRoundOneColumnDerivation,
        RelinearizationRoundOneSourceLayoutView, component_direct_witness_rows,
        decode_component_full_row,
    },
    setup_key_relation_adapter::{
        ExactKeyRelationActiveColumnSet, ExactKeyRelationDerivedRowCache,
        KeyRelationColumnDerivation,
    },
    trustee_evaluation_key::{
        RelinearizationRoundTwoSourceLayout, TrusteeEvaluationKeyRelationGeometry,
    },
};

const RELINEARIZATION_ROUND_TWO_SOURCE_REPLAY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/relinearization-round-two/source-replay-identity/v1";
const RELINEARIZATION_ROUND_TWO_SOURCE_CATALOG_BINDING_DOMAIN: &str =
    "sealed-lattice/relinearization-round-two/source-catalog-binding/v1";
const RELINEARIZATION_ROUND_TWO_SOURCE_DESCRIPTOR_BINDING_DOMAIN: &str =
    "sealed-lattice/relinearization-round-two/source-descriptor-binding/v1";

struct RelinearizationRoundTwoAuthenticatedAggregateSource {
    material_root: [u8; Hash512::BYTE_LENGTH],
    stream_digest: [u8; Hash512::BYTE_LENGTH],
    stream_total_byte_length: u64,
    descriptor_binding: [u8; Hash512::BYTE_LENGTH],
    readback: Option<CanonicalStreamReadbackVerifier>,
    authenticated_chunks: Box<[bool]>,
}

/// Compact catalog-minted source plan for fresh and reset-safe round-two proof
/// preparation. It owns authentication state and stable bindings, never the
/// aggregate component payloads or a host-provided source description.
pub(crate) struct RelinearizationRoundTwoAuthenticatedAggregateSourcePlan {
    source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
    topology: KeySwitchComponentMaterialTopology,
    sources: [RelinearizationRoundTwoAuthenticatedAggregateSource; 2],
}

impl RelinearizationRoundTwoAuthenticatedAggregateSourcePlan {
    pub(crate) fn from_catalog_source(
        generated_aggregate: &SetupGeneratedRelinearizationAggregateSourceAuthority,
        aggregate_proof_stream_descriptor: &StreamDescriptor,
    ) -> Result<Self, CommonProofProverError> {
        let components = generated_aggregate.components();
        let topology = components[0].topology().clone();
        if components[1].topology() != &topology
            || components.iter().any(|component| {
                component.stream_descriptor().total_byte_length != topology.expected_byte_length()
                    || component
                        .stream_descriptor()
                        .ordered_chunk_digests
                        .is_empty()
            })
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let proof_stream_digest = aggregate_proof_stream_descriptor
            .full_object_digest
            .into_bytes();
        let source_catalog_binding = hash_framed_parts_512(
            RELINEARIZATION_ROUND_TWO_SOURCE_CATALOG_BINDING_DOMAIN,
            &[
                &generated_aggregate.protocol_version().to_le_bytes(),
                &generated_aggregate.suite_identifier(),
                &generated_aggregate.ceremony_context_hash(),
                &generated_aggregate.action_context_hash(),
                &generated_aggregate.roster_hash(),
                &generated_aggregate.setup_proof_context_hash(),
                &generated_aggregate.schedule_position().to_le_bytes(),
                generated_aggregate.canonical_application_statement_bytes(),
                &proof_stream_digest,
                &aggregate_proof_stream_descriptor
                    .total_byte_length
                    .to_le_bytes(),
            ],
        );
        let mut prepared_sources = Vec::with_capacity(components.len());
        for (component_ordinal, component) in components.iter().enumerate() {
            let stream_descriptor = component.stream_descriptor();
            let material_root = component.material_root().into_bytes();
            let stream_digest = stream_descriptor.full_object_digest.into_bytes();
            let descriptor_binding = hash_framed_parts_512(
                RELINEARIZATION_ROUND_TWO_SOURCE_DESCRIPTOR_BINDING_DOMAIN,
                &[
                    &source_catalog_binding,
                    &u32::try_from(component_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?
                        .to_le_bytes(),
                    &component.public_polynomial_context_hash(),
                    &component.contribution_root(),
                    &material_root,
                    &stream_digest,
                    &stream_descriptor.total_byte_length.to_le_bytes(),
                ],
            );
            prepared_sources.push(RelinearizationRoundTwoAuthenticatedAggregateSource {
                material_root,
                stream_digest,
                stream_total_byte_length: stream_descriptor.total_byte_length,
                descriptor_binding,
                readback: Some(
                    component
                        .begin_authenticated_readback()
                        .map_err(|_| CommonProofProverError::InvalidInput)?,
                ),
                authenticated_chunks: vec![false; stream_descriptor.ordered_chunk_digests.len()]
                    .into_boxed_slice(),
            });
        }
        let sources: [RelinearizationRoundTwoAuthenticatedAggregateSource; 2] = prepared_sources
            .try_into()
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        Ok(Self {
            source_catalog_binding,
            topology,
            sources,
        })
    }
}

/// Internal accounting for the exact provider-retained payload allocations of
/// the streamed RKG round-two source provider. Shared stream-digest payloads
/// are counted once through the provider's retained authority; allocator
/// bookkeeping is outside this payload boundary. These values are planning
/// evidence only; none enters a statement, transcript, proof, checkpoint, or
/// accepted package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelinearizationRoundTwoSourceProviderMemoryAccounting {
    provider_fixed_owner_byte_length: u64,
    retained_catalog_heap_byte_length: u64,
    readback_chunk_digest_byte_length: u64,
    readback_authentication_flag_byte_length: u64,
    cached_quotient_byte_length: u64,
    first_aggregate_product_byte_length: u64,
    maximum_loaded_aggregate_trace_pair_byte_length: u64,
    maximum_cached_authenticated_chunk_byte_length: u64,
    maximum_pending_catalog_byte_length: u64,
    maximum_quotient_phase_populated_request_identity_byte_length: u64,
    maximum_recursive_cached_row_payload_byte_length: u64,
    maximum_recursive_cached_row_catalog_byte_length: u64,
    relation_derivation_active_column_flag_byte_length: u64,
    maximum_recursive_cache_and_relation_workspace_byte_length: u64,
    maximum_requirement_discovery_transient_byte_length: u64,
    maximum_relation_column_derivation_workspace_byte_length: u64,
    maximum_round_two_quotient_arithmetic_transient_byte_length: u64,
    loading_persistent_resident_byte_length: u64,
    post_source_polynomial_finish_persistent_resident_byte_length: u64,
    additional_loading_source_polynomials_transient_byte_length: u64,
    maximum_returned_source_polynomial_byte_length: u64,
}

impl RelinearizationRoundTwoSourceProviderMemoryAccounting {
    pub(crate) const fn provider_fixed_owner_byte_length(self) -> u64 {
        self.provider_fixed_owner_byte_length
    }

    pub(crate) const fn retained_catalog_heap_byte_length(self) -> u64 {
        self.retained_catalog_heap_byte_length
    }

    pub(crate) const fn readback_chunk_digest_byte_length(self) -> u64 {
        self.readback_chunk_digest_byte_length
    }

    pub(crate) const fn readback_authentication_flag_byte_length(self) -> u64 {
        self.readback_authentication_flag_byte_length
    }

    pub(crate) const fn cached_quotient_byte_length(self) -> u64 {
        self.cached_quotient_byte_length
    }

    pub(crate) const fn first_aggregate_product_byte_length(self) -> u64 {
        self.first_aggregate_product_byte_length
    }

    pub(crate) const fn maximum_loaded_aggregate_trace_pair_byte_length(self) -> u64 {
        self.maximum_loaded_aggregate_trace_pair_byte_length
    }

    pub(crate) const fn maximum_cached_authenticated_chunk_byte_length(self) -> u64 {
        self.maximum_cached_authenticated_chunk_byte_length
    }

    pub(crate) const fn maximum_pending_catalog_byte_length(self) -> u64 {
        self.maximum_pending_catalog_byte_length
    }

    pub(crate) const fn maximum_quotient_phase_populated_request_identity_byte_length(self) -> u64 {
        self.maximum_quotient_phase_populated_request_identity_byte_length
    }

    pub(crate) const fn maximum_recursive_cached_row_payload_byte_length(self) -> u64 {
        self.maximum_recursive_cached_row_payload_byte_length
    }

    pub(crate) const fn maximum_recursive_cached_row_catalog_byte_length(self) -> u64 {
        self.maximum_recursive_cached_row_catalog_byte_length
    }

    pub(crate) const fn relation_derivation_active_column_flag_byte_length(self) -> u64 {
        self.relation_derivation_active_column_flag_byte_length
    }

    pub(crate) const fn maximum_recursive_cache_and_relation_workspace_byte_length(self) -> u64 {
        self.maximum_recursive_cache_and_relation_workspace_byte_length
    }

    pub(crate) const fn maximum_requirement_discovery_transient_byte_length(self) -> u64 {
        self.maximum_requirement_discovery_transient_byte_length
    }

    pub(crate) const fn maximum_relation_column_derivation_workspace_byte_length(self) -> u64 {
        self.maximum_relation_column_derivation_workspace_byte_length
    }

    pub(crate) const fn maximum_round_two_quotient_arithmetic_transient_byte_length(self) -> u64 {
        self.maximum_round_two_quotient_arithmetic_transient_byte_length
    }

    pub(crate) const fn loading_persistent_resident_byte_length(self) -> u64 {
        self.loading_persistent_resident_byte_length
    }

    pub(crate) const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
        self.post_source_polynomial_finish_persistent_resident_byte_length
    }

    pub(crate) const fn additional_loading_source_polynomials_transient_byte_length(self) -> u64 {
        self.additional_loading_source_polynomials_transient_byte_length
    }

    pub(crate) const fn maximum_returned_source_polynomial_byte_length(self) -> u64 {
        self.maximum_returned_source_polynomial_byte_length
    }
}

#[derive(Clone, Copy)]
struct RelinearizationRoundTwoSourceProviderMemoryDimensions {
    retained_catalog_heap_byte_length: u64,
    total_authenticated_source_chunk_count: u64,
    maximum_trace_half_byte_length: u64,
    maximum_trace_pair_byte_length: u64,
    maximum_trace_pair_chunk_count: u64,
    maximum_recursive_cached_row_count: u64,
    maximum_relation_column_derivation_workspace_byte_length: u64,
    maximum_recursive_cache_and_relation_workspace_byte_length: u64,
    relation_column_count: u64,
    trace_column_count_per_source: u64,
    ring_degree: u64,
    trace_domain_size: u64,
}

fn checked_relinearization_provider_add(
    left: u64,
    right: u64,
) -> Result<u64, CommonProofProverError> {
    left.checked_add(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn checked_relinearization_provider_multiply(
    left: u64,
    right: u64,
) -> Result<u64, CommonProofProverError> {
    left.checked_mul(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn relinearization_provider_payload_for_count<Value>(
    count: usize,
) -> Result<u64, CommonProofProverError> {
    checked_relinearization_provider_multiply(
        u64::try_from(count).map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(size_of::<Value>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )
}

fn finish_relinearization_round_two_source_provider_memory_accounting(
    dimensions: RelinearizationRoundTwoSourceProviderMemoryDimensions,
) -> Result<RelinearizationRoundTwoSourceProviderMemoryAccounting, CommonProofProverError> {
    if dimensions.retained_catalog_heap_byte_length == 0
        || dimensions.total_authenticated_source_chunk_count == 0
        || dimensions.maximum_trace_half_byte_length == 0
        || dimensions.maximum_trace_pair_byte_length == 0
        || dimensions.maximum_trace_pair_chunk_count == 0
        || dimensions.maximum_recursive_cached_row_count == 0
        || dimensions.maximum_relation_column_derivation_workspace_byte_length == 0
        || dimensions.maximum_recursive_cache_and_relation_workspace_byte_length == 0
        || dimensions.maximum_recursive_cache_and_relation_workspace_byte_length
            < dimensions.maximum_relation_column_derivation_workspace_byte_length
        || dimensions.relation_column_count == 0
        || dimensions.trace_column_count_per_source == 0
        || dimensions.ring_degree == 0
        || dimensions.trace_domain_size == 0
        || dimensions.trace_domain_size.checked_mul(2) != Some(dimensions.ring_degree)
        || dimensions.maximum_trace_half_byte_length >= dimensions.maximum_trace_pair_byte_length
        || dimensions.maximum_trace_pair_chunk_count
            > dimensions.total_authenticated_source_chunk_count
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let provider_fixed_owner_byte_length =
        u64::try_from(size_of::<RelinearizationRoundTwoSourcePolynomialAdapter>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let readback_chunk_digest_byte_length = checked_relinearization_provider_multiply(
        dimensions.total_authenticated_source_chunk_count,
        u64::try_from(size_of::<Hash512>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    // Each source retains the readback verifier's authentication bitmap and
    // the provider's own completion bitmap used to request final coverage.
    let readback_authentication_flag_byte_length = checked_relinearization_provider_multiply(
        dimensions.total_authenticated_source_chunk_count,
        u64::try_from(size_of::<bool>() * 2).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let cached_quotient_byte_length = checked_relinearization_provider_multiply(
        dimensions.ring_degree,
        u64::try_from(size_of::<i128>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let first_aggregate_product_byte_length = cached_quotient_byte_length;
    let maximum_cached_authenticated_chunk_byte_length =
        u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let maximum_returned_source_polynomial_byte_length = checked_relinearization_provider_multiply(
        dimensions.trace_domain_size,
        u64::try_from(size_of::<super::super::ProofBaseFieldElement>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;

    let maximum_logical_requirement_catalog_byte_length =
        checked_relinearization_provider_multiply(
            4,
            u64::try_from(size_of::<AggregateTraceColumnRequirement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
    let maximum_active_load_requirement_catalog_byte_length =
        checked_relinearization_provider_multiply(
            2,
            u64::try_from(size_of::<AggregateTraceColumnRequirement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
    let maximum_loaded_trace_column_catalog_byte_length =
        checked_relinearization_provider_multiply(
            2,
            u64::try_from(size_of::<Option<LoadedAggregateTraceColumn>>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
    let maximum_request_identity_catalog_byte_length = checked_relinearization_provider_multiply(
        dimensions.total_authenticated_source_chunk_count,
        u64::try_from(size_of::<[u8; Hash512::BYTE_LENGTH]>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let maximum_pending_catalog_byte_length = [
        maximum_logical_requirement_catalog_byte_length,
        maximum_active_load_requirement_catalog_byte_length,
        maximum_loaded_trace_column_catalog_byte_length,
        maximum_request_identity_catalog_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;
    let maximum_recursive_cached_row_payload_byte_length =
        checked_relinearization_provider_multiply(
            dimensions.maximum_recursive_cached_row_count,
            checked_relinearization_provider_multiply(
                dimensions.trace_domain_size,
                u64::try_from(size_of::<i128>())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )?,
        )?;
    if dimensions.maximum_recursive_cache_and_relation_workspace_byte_length
        < maximum_recursive_cached_row_payload_byte_length
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let maximum_recursive_cached_row_catalog_byte_length =
        checked_relinearization_provider_multiply(
            dimensions.relation_column_count,
            u64::try_from(size_of::<Option<Zeroizing<Box<[i128]>>>>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
    let relation_derivation_active_column_flag_byte_length =
        checked_relinearization_provider_multiply(
            dimensions.relation_column_count,
            u64::try_from(size_of::<bool>()).map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
    let requirement_discovery_flag_byte_length = checked_relinearization_provider_multiply(
        dimensions
            .trace_column_count_per_source
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?,
        u64::try_from(size_of::<bool>()).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    // The active-column flags are explicitly dropped before the dense
    // requirement bitmap is converted into its ordered box. The quotient
    // dependency walk starts only after that conversion, so these three
    // allocations overlap pairwise, never all at once.
    let maximum_requirement_discovery_transient_byte_length = [
        checked_relinearization_provider_add(
            requirement_discovery_flag_byte_length,
            relation_derivation_active_column_flag_byte_length,
        )?,
        checked_relinearization_provider_add(
            requirement_discovery_flag_byte_length,
            maximum_logical_requirement_catalog_byte_length,
        )?,
        checked_relinearization_provider_add(
            maximum_logical_requirement_catalog_byte_length,
            relation_derivation_active_column_flag_byte_length,
        )?,
    ]
    .into_iter()
    .max()
    .ok_or(CommonProofProverError::InvalidColumn)?;

    // `exact_negacyclic_product_radix` receives one ring-sized i128 secret
    // and one centered aggregate row. For the ternary secret it owns exactly
    // one outer result, one radix digit vector, two 2N base-field evaluation
    // vectors, and one ring-sized digit product at its allocation peak.
    let maximum_round_two_quotient_arithmetic_transient_byte_length =
        checked_relinearization_provider_multiply(
            dimensions.ring_degree,
            u64::try_from(
                size_of::<i128>() * 5 + size_of::<super::super::ProofBaseFieldElement>() * 4,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;

    // The right aggregate phase retains the authenticated request identities
    // from the left phase. The two sources have the same topology, so exactly
    // two pair spans can coexist with the right-side arithmetic.
    let quotient_phase_populated_request_identity_byte_length =
        checked_relinearization_provider_multiply(
            dimensions
                .maximum_trace_pair_chunk_count
                .checked_mul(2)
                .ok_or(CommonProofProverError::CountOverflow)?
                .min(dimensions.total_authenticated_source_chunk_count),
            u64::try_from(size_of::<[u8; Hash512::BYTE_LENGTH]>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
    let quotient_phase_transient_byte_length = [
        maximum_pending_catalog_byte_length,
        dimensions.maximum_trace_pair_byte_length,
        maximum_cached_authenticated_chunk_byte_length,
        first_aggregate_product_byte_length,
        maximum_round_two_quotient_arithmetic_transient_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;
    let final_coverage_after_quotient_transient_byte_length = [
        maximum_pending_catalog_byte_length,
        maximum_cached_authenticated_chunk_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;
    let final_coverage_after_direct_trace_transient_byte_length = [
        maximum_pending_catalog_byte_length,
        dimensions.maximum_trace_pair_byte_length,
        maximum_cached_authenticated_chunk_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;
    let relation_column_derivation_transient_byte_length = [
        maximum_pending_catalog_byte_length,
        dimensions.maximum_trace_pair_byte_length,
        maximum_cached_authenticated_chunk_byte_length,
        maximum_recursive_cached_row_catalog_byte_length,
        relation_derivation_active_column_flag_byte_length,
        dimensions.maximum_recursive_cache_and_relation_workspace_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;
    let additional_loading_source_polynomials_transient_byte_length =
        quotient_phase_transient_byte_length
            .max(final_coverage_after_quotient_transient_byte_length)
            .max(final_coverage_after_direct_trace_transient_byte_length)
            .max(relation_column_derivation_transient_byte_length)
            .max(maximum_requirement_discovery_transient_byte_length);

    let post_source_polynomial_finish_persistent_resident_byte_length =
        checked_relinearization_provider_add(
            provider_fixed_owner_byte_length,
            dimensions.retained_catalog_heap_byte_length,
        )?;
    let loading_persistent_resident_byte_length = [
        post_source_polynomial_finish_persistent_resident_byte_length,
        readback_chunk_digest_byte_length,
        readback_authentication_flag_byte_length,
        cached_quotient_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;

    Ok(RelinearizationRoundTwoSourceProviderMemoryAccounting {
        provider_fixed_owner_byte_length,
        retained_catalog_heap_byte_length: dimensions.retained_catalog_heap_byte_length,
        readback_chunk_digest_byte_length,
        readback_authentication_flag_byte_length,
        cached_quotient_byte_length,
        first_aggregate_product_byte_length,
        maximum_loaded_aggregate_trace_pair_byte_length: dimensions.maximum_trace_pair_byte_length,
        maximum_cached_authenticated_chunk_byte_length,
        maximum_pending_catalog_byte_length,
        maximum_quotient_phase_populated_request_identity_byte_length:
            quotient_phase_populated_request_identity_byte_length,
        maximum_recursive_cached_row_payload_byte_length,
        maximum_recursive_cached_row_catalog_byte_length,
        relation_derivation_active_column_flag_byte_length,
        maximum_recursive_cache_and_relation_workspace_byte_length: dimensions
            .maximum_recursive_cache_and_relation_workspace_byte_length,
        maximum_requirement_discovery_transient_byte_length,
        maximum_relation_column_derivation_workspace_byte_length: dimensions
            .maximum_relation_column_derivation_workspace_byte_length,
        maximum_round_two_quotient_arithmetic_transient_byte_length,
        loading_persistent_resident_byte_length,
        post_source_polynomial_finish_persistent_resident_byte_length,
        additional_loading_source_polynomials_transient_byte_length,
        maximum_returned_source_polynomial_byte_length,
    })
}

fn relinearization_anchor_layout_heap_byte_length(
    ordered_anchors: &[super::trustee_evaluation_key::GaloisKeyShareAnchorSourceLayout],
) -> Result<u64, CommonProofProverError> {
    let mut total = relinearization_provider_payload_for_count::<
        super::trustee_evaluation_key::GaloisKeyShareAnchorSourceLayout,
    >(ordered_anchors.len())?;
    for anchor in ordered_anchors {
        total = checked_relinearization_provider_add(
            total,
            relinearization_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
                anchor.opening.hiding_secrets.capacity(),
            )?,
        )?;
        total = checked_relinearization_provider_add(
            total,
            relinearization_provider_payload_for_count::<super::key_relation::ShiftedSmallVector>(
                anchor.opening.hiding_errors.capacity(),
            )?,
        )?;
        total = checked_relinearization_provider_add(
            total,
            relinearization_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
                anchor.commitments.len(),
            )?,
        )?;
        total = checked_relinearization_provider_add(
            total,
            relinearization_provider_payload_for_count::<
                Box<[super::key_relation::RecenteredVerifierVectorWitness]>,
            >(anchor.first_matrix.len())?,
        )?;
        for matrix_row in &anchor.first_matrix {
            total = checked_relinearization_provider_add(
                total,
                relinearization_provider_payload_for_count::<
                    super::key_relation::RecenteredVerifierVectorWitness,
                >(matrix_row.len())?,
            )?;
        }
        total = checked_relinearization_provider_add(
            total,
            relinearization_provider_payload_for_count::<
                super::key_relation::RecenteredVerifierVectorWitness,
            >(anchor.second_matrix.len())?,
        )?;
        total = checked_relinearization_provider_add(
            total,
            relinearization_provider_payload_for_count::<
                super::key_relation::TrusteeRadixThreeQuotientWitness,
            >(anchor.quotients.len())?,
        )?;
    }
    Ok(total)
}

fn relinearization_round_two_source_layout_heap_byte_length(
    source_layout: &RelinearizationRoundTwoSourceLayout,
) -> Result<u64, CommonProofProverError> {
    let mut total = [
        relinearization_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            source_layout.round_one_left_rows.len(),
        )?,
        relinearization_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            source_layout.round_one_right_rows.len(),
        )?,
        relinearization_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            source_layout.aggregate_round_one_left_rows.len(),
        )?,
        relinearization_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            source_layout.aggregate_round_one_right_rows.len(),
        )?,
        relinearization_provider_payload_for_count::<super::key_relation::SplitIntegerVector>(
            source_layout.round_two_rows.len(),
        )?,
        relinearization_provider_payload_for_count::<
            super::trustee_evaluation_key::RelinearizationRoundOneErrorSourceLayout,
        >(source_layout.round_one_errors_by_block.len())?,
        relinearization_provider_payload_for_count::<
            super::trustee_evaluation_key::RelinearizationRoundOneQuotientSourceLayout,
        >(source_layout.round_one_quotients_by_row.len())?,
        relinearization_provider_payload_for_count::<
            super::trustee_evaluation_key::RelinearizationRoundTwoAggregateRowSourceLayout,
        >(source_layout.aggregate_rows.len())?,
        relinearization_provider_payload_for_count::<super::key_relation::ShiftedSmallVector>(
            source_layout.round_two_errors_by_block.len(),
        )?,
        relinearization_provider_payload_for_count::<
            super::key_relation::TrusteeRadixThreeQuotientWitness,
        >(source_layout.round_two_quotients_by_row.len())?,
        relinearization_anchor_layout_heap_byte_length(&source_layout.ordered_anchors)?,
        relinearization_provider_payload_for_count::<(u32, Box<[u32]>)>(
            source_layout.exact_radix_digits_by_column.len(),
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;
    for digits in source_layout.exact_radix_digits_by_column.values() {
        total = checked_relinearization_provider_add(
            total,
            relinearization_provider_payload_for_count::<u32>(digits.len())?,
        )?;
    }
    Ok(total)
}

fn relinearization_geometry_heap_byte_length(
    geometry: &TrusteeEvaluationKeyRelationGeometry,
) -> Result<u64, CommonProofProverError> {
    let decomposition_block_index_byte_length =
        geometry
            .decomposition_blocks
            .iter()
            .try_fold(0_u64, |total, block| {
                checked_relinearization_provider_add(
                    total,
                    relinearization_provider_payload_for_count::<u16>(
                        block.data_modulus_indices.capacity(),
                    )?,
                )
            })?;
    [
        relinearization_provider_payload_for_count::<u64>(geometry.data_moduli.capacity())?,
        relinearization_provider_payload_for_count::<u64>(geometry.special_moduli.capacity())?,
        relinearization_provider_payload_for_count::<
            super::trustee_evaluation_key::TrusteeEvaluationKeyDecompositionBlock,
        >(geometry.decomposition_blocks.capacity())?,
        decomposition_block_index_byte_length,
        relinearization_provider_payload_for_count::<u16>(
            geometry.commitment_data_modulus_indices.capacity(),
        )?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)
}

fn insert_relinearization_column_dependency(
    dependencies: &mut BTreeMap<u32, BTreeSet<u32>>,
    target_column_ordinal: u32,
    source_column_ordinal: u32,
) {
    if target_column_ordinal != source_column_ordinal {
        dependencies
            .entry(target_column_ordinal)
            .or_default()
            .insert(source_column_ordinal);
    }
}

fn relinearization_round_two_column_dependencies(
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &RelinearizationRoundTwoSourceLayout,
) -> BTreeMap<u32, BTreeSet<u32>> {
    let mut dependencies = BTreeMap::<u32, BTreeSet<u32>>::new();
    for anchor in &source_layout.ordered_anchors {
        for matrix in anchor
            .first_matrix
            .iter()
            .flat_map(|row| row.iter())
            .chain(anchor.second_matrix.iter())
        {
            for half_ordinal in 0..2 {
                let canonical = matrix.canonical.halves[half_ordinal];
                insert_relinearization_column_dependency(
                    &mut dependencies,
                    matrix.centered.source.coefficients.halves[half_ordinal],
                    canonical,
                );
                insert_relinearization_column_dependency(
                    &mut dependencies,
                    matrix.carry_columns[half_ordinal],
                    canonical,
                );
            }
        }
    }
    for (source_column_ordinal, digit_column_ordinals) in
        &source_layout.exact_radix_digits_by_column
    {
        for digit_column_ordinal in digit_column_ordinals.iter().copied() {
            insert_relinearization_column_dependency(
                &mut dependencies,
                digit_column_ordinal,
                *source_column_ordinal,
            );
        }
    }
    for semantic_cell in &relation_plan_variant.ordered_semantic_cells {
        let dependent_columns: &[u32] = match &semantic_cell.bound_certificate {
            super::RelationBoundCertificate::UnsignedRadixRecomposition {
                ordered_digit_column_ordinals,
                ..
            }
            | super::RelationBoundCertificate::ShiftedRadixRecomposition {
                ordered_digit_column_ordinals,
                ..
            } => ordered_digit_column_ordinals,
            super::RelationBoundCertificate::CanonicalModulusRecomposition {
                ordered_digit_column_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
                ..
            } => {
                for dependent_column in ordered_difference_digit_column_ordinals
                    .iter()
                    .chain(ordered_borrow_column_ordinals)
                    .copied()
                {
                    insert_relinearization_column_dependency(
                        &mut dependencies,
                        dependent_column,
                        semantic_cell.column_ordinal,
                    );
                }
                ordered_digit_column_ordinals
            }
            super::RelationBoundCertificate::Trinary { .. }
            | super::RelationBoundCertificate::Binary { .. }
            | super::RelationBoundCertificate::FiniteIntegerSet { .. } => &[],
        };
        for dependent_column in dependent_columns.iter().copied() {
            insert_relinearization_column_dependency(
                &mut dependencies,
                dependent_column,
                semantic_cell.column_ordinal,
            );
        }
    }
    for component in relation_plan_variant
        .ordered_integer_lift_batches()
        .iter()
        .flat_map(|batch| batch.ordered_components.iter())
    {
        let carry_columns = component
            .ordered_linear_terms
            .iter()
            .filter(|term| {
                term.negative
                    && term.column_offset == 0
                    && term.coefficient
                        == super::RelationIntegerLiftCoefficient::Constant(
                            super::key_relation::EXACT_INTEGER_LIFT_RADIX,
                        )
            })
            .map(|term| term.column_ordinal)
            .collect::<BTreeSet<_>>();
        for carry_column in carry_columns {
            for term in &component.ordered_linear_terms {
                if term.column_ordinal != carry_column {
                    insert_relinearization_column_dependency(
                        &mut dependencies,
                        carry_column,
                        term.column_ordinal,
                    );
                }
            }
            for product in &component.ordered_full_ring_negacyclic_products {
                for source_column in [
                    product.multiplicand_low_column_ordinal,
                    product.multiplicand_high_column_ordinal,
                    product.multiplier_low_column_ordinal,
                    product.multiplier_high_column_ordinal,
                ] {
                    insert_relinearization_column_dependency(
                        &mut dependencies,
                        carry_column,
                        source_column,
                    );
                }
            }
        }
    }
    dependencies
}

fn relinearization_round_two_recursive_column_closures(
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &RelinearizationRoundTwoSourceLayout,
) -> Result<Vec<BTreeSet<u32>>, CommonProofProverError> {
    let dependencies =
        relinearization_round_two_column_dependencies(relation_plan_variant, source_layout);
    requested_source_column_ordinals(relation_plan_variant)?
        .into_iter()
        .map(|requested_column| {
            let mut pending = vec![requested_column];
            let mut visited = BTreeSet::new();
            while let Some(column) = pending.pop() {
                if visited.insert(column) {
                    pending.extend(
                        dependencies
                            .get(&column)
                            .into_iter()
                            .flat_map(|sources| sources.iter().copied()),
                    );
                }
            }
            if visited.is_empty() {
                return Err(CommonProofProverError::InvalidColumn);
            }
            Ok(visited)
        })
        .collect()
}

fn quotient_columns(
    quotient: super::key_relation::TrusteeRadixThreeQuotientWitness,
) -> impl Iterator<Item = u32> {
    quotient
        .low_quotients
        .into_iter()
        .chain(quotient.high_carries)
}

struct RelationColumnDerivationLiveness {
    maximum_workspace_byte_length: u64,
    maximum_cache_and_workspace_byte_length: u64,
}

fn relation_column_derivation_liveness(
    relation_plan_variant: &RelationPlanVariant,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    source_layout: &RelinearizationRoundTwoSourceLayout,
    recursive_column_closures: &[BTreeSet<u32>],
) -> Result<RelationColumnDerivationLiveness, CommonProofProverError> {
    let ring_degree = geometry.ring_degree;
    let trace_domain_size = relation_plan_variant.trace_domain_size();
    let i128_byte_length =
        u64::try_from(size_of::<i128>()).map_err(|_| CommonProofProverError::CountOverflow)?;
    let base_field_byte_length = u64::try_from(size_of::<super::super::ProofBaseFieldElement>())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let baseline_workspace =
        checked_relinearization_provider_multiply(trace_domain_size, i128_byte_length)?;
    let mut maximum_workspace_byte_length = 0_u64;
    let mut maximum_cache_and_workspace_byte_length = 0_u64;

    let round_one_quotient_columns = source_layout
        .round_one_quotients_by_row
        .iter()
        .flat_map(|row| [row.left, row.right])
        .flat_map(quotient_columns)
        .collect::<BTreeSet<_>>();
    let anchor_quotient_columns = source_layout
        .ordered_anchors
        .iter()
        .flat_map(|anchor| anchor.quotients.iter().copied())
        .flat_map(quotient_columns)
        .collect::<BTreeSet<_>>();
    let full_ring_carry_columns = relation_plan_variant
        .ordered_integer_lift_batches()
        .iter()
        .flat_map(|batch| batch.ordered_components.iter())
        .filter(|component| !component.ordered_full_ring_negacyclic_products.is_empty())
        .flat_map(|component| component.ordered_linear_terms.iter())
        .filter(|term| {
            term.negative
                && term.column_offset == 0
                && term.coefficient
                    == super::RelationIntegerLiftCoefficient::Constant(
                        super::key_relation::EXACT_INTEGER_LIFT_RADIX,
                    )
        })
        .map(|term| term.column_ordinal)
        .collect::<BTreeSet<_>>();

    for closure in recursive_column_closures {
        let mut workspace_byte_length = baseline_workspace;
        if closure
            .iter()
            .any(|column| full_ring_carry_columns.contains(column))
        {
            // During one full-ring integer-lift product the provider retains
            // the accumulated trace row, four returned trace halves, two
            // full-ring operands, the full-ring product, and two 2N
            // base-field evaluation buffers.
            let full_ring_workspace = [
                checked_relinearization_provider_multiply(
                    trace_domain_size,
                    checked_relinearization_provider_multiply(11, i128_byte_length)?,
                )?,
                checked_relinearization_provider_multiply(
                    trace_domain_size,
                    checked_relinearization_provider_multiply(8, base_field_byte_length)?,
                )?,
            ]
            .into_iter()
            .try_fold(0_u64, checked_relinearization_provider_add)?;
            workspace_byte_length = workspace_byte_length.max(full_ring_workspace);
        }
        if closure
            .iter()
            .any(|column| round_one_quotient_columns.contains(column))
        {
            let round_one_workspace = checked_relinearization_provider_add(
                checked_relinearization_provider_multiply(128, ring_degree)?,
                relinearization_provider_payload_for_count::<SuiteModulusReference>(
                    geometry
                        .data_moduli
                        .len()
                        .checked_add(geometry.special_moduli.len())
                        .ok_or(CommonProofProverError::CountOverflow)?,
                )?,
            )?;
            workspace_byte_length = workspace_byte_length.max(round_one_workspace);
        }
        if closure
            .iter()
            .any(|column| anchor_quotient_columns.contains(column))
        {
            let product_column_count = u64::from(geometry.commitment_module_rank)
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let anchor_workspace = [
                checked_relinearization_provider_multiply(
                    product_column_count
                        .checked_add(7)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                    checked_relinearization_provider_multiply(ring_degree, i128_byte_length)?,
                )?,
                checked_relinearization_provider_multiply(
                    product_column_count,
                    u64::try_from(size_of::<Zeroizing<Vec<i128>>>())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )?,
                128,
            ]
            .into_iter()
            .try_fold(0_u64, checked_relinearization_provider_add)?;
            workspace_byte_length = workspace_byte_length.max(anchor_workspace);
        }
        let cached_row_payload_byte_length = checked_relinearization_provider_multiply(
            u64::try_from(closure.len()).map_err(|_| CommonProofProverError::CountOverflow)?,
            baseline_workspace,
        )?;
        maximum_workspace_byte_length = maximum_workspace_byte_length.max(workspace_byte_length);
        maximum_cache_and_workspace_byte_length =
            maximum_cache_and_workspace_byte_length.max(checked_relinearization_provider_add(
                cached_row_payload_byte_length,
                workspace_byte_length,
            )?);
    }
    if maximum_workspace_byte_length == 0 || maximum_cache_and_workspace_byte_length == 0 {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(RelationColumnDerivationLiveness {
        maximum_workspace_byte_length,
        maximum_cache_and_workspace_byte_length,
    })
}

/// Derives manual/internal provider evidence from checked topology and relation
/// owners. The returned values describe process memory only and are never
/// serialized into a cryptographic object.
pub(crate) fn relinearization_round_two_source_provider_memory_accounting(
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    source_layout: &RelinearizationRoundTwoSourceLayout,
    aggregate_topology: &KeySwitchComponentMaterialTopology,
    canonical_application_statement_byte_length: usize,
) -> Result<RelinearizationRoundTwoSourceProviderMemoryAccounting, CommonProofProverError> {
    let ring_degree = u64::try_from(aggregate_topology.polynomial_degree())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if ring_degree != geometry.ring_degree
        || relation_plan_variant.trace_domain_size().checked_mul(2) != Some(ring_degree)
        || canonical_application_statement_byte_length == 0
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let trace_column_count = aggregate_topology
        .trace_column_count()
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
    if trace_column_count == 0 || !trace_column_count.is_multiple_of(2) {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut maximum_trace_half_byte_length = 0_u64;
    let mut maximum_trace_pair_byte_length = 0_u64;
    let mut maximum_trace_pair_chunk_count = 0_u64;
    for row_ordinal in 0..trace_column_count / 2 {
        let low_half = aggregate_topology
            .trace_column(
                row_ordinal
                    .checked_mul(2)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let high_half = aggregate_topology
            .trace_column(
                row_ordinal
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(1))
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let low_half_end = low_half
            .byte_offset()
            .checked_add(low_half.byte_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if low_half_end != high_half.byte_offset() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let trace_pair_byte_length = low_half
            .byte_length()
            .checked_add(high_half.byte_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        let trace_pair_end = high_half
            .byte_offset()
            .checked_add(high_half.byte_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        let first_chunk_index = low_half.byte_offset() / stream_chunk_byte_length;
        let end_chunk_index_exclusive = trace_pair_end.div_ceil(stream_chunk_byte_length);
        maximum_trace_half_byte_length = maximum_trace_half_byte_length
            .max(low_half.byte_length())
            .max(high_half.byte_length());
        maximum_trace_pair_byte_length = maximum_trace_pair_byte_length.max(trace_pair_byte_length);
        maximum_trace_pair_chunk_count = maximum_trace_pair_chunk_count.max(
            end_chunk_index_exclusive
                .checked_sub(first_chunk_index)
                .ok_or(CommonProofProverError::CountOverflow)?,
        );
    }
    let component_chunk_count = aggregate_topology
        .expected_byte_length()
        .div_ceil(stream_chunk_byte_length);
    let total_authenticated_source_chunk_count = component_chunk_count
        .checked_mul(2)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let requested_column_count = requested_source_column_ordinals(relation_plan_variant)?.len();
    let recursive_column_closures =
        relinearization_round_two_recursive_column_closures(relation_plan_variant, source_layout)?;
    let maximum_recursive_cached_row_count = recursive_column_closures
        .iter()
        .map(BTreeSet::len)
        .max()
        .and_then(|count| u64::try_from(count).ok())
        .filter(|count| *count > 0)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let relation_column_derivation_liveness = relation_column_derivation_liveness(
        relation_plan_variant,
        geometry,
        source_layout,
        &recursive_column_closures,
    )?;
    let aggregate_topology_heap_byte_length = checked_relinearization_provider_multiply(
        u64::try_from(aggregate_topology.extended_limb_count())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(size_of::<u64>() + size_of::<u8>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let retained_catalog_heap_byte_length = [
        u64::try_from(canonical_application_statement_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        relation_plan_variant
            .resident_owned_payload_byte_length()
            .map_err(CommonProofProverError::Relation)?,
        relation_context
            .resident_owned_payload_byte_length()
            .map_err(CommonProofProverError::Relation)?,
        relinearization_geometry_heap_byte_length(geometry)?,
        relinearization_round_two_source_layout_heap_byte_length(source_layout)?,
        aggregate_topology_heap_byte_length,
        relinearization_provider_payload_for_count::<u32>(requested_column_count)?,
    ]
    .into_iter()
    .try_fold(0_u64, checked_relinearization_provider_add)?;

    finish_relinearization_round_two_source_provider_memory_accounting(
        RelinearizationRoundTwoSourceProviderMemoryDimensions {
            retained_catalog_heap_byte_length,
            total_authenticated_source_chunk_count,
            maximum_trace_half_byte_length,
            maximum_trace_pair_byte_length,
            maximum_trace_pair_chunk_count,
            maximum_recursive_cached_row_count,
            maximum_relation_column_derivation_workspace_byte_length:
                relation_column_derivation_liveness.maximum_workspace_byte_length,
            maximum_recursive_cache_and_relation_workspace_byte_length:
                relation_column_derivation_liveness.maximum_cache_and_workspace_byte_length,
            relation_column_count: u64::try_from(relation_plan_variant.ordered_columns().len())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            trace_column_count_per_source: u64::try_from(trace_column_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            ring_degree,
            trace_domain_size: relation_plan_variant.trace_domain_size(),
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AggregateTraceColumnRequirement {
    source_index: usize,
    trace_column_ordinal: usize,
}

struct ExactAggregateTraceColumnRequirementSet {
    trace_column_count_per_source: usize,
    requirement_flags: Box<[bool]>,
}

impl ExactAggregateTraceColumnRequirementSet {
    fn new(trace_column_count_per_source: usize) -> Result<Self, CommonProofProverError> {
        let requirement_count = trace_column_count_per_source
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if requirement_count == 0 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            trace_column_count_per_source,
            requirement_flags: vec![false; requirement_count].into_boxed_slice(),
        })
    }

    fn insert(
        &mut self,
        requirement: AggregateTraceColumnRequirement,
    ) -> Result<(), CommonProofProverError> {
        let index = requirement
            .source_index
            .checked_mul(self.trace_column_count_per_source)
            .and_then(|start| start.checked_add(requirement.trace_column_ordinal))
            .filter(|index| *index < self.requirement_flags.len())
            .ok_or(CommonProofProverError::InvalidColumn)?;
        self.requirement_flags[index] = true;
        Ok(())
    }

    fn into_ordered_requirements(
        self,
    ) -> Result<Box<[AggregateTraceColumnRequirement]>, CommonProofProverError> {
        let requirement_count = self
            .requirement_flags
            .iter()
            .filter(|required| **required)
            .count();
        let mut ordered_requirements = vec![
            AggregateTraceColumnRequirement {
                source_index: 0,
                trace_column_ordinal: 0,
            };
            requirement_count
        ]
        .into_boxed_slice();
        let mut destination_index = 0_usize;
        for (flat_index, required) in self.requirement_flags.iter().copied().enumerate() {
            if !required {
                continue;
            }
            let requirement = AggregateTraceColumnRequirement {
                source_index: flat_index / self.trace_column_count_per_source,
                trace_column_ordinal: flat_index % self.trace_column_count_per_source,
            };
            *ordered_requirements
                .get_mut(destination_index)
                .ok_or(CommonProofProverError::InvalidColumn)? = requirement;
            destination_index = destination_index
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
        if destination_index != ordered_requirements.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(ordered_requirements)
    }
}

struct LoadedAggregateTraceColumn {
    requirement: AggregateTraceColumnRequirement,
    bytes: Zeroizing<Box<[u8]>>,
}

struct ExactLoadedAggregateTraceColumnCatalog {
    ordered_columns: Box<[Option<LoadedAggregateTraceColumn>]>,
    loaded_column_count: usize,
}

impl ExactLoadedAggregateTraceColumnCatalog {
    fn new(maximum_loaded_column_count: usize) -> Self {
        Self {
            ordered_columns: (0..maximum_loaded_column_count)
                .map(|_| None)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            loaded_column_count: 0,
        }
    }

    fn push(&mut self, column: LoadedAggregateTraceColumn) -> Result<(), CommonProofProverError> {
        let slot = self
            .ordered_columns
            .get_mut(self.loaded_column_count)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if slot.is_some() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        *slot = Some(column);
        self.loaded_column_count = self
            .loaded_column_count
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    fn clear(&mut self) {
        for column in &mut self.ordered_columns[..self.loaded_column_count] {
            *column = None;
        }
        self.loaded_column_count = 0;
    }

    fn iter(&self) -> impl Iterator<Item = &LoadedAggregateTraceColumn> {
        self.ordered_columns[..self.loaded_column_count]
            .iter()
            .flatten()
    }

    #[cfg(test)]
    fn descriptor_slot_count(&self) -> usize {
        self.ordered_columns.len()
    }
}

struct ExactAggregateSourceRequestIdentityCatalog {
    ordered_request_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    request_identity_count: usize,
}

impl ExactAggregateSourceRequestIdentityCatalog {
    fn new(maximum_request_identity_count: usize) -> Self {
        Self {
            ordered_request_identities: vec![
                [0_u8; Hash512::BYTE_LENGTH];
                maximum_request_identity_count
            ]
            .into_boxed_slice(),
            request_identity_count: 0,
        }
    }

    fn push(
        &mut self,
        request_identity: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<(), CommonProofProverError> {
        let slot = self
            .ordered_request_identities
            .get_mut(self.request_identity_count)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        *slot = request_identity;
        self.request_identity_count = self
            .request_identity_count
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(())
    }

    fn as_slice(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_request_identities[..self.request_identity_count]
    }

    const fn len(&self) -> usize {
        self.request_identity_count
    }

    #[cfg(test)]
    fn allocated_identity_slot_count(&self) -> usize {
        self.ordered_request_identities.len()
    }
}

struct PendingAggregateTraceColumn {
    requirement: AggregateTraceColumnRequirement,
    trace_column: KeySwitchComponentTraceColumn,
    bytes: Zeroizing<Box<[u8]>>,
    filled_byte_length: usize,
}

struct CachedAggregateSourceChunk {
    source_index: usize,
    stream_byte_offset: u64,
    bytes: Zeroizing<Box<[u8]>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateSourceReadPurpose {
    TraceColumn,
    FinalCoverage,
}

struct OutstandingAggregateSourceRead {
    request: CommonProofAuthenticatedSourceReadRequest,
    source_index: usize,
    purpose: AggregateSourceReadPurpose,
}

struct PendingRelinearizationRoundTwoColumn {
    column_ordinal: u32,
    logical_requirements: Box<[AggregateTraceColumnRequirement]>,
    load_requirements: Box<[AggregateTraceColumnRequirement]>,
    next_load_requirement_index: usize,
    current_trace_column: Option<PendingAggregateTraceColumn>,
    loaded_trace_columns: ExactLoadedAggregateTraceColumnCatalog,
    ordered_request_identities: ExactAggregateSourceRequestIdentityCatalog,
    quotient_phase: PendingRelinearizationRoundTwoQuotientPhase,
}

enum PendingRelinearizationRoundTwoQuotientPhase {
    NotRequired,
    LoadAggregateLeft {
        row_ordinal: usize,
    },
    LoadAggregateRight {
        row_ordinal: usize,
        secret_times_aggregate_left: Zeroizing<Vec<i128>>,
    },
}

struct LoadedRelinearizationRoundTwoAggregateColumns<'source> {
    topology: &'source KeySwitchComponentMaterialTopology,
    columns: &'source ExactLoadedAggregateTraceColumnCatalog,
}

impl LoadedRelinearizationRoundTwoAggregateColumns<'_> {
    fn decoded_trace_rows(
        &self,
        requirement: AggregateTraceColumnRequirement,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let loaded = self
            .columns
            .iter()
            .find(|loaded| loaded.requirement == requirement)
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let trace_column = self
            .topology
            .trace_column(requirement.trace_column_ordinal)?;
        trace_column
            .decode_authenticated_bytes(&loaded.bytes)
            .map(|rows| {
                Zeroizing::new(
                    rows.into_iter()
                        .map(|value| i128::from(value.canonical()))
                        .collect(),
                )
            })
    }

    fn direct_witness_rows(
        &self,
        source_index: usize,
        rows: &[super::key_relation::SplitIntegerVector],
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        for (row_ordinal, row) in rows.iter().copied().enumerate() {
            if let Some(half_ordinal) = half_position(row, column_ordinal) {
                return self
                    .decoded_trace_rows(AggregateTraceColumnRequirement {
                        source_index,
                        trace_column_ordinal: row_ordinal
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(half_ordinal))
                            .ok_or(RefusalReason::OutsideSupportedProfile)?,
                    })
                    .map(Some);
            }
        }
        Ok(None)
    }

    fn centered_full_row(
        &self,
        source_index: usize,
        row_ordinal: usize,
        modulus: u64,
    ) -> Result<Zeroizing<Vec<i128>>, RefusalReason> {
        let mut coefficients =
            Zeroizing::new(Vec::with_capacity(self.topology.polynomial_degree()));
        for half_ordinal in 0..2 {
            let requirement = AggregateTraceColumnRequirement {
                source_index,
                trace_column_ordinal: row_ordinal
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(half_ordinal))
                    .ok_or(RefusalReason::OutsideSupportedProfile)?,
            };
            let loaded = self
                .columns
                .iter()
                .find(|loaded| loaded.requirement == requirement)
                .ok_or(RefusalReason::MissingPrerequisite)?;
            let trace_column = self
                .topology
                .trace_column(requirement.trace_column_ordinal)?;
            let decoded_half = trace_column.decode_authenticated_bytes(&loaded.bytes)?;
            coefficients.extend(
                decoded_half
                    .into_iter()
                    .map(|value| centered_residue(value.canonical(), modulus)),
            );
        }
        if coefficients.len() != self.topology.polynomial_degree() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(coefficients)
    }
}

struct RelinearizationRoundTwoColumnDerivation<'borrow, 'authority, 'statement, 'plan> {
    source: &'borrow SetupGenerationRelinearizationRoundTwoSource<'authority, 'statement>,
    common: RelinearizationRoundOneColumnDerivation<'borrow, 'plan>,
    source_layout: &'plan RelinearizationRoundTwoSourceLayout,
    aggregate_columns: LoadedRelinearizationRoundTwoAggregateColumns<'borrow>,
}

impl KeyRelationColumnDerivation for RelinearizationRoundTwoColumnDerivation<'_, '_, '_, '_> {
    fn relation_plan_variant(&self) -> &RelationPlanVariant {
        self.common.relation_plan_variant
    }

    fn relation_context(&self) -> &RelationPlanCheckContext {
        self.common.relation_context
    }

    fn exact_radix_digits_by_column(&self) -> &super::key_relation::ExactRadixDigitColumnCatalog {
        self.common.source_layout.exact_radix_digits_by_column
    }

    fn cached_rows(&self) -> &ExactKeyRelationDerivedRowCache {
        &self.common.cached_rows
    }

    fn cached_rows_mut(&mut self) -> &mut ExactKeyRelationDerivedRowCache {
        &mut self.common.cached_rows
    }

    fn active_columns_mut(&mut self) -> &mut ExactKeyRelationActiveColumnSet {
        &mut self.common.active_columns
    }

    fn direct_witness_rows(
        &mut self,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        if let Some(rows) = self.common.common_direct_witness_rows(column_ordinal)? {
            return Ok(Some(rows));
        }
        if let Some(rows) = component_direct_witness_rows(
            self.source.round_two_component(),
            &self.source_layout.round_two_rows,
            column_ordinal,
        )? {
            return Ok(Some(rows));
        }
        for (source_index, rows) in [
            (0, self.source_layout.aggregate_round_one_left_rows.as_ref()),
            (
                1,
                self.source_layout.aggregate_round_one_right_rows.as_ref(),
            ),
        ] {
            if let Some(rows) =
                self.aggregate_columns
                    .direct_witness_rows(source_index, rows, column_ordinal)?
            {
                return Ok(Some(rows));
            }
        }
        for (row_ordinal, aggregate_layout) in self.source_layout.aggregate_rows.iter().enumerate()
        {
            for (source_index, recentered_layout) in
                [(0, &aggregate_layout.left), (1, &aggregate_layout.right)]
            {
                if let Some(rows) = self.recentered_aggregate_rows(
                    source_index,
                    recentered_layout,
                    row_ordinal,
                    column_ordinal,
                )? {
                    return Ok(Some(rows));
                }
            }
        }
        for (decomposition_block_index, error_layout) in self
            .source_layout
            .round_two_errors_by_block
            .iter()
            .enumerate()
        {
            if let Some(half_ordinal) = half_position(error_layout.coefficients, column_ordinal) {
                let error = self
                    .source
                    .round_two_errors_by_block()
                    .get(decomposition_block_index)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                return split_signed_i8_polynomial(error, half_ordinal).map(Some);
            }
        }
        for (row_ordinal, quotient_layout) in self
            .source_layout
            .round_two_quotients_by_row
            .iter()
            .copied()
            .enumerate()
        {
            for half_ordinal in 0..2 {
                if quotient_layout.low_quotients[half_ordinal] == column_ordinal {
                    let quotient = self.cached_round_two_quotient(row_ordinal)?;
                    return split_balanced_quotient(quotient, half_ordinal, false).map(Some);
                }
                if quotient_layout.high_carries[half_ordinal] == column_ordinal {
                    let quotient = self.cached_round_two_quotient(row_ordinal)?;
                    return split_balanced_quotient(quotient, half_ordinal, true).map(Some);
                }
            }
        }
        Ok(None)
    }

    fn full_verifier_sequence(
        &self,
        source: &RelationVerifierSource,
    ) -> Result<Vec<u64>, RefusalReason> {
        self.common.common_full_verifier_sequence(source)
    }
}

impl RelinearizationRoundTwoColumnDerivation<'_, '_, '_, '_> {
    fn recentered_aggregate_rows(
        &self,
        source_index: usize,
        layout: &super::key_relation::RecenteredVerifierVectorWitness,
        row_ordinal: usize,
        column_ordinal: u32,
    ) -> Result<Option<Zeroizing<Vec<i128>>>, RefusalReason> {
        for half_ordinal in 0..2 {
            let is_centered =
                layout.centered.source.coefficients.halves[half_ordinal] == column_ordinal;
            let is_carry = layout.carry_columns[half_ordinal] == column_ordinal;
            if !is_centered && !is_carry {
                continue;
            }
            let canonical =
                self.aggregate_columns
                    .decoded_trace_rows(AggregateTraceColumnRequirement {
                        source_index,
                        trace_column_ordinal: row_ordinal
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(half_ordinal))
                            .ok_or(RefusalReason::OutsideSupportedProfile)?,
                    })?;
            let modulus_references = self.ordered_modulus_references()?;
            let modulus_reference = modulus_references
                .get(row_ordinal % modulus_references.len())
                .copied()
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let modulus = i128::from(
                self.common
                    .relation_context
                    .resolved_modulus(modulus_reference)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
            );
            let offset = (modulus - 1) / 2;
            return Ok(Some(Zeroizing::new(
                canonical
                    .iter()
                    .map(|value| {
                        if *value <= offset {
                            if is_carry { 0 } else { *value + offset }
                        } else if is_carry {
                            1
                        } else {
                            *value + offset - modulus
                        }
                    })
                    .collect(),
            )));
        }
        Ok(None)
    }

    fn cached_round_two_quotient(&mut self, row_ordinal: usize) -> Result<&[i128], RefusalReason> {
        let key = CachedQuotientKey::RoundTwo { row_ordinal };
        self.common
            .cached_quotient
            .as_ref()
            .filter(|cache| cache.key == key)
            .map(|cache| cache.coefficients.as_slice())
            .ok_or(RefusalReason::MissingPrerequisite)
    }

    fn ordered_modulus_references(&self) -> Result<Vec<SuiteModulusReference>, RefusalReason> {
        let mut references = Vec::with_capacity(
            self.common
                .geometry
                .data_moduli
                .len()
                .checked_add(self.common.geometry.special_moduli.len())
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        );
        for modulus_index in 0..self.common.geometry.data_moduli.len() {
            references.push(SuiteModulusReference::data(
                u16::try_from(modulus_index).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            ));
        }
        for modulus_index in 0..self.common.geometry.special_moduli.len() {
            references.push(SuiteModulusReference::special(
                u16::try_from(modulus_index).map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            ));
        }
        if references.is_empty() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(references)
    }
}

pub(crate) struct RelinearizationRoundTwoSourcePolynomialAdapter {
    authority_identifier: u32,
    prepared_attempt: PreparedActionProofAttemptSource,
    canonical_application_statement_bytes: Box<[u8]>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    schedule_position: u32,
    setup_attempt_identifier: [u8; 32],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    anchor_commitment_roots: [[u8; Hash512::BYTE_LENGTH]; 3],
    round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    aggregate_round_one_root_pair: [[u8; Hash512::BYTE_LENGTH]; 2],
    contribution_root: [u8; Hash512::BYTE_LENGTH],
    request_context: CommonProofSourcePolynomialRequestContext,
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    geometry: TrusteeEvaluationKeyRelationGeometry,
    source_layout: RelinearizationRoundTwoSourceLayout,
    source_catalog_binding: [u8; Hash512::BYTE_LENGTH],
    aggregate_topology: KeySwitchComponentMaterialTopology,
    aggregate_sources: [RelinearizationRoundTwoAuthenticatedAggregateSource; 2],
    requested_column_ordinals: Box<[u32]>,
    next_source_index: usize,
    pending_column: Option<PendingRelinearizationRoundTwoColumn>,
    cached_source_chunk: Option<CachedAggregateSourceChunk>,
    outstanding_source_read: Option<OutstandingAggregateSourceRead>,
    cached_quotient: Option<CachedQuotient>,
    memory_accounting: RelinearizationRoundTwoSourceProviderMemoryAccounting,
    source_polynomials_finished: bool,
}

impl RelinearizationRoundTwoSourcePolynomialAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source: &SetupGenerationRelinearizationRoundTwoSource<'_, '_>,
        relation_plan: &CommonProofRelationPlanCapability,
        relation_plan_variant: RelationPlanVariant,
        relation_context: RelationPlanCheckContext,
        geometry: TrusteeEvaluationKeyRelationGeometry,
        source_layout: RelinearizationRoundTwoSourceLayout,
        aggregate_source_plan: RelinearizationRoundTwoAuthenticatedAggregateSourcePlan,
    ) -> Result<Self, CommonProofProverError> {
        let component_topology = source.round_two_component().topology();
        let generated_source = source.generated_source_authority();
        if relation_plan_variant.schedule_position() != Some(source.schedule_position())
            || relation_plan_variant.top_count().is_some()
            || usize::try_from(relation_plan_variant.trace_domain_size())
                .ok()
                .and_then(|trace_size| trace_size.checked_mul(2))
                != usize::try_from(geometry.ring_degree).ok()
            || component_topology != source.round_one_left_component().topology()
            || component_topology != source.round_one_right_component().topology()
            || component_topology != &aggregate_source_plan.topology
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let RelinearizationRoundTwoAuthenticatedAggregateSourcePlan {
            source_catalog_binding,
            topology: aggregate_topology,
            sources: aggregate_sources,
        } = aggregate_source_plan;
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            source.protocol_version(),
            source.suite_identifier(),
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
            source
                .prepared_attempt()
                .application_statement_hash()
                .into_bytes(),
            relation_plan.relation_plan_hash(),
            relation_plan.relation_plan_variant_hash(),
            relation_plan_variant.schedule_position(),
            relation_plan_variant.top_count(),
        );
        let requested_column_ordinals =
            requested_source_column_ordinals(&relation_plan_variant)?.into_boxed_slice();
        let memory_accounting = relinearization_round_two_source_provider_memory_accounting(
            &relation_plan_variant,
            &relation_context,
            &geometry,
            &source_layout,
            &aggregate_topology,
            source.canonical_application_statement_bytes().len(),
        )?;
        let expected_total_chunk_count = aggregate_topology
            .expected_byte_length()
            .div_ceil(
                u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let actual_total_chunk_count =
            aggregate_sources
                .iter()
                .try_fold(0_u64, |total, aggregate_source| {
                    total
                        .checked_add(
                            u64::try_from(aggregate_source.authenticated_chunks.len())
                                .map_err(|_| CommonProofProverError::CountOverflow)?,
                        )
                        .ok_or(CommonProofProverError::CountOverflow)
                })?;
        if actual_total_chunk_count != expected_total_chunk_count {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(Self {
            authority_identifier: source.authority_identifier(),
            prepared_attempt: *source.prepared_attempt(),
            canonical_application_statement_bytes: source
                .canonical_application_statement_bytes()
                .to_vec()
                .into_boxed_slice(),
            setup_proof_context_hash: source.setup_proof_context_hash(),
            roster_hash: source.roster_hash(),
            participant_identity: source.participant_identity(),
            roster_position: source.roster_position(),
            schedule_position: source.schedule_position(),
            setup_attempt_identifier: source.setup_attempt_identifier(),
            source_setup_intent_object_hash: source.source_setup_intent_object_hash(),
            action_randomness_authorization_hash: source.action_randomness_authorization_hash(),
            anchor_commitment_roots: source.anchor_commitment_roots(),
            round_one_root_pair: generated_source.round_one_root_pair(),
            aggregate_round_one_root_pair: generated_source.aggregate_round_one_root_pair(),
            contribution_root: generated_source.component().contribution_root(),
            request_context,
            relation_plan_variant,
            relation_context,
            geometry,
            source_layout,
            source_catalog_binding,
            aggregate_topology,
            aggregate_sources,
            requested_column_ordinals,
            next_source_index: 0,
            pending_column: None,
            cached_source_chunk: None,
            outstanding_source_read: None,
            cached_quotient: None,
            memory_accounting,
            source_polynomials_finished: false,
        })
    }

    fn collect_direct_aggregate_requirements(
        &self,
        column_ordinal: u32,
        requirements: &mut ExactAggregateTraceColumnRequirementSet,
    ) -> Result<bool, CommonProofProverError> {
        for (source_index, rows) in [
            (0, self.source_layout.aggregate_round_one_left_rows.as_ref()),
            (
                1,
                self.source_layout.aggregate_round_one_right_rows.as_ref(),
            ),
        ] {
            for (row_ordinal, row) in rows.iter().copied().enumerate() {
                if let Some(half_ordinal) = half_position(row, column_ordinal) {
                    requirements.insert(AggregateTraceColumnRequirement {
                        source_index,
                        trace_column_ordinal: row_ordinal
                            .checked_mul(2)
                            .and_then(|value| value.checked_add(half_ordinal))
                            .ok_or(CommonProofProverError::CountOverflow)?,
                    })?;
                    return Ok(true);
                }
            }
        }
        for (row_ordinal, aggregate_layout) in self.source_layout.aggregate_rows.iter().enumerate()
        {
            for (source_index, layout) in
                [(0, &aggregate_layout.left), (1, &aggregate_layout.right)]
            {
                for half_ordinal in 0..2 {
                    if layout.centered.source.coefficients.halves[half_ordinal] == column_ordinal
                        || layout.carry_columns[half_ordinal] == column_ordinal
                    {
                        requirements.insert(AggregateTraceColumnRequirement {
                            source_index,
                            trace_column_ordinal: row_ordinal
                                .checked_mul(2)
                                .and_then(|value| value.checked_add(half_ordinal))
                                .ok_or(CommonProofProverError::CountOverflow)?,
                        })?;
                        return Ok(true);
                    }
                }
            }
        }
        for (row_ordinal, quotient_layout) in self
            .source_layout
            .round_two_quotients_by_row
            .iter()
            .enumerate()
        {
            if quotient_layout
                .low_quotients
                .iter()
                .chain(&quotient_layout.high_carries)
                .any(|candidate| *candidate == column_ordinal)
            {
                for source_index in 0..2 {
                    for half_ordinal in 0..2 {
                        requirements.insert(AggregateTraceColumnRequirement {
                            source_index,
                            trace_column_ordinal: row_ordinal
                                .checked_mul(2)
                                .and_then(|value| value.checked_add(half_ordinal))
                                .ok_or(CommonProofProverError::CountOverflow)?,
                        })?;
                    }
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn collect_aggregate_requirements(
        &self,
        column_ordinal: u32,
        active_columns: &mut ExactKeyRelationActiveColumnSet,
        requirements: &mut ExactAggregateTraceColumnRequirementSet,
    ) -> Result<(), CommonProofProverError> {
        if !active_columns
            .insert(column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if self.collect_direct_aggregate_requirements(column_ordinal, requirements)? {
            active_columns
                .remove(column_ordinal)
                .map_err(|_| CommonProofProverError::InvalidColumn)?;
            return Ok(());
        }
        if let Some(source_column_ordinal) = self
            .source_layout
            .exact_radix_digits_by_column
            .iter()
            .find_map(|(source_column_ordinal, digit_columns)| {
                digit_columns
                    .contains(&column_ordinal)
                    .then_some(*source_column_ordinal)
            })
        {
            self.collect_aggregate_requirements(
                source_column_ordinal,
                active_columns,
                requirements,
            )?;
            active_columns
                .remove(column_ordinal)
                .map_err(|_| CommonProofProverError::InvalidColumn)?;
            return Ok(());
        }
        if let Some(target_column_ordinal) = self
            .relation_plan_variant
            .ordered_semantic_cells
            .iter()
            .find_map(|semantic_cell| {
                let contains_column = match &semantic_cell.bound_certificate {
                    super::RelationBoundCertificate::UnsignedRadixRecomposition {
                        ordered_digit_column_ordinals,
                        ..
                    }
                    | super::RelationBoundCertificate::ShiftedRadixRecomposition {
                        ordered_digit_column_ordinals,
                        ..
                    } => ordered_digit_column_ordinals.contains(&column_ordinal),
                    super::RelationBoundCertificate::CanonicalModulusRecomposition {
                        ordered_digit_column_ordinals,
                        ordered_difference_digit_column_ordinals,
                        ordered_borrow_column_ordinals,
                        ..
                    } => {
                        ordered_digit_column_ordinals.contains(&column_ordinal)
                            || ordered_difference_digit_column_ordinals.contains(&column_ordinal)
                            || ordered_borrow_column_ordinals.contains(&column_ordinal)
                    }
                    _ => false,
                };
                contains_column.then_some(semantic_cell.column_ordinal)
            })
        {
            self.collect_aggregate_requirements(
                target_column_ordinal,
                active_columns,
                requirements,
            )?;
        }
        if let Some(component) = self
            .relation_plan_variant
            .ordered_integer_lift_batches()
            .iter()
            .flat_map(|batch| batch.ordered_components.iter())
            .find(|component| {
                component.ordered_linear_terms.iter().any(|term| {
                    term.negative
                        && term.column_ordinal == column_ordinal
                        && term.column_offset == 0
                        && term.coefficient
                            == super::RelationIntegerLiftCoefficient::Constant(
                                super::key_relation::EXACT_INTEGER_LIFT_RADIX,
                            )
                })
            })
        {
            for dependency in component
                .ordered_linear_terms
                .iter()
                .filter(|term| term.column_ordinal != column_ordinal)
                .map(|term| term.column_ordinal)
                .chain(
                    component
                        .ordered_full_ring_negacyclic_products
                        .iter()
                        .flat_map(|product| {
                            [
                                product.multiplicand_low_column_ordinal,
                                product.multiplicand_high_column_ordinal,
                                product.multiplier_low_column_ordinal,
                                product.multiplier_high_column_ordinal,
                            ]
                        }),
                )
            {
                self.collect_aggregate_requirements(dependency, active_columns, requirements)?;
            }
        }
        active_columns
            .remove(column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        Ok(())
    }

    fn quotient_dependency_row(
        &self,
        column_ordinal: u32,
        active_columns: &mut ExactKeyRelationActiveColumnSet,
    ) -> Result<Option<usize>, CommonProofProverError> {
        if !active_columns
            .insert(column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if let Some(row_ordinal) = self
            .source_layout
            .round_two_quotients_by_row
            .iter()
            .position(|layout| {
                layout
                    .low_quotients
                    .iter()
                    .chain(&layout.high_carries)
                    .any(|candidate| *candidate == column_ordinal)
            })
        {
            active_columns
                .remove(column_ordinal)
                .map_err(|_| CommonProofProverError::InvalidColumn)?;
            return Ok(Some(row_ordinal));
        }
        let dependency = self
            .source_layout
            .exact_radix_digits_by_column
            .iter()
            .find_map(|(source_column_ordinal, digit_columns)| {
                digit_columns
                    .contains(&column_ordinal)
                    .then_some(*source_column_ordinal)
            })
            .or_else(|| {
                self.relation_plan_variant
                    .ordered_semantic_cells
                    .iter()
                    .find_map(|semantic_cell| match &semantic_cell.bound_certificate {
                        super::RelationBoundCertificate::UnsignedRadixRecomposition {
                            ordered_digit_column_ordinals,
                            ..
                        }
                        | super::RelationBoundCertificate::ShiftedRadixRecomposition {
                            ordered_digit_column_ordinals,
                            ..
                        } if ordered_digit_column_ordinals.contains(&column_ordinal) => {
                            Some(semantic_cell.column_ordinal)
                        }
                        super::RelationBoundCertificate::CanonicalModulusRecomposition {
                            ordered_digit_column_ordinals,
                            ordered_difference_digit_column_ordinals,
                            ordered_borrow_column_ordinals,
                            ..
                        } if ordered_digit_column_ordinals.contains(&column_ordinal)
                            || ordered_difference_digit_column_ordinals
                                .contains(&column_ordinal)
                            || ordered_borrow_column_ordinals.contains(&column_ordinal) =>
                        {
                            Some(semantic_cell.column_ordinal)
                        }
                        _ => None,
                    })
            });
        let result = match dependency {
            Some(dependency) => self.quotient_dependency_row(dependency, active_columns)?,
            None => None,
        };
        active_columns
            .remove(column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        Ok(result)
    }

    fn aggregate_row_pair_requirement_array(
        source_index: usize,
        row_ordinal: usize,
    ) -> Result<[AggregateTraceColumnRequirement; 2], CommonProofProverError> {
        let first_trace_column_ordinal = row_ordinal
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let second_trace_column_ordinal = first_trace_column_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok([
            AggregateTraceColumnRequirement {
                source_index,
                trace_column_ordinal: first_trace_column_ordinal,
            },
            AggregateTraceColumnRequirement {
                source_index,
                trace_column_ordinal: second_trace_column_ordinal,
            },
        ])
    }

    fn aggregate_row_pair_requirements(
        source_index: usize,
        row_ordinal: usize,
    ) -> Result<Box<[AggregateTraceColumnRequirement]>, CommonProofProverError> {
        Ok(Box::new(Self::aggregate_row_pair_requirement_array(
            source_index,
            row_ordinal,
        )?))
    }

    fn begin_pending_column(
        &self,
        column_ordinal: u32,
    ) -> Result<PendingRelinearizationRoundTwoColumn, CommonProofProverError> {
        let trace_column_count = self
            .aggregate_topology
            .trace_column_count()
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let relation_column_count = self.relation_plan_variant.ordered_columns().len();
        let mut requirements = ExactAggregateTraceColumnRequirementSet::new(trace_column_count)?;
        let mut active_requirement_columns =
            ExactKeyRelationActiveColumnSet::new(relation_column_count);
        self.collect_aggregate_requirements(
            column_ordinal,
            &mut active_requirement_columns,
            &mut requirements,
        )?;
        drop(active_requirement_columns);
        let logical_requirements = requirements.into_ordered_requirements()?;
        let mut active_quotient_columns =
            ExactKeyRelationActiveColumnSet::new(relation_column_count);
        let quotient_row_ordinal =
            self.quotient_dependency_row(column_ordinal, &mut active_quotient_columns)?;
        drop(active_quotient_columns);
        let quotient_is_cached = quotient_row_ordinal.is_some_and(|row_ordinal| {
            self.cached_quotient.as_ref().map(|cached| cached.key)
                == Some(CachedQuotientKey::RoundTwo { row_ordinal })
        });
        let (load_requirements, quotient_phase): (
            Box<[AggregateTraceColumnRequirement]>,
            PendingRelinearizationRoundTwoQuotientPhase,
        ) = match quotient_row_ordinal {
            Some(_) if quotient_is_cached => (
                Vec::new().into_boxed_slice(),
                PendingRelinearizationRoundTwoQuotientPhase::NotRequired,
            ),
            Some(row_ordinal) => {
                let left_requirements = Self::aggregate_row_pair_requirement_array(0, row_ordinal)?;
                let right_requirements =
                    Self::aggregate_row_pair_requirement_array(1, row_ordinal)?;
                let expected_logical_requirements = [
                    left_requirements[0],
                    left_requirements[1],
                    right_requirements[0],
                    right_requirements[1],
                ];
                if logical_requirements.as_ref() != expected_logical_requirements.as_slice() {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                (
                    Box::new(left_requirements),
                    PendingRelinearizationRoundTwoQuotientPhase::LoadAggregateLeft { row_ordinal },
                )
            }
            None => (
                logical_requirements.clone(),
                PendingRelinearizationRoundTwoQuotientPhase::NotRequired,
            ),
        };
        if load_requirements.len() > 2 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let maximum_request_identity_count =
            self.aggregate_sources
                .iter()
                .try_fold(0_usize, |total, source| {
                    total
                        .checked_add(source.authenticated_chunks.len())
                        .ok_or(CommonProofProverError::CountOverflow)
                })?;
        Ok(PendingRelinearizationRoundTwoColumn {
            column_ordinal,
            logical_requirements,
            load_requirements,
            next_load_requirement_index: 0,
            current_trace_column: None,
            loaded_trace_columns: ExactLoadedAggregateTraceColumnCatalog::new(2),
            ordered_request_identities: ExactAggregateSourceRequestIdentityCatalog::new(
                maximum_request_identity_count,
            ),
            quotient_phase,
        })
    }

    fn resolved_round_two_row(&self, row_ordinal: usize) -> Result<(u64, usize), RefusalReason> {
        let extended_limb_count = self
            .geometry
            .data_moduli
            .len()
            .checked_add(self.geometry.special_moduli.len())
            .filter(|count| *count > 0)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let extended_limb_ordinal = row_ordinal % extended_limb_count;
        let decomposition_block_index = row_ordinal / extended_limb_count;
        if decomposition_block_index >= self.aggregate_topology.data_block_count() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let modulus_reference = if extended_limb_ordinal < self.geometry.data_moduli.len() {
            SuiteModulusReference::data(
                u16::try_from(extended_limb_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
        } else {
            SuiteModulusReference::special(
                u16::try_from(extended_limb_ordinal - self.geometry.data_moduli.len())
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
        };
        let modulus = self
            .relation_context
            .resolved_modulus(modulus_reference)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        if self
            .aggregate_topology
            .ordered_moduli()
            .get(extended_limb_ordinal)
            .copied()
            != Some(modulus)
        {
            return Err(RefusalReason::WrongContext);
        }
        Ok((modulus, decomposition_block_index))
    }

    fn derive_secret_times_aggregate_left(
        &self,
        row_ordinal: usize,
        loaded_trace_columns: &ExactLoadedAggregateTraceColumnCatalog,
    ) -> Result<Zeroizing<Vec<i128>>, CommonProofProverError> {
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(self.authority_identifier);
        let application = SetupGenerationRelinearizationRoundTwoApplication::from_decoded_statement(
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.participant_identity,
            self.roster_position,
            self.schedule_position,
            self.anchor_commitment_roots,
            self.round_one_root_pair,
            self.aggregate_round_one_root_pair,
            self.contribution_root,
        );
        let (modulus, _) = self
            .resolved_round_two_row(row_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let aggregate_topology = &self.aggregate_topology;
        with_setup_generation_relinearization_round_two_witness::<_, RefusalReason>(
            &authority_handle,
            &application,
            |source| {
                let aggregate_left = LoadedRelinearizationRoundTwoAggregateColumns {
                    topology: aggregate_topology,
                    columns: loaded_trace_columns,
                }
                .centered_full_row(0, row_ordinal, modulus)?;
                let common_secret = Zeroizing::new(
                    source
                        .common_secret_coefficients()
                        .iter()
                        .copied()
                        .map(i128::from)
                        .collect::<Vec<_>>(),
                );
                exact_negacyclic_product_radix(&common_secret, &aggregate_left)
            },
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)
    }

    fn finish_streamed_round_two_quotient(
        &self,
        row_ordinal: usize,
        mut secret_times_aggregate_left: Zeroizing<Vec<i128>>,
        loaded_trace_columns: &ExactLoadedAggregateTraceColumnCatalog,
    ) -> Result<Zeroizing<Vec<i128>>, CommonProofProverError> {
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(self.authority_identifier);
        let application = SetupGenerationRelinearizationRoundTwoApplication::from_decoded_statement(
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.participant_identity,
            self.roster_position,
            self.schedule_position,
            self.anchor_commitment_roots,
            self.round_one_root_pair,
            self.aggregate_round_one_root_pair,
            self.contribution_root,
        );
        let (modulus, decomposition_block_index) = self
            .resolved_round_two_row(row_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let aggregate_topology = &self.aggregate_topology;
        with_setup_generation_relinearization_round_two_witness::<_, RefusalReason>(
            &authority_handle,
            &application,
            |source| {
                if secret_times_aggregate_left.len() != aggregate_topology.polynomial_degree() {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                let aggregate_right = LoadedRelinearizationRoundTwoAggregateColumns {
                    topology: aggregate_topology,
                    columns: loaded_trace_columns,
                }
                .centered_full_row(1, row_ordinal, modulus)?;
                let ephemeral_secret = Zeroizing::new(
                    source
                        .ephemeral_secret_coefficients()
                        .iter()
                        .copied()
                        .map(i128::from)
                        .collect::<Vec<_>>(),
                );
                let ephemeral_times_aggregate_right =
                    exact_negacyclic_product_radix(&ephemeral_secret, &aggregate_right)?;
                for (partial_numerator, ephemeral_product) in secret_times_aggregate_left
                    .iter_mut()
                    .zip(ephemeral_times_aggregate_right.iter().copied())
                {
                    *partial_numerator = partial_numerator
                        .checked_neg()
                        .and_then(|value| value.checked_sub(ephemeral_product))
                        .ok_or(RefusalReason::InvalidArithmeticRelation)?;
                }
                drop(ephemeral_times_aggregate_right);
                drop(ephemeral_secret);

                let common_secret = Zeroizing::new(
                    source
                        .common_secret_coefficients()
                        .iter()
                        .copied()
                        .map(i128::from)
                        .collect::<Vec<_>>(),
                );
                let secret_times_aggregate_right =
                    exact_negacyclic_product_radix(&common_secret, &aggregate_right)?;
                for (partial_numerator, secret_product) in secret_times_aggregate_left
                    .iter_mut()
                    .zip(secret_times_aggregate_right.iter().copied())
                {
                    *partial_numerator = partial_numerator
                        .checked_add(secret_product)
                        .ok_or(RefusalReason::InvalidArithmeticRelation)?;
                }
                drop(secret_times_aggregate_right);
                drop(common_secret);
                drop(aggregate_right);

                let bound = decode_component_full_row(source.round_two_component(), row_ordinal)?;
                let error = source
                    .round_two_errors_by_block()
                    .get(decomposition_block_index)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                exact_modular_quotient(
                    bound
                        .iter()
                        .copied()
                        .zip(secret_times_aggregate_left.iter().copied())
                        .zip(error.iter().copied()),
                    modulus,
                    |((bound, partial_numerator), error)| {
                        bound.checked_add(partial_numerator).and_then(|value| {
                            value.checked_sub(i128::from(PLAINTEXT_MODULUS) * i128::from(error))
                        })
                    },
                )
            },
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)
    }

    fn advance_pending_round_two_quotient(&mut self) -> Result<bool, CommonProofProverError> {
        if !self.requirements_are_loaded() {
            return Ok(false);
        }
        let mut pending = self
            .pending_column
            .take()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        match core::mem::replace(
            &mut pending.quotient_phase,
            PendingRelinearizationRoundTwoQuotientPhase::NotRequired,
        ) {
            PendingRelinearizationRoundTwoQuotientPhase::NotRequired => {
                self.pending_column = Some(pending);
                Ok(false)
            }
            PendingRelinearizationRoundTwoQuotientPhase::LoadAggregateLeft { row_ordinal } => {
                let secret_times_aggregate_left = self.derive_secret_times_aggregate_left(
                    row_ordinal,
                    &pending.loaded_trace_columns,
                )?;
                pending.loaded_trace_columns.clear();
                pending.load_requirements = Self::aggregate_row_pair_requirements(1, row_ordinal)?;
                pending.next_load_requirement_index = 0;
                pending.quotient_phase =
                    PendingRelinearizationRoundTwoQuotientPhase::LoadAggregateRight {
                        row_ordinal,
                        secret_times_aggregate_left,
                    };
                self.pending_column = Some(pending);
                Ok(true)
            }
            PendingRelinearizationRoundTwoQuotientPhase::LoadAggregateRight {
                row_ordinal,
                secret_times_aggregate_left,
            } => {
                let quotient = self.finish_streamed_round_two_quotient(
                    row_ordinal,
                    secret_times_aggregate_left,
                    &pending.loaded_trace_columns,
                )?;
                pending.loaded_trace_columns.clear();
                pending.load_requirements = Vec::new().into_boxed_slice();
                pending.next_load_requirement_index = 0;
                self.cached_quotient = Some(CachedQuotient {
                    key: CachedQuotientKey::RoundTwo { row_ordinal },
                    coefficients: quotient,
                });
                self.pending_column = Some(pending);
                Ok(true)
            }
        }
    }

    fn ensure_current_trace_column(&mut self) -> Result<(), CommonProofProverError> {
        let pending = self
            .pending_column
            .as_mut()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if pending.current_trace_column.is_some()
            || pending.next_load_requirement_index >= pending.load_requirements.len()
        {
            return Ok(());
        }
        let requirement = pending.load_requirements[pending.next_load_requirement_index];
        let trace_column = self
            .aggregate_topology
            .trace_column(requirement.trace_column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let byte_length = usize::try_from(trace_column.byte_length())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        pending.current_trace_column = Some(PendingAggregateTraceColumn {
            requirement,
            trace_column,
            bytes: Zeroizing::new(vec![0_u8; byte_length].into_boxed_slice()),
            filled_byte_length: 0,
        });
        Ok(())
    }

    fn absorb_cached_source_chunk(&mut self) -> Result<(), CommonProofProverError> {
        let Some(cached) = self.cached_source_chunk.as_ref() else {
            return Ok(());
        };
        let Some(pending_trace) = self
            .pending_column
            .as_mut()
            .and_then(|pending| pending.current_trace_column.as_mut())
        else {
            return Ok(());
        };
        if cached.source_index != pending_trace.requirement.source_index {
            return Ok(());
        }
        let next_trace_byte_offset = pending_trace
            .trace_column
            .byte_offset()
            .checked_add(
                u64::try_from(pending_trace.filled_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let cached_end = cached
            .stream_byte_offset
            .checked_add(
                u64::try_from(cached.bytes.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if next_trace_byte_offset < cached.stream_byte_offset
            || next_trace_byte_offset >= cached_end
        {
            return Ok(());
        }
        let trace_end = pending_trace
            .trace_column
            .byte_offset()
            .checked_add(pending_trace.trace_column.byte_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        let copy_end = trace_end.min(cached_end);
        let cached_start = usize::try_from(next_trace_byte_offset - cached.stream_byte_offset)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let cached_copy_end = usize::try_from(copy_end - cached.stream_byte_offset)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let copied_byte_length = cached_copy_end
            .checked_sub(cached_start)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let pending_end = pending_trace
            .filled_byte_length
            .checked_add(copied_byte_length)
            .filter(|end| *end <= pending_trace.bytes.len())
            .ok_or(CommonProofProverError::CountOverflow)?;
        pending_trace.bytes[pending_trace.filled_byte_length..pending_end]
            .copy_from_slice(&cached.bytes[cached_start..cached_copy_end]);
        pending_trace.filled_byte_length = pending_end;
        Ok(())
    }

    fn finish_loaded_trace_column(&mut self) -> Result<bool, CommonProofProverError> {
        let pending = self
            .pending_column
            .as_mut()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let is_complete = pending
            .current_trace_column
            .as_ref()
            .is_some_and(|current| {
                u64::try_from(current.filled_byte_length).ok()
                    == Some(current.trace_column.byte_length())
            });
        if !is_complete {
            return Ok(false);
        }
        let current = pending
            .current_trace_column
            .take()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        pending
            .loaded_trace_columns
            .push(LoadedAggregateTraceColumn {
                requirement: current.requirement,
                bytes: current.bytes,
            })?;
        pending.next_load_requirement_index = pending
            .next_load_requirement_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(true)
    }

    fn requirements_are_loaded(&self) -> bool {
        self.pending_column.as_ref().is_some_and(|pending| {
            pending.current_trace_column.is_none()
                && pending.next_load_requirement_index == pending.load_requirements.len()
        })
    }

    fn make_source_read_request(
        &self,
        engine_request: CommonProofSourcePolynomialRequest<'_>,
        source_index: usize,
        chunk_index: usize,
    ) -> Result<CommonProofAuthenticatedSourceReadRequest, CommonProofProverError> {
        let source = self
            .aggregate_sources
            .get(source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let stream_byte_offset = u64::try_from(chunk_index)
            .ok()
            .and_then(|index| index.checked_mul(chunk_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let source_byte_length = source
            .stream_total_byte_length
            .checked_sub(stream_byte_offset)
            .map(|remaining| remaining.min(chunk_byte_length))
            .and_then(|length| u32::try_from(length).ok())
            .filter(|length| *length > 0)
            .ok_or(CommonProofProverError::CountOverflow)?;
        CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
            engine_request,
            self.source_catalog_binding,
            source.descriptor_binding,
            source.material_root,
            source.stream_digest,
            source.stream_total_byte_length,
            stream_byte_offset,
            stream_byte_offset,
            source_byte_length,
            u32::try_from(chunk_index).map_err(|_| CommonProofProverError::CountOverflow)?,
        )
    }

    fn next_trace_source_read(
        &self,
        engine_request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<OutstandingAggregateSourceRead, CommonProofProverError> {
        let current = self
            .pending_column
            .as_ref()
            .and_then(|pending| pending.current_trace_column.as_ref())
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let next_byte_offset = current
            .trace_column
            .byte_offset()
            .checked_add(
                u64::try_from(current.filled_byte_length)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let chunk_index = usize::try_from(next_byte_offset / chunk_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        Ok(OutstandingAggregateSourceRead {
            request: self.make_source_read_request(
                engine_request,
                current.requirement.source_index,
                chunk_index,
            )?,
            source_index: current.requirement.source_index,
            purpose: AggregateSourceReadPurpose::TraceColumn,
        })
    }

    fn next_final_coverage_source_read(
        &self,
        engine_request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<Option<OutstandingAggregateSourceRead>, CommonProofProverError> {
        for (source_index, source) in self.aggregate_sources.iter().enumerate() {
            if let Some(chunk_index) = source
                .authenticated_chunks
                .iter()
                .position(|authenticated| !authenticated)
            {
                return Ok(Some(OutstandingAggregateSourceRead {
                    request: self.make_source_read_request(
                        engine_request,
                        source_index,
                        chunk_index,
                    )?,
                    source_index,
                    purpose: AggregateSourceReadPurpose::FinalCoverage,
                }));
            }
        }
        Ok(None)
    }

    fn replay_identity(
        &self,
        pending: &PendingRelinearizationRoundTwoColumn,
    ) -> Result<CommonProofSourcePolynomialReplayIdentity, CommonProofProverError> {
        const FIXED_PART_COUNT: u64 = 26;
        let part_count = u64::try_from(pending.logical_requirements.len())
            .ok()
            .and_then(|count| count.checked_add(FIXED_PART_COUNT))
            .and_then(|count| {
                count.checked_add(u64::try_from(pending.ordered_request_identities.len()).ok()?)
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
        let mut hasher = StreamingHash512::new(
            RELINEARIZATION_ROUND_TWO_SOURCE_REPLAY_IDENTITY_DOMAIN,
            part_count,
        );
        hasher.absorb_part(&self.request_context.stable_generation_binding_hash());
        hasher.absorb_part(&pending.column_ordinal.to_le_bytes());
        hasher.absorb_part(&self.setup_attempt_identifier);
        hasher.absorb_part(&self.source_setup_intent_object_hash);
        hasher.absorb_part(&self.action_randomness_authorization_hash);
        hasher.absorb_part(&self.setup_proof_context_hash);
        hasher.absorb_part(&self.roster_hash);
        hasher.absorb_part(&self.participant_identity);
        hasher.absorb_part(&self.roster_position.to_le_bytes());
        hasher.absorb_part(&self.schedule_position.to_le_bytes());
        hasher.absorb_part(&self.source_catalog_binding);
        hasher.absorb_part(&self.aggregate_topology.expected_byte_length().to_le_bytes());
        hasher.absorb_part(
            &u64::try_from(self.aggregate_topology.polynomial_degree())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .to_le_bytes(),
        );
        hasher.absorb_part(
            &u64::try_from(
                self.aggregate_topology
                    .trace_column_count()
                    .map_err(|_| CommonProofProverError::InvalidColumn)?,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .to_le_bytes(),
        );
        hasher.absorb_part(
            &u64::try_from(pending.logical_requirements.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .to_le_bytes(),
        );
        hasher.absorb_part(
            &u64::try_from(pending.ordered_request_identities.len())
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .to_le_bytes(),
        );
        for source in &self.aggregate_sources {
            hasher.absorb_part(&source.descriptor_binding);
            hasher.absorb_part(&source.material_root);
            hasher.absorb_part(&source.stream_digest);
            hasher.absorb_part(&source.stream_total_byte_length.to_le_bytes());
            hasher.absorb_part(
                &u64::try_from(source.authenticated_chunks.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .to_le_bytes(),
            );
        }
        for requirement in pending.logical_requirements.iter().copied() {
            let mut encoded_requirement = [0_u8; 16];
            encoded_requirement[..8].copy_from_slice(
                &u64::try_from(requirement.source_index)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .to_le_bytes(),
            );
            encoded_requirement[8..].copy_from_slice(
                &u64::try_from(requirement.trace_column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
                    .to_le_bytes(),
            );
            hasher.absorb_part(&encoded_requirement);
        }
        for request_identity in pending.ordered_request_identities.as_slice() {
            hasher.absorb_part(request_identity);
        }
        CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(hasher.finalize())
    }

    fn derive_source_polynomial(
        &mut self,
        column_ordinal: u32,
        loaded_aggregate_trace_columns: &ExactLoadedAggregateTraceColumnCatalog,
    ) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let authority_handle =
            SetupGenerationAuthorityHandle::from_identifier(self.authority_identifier);
        let application = SetupGenerationRelinearizationRoundTwoApplication::from_decoded_statement(
            self.prepared_attempt,
            &self.canonical_application_statement_bytes,
            self.setup_proof_context_hash,
            self.participant_identity,
            self.roster_position,
            self.schedule_position,
            self.anchor_commitment_roots,
            self.round_one_root_pair,
            self.aggregate_round_one_root_pair,
            self.contribution_root,
        );
        let relation_plan_variant = &self.relation_plan_variant;
        let relation_context = &self.relation_context;
        let geometry = &self.geometry;
        let source_layout = &self.source_layout;
        let aggregate_topology = &self.aggregate_topology;
        let cached_quotient = &mut self.cached_quotient;
        let mut field_values = with_setup_generation_relinearization_round_two_witness::<
            _,
            RefusalReason,
        >(&authority_handle, &application, |source| {
            let common = RelinearizationRoundOneColumnDerivation {
                source: &source,
                relation_plan_variant,
                relation_context,
                geometry,
                source_layout: RelinearizationRoundOneSourceLayoutView::from_round_two(
                    source_layout,
                ),
                cached_rows: ExactKeyRelationDerivedRowCache::new(
                    relation_plan_variant.ordered_columns().len(),
                ),
                active_columns: ExactKeyRelationActiveColumnSet::new(
                    relation_plan_variant.ordered_columns().len(),
                ),
                cached_quotient,
            };
            let mut derivation = RelinearizationRoundTwoColumnDerivation {
                source: &source,
                common,
                source_layout,
                aggregate_columns: LoadedRelinearizationRoundTwoAggregateColumns {
                    topology: aggregate_topology,
                    columns: loaded_aggregate_trace_columns,
                },
            };
            let signed_rows = derivation.derive_rows(column_ordinal)?;
            signed_rows
                .iter()
                .copied()
                .map(signed_integer_to_base_field)
                .collect::<Result<Vec<_>, _>>()
                .map(Zeroizing::new)
        })
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let descriptor = self
            .relation_plan_variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let _ = descriptor;
        ProofEvaluationDomain::new_subgroup(
            usize::try_from(self.relation_plan_variant.trace_domain_size())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?
        .interpolate_base_polynomial_in_place(&mut field_values)?;
        Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(field_values))
    }
}

impl CommonProofSourcePolynomialProvider for RelinearizationRoundTwoSourcePolynomialAdapter {
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
        if self.source_polynomials_finished
            || request.request_context() != self.request_context
            || self
                .requested_column_ordinals
                .get(self.next_source_index)
                .copied()
                != Some(request.column_ordinal())
            || self.relation_plan_variant.ordered_columns().get(
                usize::try_from(request.column_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            ) != Some(request.descriptor())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        if let Some(outstanding) = self.outstanding_source_read.as_ref() {
            return Ok(
                CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(
                    outstanding.request,
                ),
            );
        }
        let column_ordinal = request.column_ordinal();
        if self.pending_column.is_none() {
            self.pending_column = Some(self.begin_pending_column(column_ordinal)?);
        } else if self
            .pending_column
            .as_ref()
            .is_none_or(|pending| pending.column_ordinal != column_ordinal)
        {
            return Err(CommonProofProverError::InvalidColumn);
        }

        loop {
            self.ensure_current_trace_column()?;
            self.absorb_cached_source_chunk()?;
            if self.finish_loaded_trace_column()? {
                continue;
            }
            if self.requirements_are_loaded() {
                match self.advance_pending_round_two_quotient() {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => {
                        self.pending_column = None;
                        self.cached_source_chunk = None;
                        self.cached_quotient = None;
                        self.source_polynomials_finished = true;
                        return Err(error);
                    }
                }
                let is_final_source_column = self
                    .next_source_index
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?
                    == self.requested_column_ordinals.len();
                if is_final_source_column {
                    if let Some(outstanding) = self.next_final_coverage_source_read(request)? {
                        let authenticated_source_request = outstanding.request;
                        self.cached_source_chunk = None;
                        self.outstanding_source_read = Some(outstanding);
                        return Ok(
                            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(
                                authenticated_source_request,
                            ),
                        );
                    }
                }
                let pending = self
                    .pending_column
                    .take()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let replay_identity = self.replay_identity(&pending)?;
                let polynomial = match self
                    .derive_source_polynomial(column_ordinal, &pending.loaded_trace_columns)
                {
                    Ok(polynomial) => polynomial,
                    Err(error) => {
                        self.cached_source_chunk = None;
                        self.cached_quotient = None;
                        self.source_polynomials_finished = true;
                        return Err(error);
                    }
                };
                self.next_source_index = self
                    .next_source_index
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                return Ok(CommonProofSourcePolynomialProviderPoll::Ready(
                    ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
                ));
            }
            let outstanding = self.next_trace_source_read(request)?;
            let authenticated_source_request = outstanding.request;
            // The retained chunk has contributed every byte it can to this
            // trace range. Drop it before the host allocates the next chunk.
            self.cached_source_chunk = None;
            self.outstanding_source_read = Some(outstanding);
            return Ok(
                CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired(
                    authenticated_source_request,
                ),
            );
        }
    }

    fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        let Some(outstanding) = self.outstanding_source_read.take() else {
            return Err(CommonProofProverError::InvalidColumn);
        };
        if self.source_polynomials_finished
            || outstanding.request != request
            || authenticated_bytes.len()
                != usize::try_from(request.source_byte_length())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            self.pending_column = None;
            self.cached_source_chunk = None;
            self.cached_quotient = None;
            self.source_polynomials_finished = true;
            return Err(CommonProofProverError::InvalidColumn);
        }
        let chunk_index = usize::try_from(request.authentication_chunk_index())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let source = self
            .aggregate_sources
            .get_mut(outstanding.source_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if source
            .readback
            .as_mut()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .authenticate_chunk(chunk_index, &authenticated_bytes)
            .is_err()
        {
            self.pending_column = None;
            self.cached_source_chunk = None;
            self.cached_quotient = None;
            self.source_polynomials_finished = true;
            return Err(CommonProofProverError::InvalidColumn);
        }
        *source
            .authenticated_chunks
            .get_mut(chunk_index)
            .ok_or(CommonProofProverError::InvalidColumn)? = true;
        self.pending_column
            .as_mut()
            .ok_or(CommonProofProverError::InvalidColumn)?
            .ordered_request_identities
            .push(request.request_identity())?;
        match outstanding.purpose {
            AggregateSourceReadPurpose::TraceColumn => {
                self.cached_source_chunk = Some(CachedAggregateSourceChunk {
                    source_index: outstanding.source_index,
                    stream_byte_offset: request.source_stream_byte_offset(),
                    bytes: authenticated_bytes,
                });
            }
            AggregateSourceReadPurpose::FinalCoverage => {
                self.cached_source_chunk = None;
            }
        }
        Ok(())
    }

    fn cancel_pending_authenticated_source_read(&mut self) {
        self.pending_column = None;
        self.cached_source_chunk = None;
        self.outstanding_source_read = None;
        self.cached_quotient = None;
        self.source_polynomials_finished = true;
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        if self.source_polynomials_finished
            || self.pending_column.is_some()
            || self.outstanding_source_read.is_some()
            || self.next_source_index != self.requested_column_ordinals.len()
            || self.aggregate_sources.iter().any(|source| {
                source
                    .authenticated_chunks
                    .iter()
                    .any(|authenticated| !authenticated)
            })
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.cached_source_chunk = None;
        self.cached_quotient = None;
        for source in &mut self.aggregate_sources {
            source
                .readback
                .take()
                .ok_or(CommonProofProverError::InvalidColumn)?
                .finish()
                .into_result()
                .map_err(|_| CommonProofProverError::InvalidColumn)?;
            source.authenticated_chunks = Vec::new().into_boxed_slice();
        }
        self.source_polynomials_finished = true;
        Ok(())
    }

    fn finish_bound_tree_leaf_salts(&mut self) -> Result<(), CommonProofProverError> {
        if !self.source_polynomials_finished {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(())
    }
}

pub(crate) fn relinearization_round_two_relation_tree_inputs(
    source: &SetupGenerationRelinearizationRoundTwoSource<'_, '_>,
    relation_plan_variant: &RelationPlanVariant,
    source_layout: &RelinearizationRoundTwoSourceLayout,
) -> Result<Vec<RelationProofTreeInput>, CommonProofProverError> {
    let round_one_source = source
        .generated_round_one_source_authority()
        .map_err(|_| CommonProofProverError::InvalidTree)?;
    let round_one_components = round_one_source.components();
    let round_two_component = source.generated_source_authority().component();
    let aggregate_contexts = [
        SetupPublicPolynomialContext::new(
            source.setup_proof_context_hash(),
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneLeft,
            None,
            None,
            Some(source.schedule_position()),
            None,
        )
        .and_then(|context| context.context_hash())
        .map_err(|_| CommonProofProverError::InvalidTree)?,
        SetupPublicPolynomialContext::new(
            source.setup_proof_context_hash(),
            SetupPublicPolynomialRootRole::RelinearizationAggregateRoundOneRight,
            None,
            None,
            Some(source.schedule_position()),
            None,
        )
        .and_then(|context| context.context_hash())
        .map_err(|_| CommonProofProverError::InvalidTree)?,
    ];
    let aggregate_roots = source
        .generated_source_authority()
        .aggregate_round_one_root_pair();
    let mut relation_trees = Vec::with_capacity(relation_plan_variant.ordered_trees().len());
    for tree in relation_plan_variant.ordered_trees() {
        match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let tree_role = match *proof_tree_role {
                    value if value == ProofTreeRole::BaseOracle as u16 => ProofTreeRole::BaseOracle,
                    value if value == ProofTreeRole::AuxiliaryOracle as u16 => {
                        ProofTreeRole::AuxiliaryOracle
                    }
                    _ => return Err(CommonProofProverError::InvalidTree),
                };
                let leaf_visibility = ordered_column_ordinals.iter().try_fold(
                    ProofLeafVisibility::Public,
                    |visibility, column_ordinal| {
                        let column = relation_plan_variant
                            .ordered_columns()
                            .get(
                                usize::try_from(*column_ordinal)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::InvalidColumn)?;
                        Ok::<_, CommonProofProverError>(
                            if matches!(column.origin(), RelationColumnOrigin::Prover) {
                                ProofLeafVisibility::SecretBearing
                            } else {
                                visibility
                            },
                        )
                    },
                )?;
                relation_trees.push(RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    leaf_visibility,
                });
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } => {
                let row_width = u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                let source_binding = if split_rows_match(
                    &source_layout.round_one_left_rows,
                    ordered_column_ordinals,
                ) {
                    round_one_components.first().map(|component| {
                        (
                            component.public_polynomial_context_hash(),
                            component.contribution_root(),
                        )
                    })
                } else if split_rows_match(
                    &source_layout.round_one_right_rows,
                    ordered_column_ordinals,
                ) {
                    round_one_components.get(1).map(|component| {
                        (
                            component.public_polynomial_context_hash(),
                            component.contribution_root(),
                        )
                    })
                } else if split_rows_match(
                    &source_layout.aggregate_round_one_left_rows,
                    ordered_column_ordinals,
                ) {
                    Some((aggregate_contexts[0], aggregate_roots[0]))
                } else if split_rows_match(
                    &source_layout.aggregate_round_one_right_rows,
                    ordered_column_ordinals,
                ) {
                    Some((aggregate_contexts[1], aggregate_roots[1]))
                } else if split_rows_match(&source_layout.round_two_rows, ordered_column_ordinals) {
                    Some((
                        round_two_component.public_polynomial_context_hash(),
                        round_two_component.contribution_root(),
                    ))
                } else {
                    None
                };
                if let Some((public_polynomial_context_hash, expected_root)) = source_binding {
                    relation_trees.push(RelationProofTreeInput::BoundPublic(
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash,
                            row_width,
                            expected_root,
                        },
                    ));
                } else if let Some(anchor_ordinal) =
                    source_layout.ordered_anchors.iter().position(|anchor| {
                        split_rows_match(&anchor.commitments, ordered_column_ordinals)
                    })
                {
                    let anchor = source
                        .anchor_openings()
                        .get(anchor_ordinal)
                        .ok_or(CommonProofProverError::InvalidTree)?;
                    relation_trees.push(RelationProofTreeInput::BoundPublic(
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: anchor.public_polynomial_context_hash(),
                            row_width,
                            expected_root: anchor.root(),
                        },
                    ));
                } else {
                    return Err(CommonProofProverError::InvalidTree);
                }
            }
            RelationTreeDescriptor::BoundPublic { .. } => {
                return Err(CommonProofProverError::InvalidTree);
            }
        }
    }
    Ok(relation_trees)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_memory_dimensions() -> RelinearizationRoundTwoSourceProviderMemoryDimensions {
        RelinearizationRoundTwoSourceProviderMemoryDimensions {
            retained_catalog_heap_byte_length: 4_096,
            total_authenticated_source_chunk_count: 8,
            maximum_trace_half_byte_length: 128,
            maximum_trace_pair_byte_length: 256,
            maximum_trace_pair_chunk_count: 2,
            maximum_recursive_cached_row_count: 3,
            maximum_relation_column_derivation_workspace_byte_length: 2_048,
            maximum_recursive_cache_and_relation_workspace_byte_length: 2_240,
            relation_column_count: 11,
            trace_column_count_per_source: 16,
            ring_degree: 8,
            trace_domain_size: 4,
        }
    }

    #[test]
    fn quotient_loader_retains_one_component_trace_half_pair_per_phase() {
        let row_ordinal = 7;
        let left_requirements =
            RelinearizationRoundTwoSourcePolynomialAdapter::aggregate_row_pair_requirements(
                0,
                row_ordinal,
            )
            .expect("left aggregate row pair");
        let right_requirements =
            RelinearizationRoundTwoSourcePolynomialAdapter::aggregate_row_pair_requirements(
                1,
                row_ordinal,
            )
            .expect("right aggregate row pair");

        assert_eq!(left_requirements.len(), 2);
        assert_eq!(right_requirements.len(), 2);
        assert!(
            left_requirements
                .iter()
                .all(|requirement| requirement.source_index == 0)
        );
        assert!(
            right_requirements
                .iter()
                .all(|requirement| requirement.source_index == 1)
        );
        assert_eq!(left_requirements[0].trace_column_ordinal, row_ordinal * 2);
        assert_eq!(
            left_requirements[1].trace_column_ordinal,
            row_ordinal * 2 + 1
        );
        assert_eq!(right_requirements[0].trace_column_ordinal, row_ordinal * 2);
        assert_eq!(
            right_requirements[1].trace_column_ordinal,
            row_ordinal * 2 + 1
        );
    }

    #[test]
    fn provider_derivation_and_pending_catalogs_use_exact_topology_sized_storage() {
        let derived_rows = ExactKeyRelationDerivedRowCache::new(11);
        let active_columns = ExactKeyRelationActiveColumnSet::new(11);
        let loaded_columns = ExactLoadedAggregateTraceColumnCatalog::new(2);
        let mut request_identities = ExactAggregateSourceRequestIdentityCatalog::new(8);
        let radix_digits = [(7_u32, vec![8_u32, 9].into_boxed_slice())]
            .into_iter()
            .collect::<super::super::key_relation::ExactRadixDigitColumnCatalog>();
        request_identities
            .push([1_u8; Hash512::BYTE_LENGTH])
            .expect("first request identity");
        request_identities
            .push([2_u8; Hash512::BYTE_LENGTH])
            .expect("second request identity");

        assert_eq!(derived_rows.descriptor_slot_count(), 11);
        assert_eq!(active_columns.flag_count(), 11);
        assert_eq!(loaded_columns.descriptor_slot_count(), 2);
        assert_eq!(request_identities.allocated_identity_slot_count(), 8);
        assert_eq!(request_identities.len(), 2);
        assert_eq!(radix_digits.len(), 1);
        assert_eq!(
            radix_digits.values().next().map(Box::as_ref),
            Some([8_u32, 9].as_slice())
        );
        assert_eq!(
            request_identities.as_slice()[1],
            [2_u8; Hash512::BYTE_LENGTH]
        );
    }

    #[test]
    fn provider_accounting_charges_one_raw_pair_and_exact_product_cache_overlap() {
        let accounting = finish_relinearization_round_two_source_provider_memory_accounting(
            valid_memory_dimensions(),
        )
        .expect("valid provider accounting");

        assert_eq!(
            accounting.maximum_loaded_aggregate_trace_pair_byte_length(),
            256
        );
        assert!(
            accounting.maximum_loaded_aggregate_trace_pair_byte_length()
                < valid_memory_dimensions().maximum_trace_half_byte_length * 4
        );
        assert_eq!(
            accounting.first_aggregate_product_byte_length(),
            accounting.cached_quotient_byte_length()
        );
        assert_eq!(
            accounting.maximum_quotient_phase_populated_request_identity_byte_length(),
            valid_memory_dimensions().maximum_trace_pair_chunk_count
                * 2
                * u64::try_from(size_of::<[u8; Hash512::BYTE_LENGTH]>())
                    .expect("request identity size")
        );
        assert!(
            accounting.additional_loading_source_polynomials_transient_byte_length()
                >= accounting.first_aggregate_product_byte_length()
                    + accounting.maximum_loaded_aggregate_trace_pair_byte_length()
                    + accounting.maximum_cached_authenticated_chunk_byte_length()
                    + accounting.maximum_round_two_quotient_arithmetic_transient_byte_length()
        );
    }

    #[test]
    fn provider_accounting_separates_loading_and_post_finish_lifetimes() {
        let accounting = finish_relinearization_round_two_source_provider_memory_accounting(
            valid_memory_dimensions(),
        )
        .expect("valid provider accounting");

        assert_eq!(
            accounting.post_source_polynomial_finish_persistent_resident_byte_length(),
            accounting.provider_fixed_owner_byte_length()
                + accounting.retained_catalog_heap_byte_length()
        );
        assert_eq!(
            accounting.loading_persistent_resident_byte_length(),
            accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                + accounting.readback_chunk_digest_byte_length()
                + accounting.readback_authentication_flag_byte_length()
                + accounting.cached_quotient_byte_length()
        );
        assert!(
            accounting.loading_persistent_resident_byte_length()
                > accounting.post_source_polynomial_finish_persistent_resident_byte_length()
        );
        assert!(accounting.maximum_pending_catalog_byte_length() > 0);
        assert!(accounting.maximum_recursive_cached_row_payload_byte_length() > 0);
        assert_eq!(
            accounting.maximum_recursive_cached_row_catalog_byte_length(),
            valid_memory_dimensions().relation_column_count
                * u64::try_from(size_of::<Option<Zeroizing<Box<[i128]>>>>())
                    .expect("derived row descriptor size")
        );
        assert_eq!(
            accounting.relation_derivation_active_column_flag_byte_length(),
            valid_memory_dimensions().relation_column_count
                * u64::try_from(size_of::<bool>()).expect("active flag size")
        );
        let requirement_flag_byte_length = valid_memory_dimensions().trace_column_count_per_source
            * 2
            * u64::try_from(size_of::<bool>()).expect("requirement flag size");
        let logical_requirement_catalog_byte_length =
            4 * u64::try_from(size_of::<AggregateTraceColumnRequirement>())
                .expect("logical requirement size");
        assert_eq!(
            accounting.maximum_requirement_discovery_transient_byte_length(),
            (requirement_flag_byte_length
                + accounting.relation_derivation_active_column_flag_byte_length())
            .max(requirement_flag_byte_length + logical_requirement_catalog_byte_length)
            .max(
                logical_requirement_catalog_byte_length
                    + accounting.relation_derivation_active_column_flag_byte_length()
            )
        );
        assert_eq!(
            accounting.maximum_relation_column_derivation_workspace_byte_length(),
            valid_memory_dimensions().maximum_relation_column_derivation_workspace_byte_length
        );
        assert_eq!(
            accounting.maximum_recursive_cache_and_relation_workspace_byte_length(),
            valid_memory_dimensions().maximum_recursive_cache_and_relation_workspace_byte_length
        );
        assert!(accounting.maximum_returned_source_polynomial_byte_length() > 0);
    }

    #[test]
    fn provider_accounting_rejects_zero_and_overflowing_dimensions() {
        let mut zero_ring_degree = valid_memory_dimensions();
        zero_ring_degree.ring_degree = 0;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(zero_ring_degree),
            Err(CommonProofProverError::InvalidColumn)
        ));

        let mut zero_chunk_count = valid_memory_dimensions();
        zero_chunk_count.total_authenticated_source_chunk_count = 0;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(zero_chunk_count),
            Err(CommonProofProverError::InvalidColumn)
        ));

        let mut zero_recursive_row_count = valid_memory_dimensions();
        zero_recursive_row_count.maximum_recursive_cached_row_count = 0;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(
                zero_recursive_row_count
            ),
            Err(CommonProofProverError::InvalidColumn)
        ));

        let mut zero_relation_column_count = valid_memory_dimensions();
        zero_relation_column_count.relation_column_count = 0;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(
                zero_relation_column_count
            ),
            Err(CommonProofProverError::InvalidColumn)
        ));

        let mut zero_trace_column_count = valid_memory_dimensions();
        zero_trace_column_count.trace_column_count_per_source = 0;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(
                zero_trace_column_count
            ),
            Err(CommonProofProverError::InvalidColumn)
        ));

        let mut odd_ring_degree = valid_memory_dimensions();
        odd_ring_degree.ring_degree = 9;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(odd_ring_degree),
            Err(CommonProofProverError::InvalidColumn)
        ));

        let mut overflowing_catalog = valid_memory_dimensions();
        overflowing_catalog.retained_catalog_heap_byte_length = u64::MAX;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(overflowing_catalog),
            Err(CommonProofProverError::CountOverflow)
        ));

        let mut overflowing_chunk_count = valid_memory_dimensions();
        overflowing_chunk_count.total_authenticated_source_chunk_count = u64::MAX;
        overflowing_chunk_count.maximum_trace_pair_chunk_count = 1;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(
                overflowing_chunk_count
            ),
            Err(CommonProofProverError::CountOverflow)
        ));

        let mut overflowing_relation_column_count = valid_memory_dimensions();
        overflowing_relation_column_count.relation_column_count = u64::MAX;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(
                overflowing_relation_column_count
            ),
            Err(CommonProofProverError::CountOverflow)
        ));

        let mut overflowing_trace_column_count = valid_memory_dimensions();
        overflowing_trace_column_count.trace_column_count_per_source = u64::MAX;
        assert!(matches!(
            finish_relinearization_round_two_source_provider_memory_accounting(
                overflowing_trace_column_count
            ),
            Err(CommonProofProverError::CountOverflow)
        ));
    }
}
