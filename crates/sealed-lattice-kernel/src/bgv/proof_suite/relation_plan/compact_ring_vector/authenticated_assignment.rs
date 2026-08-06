//! Authenticated source mapping for the compact public-key assignment.
//!
//! The compact relation consumes only the canonical public, small-secret, and
//! exact-quotient ring vectors named by its source-derived catalog. This owner
//! maps those vectors to the existing ordered authenticated polynomial source
//! boundary without inheriting unrelated row-code columns.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::bgv::proof_suite::{
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain,
    prover::{
        CommonProofProverError, CommonProofSourcePolynomialProvider,
        CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialRequestContext,
        base_trace_rows, requested_pre_challenge_source_column_ordinals, validate_source_column,
    },
    relation_plan::{RelationColumnOrigin, RelationColumnValueType, RelationPlanVariant},
};
use crate::hashing::StreamingHash512;

use super::super::key_relation::MODULAR_QUOTIENT_ENCODING_OFFSET;
use super::{
    CompactPublicKeyRelationCatalog, CompactRingVectorReference, CompactSmallVectorKind,
    CompactStructuredLinearTerm, CompactWitnessSegmentKind, RelationPlanError,
};

const COMPACT_AUTHENTICATED_ASSIGNMENT_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-ring-vector/authenticated-assignment-binding/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompactAssignmentStorage {
    PublicInput,
    Witness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactAuthenticatedSourceRole {
    PublicInput {
        vector_ordinal: u64,
        half_ordinal: u8,
    },
    ModularQuotient {
        relation_ordinal: u64,
        half_ordinal: u8,
    },
    ShiftedSmallValue {
        kind: CompactSmallVectorKind,
        vector_ordinal_within_kind: u64,
        half_ordinal: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactAuthenticatedSourceHalf {
    source_column_ordinal: u32,
    source_degree_bound_exclusive: u64,
    source_origin: CompactAuthenticatedSourceOrigin,
    role: CompactAuthenticatedSourceRole,
    destination_storage: CompactAssignmentStorage,
    destination_first_element: u64,
    element_count: u64,
}

impl CompactAuthenticatedSourceHalf {
    const fn source_column_ordinal(self) -> u32 {
        self.source_column_ordinal
    }

    const fn source_degree_bound_exclusive(self) -> u64 {
        self.source_degree_bound_exclusive
    }

    const fn source_origin(self) -> CompactAuthenticatedSourceOrigin {
        self.source_origin
    }

    const fn role(self) -> CompactAuthenticatedSourceRole {
        self.role
    }

    const fn destination_storage(self) -> CompactAssignmentStorage {
        self.destination_storage
    }

    const fn destination_first_element(self) -> u64 {
        self.destination_first_element
    }

    const fn element_count(self) -> u64 {
        self.element_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactAuthenticatedSourceOrigin {
    VerifierSequence,
    BoundTree,
    Prover,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactAuthenticatedAssignmentCatalog {
    relation_plan_hash: [u8; 64],
    trace_domain_size: u64,
    requested_source_column_count: u64,
    ignored_source_column_count: u64,
    ordered_source_halves: Vec<CompactAuthenticatedSourceHalf>,
}

impl CompactAuthenticatedAssignmentCatalog {
    pub(crate) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: &RelationPlanVariant,
    ) -> Result<Self, RelationPlanError> {
        let catalog = Self::derive_without_check(relation, relation_plan_variant)?;
        catalog.check(relation, relation_plan_variant)?;
        Ok(catalog)
    }

    fn derive_without_check(
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: &RelationPlanVariant,
    ) -> Result<Self, RelationPlanError> {
        let relation_plan_hash = relation_plan_variant.canonical_hash()?;
        let trace_domain_size = relation_plan_variant.trace_domain_size();
        if relation.relation_plan_hash != relation_plan_hash
            || trace_domain_size
                .checked_mul(2)
                .is_none_or(|ring_degree| ring_degree != relation.ring_degree)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let requested_source_columns =
            requested_pre_challenge_source_column_ordinals(relation_plan_variant)
                .map_err(|_| RelationPlanError::InvalidConstraint)?;
        if requested_source_columns
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        let requested_source_column_set = requested_source_columns
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut source_halves_by_column = BTreeMap::new();

        for (vector_ordinal, vector) in relation.ordered_public_vectors.iter().enumerate() {
            let vector_ordinal =
                u64::try_from(vector_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            insert_vector_halves(
                relation_plan_variant,
                &requested_source_column_set,
                &mut source_halves_by_column,
                *vector,
                CompactAssignmentStorage::PublicInput,
                1_u64
                    .checked_add(
                        vector_ordinal
                            .checked_mul(relation.ring_degree)
                            .ok_or(RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::CountOverflow)?,
                trace_domain_size,
                |half_ordinal| CompactAuthenticatedSourceRole::PublicInput {
                    vector_ordinal,
                    half_ordinal,
                },
            )?;
        }

        let mut next_ternary_vector_ordinal = 0_u64;
        let mut next_eta_two_vector_ordinal = 0_u64;
        for descriptor in &relation.ordered_private_small_vectors {
            let (witness_segment_kind, vector_ordinal_within_kind) = match descriptor.kind {
                CompactSmallVectorKind::ShiftedTernary => {
                    let ordinal = next_ternary_vector_ordinal;
                    next_ternary_vector_ordinal = next_ternary_vector_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                    (CompactWitnessSegmentKind::ShiftedTernaryValues, ordinal)
                }
                CompactSmallVectorKind::ShiftedEtaTwo => {
                    let ordinal = next_eta_two_vector_ordinal;
                    next_eta_two_vector_ordinal = next_eta_two_vector_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                    (CompactWitnessSegmentKind::ShiftedEtaTwoValues, ordinal)
                }
            };
            let destination_first_element = witness_vector_first_element(
                relation,
                witness_segment_kind,
                vector_ordinal_within_kind,
            )?;
            insert_vector_halves(
                relation_plan_variant,
                &requested_source_column_set,
                &mut source_halves_by_column,
                descriptor.vector,
                CompactAssignmentStorage::Witness,
                destination_first_element,
                trace_domain_size,
                |half_ordinal| CompactAuthenticatedSourceRole::ShiftedSmallValue {
                    kind: descriptor.kind,
                    vector_ordinal_within_kind,
                    half_ordinal,
                },
            )?;
        }

        for (relation_ordinal, structured_relation) in relation.ordered_relations.iter().enumerate()
        {
            let quotient_vectors = structured_relation
                .ordered_terms
                .iter()
                .filter_map(|term| match term {
                    CompactStructuredLinearTerm::ModulusQuotient {
                        quotient_vector, ..
                    } => Some(*quotient_vector),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [quotient_vector] = quotient_vectors.as_slice() else {
                return Err(RelationPlanError::InvalidConstraint);
            };
            let relation_ordinal =
                u64::try_from(relation_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            let destination_first_element = witness_vector_first_element(
                relation,
                CompactWitnessSegmentKind::ModularQuotients,
                relation_ordinal,
            )?;
            insert_vector_halves(
                relation_plan_variant,
                &requested_source_column_set,
                &mut source_halves_by_column,
                *quotient_vector,
                CompactAssignmentStorage::Witness,
                destination_first_element,
                trace_domain_size,
                |half_ordinal| CompactAuthenticatedSourceRole::ModularQuotient {
                    relation_ordinal,
                    half_ordinal,
                },
            )?;
        }

        check_destination_intervals(
            source_halves_by_column.values().copied(),
            relation.padded_public_input_element_count,
            relation.padded_witness_element_count,
        )?;
        let mut ordered_source_halves = Vec::new();
        ordered_source_halves
            .try_reserve_exact(source_halves_by_column.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for column_ordinal in &requested_source_columns {
            if let Some(source_half) = source_halves_by_column.remove(column_ordinal) {
                ordered_source_halves.push(source_half);
            }
        }
        if !source_halves_by_column.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let requested_source_column_count = u64::try_from(requested_source_columns.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let used_source_column_count = u64::try_from(ordered_source_halves.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let ignored_source_column_count = requested_source_column_count
            .checked_sub(used_source_column_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        Ok(Self {
            relation_plan_hash,
            trace_domain_size,
            requested_source_column_count,
            ignored_source_column_count,
            ordered_source_halves,
        })
    }

    pub(crate) fn check(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        if self != &Self::derive_without_check(relation, relation_plan_variant)? {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(())
    }

    pub(crate) fn source_column_ordinals(&self) -> Vec<u32> {
        self.ordered_source_halves
            .iter()
            .map(|source| source.source_column_ordinal)
            .collect()
    }

    pub(crate) const fn requested_source_column_count(&self) -> u64 {
        self.requested_source_column_count
    }

    pub(crate) const fn ignored_source_column_count(&self) -> u64 {
        self.ignored_source_column_count
    }

    pub(crate) fn ordered_source_halves(&self) -> &[CompactAuthenticatedSourceHalf] {
        &self.ordered_source_halves
    }

    pub(super) fn resident_owned_heap_byte_length(&self) -> Result<u64, CommonProofProverError> {
        u64::try_from(self.ordered_source_halves.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(
                    u64::try_from(core::mem::size_of::<CompactAuthenticatedSourceHalf>()).ok()?,
                )
            })
            .ok_or(CommonProofProverError::CountOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactAuthenticatedAssignmentMemoryGeometry {
    public_input_prefix_element_count: u64,
    base_witness_prefix_element_count: u64,
    lookup_inverse_element_count: u64,
    padded_public_input_element_count: u64,
    padded_witness_element_count: u64,
    base_assignment_payload_byte_length: u64,
    completed_assignment_payload_byte_length: u64,
    lookup_materializer_resident_owned_byte_length: u64,
    completed_assignment_resident_owned_byte_length: u64,
}

impl CompactAuthenticatedAssignmentMemoryGeometry {
    fn derive(relation: &CompactPublicKeyRelationCatalog) -> Result<Self, CommonProofProverError> {
        let public_input_prefix_element_count = relation
            .public_input_ring_vector_count
            .checked_mul(relation.ring_degree)
            .and_then(|count| count.checked_add(1))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let lookup_inverse_segment =
            witness_segment(relation, CompactWitnessSegmentKind::LookupInverses)?;
        let base_witness_prefix_element_count = lookup_inverse_segment.first_element;
        let lookup_inverse_element_count = lookup_inverse_segment.element_count;
        let base_field_element_byte_length =
            u64::try_from(core::mem::size_of::<ProofBaseFieldElement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let extension_element_byte_length =
            u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                .map_err(|_| CommonProofProverError::CountOverflow)?;
        let base_assignment_payload_byte_length = public_input_prefix_element_count
            .checked_add(base_witness_prefix_element_count)
            .and_then(|count| count.checked_mul(base_field_element_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let completed_assignment_payload_byte_length = lookup_inverse_element_count
            .checked_mul(extension_element_byte_length)
            .and_then(|inverse_bytes| {
                base_assignment_payload_byte_length.checked_add(inverse_bytes)
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
        let lookup_materializer_resident_owned_byte_length =
            completed_assignment_payload_byte_length
                .checked_add(
                    u64::try_from(core::mem::size_of::<CompactLookupInverseMaterializer>())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::CountOverflow)?;
        let completed_assignment_resident_owned_byte_length =
            completed_assignment_payload_byte_length
                .checked_add(
                    u64::try_from(core::mem::size_of::<CompactPublicKeyAssignment>())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::CountOverflow)?;
        let geometry = Self {
            public_input_prefix_element_count,
            base_witness_prefix_element_count,
            lookup_inverse_element_count,
            padded_public_input_element_count: relation.padded_public_input_element_count,
            padded_witness_element_count: relation.padded_witness_element_count,
            base_assignment_payload_byte_length,
            completed_assignment_payload_byte_length,
            lookup_materializer_resident_owned_byte_length,
            completed_assignment_resident_owned_byte_length,
        };
        if geometry.public_input_prefix_element_count > geometry.padded_public_input_element_count
            || geometry
                .base_witness_prefix_element_count
                .checked_add(geometry.lookup_inverse_element_count)
                .is_none_or(|count| count > geometry.padded_witness_element_count)
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(geometry)
    }

    pub(crate) const fn public_input_prefix_element_count(self) -> u64 {
        self.public_input_prefix_element_count
    }

    pub(crate) const fn base_witness_prefix_element_count(self) -> u64 {
        self.base_witness_prefix_element_count
    }

    pub(crate) const fn lookup_inverse_element_count(self) -> u64 {
        self.lookup_inverse_element_count
    }

    pub(crate) const fn padded_public_input_element_count(self) -> u64 {
        self.padded_public_input_element_count
    }

    pub(crate) const fn padded_witness_element_count(self) -> u64 {
        self.padded_witness_element_count
    }

    pub(crate) const fn base_assignment_payload_byte_length(self) -> u64 {
        self.base_assignment_payload_byte_length
    }

    pub(crate) const fn completed_assignment_payload_byte_length(self) -> u64 {
        self.completed_assignment_payload_byte_length
    }

    pub(crate) const fn lookup_materializer_resident_owned_byte_length(self) -> u64 {
        self.lookup_materializer_resident_owned_byte_length
    }

    pub(crate) const fn completed_assignment_resident_owned_byte_length(self) -> u64 {
        self.completed_assignment_resident_owned_byte_length
    }
}

pub(crate) fn compact_authenticated_assignment_memory_geometry(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactAuthenticatedAssignmentMemoryGeometry, CommonProofProverError> {
    CompactAuthenticatedAssignmentMemoryGeometry::derive(relation)
}

struct CompactBaseAssignmentBuffers {
    public_input_prefix: Zeroizing<Vec<ProofBaseFieldElement>>,
    base_witness_prefix: Zeroizing<Vec<ProofBaseFieldElement>>,
}

impl CompactBaseAssignmentBuffers {
    fn new(
        geometry: CompactAuthenticatedAssignmentMemoryGeometry,
    ) -> Result<Self, CommonProofProverError> {
        let mut public_input_prefix =
            fallible_zero_base_vector(geometry.public_input_prefix_element_count)?;
        public_input_prefix[0] = ProofBaseFieldElement::ONE;
        Ok(Self {
            public_input_prefix,
            base_witness_prefix: fallible_zero_base_vector(
                geometry.base_witness_prefix_element_count,
            )?,
        })
    }
}

pub(crate) enum CompactAuthenticatedAssignmentPoll {
    AuthenticatedSourceReadRequired,
    SourceLoaded { column_ordinal: u32 },
    Complete,
}

pub(crate) struct CompactAuthenticatedAssignmentCursor {
    catalog: CompactAuthenticatedAssignmentCatalog,
    geometry: CompactAuthenticatedAssignmentMemoryGeometry,
    trace_domain: ProofEvaluationDomain,
    request_context: CommonProofSourcePolynomialRequestContext,
    next_source_index: usize,
    source_identity_hasher: Option<StreamingHash512>,
    buffers: Option<CompactBaseAssignmentBuffers>,
    completed_assignment: Option<CompactPublicKeyBaseAssignment>,
}

impl CompactAuthenticatedAssignmentCursor {
    pub(crate) fn new(
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: &RelationPlanVariant,
        request_context: CommonProofSourcePolynomialRequestContext,
    ) -> Result<Self, CommonProofProverError> {
        let catalog =
            CompactAuthenticatedAssignmentCatalog::derive(relation, relation_plan_variant)?;
        if request_context.relation_plan_variant_hash() != catalog.relation_plan_hash
            || request_context.schedule_position() != relation_plan_variant.schedule_position()
            || request_context.top_count() != relation_plan_variant.top_count()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let geometry = CompactAuthenticatedAssignmentMemoryGeometry::derive(relation)?;
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(catalog.trace_domain_size)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
        let source_count = u64::try_from(catalog.ordered_source_halves.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let mut source_identity_hasher = StreamingHash512::new(
            COMPACT_AUTHENTICATED_ASSIGNMENT_BINDING_DOMAIN,
            source_count
                .checked_add(3)
                .ok_or(CommonProofProverError::CountOverflow)?,
        );
        source_identity_hasher.absorb_part(&request_context.stable_generation_binding_hash());
        source_identity_hasher.absorb_part(&catalog.relation_plan_hash);
        source_identity_hasher.absorb_part(&source_count.to_le_bytes());
        Ok(Self {
            catalog,
            geometry,
            trace_domain,
            request_context,
            next_source_index: 0,
            source_identity_hasher: Some(source_identity_hasher),
            buffers: Some(CompactBaseAssignmentBuffers::new(geometry)?),
            completed_assignment: None,
        })
    }

    pub(crate) const fn memory_geometry(&self) -> CompactAuthenticatedAssignmentMemoryGeometry {
        self.geometry
    }

    pub(crate) fn next_source(
        &mut self,
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: &RelationPlanVariant,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
    ) -> Result<CompactAuthenticatedAssignmentPoll, CommonProofProverError> {
        self.catalog.check(relation, relation_plan_variant)?;
        if self.request_context.relation_plan_variant_hash() != self.catalog.relation_plan_hash {
            return Err(CommonProofProverError::InvalidInput);
        }
        let Some(source_half) = self
            .catalog
            .ordered_source_halves
            .get(self.next_source_index)
            .copied()
        else {
            if self.completed_assignment.is_some() {
                return Err(CommonProofProverError::InvalidInput);
            }
            source_provider.finish()?;
            let source_replay_binding = self
                .source_identity_hasher
                .take()
                .ok_or(CommonProofProverError::InvalidInput)?
                .finalize();
            let buffers = self
                .buffers
                .take()
                .ok_or(CommonProofProverError::InvalidInput)?;
            self.completed_assignment = Some(CompactPublicKeyBaseAssignment {
                geometry: self.geometry,
                source_replay_binding,
                public_input_prefix: buffers.public_input_prefix,
                base_witness_prefix: buffers.base_witness_prefix,
            });
            return Ok(CompactAuthenticatedAssignmentPoll::Complete);
        };
        let column_ordinal = source_half.source_column_ordinal();
        let descriptor = relation_plan_variant
            .ordered_columns()
            .get(
                usize::try_from(column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if descriptor.source_degree_bound_exclusive() != source_half.source_degree_bound_exclusive()
            || descriptor_origin(descriptor.origin()) != source_half.source_origin()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let provided = match source_provider
            .poll_source_polynomial(self.request_context.request(column_ordinal, descriptor))?
        {
            CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired => {
                return Ok(CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired);
            }
            CommonProofSourcePolynomialProviderPoll::Ready(provided) => provided,
        };
        let (source, replay_identity) = provided.into_parts();
        validate_source_column(descriptor, &source, self.catalog.trace_domain_size)?;
        let trace_rows = base_trace_rows(&source, self.trace_domain)?;
        drop(source);
        if trace_rows.len()
            != usize::try_from(source_half.element_count())
                .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        store_source_rows(
            relation,
            source_half,
            &trace_rows,
            self.buffers
                .as_mut()
                .ok_or(CommonProofProverError::InvalidInput)?,
        )?;
        let mut coordinate_identity = [0_u8; 68];
        coordinate_identity[..4].copy_from_slice(&column_ordinal.to_le_bytes());
        coordinate_identity[4..].copy_from_slice(&replay_identity.bytes());
        self.source_identity_hasher
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)?
            .absorb_part(&coordinate_identity);
        self.next_source_index = self
            .next_source_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        Ok(CompactAuthenticatedAssignmentPoll::SourceLoaded { column_ordinal })
    }

    pub(crate) fn finish(
        mut self,
        relation: &CompactPublicKeyRelationCatalog,
        relation_plan_variant: &RelationPlanVariant,
    ) -> Result<CompactPublicKeyBaseAssignment, CommonProofProverError> {
        self.catalog.check(relation, relation_plan_variant)?;
        if self.request_context.relation_plan_variant_hash() != self.catalog.relation_plan_hash
            || self.next_source_index != self.catalog.ordered_source_halves.len()
            || self.source_identity_hasher.is_some()
            || self.buffers.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let assignment = self
            .completed_assignment
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        if assignment.geometry != self.geometry {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(assignment)
    }
}

pub(crate) struct CompactPublicKeyBaseAssignment {
    geometry: CompactAuthenticatedAssignmentMemoryGeometry,
    source_replay_binding: [u8; 64],
    public_input_prefix: Zeroizing<Vec<ProofBaseFieldElement>>,
    base_witness_prefix: Zeroizing<Vec<ProofBaseFieldElement>>,
}

impl CompactPublicKeyBaseAssignment {
    pub(crate) const fn memory_geometry(&self) -> CompactAuthenticatedAssignmentMemoryGeometry {
        self.geometry
    }

    pub(crate) const fn source_replay_binding(&self) -> [u8; 64] {
        self.source_replay_binding
    }

    pub(crate) fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        value_from_base_prefix(
            &self.public_input_prefix,
            self.geometry.padded_public_input_element_count,
            element_ordinal,
        )
    }

    pub(crate) fn witness_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        if element_ordinal >= self.geometry.base_witness_prefix_element_count {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.base_witness_prefix
            .get(
                usize::try_from(element_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .copied()
            .ok_or(CommonProofProverError::InvalidColumn)
    }

    pub(crate) fn begin_lookup_inverse_materialization(
        self,
        lookup_challenge: ProofChallengeExtensionElement,
    ) -> Result<CompactLookupInverseMaterializer, CommonProofProverError> {
        validate_lookup_challenge(lookup_challenge)?;
        let mut lookup_inverse_prefix_products = Vec::new();
        lookup_inverse_prefix_products
            .try_reserve_exact(
                usize::try_from(self.geometry.lookup_inverse_element_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(CompactLookupInverseMaterializer {
            base_assignment: Some(self),
            lookup_challenge,
            lookup_inverse_prefix_products: Zeroizing::new(lookup_inverse_prefix_products),
            phase: CompactLookupInverseMaterializationPhase::Forward {
                next_quotient_ordinal: 0,
                running_product: ProofChallengeExtensionElement::ONE,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactLookupInverseMaterializationPhase {
    Forward {
        next_quotient_ordinal: u64,
        running_product: ProofChallengeExtensionElement,
    },
    InvertTotalProduct {
        total_product: ProofChallengeExtensionElement,
    },
    Reverse {
        remaining_element_count: u64,
        accumulated_inverse: ProofChallengeExtensionElement,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactLookupInverseMaterializationPoll {
    ArithmeticStepCompleted { processed_element_count: u64 },
    Complete,
}

pub(crate) struct CompactLookupInverseMaterializer {
    base_assignment: Option<CompactPublicKeyBaseAssignment>,
    lookup_challenge: ProofChallengeExtensionElement,
    lookup_inverse_prefix_products: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    phase: CompactLookupInverseMaterializationPhase,
}

impl CompactLookupInverseMaterializer {
    pub(crate) fn advance(
        &mut self,
        maximum_element_count: u64,
    ) -> Result<CompactLookupInverseMaterializationPoll, CommonProofProverError> {
        if maximum_element_count == 0 {
            return Err(CommonProofProverError::InvalidInput);
        }
        let base_assignment = self
            .base_assignment
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?;
        match self.phase {
            CompactLookupInverseMaterializationPhase::Forward {
                next_quotient_ordinal,
                mut running_product,
            } => {
                let remaining = base_assignment
                    .geometry
                    .lookup_inverse_element_count
                    .checked_sub(next_quotient_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if remaining == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let processed_element_count = remaining.min(maximum_element_count);
                let end = next_quotient_ordinal
                    .checked_add(processed_element_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                for quotient_ordinal in next_quotient_ordinal..end {
                    let denominator = lookup_denominator(
                        base_assignment,
                        self.lookup_challenge,
                        quotient_ordinal,
                    )?;
                    running_product = running_product.multiply(denominator);
                    self.lookup_inverse_prefix_products.push(running_product);
                }
                self.phase = if end == base_assignment.geometry.lookup_inverse_element_count {
                    CompactLookupInverseMaterializationPhase::InvertTotalProduct {
                        total_product: running_product,
                    }
                } else {
                    CompactLookupInverseMaterializationPhase::Forward {
                        next_quotient_ordinal: end,
                        running_product,
                    }
                };
                Ok(
                    CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                        processed_element_count,
                    },
                )
            }
            CompactLookupInverseMaterializationPhase::InvertTotalProduct { total_product } => {
                let accumulated_inverse = total_product.inverse()?;
                self.phase = CompactLookupInverseMaterializationPhase::Reverse {
                    remaining_element_count: base_assignment.geometry.lookup_inverse_element_count,
                    accumulated_inverse,
                };
                Ok(
                    CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                        processed_element_count: 1,
                    },
                )
            }
            CompactLookupInverseMaterializationPhase::Reverse {
                remaining_element_count,
                mut accumulated_inverse,
            } => {
                if remaining_element_count == 0 {
                    if accumulated_inverse != ProofChallengeExtensionElement::ONE {
                        return Err(CommonProofProverError::InvalidQuotient);
                    }
                    self.phase = CompactLookupInverseMaterializationPhase::Complete;
                    return Ok(CompactLookupInverseMaterializationPoll::Complete);
                }
                let processed_element_count = remaining_element_count.min(maximum_element_count);
                let first_ordinal = remaining_element_count
                    .checked_sub(processed_element_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                for quotient_ordinal in (first_ordinal..remaining_element_count).rev() {
                    let denominator = lookup_denominator(
                        base_assignment,
                        self.lookup_challenge,
                        quotient_ordinal,
                    )?;
                    let prior_prefix = if quotient_ordinal == 0 {
                        ProofChallengeExtensionElement::ONE
                    } else {
                        *self
                            .lookup_inverse_prefix_products
                            .get(
                                usize::try_from(quotient_ordinal - 1)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::InvalidQuotient)?
                    };
                    let inverse = accumulated_inverse.multiply(prior_prefix);
                    accumulated_inverse = accumulated_inverse.multiply(denominator);
                    *self
                        .lookup_inverse_prefix_products
                        .get_mut(
                            usize::try_from(quotient_ordinal)
                                .map_err(|_| CommonProofProverError::CountOverflow)?,
                        )
                        .ok_or(CommonProofProverError::InvalidQuotient)? = inverse;
                }
                self.phase = if first_ordinal == 0 {
                    if accumulated_inverse != ProofChallengeExtensionElement::ONE {
                        return Err(CommonProofProverError::InvalidQuotient);
                    }
                    CompactLookupInverseMaterializationPhase::Complete
                } else {
                    CompactLookupInverseMaterializationPhase::Reverse {
                        remaining_element_count: first_ordinal,
                        accumulated_inverse,
                    }
                };
                Ok(
                    CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                        processed_element_count,
                    },
                )
            }
            CompactLookupInverseMaterializationPhase::Complete => {
                Ok(CompactLookupInverseMaterializationPoll::Complete)
            }
        }
    }

    pub(crate) fn finish(self) -> Result<CompactPublicKeyAssignment, CommonProofProverError> {
        if self.phase != CompactLookupInverseMaterializationPhase::Complete
            || self.lookup_inverse_prefix_products.len()
                != usize::try_from(
                    self.base_assignment
                        .as_ref()
                        .ok_or(CommonProofProverError::InvalidInput)?
                        .geometry
                        .lookup_inverse_element_count,
                )
                .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(CompactPublicKeyAssignment {
            base_assignment: self
                .base_assignment
                .ok_or(CommonProofProverError::InvalidInput)?,
            lookup_challenge: self.lookup_challenge,
            lookup_inverses: self.lookup_inverse_prefix_products,
        })
    }
}

pub(crate) struct CompactPublicKeyAssignment {
    base_assignment: CompactPublicKeyBaseAssignment,
    lookup_challenge: ProofChallengeExtensionElement,
    lookup_inverses: Zeroizing<Vec<ProofChallengeExtensionElement>>,
}

impl CompactPublicKeyAssignment {
    pub(crate) const fn memory_geometry(&self) -> CompactAuthenticatedAssignmentMemoryGeometry {
        self.base_assignment.geometry
    }

    pub(crate) const fn source_replay_binding(&self) -> [u8; 64] {
        self.base_assignment.source_replay_binding
    }

    pub(crate) const fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
        self.lookup_challenge
    }

    pub(crate) fn public_input_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        self.base_assignment
            .public_input_base_value(element_ordinal)
            .map(ProofChallengeExtensionElement::from_base)
    }

    pub(super) fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        self.base_assignment
            .public_input_base_value(element_ordinal)
    }

    pub(super) fn base_witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        self.base_assignment.witness_base_value(element_ordinal)
    }

    pub(crate) fn witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        if element_ordinal
            < self
                .base_assignment
                .geometry
                .base_witness_prefix_element_count
        {
            return self
                .base_assignment
                .witness_base_value(element_ordinal)
                .map(ProofChallengeExtensionElement::from_base);
        }
        let inverse_ordinal = element_ordinal
            .checked_sub(
                self.base_assignment
                    .geometry
                    .base_witness_prefix_element_count,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if inverse_ordinal < self.base_assignment.geometry.lookup_inverse_element_count {
            return self
                .lookup_inverses
                .get(
                    usize::try_from(inverse_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn);
        }
        if element_ordinal < self.base_assignment.geometry.padded_witness_element_count {
            return Ok(ProofChallengeExtensionElement::ZERO);
        }
        Err(CommonProofProverError::InvalidColumn)
    }
}

fn descriptor_origin(origin: &RelationColumnOrigin) -> CompactAuthenticatedSourceOrigin {
    match origin {
        RelationColumnOrigin::VerifierSequence { .. } => {
            CompactAuthenticatedSourceOrigin::VerifierSequence
        }
        RelationColumnOrigin::BoundTree { .. } => CompactAuthenticatedSourceOrigin::BoundTree,
        RelationColumnOrigin::Prover => CompactAuthenticatedSourceOrigin::Prover,
    }
}

fn witness_segment(
    relation: &CompactPublicKeyRelationCatalog,
    kind: CompactWitnessSegmentKind,
) -> Result<super::CompactWitnessSegment, CommonProofProverError> {
    relation
        .ordered_witness_segments
        .iter()
        .find(|segment| segment.kind == kind)
        .copied()
        .ok_or(CommonProofProverError::InvalidColumn)
}

fn fallible_zero_base_vector(
    element_count: u64,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofProverError> {
    let element_count =
        usize::try_from(element_count).map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(element_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    values.resize(element_count, ProofBaseFieldElement::ZERO);
    Ok(Zeroizing::new(values))
}

fn value_from_base_prefix(
    prefix: &[ProofBaseFieldElement],
    padded_element_count: u64,
    element_ordinal: u64,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    if let Some(value) = usize::try_from(element_ordinal)
        .ok()
        .and_then(|ordinal| prefix.get(ordinal))
        .copied()
    {
        return Ok(value);
    }
    if element_ordinal < padded_element_count {
        return Ok(ProofBaseFieldElement::ZERO);
    }
    Err(CommonProofProverError::InvalidColumn)
}

fn store_source_rows(
    relation: &CompactPublicKeyRelationCatalog,
    source_half: CompactAuthenticatedSourceHalf,
    trace_rows: &[ProofBaseFieldElement],
    buffers: &mut CompactBaseAssignmentBuffers,
) -> Result<(), CommonProofProverError> {
    let first_destination = usize::try_from(source_half.destination_first_element())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let destination_end = first_destination
        .checked_add(trace_rows.len())
        .ok_or(CommonProofProverError::CountOverflow)?;
    match source_half.destination_storage() {
        CompactAssignmentStorage::PublicInput => {
            let destination = buffers
                .public_input_prefix
                .get_mut(first_destination..destination_end)
                .ok_or(CommonProofProverError::InvalidColumn)?;
            destination.copy_from_slice(trace_rows);
        }
        CompactAssignmentStorage::Witness => match source_half.role() {
            CompactAuthenticatedSourceRole::ModularQuotient { .. } => {
                store_modular_quotient_rows(relation, source_half, trace_rows, buffers)?;
            }
            CompactAuthenticatedSourceRole::ShiftedSmallValue { kind, .. } => {
                store_shifted_small_rows(relation, source_half, kind, trace_rows, buffers)?;
            }
            CompactAuthenticatedSourceRole::PublicInput { .. } => {
                return Err(CommonProofProverError::InvalidColumn);
            }
        },
    }
    Ok(())
}

fn store_modular_quotient_rows(
    relation: &CompactPublicKeyRelationCatalog,
    source_half: CompactAuthenticatedSourceHalf,
    trace_rows: &[ProofBaseFieldElement],
    buffers: &mut CompactBaseAssignmentBuffers,
) -> Result<(), CommonProofProverError> {
    let quotient_offset = ProofBaseFieldElement::from_canonical(MODULAR_QUOTIENT_ENCODING_OFFSET)?;
    let quotient_first = usize::try_from(source_half.destination_first_element())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let multiplicity_segment =
        witness_segment(relation, CompactWitnessSegmentKind::LookupMultiplicities)?;
    for (local_ordinal, row) in trace_rows.iter().copied().enumerate() {
        let encoded = row.add(quotient_offset);
        let table_ordinal = encoded.canonical();
        if table_ordinal >= relation.quotient_lookup_table_value_count {
            return Err(CommonProofProverError::InvalidQuotient);
        }
        let quotient_destination = quotient_first
            .checked_add(local_ordinal)
            .ok_or(CommonProofProverError::CountOverflow)?;
        *buffers
            .base_witness_prefix
            .get_mut(quotient_destination)
            .ok_or(CommonProofProverError::InvalidColumn)? = encoded;
        let multiplicity_destination = multiplicity_segment
            .first_element
            .checked_add(table_ordinal)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let multiplicity = buffers
            .base_witness_prefix
            .get_mut(
                usize::try_from(multiplicity_destination)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        *multiplicity = multiplicity.add(ProofBaseFieldElement::ONE);
    }
    Ok(())
}

fn store_shifted_small_rows(
    relation: &CompactPublicKeyRelationCatalog,
    source_half: CompactAuthenticatedSourceHalf,
    kind: CompactSmallVectorKind,
    trace_rows: &[ProofBaseFieldElement],
    buffers: &mut CompactBaseAssignmentBuffers,
) -> Result<(), CommonProofProverError> {
    let shifted_first = usize::try_from(source_half.destination_first_element())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let product_segment = witness_segment(relation, CompactWitnessSegmentKind::SmallSetProducts)?;
    let CompactAuthenticatedSourceRole::ShiftedSmallValue {
        vector_ordinal_within_kind,
        half_ordinal,
        ..
    } = source_half.role()
    else {
        return Err(CommonProofProverError::InvalidColumn);
    };
    let coefficient_offset = u64::from(half_ordinal)
        .checked_mul(source_half.element_count())
        .ok_or(CommonProofProverError::CountOverflow)?;
    let ternary_vector_count = relation.shifted_ternary_vector_count();
    for (local_ordinal, value) in trace_rows.iter().copied().enumerate() {
        let canonical_value = value.canonical();
        let maximum_value = match kind {
            CompactSmallVectorKind::ShiftedTernary => 2,
            CompactSmallVectorKind::ShiftedEtaTwo => 4,
        };
        if canonical_value > maximum_value {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let shifted_destination = shifted_first
            .checked_add(local_ordinal)
            .ok_or(CommonProofProverError::CountOverflow)?;
        *buffers
            .base_witness_prefix
            .get_mut(shifted_destination)
            .ok_or(CommonProofProverError::InvalidColumn)? = value;
        let coefficient_ordinal = coefficient_offset
            .checked_add(
                u64::try_from(local_ordinal).map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        match kind {
            CompactSmallVectorKind::ShiftedTernary => {
                let product = value.multiply(value.subtract(ProofBaseFieldElement::ONE));
                store_small_product(
                    relation,
                    product_segment.first_element,
                    vector_ordinal_within_kind,
                    coefficient_ordinal,
                    product,
                    buffers,
                )?;
            }
            CompactSmallVectorKind::ShiftedEtaTwo => {
                let first_product = value.multiply(value.subtract(ProofBaseFieldElement::ONE));
                let second_product = first_product
                    .multiply(value.subtract(ProofBaseFieldElement::from_canonical(2)?));
                let third_product = second_product
                    .multiply(value.subtract(ProofBaseFieldElement::from_canonical(3)?));
                let first_product_vector_ordinal = ternary_vector_count
                    .checked_add(
                        vector_ordinal_within_kind
                            .checked_mul(3)
                            .ok_or(CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::CountOverflow)?;
                for (product_ordinal, product) in [first_product, second_product, third_product]
                    .into_iter()
                    .enumerate()
                {
                    store_small_product(
                        relation,
                        product_segment.first_element,
                        first_product_vector_ordinal
                            .checked_add(
                                u64::try_from(product_ordinal)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::CountOverflow)?,
                        coefficient_ordinal,
                        product,
                        buffers,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn store_small_product(
    relation: &CompactPublicKeyRelationCatalog,
    product_segment_first_element: u64,
    product_vector_ordinal: u64,
    coefficient_ordinal: u64,
    product: ProofBaseFieldElement,
    buffers: &mut CompactBaseAssignmentBuffers,
) -> Result<(), CommonProofProverError> {
    let destination = product_segment_first_element
        .checked_add(
            product_vector_ordinal
                .checked_mul(relation.ring_degree)
                .ok_or(CommonProofProverError::CountOverflow)?,
        )
        .and_then(|first| first.checked_add(coefficient_ordinal))
        .ok_or(CommonProofProverError::CountOverflow)?;
    *buffers
        .base_witness_prefix
        .get_mut(usize::try_from(destination).map_err(|_| CommonProofProverError::CountOverflow)?)
        .ok_or(CommonProofProverError::InvalidColumn)? = product;
    Ok(())
}

fn validate_lookup_challenge(
    lookup_challenge: ProofChallengeExtensionElement,
) -> Result<(), CommonProofProverError> {
    if lookup_challenge.canonical_coordinates()[1..]
        .iter()
        .all(|coordinate| *coordinate == 0)
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    Ok(())
}

fn lookup_denominator(
    base_assignment: &CompactPublicKeyBaseAssignment,
    lookup_challenge: ProofChallengeExtensionElement,
    quotient_ordinal: u64,
) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
    if quotient_ordinal >= base_assignment.geometry.lookup_inverse_element_count {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    let quotient = base_assignment.witness_base_value(quotient_ordinal)?;
    let denominator = lookup_challenge.add(ProofChallengeExtensionElement::from_base(quotient));
    if denominator.is_zero() {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    Ok(denominator)
}

fn insert_vector_halves(
    relation_plan_variant: &RelationPlanVariant,
    requested_source_column_set: &BTreeSet<u32>,
    source_halves_by_column: &mut BTreeMap<u32, CompactAuthenticatedSourceHalf>,
    vector: CompactRingVectorReference,
    destination_storage: CompactAssignmentStorage,
    destination_first_element: u64,
    trace_domain_size: u64,
    mut role: impl FnMut(u8) -> CompactAuthenticatedSourceRole,
) -> Result<(), RelationPlanError> {
    for (half_ordinal, source_column_ordinal) in vector.column_ordinals.into_iter().enumerate() {
        let descriptor = relation_plan_variant
            .ordered_columns()
            .get(
                usize::try_from(source_column_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::InvalidConstraint)?;
        if descriptor.value_type() != RelationColumnValueType::BaseField
            || descriptor.source_degree_bound_exclusive() == 0
            || descriptor.source_degree_bound_exclusive()
                > relation_plan_variant.evaluation_domain_size()
            || !requested_source_column_set.contains(&source_column_ordinal)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let source_origin = match descriptor.origin() {
            RelationColumnOrigin::VerifierSequence { .. } => {
                CompactAuthenticatedSourceOrigin::VerifierSequence
            }
            RelationColumnOrigin::BoundTree { .. } => CompactAuthenticatedSourceOrigin::BoundTree,
            RelationColumnOrigin::Prover => CompactAuthenticatedSourceOrigin::Prover,
        };
        let half_ordinal =
            u8::try_from(half_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        let half_offset = u64::from(half_ordinal)
            .checked_mul(trace_domain_size)
            .ok_or(RelationPlanError::CountOverflow)?;
        if source_halves_by_column
            .insert(
                source_column_ordinal,
                CompactAuthenticatedSourceHalf {
                    source_column_ordinal,
                    source_degree_bound_exclusive: descriptor.source_degree_bound_exclusive(),
                    source_origin,
                    role: role(half_ordinal),
                    destination_storage,
                    destination_first_element: destination_first_element
                        .checked_add(half_offset)
                        .ok_or(RelationPlanError::CountOverflow)?,
                    element_count: trace_domain_size,
                },
            )
            .is_some()
        {
            return Err(RelationPlanError::DuplicateItem);
        }
    }
    Ok(())
}

fn witness_vector_first_element(
    relation: &CompactPublicKeyRelationCatalog,
    kind: CompactWitnessSegmentKind,
    vector_ordinal: u64,
) -> Result<u64, RelationPlanError> {
    let segment = relation
        .ordered_witness_segments
        .iter()
        .find(|segment| segment.kind == kind)
        .ok_or(RelationPlanError::InvalidConstraint)?;
    if vector_ordinal >= segment.ring_vector_count {
        return Err(RelationPlanError::InvalidConstraint);
    }
    segment
        .first_element
        .checked_add(
            vector_ordinal
                .checked_mul(relation.ring_degree)
                .ok_or(RelationPlanError::CountOverflow)?,
        )
        .ok_or(RelationPlanError::CountOverflow)
}

fn check_destination_intervals(
    source_halves: impl Iterator<Item = CompactAuthenticatedSourceHalf>,
    public_input_length: u64,
    witness_length: u64,
) -> Result<(), RelationPlanError> {
    let mut intervals = source_halves
        .map(|source| {
            let end = source
                .destination_first_element
                .checked_add(source.element_count)
                .ok_or(RelationPlanError::CountOverflow)?;
            let storage_length = match source.destination_storage {
                CompactAssignmentStorage::PublicInput => public_input_length,
                CompactAssignmentStorage::Witness => witness_length,
            };
            if end > storage_length {
                return Err(RelationPlanError::InvalidConstraint);
            }
            Ok((
                source.destination_storage,
                source.destination_first_element,
                end,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    intervals.sort_unstable();
    if intervals
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].2 > pair[1].1)
    {
        return Err(RelationPlanError::DuplicateItem);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        PROOF_BASE_FIELD_MODULUS,
        prover::{
            CommonProofAuthenticatedSourceReadRequest, CommonProofSourcePolynomial,
            CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
            CommonProofSourceProviderMemoryAccounting, ProvidedCommonProofSourcePolynomial,
        },
        relation_plan::compile_public_key_share_relation_with_source_layout,
        selected_public_key_share_relation_plan_input, selected_relation_plan_check_context,
    };
    use crate::foundation::ProofApplicationSlotCeilings;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestSourceFault {
        None,
        ExtensionAtFirstSource,
    }

    struct DeterministicTestSourceProvider {
        catalog: CompactAuthenticatedAssignmentCatalog,
        relation_plan_variant: RelationPlanVariant,
        request_context: CommonProofSourcePolynomialRequestContext,
        authenticated_read_source_index: Option<usize>,
        authenticated_read_satisfied: bool,
        pending_authenticated_read: Option<CommonProofAuthenticatedSourceReadRequest>,
        next_source_index: usize,
        fault: TestSourceFault,
        finished: bool,
    }

    impl DeterministicTestSourceProvider {
        fn new(
            catalog: CompactAuthenticatedAssignmentCatalog,
            relation_plan_variant: RelationPlanVariant,
            request_context: CommonProofSourcePolynomialRequestContext,
            authenticated_read_source_index: Option<usize>,
            fault: TestSourceFault,
        ) -> Self {
            Self {
                catalog,
                relation_plan_variant,
                request_context,
                authenticated_read_source_index,
                authenticated_read_satisfied: false,
                pending_authenticated_read: None,
                next_source_index: 0,
                fault,
                finished: false,
            }
        }

        fn source_value(source_half: CompactAuthenticatedSourceHalf) -> ProofBaseFieldElement {
            let canonical = match source_half.role() {
                CompactAuthenticatedSourceRole::PublicInput { .. }
                | CompactAuthenticatedSourceRole::ModularQuotient { .. } => 0,
                CompactAuthenticatedSourceRole::ShiftedSmallValue {
                    kind: CompactSmallVectorKind::ShiftedTernary,
                    ..
                } => 1,
                CompactAuthenticatedSourceRole::ShiftedSmallValue {
                    kind: CompactSmallVectorKind::ShiftedEtaTwo,
                    ..
                } => 2,
            };
            ProofBaseFieldElement::from_canonical(canonical)
                .expect("test source value is canonical")
        }

        fn replay_identity(
            source_half: CompactAuthenticatedSourceHalf,
        ) -> CommonProofSourcePolynomialReplayIdentity {
            let column_ordinal = source_half.source_column_ordinal().to_le_bytes();
            let value = Self::source_value(source_half).canonical().to_le_bytes();
            CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
                crate::hashing::hash_framed_parts_512(
                    "sealed-lattice/test/compact-assignment-source/v1",
                    &[&column_ordinal, &value],
                ),
            )
            .expect("test replay identity is nonzero")
        }

        fn validate_request(
            &self,
            request: CommonProofSourcePolynomialRequest<'_>,
        ) -> Result<CompactAuthenticatedSourceHalf, CommonProofProverError> {
            let source_half = self
                .catalog
                .ordered_source_halves()
                .get(self.next_source_index)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            if self.finished
                || request.request_context() != self.request_context
                || request.column_ordinal() != source_half.source_column_ordinal()
                || self.relation_plan_variant.ordered_columns().get(
                    usize::try_from(request.column_ordinal())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                ) != Some(request.descriptor())
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            Ok(source_half)
        }
    }

    impl CommonProofSourcePolynomialProvider for DeterministicTestSourceProvider {
        fn memory_accounting(
            &self,
        ) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
            Ok(CommonProofSourceProviderMemoryAccounting::new(1, 1, 8, 8))
        }

        fn poll_source_polynomial(
            &mut self,
            request: CommonProofSourcePolynomialRequest<'_>,
        ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
            let source_half = self.validate_request(request)?;
            if self.authenticated_read_source_index == Some(self.next_source_index)
                && !self.authenticated_read_satisfied
            {
                if self.pending_authenticated_read.is_none() {
                    self.pending_authenticated_read = Some(
                        CommonProofAuthenticatedSourceReadRequest::from_authenticated_source(
                            request,
                            [11_u8; 64],
                            [12_u8; 64],
                            [13_u8; 64],
                            [14_u8; 64],
                            8,
                            0,
                            u64::try_from(self.next_source_index)
                                .map_err(|_| CommonProofProverError::CountOverflow)?
                                .checked_mul(8)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                            8,
                            u32::try_from(self.next_source_index)
                                .map_err(|_| CommonProofProverError::CountOverflow)?,
                        )?,
                    );
                }
                return Ok(
                    CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired,
                );
            }
            let polynomial = if self.fault == TestSourceFault::ExtensionAtFirstSource
                && self.next_source_index == 0
            {
                CommonProofSourcePolynomial::from_extension_coefficients(vec![
                    ProofChallengeExtensionElement::ZERO,
                ])
            } else {
                CommonProofSourcePolynomial::from_base_coefficients(vec![Self::source_value(
                    source_half,
                )])
            };
            let replay_identity = Self::replay_identity(source_half);
            self.next_source_index = self
                .next_source_index
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
            Ok(CommonProofSourcePolynomialProviderPoll::Ready(
                ProvidedCommonProofSourcePolynomial::new(polynomial, replay_identity),
            ))
        }

        fn poll_replayed_source_polynomial(
            &mut self,
            _request: CommonProofSourcePolynomialRequest<'_>,
        ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
            Err(CommonProofProverError::InvalidColumn)
        }

        fn pending_authenticated_source_read_request(
            &self,
        ) -> Result<Option<CommonProofAuthenticatedSourceReadRequest>, CommonProofProverError>
        {
            Ok(self.pending_authenticated_read)
        }

        fn supply_authenticated_source_range(
            &mut self,
            request: CommonProofAuthenticatedSourceReadRequest,
            authenticated_bytes: Zeroizing<Box<[u8]>>,
        ) -> Result<(), CommonProofProverError> {
            if self.pending_authenticated_read != Some(request)
                || authenticated_bytes.as_ref() != [0xa5_u8; 8]
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            self.pending_authenticated_read = None;
            self.authenticated_read_satisfied = true;
            Ok(())
        }

        fn cancel_pending_authenticated_source_read(&mut self) {
            self.pending_authenticated_read = None;
        }

        fn finish(&mut self) -> Result<(), CommonProofProverError> {
            if self.finished
                || self.pending_authenticated_read.is_some()
                || self.next_source_index != self.catalog.ordered_source_halves().len()
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            self.finished = true;
            Ok(())
        }
    }

    fn selected_assignment_catalog() -> (
        CompactPublicKeyRelationCatalog,
        RelationPlanVariant,
        CompactAuthenticatedAssignmentCatalog,
    ) {
        let input = selected_public_key_share_relation_plan_input()
            .expect("selected public-key relation input");
        let context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected public-key relation context");
        let compiled = compile_public_key_share_relation_with_source_layout(&input, &context)
            .expect("selected public-key relation compiles");
        let relation_plan_variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("selected public-key relation variant")
            .clone();
        let relation = super::super::derive_compact_public_key_relation_catalog(
            &input,
            &relation_plan_variant,
            &compiled.source_layout,
        )
        .expect("selected compact relation derives");
        let catalog =
            CompactAuthenticatedAssignmentCatalog::derive(&relation, &relation_plan_variant)
                .expect("compact authenticated assignment mapping derives");
        (relation, relation_plan_variant, catalog)
    }

    fn test_request_context(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> CommonProofSourcePolynomialRequestContext {
        CommonProofSourcePolynomialRequestContext::new(
            1,
            [2_u8; 64],
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            [3_u8; 64],
            [4_u8; 64],
            relation.relation_plan_hash(),
            None,
            None,
        )
    }

    fn expected_source_replay_binding(
        catalog: &CompactAuthenticatedAssignmentCatalog,
        request_context: CommonProofSourcePolynomialRequestContext,
    ) -> [u8; 64] {
        let source_count = u64::try_from(catalog.ordered_source_halves().len())
            .expect("test source count fits u64");
        let mut hasher = StreamingHash512::new(
            COMPACT_AUTHENTICATED_ASSIGNMENT_BINDING_DOMAIN,
            source_count + 3,
        );
        hasher.absorb_part(&request_context.stable_generation_binding_hash());
        hasher.absorb_part(&catalog.relation_plan_hash);
        hasher.absorb_part(&source_count.to_le_bytes());
        for source_half in catalog.ordered_source_halves() {
            let mut coordinate_identity = [0_u8; 68];
            coordinate_identity[..4]
                .copy_from_slice(&source_half.source_column_ordinal().to_le_bytes());
            coordinate_identity[4..].copy_from_slice(
                &DeterministicTestSourceProvider::replay_identity(*source_half).bytes(),
            );
            hasher.absorb_part(&coordinate_identity);
        }
        hasher.finalize()
    }

    #[test]
    fn compact_assignment_uses_only_its_exact_authenticated_source_halves() {
        let (relation, relation_plan_variant, catalog) = selected_assignment_catalog();
        let source_halves = catalog.ordered_source_halves();

        assert_eq!(catalog.requested_source_column_count(), 3_302);
        assert_eq!(source_halves.len(), 202);
        assert_eq!(catalog.ignored_source_column_count(), 3_100);
        assert_eq!(catalog.source_column_ordinals().len(), source_halves.len());
        assert_eq!(
            source_halves
                .iter()
                .filter(|source| matches!(
                    source.role,
                    CompactAuthenticatedSourceRole::PublicInput { .. }
                ))
                .count(),
            122,
        );
        assert_eq!(
            source_halves
                .iter()
                .filter(|source| matches!(
                    source.role,
                    CompactAuthenticatedSourceRole::ModularQuotient { .. }
                ))
                .count(),
            58,
        );
        assert_eq!(
            source_halves
                .iter()
                .filter(|source| matches!(
                    source.role,
                    CompactAuthenticatedSourceRole::ShiftedSmallValue { .. }
                ))
                .count(),
            22,
        );
        assert!(
            source_halves
                .windows(2)
                .all(|pair| { pair[0].source_column_ordinal < pair[1].source_column_ordinal })
        );
        catalog
            .check(&relation, &relation_plan_variant)
            .expect("independent assignment mapping check");
    }

    #[test]
    fn compact_assignment_mapping_refuses_source_and_destination_mutations() {
        let (relation, relation_plan_variant, catalog) = selected_assignment_catalog();

        let mut changed_source = catalog.clone();
        changed_source.ordered_source_halves[0].source_column_ordinal = u32::MAX;
        assert_eq!(
            changed_source.check(&relation, &relation_plan_variant),
            Err(RelationPlanError::InvalidConstraint),
        );

        let mut changed_destination = catalog;
        changed_destination.ordered_source_halves[0].destination_first_element += 1;
        assert_eq!(
            changed_destination.check(&relation, &relation_plan_variant),
            Err(RelationPlanError::InvalidConstraint),
        );
    }

    #[test]
    fn compact_assignment_streams_authenticated_sources_and_materializes_bounded_inverses() {
        let (relation, relation_plan_variant, catalog) = selected_assignment_catalog();
        let request_context = test_request_context(&relation);
        let expected_source_replay_binding =
            expected_source_replay_binding(&catalog, request_context);
        let mut source_provider = DeterministicTestSourceProvider::new(
            catalog.clone(),
            relation_plan_variant.clone(),
            request_context,
            Some(0),
            TestSourceFault::None,
        );
        let provider_memory = source_provider
            .memory_accounting()
            .expect("test provider memory accounting");
        assert_eq!(
            provider_memory.maximum_returned_source_polynomial_byte_length(),
            8
        );
        let mut cursor = CompactAuthenticatedAssignmentCursor::new(
            &relation,
            &relation_plan_variant,
            request_context,
        )
        .expect("compact assignment cursor starts");
        let geometry = cursor.memory_geometry();
        assert_eq!(geometry.public_input_prefix_element_count(), 1_998_849);
        assert_eq!(geometry.base_witness_prefix_element_count(), 1_867_776);
        assert_eq!(geometry.lookup_inverse_element_count(), 950_272);
        assert_eq!(geometry.base_assignment_payload_byte_length(), 30_933_000);
        assert_eq!(
            geometry.completed_assignment_payload_byte_length(),
            68_943_880,
        );

        assert!(matches!(
            cursor
                .next_source(&relation, &relation_plan_variant, &mut source_provider)
                .expect("first source poll requests authenticated bytes"),
            CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired,
        ));
        assert_eq!(source_provider.next_source_index, 0);
        let authenticated_read = source_provider
            .pending_authenticated_source_read_request()
            .expect("pending authenticated request is readable")
            .expect("authenticated request exists");
        assert_eq!(authenticated_read.source_stream_total_byte_length(), 8);
        assert_eq!(authenticated_read.source_stream_byte_offset(), 0);
        source_provider
            .supply_authenticated_source_range(
                authenticated_read,
                Zeroizing::new(vec![0xa5_u8; 8].into_boxed_slice()),
            )
            .expect("exact authenticated bytes are supplied");

        let mut loaded_source_count = 0_usize;
        loop {
            match cursor
                .next_source(&relation, &relation_plan_variant, &mut source_provider)
                .expect("compact authenticated source poll succeeds")
            {
                CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired => {
                    panic!("the one authenticated test range was already supplied")
                }
                CompactAuthenticatedAssignmentPoll::SourceLoaded { column_ordinal } => {
                    assert_eq!(
                        Some(column_ordinal),
                        catalog
                            .ordered_source_halves()
                            .get(loaded_source_count)
                            .map(|source| source.source_column_ordinal()),
                    );
                    loaded_source_count += 1;
                }
                CompactAuthenticatedAssignmentPoll::Complete => break,
            }
        }
        let base_assignment = cursor
            .finish(&relation, &relation_plan_variant)
            .expect("completed compact assignment cursor finishes");
        assert_eq!(loaded_source_count, 202);
        assert!(source_provider.finished);
        assert_eq!(base_assignment.memory_geometry(), geometry);
        assert_eq!(
            base_assignment.source_replay_binding(),
            expected_source_replay_binding,
        );
        assert_ne!(base_assignment.source_replay_binding(), [0_u8; 64]);
        assert_eq!(
            base_assignment
                .public_input_base_value(0)
                .expect("public one exists"),
            ProofBaseFieldElement::ONE,
        );
        assert_eq!(
            base_assignment
                .public_input_base_value(geometry.public_input_prefix_element_count())
                .expect("public padding is implicit"),
            ProofBaseFieldElement::ZERO,
        );

        let quotient_segment =
            witness_segment(&relation, CompactWitnessSegmentKind::ModularQuotients)
                .expect("quotient segment exists");
        let multiplicity_segment =
            witness_segment(&relation, CompactWitnessSegmentKind::LookupMultiplicities)
                .expect("multiplicity segment exists");
        let shifted_ternary_segment =
            witness_segment(&relation, CompactWitnessSegmentKind::ShiftedTernaryValues)
                .expect("ternary segment exists");
        let shifted_eta_two_segment =
            witness_segment(&relation, CompactWitnessSegmentKind::ShiftedEtaTwoValues)
                .expect("eta-two segment exists");
        let product_segment =
            witness_segment(&relation, CompactWitnessSegmentKind::SmallSetProducts)
                .expect("small-product segment exists");
        let encoded_zero_quotient =
            ProofBaseFieldElement::from_canonical(MODULAR_QUOTIENT_ENCODING_OFFSET)
                .expect("quotient offset is canonical");
        for quotient_ordinal in [
            quotient_segment.first_element,
            quotient_segment.first_element + quotient_segment.element_count / 2,
            quotient_segment.first_element + quotient_segment.element_count - 1,
        ] {
            assert_eq!(
                base_assignment
                    .witness_base_value(quotient_ordinal)
                    .expect("encoded quotient exists"),
                encoded_zero_quotient,
            );
        }
        assert_eq!(
            base_assignment
                .witness_base_value(
                    multiplicity_segment.first_element + MODULAR_QUOTIENT_ENCODING_OFFSET,
                )
                .expect("zero-quotient multiplicity exists")
                .canonical(),
            quotient_segment.element_count,
        );
        assert_eq!(
            base_assignment
                .witness_base_value(multiplicity_segment.first_element)
                .expect("unused lookup multiplicity exists"),
            ProofBaseFieldElement::ZERO,
        );
        assert_eq!(
            base_assignment
                .witness_base_value(shifted_ternary_segment.first_element)
                .expect("shifted ternary value exists")
                .canonical(),
            1,
        );
        assert_eq!(
            base_assignment
                .witness_base_value(shifted_eta_two_segment.first_element)
                .expect("shifted eta-two value exists")
                .canonical(),
            2,
        );
        assert_eq!(
            base_assignment
                .witness_base_value(product_segment.first_element)
                .expect("first ternary product exists"),
            ProofBaseFieldElement::ZERO,
        );
        let first_eta_product = product_segment.first_element
            + relation.shifted_ternary_vector_count() * relation.ring_degree();
        assert_eq!(
            base_assignment
                .witness_base_value(first_eta_product)
                .expect("first eta-two product exists")
                .canonical(),
            2,
        );
        assert_eq!(
            base_assignment
                .witness_base_value(first_eta_product + relation.ring_degree())
                .expect("second eta-two product exists"),
            ProofBaseFieldElement::ZERO,
        );
        assert_eq!(
            base_assignment
                .witness_base_value(first_eta_product + 2 * relation.ring_degree())
                .expect("third eta-two product exists"),
            ProofBaseFieldElement::ZERO,
        );

        assert_eq!(
            validate_lookup_challenge(
                ProofChallengeExtensionElement::from_canonical_coordinates([7, 0, 0, 0, 0])
                    .expect("base-subfield challenge is canonical"),
            ),
            Err(CommonProofProverError::InvalidInput),
        );
        let lookup_challenge =
            ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
                .expect("extension challenge is canonical");
        let expected_inverse = lookup_challenge
            .add(ProofChallengeExtensionElement::from_base(
                encoded_zero_quotient,
            ))
            .inverse()
            .expect("lookup denominator is nonzero");
        let mut materializer = base_assignment
            .begin_lookup_inverse_materialization(lookup_challenge)
            .expect("bounded lookup inverse materializer starts");
        let mut materialization_poll_count = 0_u64;
        loop {
            match materializer
                .advance(8_192)
                .expect("bounded lookup inverse step succeeds")
            {
                CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                    processed_element_count,
                } => {
                    assert!(processed_element_count > 0);
                    materialization_poll_count += 1;
                }
                CompactLookupInverseMaterializationPoll::Complete => break,
            }
        }
        assert_eq!(materialization_poll_count, 233);
        let assignment = materializer
            .finish()
            .expect("completed lookup inverse materialization finishes");
        assert_eq!(assignment.memory_geometry(), geometry);
        assert_eq!(
            assignment.source_replay_binding(),
            expected_source_replay_binding,
        );
        assert_eq!(assignment.lookup_challenge(), lookup_challenge);
        assert_eq!(
            assignment
                .public_input_value(0)
                .expect("public one promotes lazily"),
            ProofChallengeExtensionElement::ONE,
        );
        for inverse_ordinal in [0, geometry.lookup_inverse_element_count() / 2, 950_271] {
            assert_eq!(
                assignment
                    .witness_value(geometry.base_witness_prefix_element_count() + inverse_ordinal,)
                    .expect("lookup inverse exists"),
                expected_inverse,
            );
        }
        assert_eq!(
            assignment
                .witness_value(geometry.padded_witness_element_count - 1)
                .expect("witness padding is implicit"),
            ProofChallengeExtensionElement::ZERO,
        );
        assert_eq!(
            assignment.witness_value(geometry.padded_witness_element_count),
            Err(CommonProofProverError::InvalidColumn),
        );
    }

    #[test]
    fn compact_assignment_refuses_wrong_source_types_contexts_and_value_ranges() {
        let (relation, relation_plan_variant, catalog) = selected_assignment_catalog();
        let request_context = test_request_context(&relation);
        let mut wrong_type_provider = DeterministicTestSourceProvider::new(
            catalog.clone(),
            relation_plan_variant.clone(),
            request_context,
            None,
            TestSourceFault::ExtensionAtFirstSource,
        );
        let mut cursor = CompactAuthenticatedAssignmentCursor::new(
            &relation,
            &relation_plan_variant,
            request_context,
        )
        .expect("compact assignment cursor starts");
        assert!(matches!(
            cursor.next_source(&relation, &relation_plan_variant, &mut wrong_type_provider,),
            Err(CommonProofProverError::InvalidColumn),
        ));

        let wrong_context = CommonProofSourcePolynomialRequestContext::new(
            1,
            [2_u8; 64],
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            [3_u8; 64],
            [4_u8; 64],
            [9_u8; 64],
            None,
            None,
        );
        assert!(matches!(
            CompactAuthenticatedAssignmentCursor::new(
                &relation,
                &relation_plan_variant,
                wrong_context,
            ),
            Err(CommonProofProverError::InvalidInput),
        ));

        let geometry = CompactAuthenticatedAssignmentMemoryGeometry::derive(&relation)
            .expect("assignment memory geometry derives");
        let quotient_source = catalog
            .ordered_source_halves()
            .iter()
            .copied()
            .find(|source| {
                matches!(
                    source.role(),
                    CompactAuthenticatedSourceRole::ModularQuotient { .. }
                )
            })
            .expect("quotient source exists");
        let mut endpoint_buffers =
            CompactBaseAssignmentBuffers::new(geometry).expect("assignment buffers allocate");
        let encoded_minimum = ProofBaseFieldElement::from_canonical(
            PROOF_BASE_FIELD_MODULUS - MODULAR_QUOTIENT_ENCODING_OFFSET,
        )
        .expect("minimum signed quotient encoding is canonical");
        let encoded_maximum = ProofBaseFieldElement::from_canonical(
            relation.quotient_lookup_table_value_count - MODULAR_QUOTIENT_ENCODING_OFFSET - 1,
        )
        .expect("maximum signed quotient encoding is canonical");
        store_modular_quotient_rows(
            &relation,
            quotient_source,
            &[encoded_minimum, encoded_maximum],
            &mut endpoint_buffers,
        )
        .expect("both exact quotient interval endpoints encode");
        assert_eq!(
            endpoint_buffers.base_witness_prefix[usize::try_from(
                quotient_source.destination_first_element()
            )
            .expect("destination fits usize")]
            .canonical(),
            0,
        );
        assert_eq!(
            endpoint_buffers.base_witness_prefix[usize::try_from(
                quotient_source.destination_first_element() + 1
            )
            .expect("destination fits usize")]
            .canonical(),
            relation.quotient_lookup_table_value_count - 1,
        );
        let first_out_of_range_positive = ProofBaseFieldElement::from_canonical(
            relation.quotient_lookup_table_value_count - MODULAR_QUOTIENT_ENCODING_OFFSET,
        )
        .expect("out-of-range test value is canonical");
        assert_eq!(
            store_modular_quotient_rows(
                &relation,
                quotient_source,
                &[first_out_of_range_positive],
                &mut endpoint_buffers,
            ),
            Err(CommonProofProverError::InvalidQuotient),
        );

        let ternary_source = catalog
            .ordered_source_halves()
            .iter()
            .copied()
            .find(|source| {
                matches!(
                    source.role(),
                    CompactAuthenticatedSourceRole::ShiftedSmallValue {
                        kind: CompactSmallVectorKind::ShiftedTernary,
                        ..
                    }
                )
            })
            .expect("ternary source exists");
        assert_eq!(
            store_shifted_small_rows(
                &relation,
                ternary_source,
                CompactSmallVectorKind::ShiftedTernary,
                &[ProofBaseFieldElement::from_canonical(3)
                    .expect("out-of-range ternary value is canonical")],
                &mut endpoint_buffers,
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
    }
}
