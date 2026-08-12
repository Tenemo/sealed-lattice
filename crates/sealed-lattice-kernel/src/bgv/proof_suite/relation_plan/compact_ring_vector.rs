//! Source-derived compact ring-vector relation catalog.
//!
//! This module lowers the selected public-key-share relation into the
//! structured extension-field R1CS geometry used by the compact successor.
//! It does not generate a proof and does not carry a producer-supplied status
//! bit. Callers must run [`CompactPublicKeyRelationCatalog::check`] against the
//! independently checked production relation before using any catalog value.

use std::collections::{BTreeMap, BTreeSet};

use crate::bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE};
use crate::foundation::ProofApplicationSlotCeilings;
use crate::hashing::StreamingHash512;

#[cfg(test)]
use super::super::{CommonProofProverError, CommonProofRelationPlanCapability};
#[cfg(test)]
use crate::bgv::setup::{SetupGenerationKeyRelationSource, SetupKeyRelationProofFamily};

use super::key_relation::{
    MODULAR_QUOTIENT_ENCODING_OFFSET, MODULAR_QUOTIENT_VALUE_COUNT,
    PublicKeyShareRelationPlanInput, SplitIntegerVector,
};
use super::public_key_share::{
    PublicKeyShareSourceLayout, compile_public_key_share_relation_with_source_layout,
};
use super::{
    RelationColumnOrigin, RelationEmbeddingKind, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, RelationVerifierSource,
};

const GOLDILOCKS_BASE_FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;
const QUINTIC_EXTENSION_DEGREE: u32 = 5;
const PUBLIC_KEY_SHARE_PRODUCT_COUNT: u64 = 23;
const ANCHOR_PRODUCT_COUNT: u64 = 9;
const MODULAR_QUOTIENT_MINIMUM: i64 = -(MODULAR_QUOTIENT_ENCODING_OFFSET as i64);
const MODULAR_QUOTIENT_MAXIMUM: i64 =
    (MODULAR_QUOTIENT_VALUE_COUNT - MODULAR_QUOTIENT_ENCODING_OFFSET - 1) as i64;
const COMPACT_RELATION_SCHEMA_DIGEST_DOMAIN: &str =
    "sealed-lattice/compact-public-key-relation-schema/v1";
const COMPACT_RELATION_SCHEMA_FIXED_PART_COUNT: u64 = 20;

const RELATION_PLAN_VARIANT_HASH_FIELD_TAG: u16 = 0x0001;
const RING_DEGREE_FIELD_TAG: u16 = 0x0002;
const EXTENSION_DEGREE_FIELD_TAG: u16 = 0x0003;
const STRUCTURED_PUBLIC_RING_PRODUCT_COUNT_FIELD_TAG: u16 = 0x0004;
const ORDERED_RELATIONS_FIELD_TAG: u16 = 0x0005;
const ORDERED_QUOTIENT_INTERVALS_FIELD_TAG: u16 = 0x0006;
const ORDERED_PUBLIC_VECTORS_FIELD_TAG: u16 = 0x0007;
const ORDERED_PRIVATE_SMALL_VECTORS_FIELD_TAG: u16 = 0x0008;
const ORDERED_WITNESS_SEGMENTS_FIELD_TAG: u16 = 0x0009;
const ORDERED_CONSTRAINT_SEGMENTS_FIELD_TAG: u16 = 0x000a;
const PUBLIC_INPUT_RING_VECTOR_COUNT_FIELD_TAG: u16 = 0x000b;
const WITNESS_RING_VECTOR_COUNT_FIELD_TAG: u16 = 0x000c;
const PADDED_PUBLIC_INPUT_ELEMENT_COUNT_FIELD_TAG: u16 = 0x000d;
const PADDED_WITNESS_ELEMENT_COUNT_FIELD_TAG: u16 = 0x000e;
const OPERATIVE_CONSTRAINT_COUNT_FIELD_TAG: u16 = 0x000f;
const PADDED_CONSTRAINT_COUNT_FIELD_TAG: u16 = 0x0010;
const QUOTIENT_LOOKUP_TABLE_VALUE_COUNT_FIELD_TAG: u16 = 0x0011;
const QUOTIENT_LOOKUP_TABLE_RING_VECTOR_COUNT_FIELD_TAG: u16 = 0x0012;
const LOOKUP_SOUNDNESS_NUMERATOR_FIELD_TAG: u16 = 0x0013;
const LOOKUP_CHALLENGE_EXCLUDES_BASE_SUBFIELD_FIELD_TAG: u16 = 0x0014;

const STRUCTURED_RELATION_RECORD_TAG: u16 = 0x0101;
const DIRECT_TERM_RECORD_TAG: u16 = 0x0111;
const NEGACYCLIC_PUBLIC_PRODUCT_TERM_RECORD_TAG: u16 = 0x0112;
const MODULUS_QUOTIENT_TERM_RECORD_TAG: u16 = 0x0113;
const QUOTIENT_INTERVAL_RECORD_TAG: u16 = 0x0201;
const PUBLIC_VECTOR_RECORD_TAG: u16 = 0x0301;
const PRIVATE_SMALL_VECTOR_RECORD_TAG: u16 = 0x0401;
const WITNESS_SEGMENT_RECORD_TAG: u16 = 0x0501;
const CONSTRAINT_SEGMENT_RECORD_TAG: u16 = 0x0601;

mod authenticated_assignment;
mod structured_r1cs;

#[cfg(test)]
use super::setup_key_relation_adapter::SetupKeyRelationSourcePolynomialAdapter;
use authenticated_assignment::validate_compact_authenticated_assignment;
#[cfg(test)]
use authenticated_assignment::{
    CompactAuthenticatedAssignmentCatalog, CompactAuthenticatedAssignmentCursor,
    CompactPublicKeyBaseAssignment,
};
#[cfg(test)]
pub(crate) use structured_r1cs::{
    compact_structured_r1cs_row_source_geometry, compact_structured_witness_covector_geometry,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CompactRingVectorReference {
    column_ordinals: [u32; 2],
}

impl From<SplitIntegerVector> for CompactRingVectorReference {
    fn from(value: SplitIntegerVector) -> Self {
        Self {
            column_ordinals: value.halves,
        }
    }
}

impl CompactRingVectorReference {
    pub(crate) const fn column_ordinals(self) -> [u32; 2] {
        self.column_ordinals
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyRelationFamily {
    PublicKeyShare,
    OrdinaryAnchor,
    FinalAnchor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactStructuredLinearTerm {
    Direct {
        vector: CompactRingVectorReference,
        centered_offset: u64,
        integer_coefficient: i128,
    },
    NegacyclicPublicProduct {
        public_vector: CompactRingVectorReference,
        private_vector: CompactRingVectorReference,
        private_centered_offset: u64,
        integer_coefficient: i8,
    },
    ModulusQuotient {
        quotient_vector: CompactRingVectorReference,
        modulus: u64,
        integer_coefficient: i8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactStructuredRelation {
    family: CompactPublicKeyRelationFamily,
    data_modulus_index: u16,
    modulus: u64,
    ordered_terms: Vec<CompactStructuredLinearTerm>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactExactQuotientInterval {
    family: CompactPublicKeyRelationFamily,
    data_modulus_index: u16,
    modulus: u64,
    numerator_minimum: i128,
    numerator_maximum: i128,
    quotient_minimum: i64,
    quotient_maximum: i64,
    codec_minimum: i64,
    codec_maximum: i64,
    residual_minimum: i128,
    residual_maximum: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompactWitnessSegmentKind {
    ModularQuotients,
    LookupMultiplicities,
    ShiftedTernaryValues,
    ShiftedEtaTwoValues,
    SmallSetProducts,
    LookupInverses,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompactSmallVectorKind {
    ShiftedTernary,
    ShiftedEtaTwo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactSmallVectorDescriptor {
    vector: CompactRingVectorReference,
    kind: CompactSmallVectorKind,
    centered_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactWitnessSegment {
    kind: CompactWitnessSegmentKind,
    first_element: u64,
    ring_vector_count: u64,
    element_count: u64,
}

/// Exact production coefficient ranges used by the lookup reduction.
///
/// The pre-challenge source contains the modular quotients followed by one
/// multiplicity for every table value. The challenge-dependent inverses live
/// in the final operative segment of the complete main witness. Keeping these
/// ranges in the relation owner prevents semantic proof code from reconstructing
/// a parallel layout or accepting an inverse vector unrelated to the committed
/// main witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CompactLookupRelationGeometry {
    source_first_element: u64,
    source_element_count: u64,
    multiplicity_first_element: u64,
    table_value_count: u64,
    inverse_first_element: u64,
    inverse_element_count: u64,
    pre_challenge_message_element_count: u64,
    main_message_element_count: u64,
    soundness_numerator: u64,
    challenge_excludes_base_subfield: bool,
}

#[cfg(test)]
impl CompactLookupRelationGeometry {
    fn derive(catalog: &CompactPublicKeyRelationCatalog) -> Result<Self, RelationPlanError> {
        let quotient_segment =
            unique_witness_segment(catalog, CompactWitnessSegmentKind::ModularQuotients)?;
        let multiplicity_segment =
            unique_witness_segment(catalog, CompactWitnessSegmentKind::LookupMultiplicities)?;
        let inverse_segment =
            unique_witness_segment(catalog, CompactWitnessSegmentKind::LookupInverses)?;
        let cross_epoch_geometry = CompactCrossEpochCopyGeometry::derive(catalog)?;
        let occupied_pre_challenge_element_count = quotient_segment
            .element_count
            .checked_add(multiplicity_segment.element_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        let expected_soundness_numerator = occupied_pre_challenge_element_count
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let inverse_end = inverse_segment
            .first_element
            .checked_add(inverse_segment.element_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        if quotient_segment.first_element != 0
            || quotient_segment.element_count == 0
            || quotient_segment.ring_vector_count != catalog.quotient_vector_count()
            || multiplicity_segment.first_element != quotient_segment.element_count
            || multiplicity_segment.element_count != catalog.quotient_lookup_table_value_count
            || multiplicity_segment.ring_vector_count
                != catalog.quotient_lookup_table_ring_vector_count
            || inverse_segment.element_count != quotient_segment.element_count
            || inverse_segment.ring_vector_count != quotient_segment.ring_vector_count
            || inverse_end > catalog.padded_witness_element_count
            || occupied_pre_challenge_element_count != cross_epoch_geometry.copied_element_count
            || expected_soundness_numerator != catalog.lookup_soundness_numerator
            || !catalog.lookup_challenge_excludes_base_subfield
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(Self {
            source_first_element: quotient_segment.first_element,
            source_element_count: quotient_segment.element_count,
            multiplicity_first_element: multiplicity_segment.first_element,
            table_value_count: multiplicity_segment.element_count,
            inverse_first_element: inverse_segment.first_element,
            inverse_element_count: inverse_segment.element_count,
            pre_challenge_message_element_count: cross_epoch_geometry
                .pre_challenge_message_element_count,
            main_message_element_count: cross_epoch_geometry.main_message_element_count,
            soundness_numerator: catalog.lookup_soundness_numerator,
            challenge_excludes_base_subfield: catalog.lookup_challenge_excludes_base_subfield,
        })
    }

    pub(crate) const fn source_first_element(self) -> u64 {
        self.source_first_element
    }

    pub(crate) const fn source_element_count(self) -> u64 {
        self.source_element_count
    }

    pub(crate) const fn multiplicity_first_element(self) -> u64 {
        self.multiplicity_first_element
    }

    pub(crate) const fn table_value_count(self) -> u64 {
        self.table_value_count
    }

    pub(crate) const fn inverse_first_element(self) -> u64 {
        self.inverse_first_element
    }

    pub(crate) const fn inverse_element_count(self) -> u64 {
        self.inverse_element_count
    }

    pub(crate) const fn pre_challenge_message_element_count(self) -> u64 {
        self.pre_challenge_message_element_count
    }

    pub(crate) const fn main_message_element_count(self) -> u64 {
        self.main_message_element_count
    }

    pub(crate) const fn soundness_numerator(self) -> u64 {
        self.soundness_numerator
    }

    pub(crate) const fn challenge_excludes_base_subfield(self) -> bool {
        self.challenge_excludes_base_subfield
    }
}

/// Exact coefficient layout used to bind the pre-challenge lookup message to
/// its copy at the front of the complete R1CS witness.
///
/// The pre-challenge message contains the modular quotients followed by the
/// lookup multiplicities and canonical zero padding. The complete witness
/// begins with those same two segments, but its later witness segments are not
/// part of the copy relation. Consequently the main-epoch linear functional
/// has the pre-challenge multilinear weights on the copied prefix and zero on
/// every later main-witness coefficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCrossEpochCopyGeometry {
    copied_ring_vector_count: u64,
    copied_element_count: u64,
    pre_challenge_message_element_count: u64,
    main_message_element_count: u64,
    point_coordinate_count: u32,
}

impl CompactCrossEpochCopyGeometry {
    fn derive(catalog: &CompactPublicKeyRelationCatalog) -> Result<Self, RelationPlanError> {
        let [
            quotient_segment,
            multiplicity_segment,
            remaining_segments @ ..,
        ] = catalog.ordered_witness_segments.as_slice()
        else {
            return Err(RelationPlanError::InvalidConstraint);
        };
        let expected_first_remaining_element = quotient_segment
            .element_count
            .checked_add(multiplicity_segment.element_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        if quotient_segment.kind != CompactWitnessSegmentKind::ModularQuotients
            || quotient_segment.first_element != 0
            || quotient_segment.ring_vector_count != catalog.quotient_vector_count()
            || multiplicity_segment.kind != CompactWitnessSegmentKind::LookupMultiplicities
            || multiplicity_segment.first_element != quotient_segment.element_count
            || multiplicity_segment.ring_vector_count
                != catalog.quotient_lookup_table_ring_vector_count
            || remaining_segments
                .first()
                .is_none_or(|segment| segment.first_element != expected_first_remaining_element)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let copied_ring_vector_count = quotient_segment
            .ring_vector_count
            .checked_add(multiplicity_segment.ring_vector_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        let copied_element_count = copied_ring_vector_count
            .checked_mul(catalog.ring_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        if copied_element_count
            != quotient_segment
                .element_count
                .checked_add(multiplicity_segment.element_count)
                .ok_or(RelationPlanError::CountOverflow)?
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let pre_challenge_message_element_count = copied_element_count
            .checked_next_power_of_two()
            .ok_or(RelationPlanError::CountOverflow)?;
        let main_message_element_count = catalog.padded_witness_element_count;
        let expected_main_message_element_count = pre_challenge_message_element_count
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?;
        if copied_element_count == 0
            || pre_challenge_message_element_count >= main_message_element_count
            || main_message_element_count != expected_main_message_element_count
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let point_coordinate_count = pre_challenge_message_element_count.ilog2();

        Ok(Self {
            copied_ring_vector_count,
            copied_element_count,
            pre_challenge_message_element_count,
            main_message_element_count,
            point_coordinate_count,
        })
    }

    pub(crate) const fn copied_ring_vector_count(self) -> u64 {
        self.copied_ring_vector_count
    }

    pub(crate) const fn copied_element_count(self) -> u64 {
        self.copied_element_count
    }

    pub(crate) const fn pre_challenge_message_element_count(self) -> u64 {
        self.pre_challenge_message_element_count
    }

    pub(crate) const fn main_message_element_count(self) -> u64 {
        self.main_message_element_count
    }

    pub(crate) const fn point_coordinate_count(self) -> u32 {
        self.point_coordinate_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactR1csConstraintKind {
    ExactIntegerLift,
    LookupInverse,
    TernaryFirstProduct,
    TernaryTerminalProduct,
    EtaTwoFirstProduct,
    EtaTwoSecondProduct,
    EtaTwoThirdProduct,
    EtaTwoTerminalProduct,
    LookupLogDerivativeEquality,
    ZeroPadding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactR1csConstraintSegment {
    kind: CompactR1csConstraintKind,
    first_row: u64,
    row_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactPublicKeyRelationCatalog {
    relation_plan_variant_hash: [u8; 64],
    ring_degree: u64,
    extension_degree: u32,
    structured_public_ring_product_count: u64,
    ordered_relations: Vec<CompactStructuredRelation>,
    ordered_quotient_intervals: Vec<CompactExactQuotientInterval>,
    ordered_public_vectors: Vec<CompactRingVectorReference>,
    ordered_private_small_vectors: Vec<CompactSmallVectorDescriptor>,
    ordered_witness_segments: Vec<CompactWitnessSegment>,
    ordered_constraint_segments: Vec<CompactR1csConstraintSegment>,
    public_input_ring_vector_count: u64,
    witness_ring_vector_count: u64,
    padded_public_input_element_count: u64,
    padded_witness_element_count: u64,
    operative_constraint_count: u64,
    padded_constraint_count: u64,
    quotient_lookup_table_value_count: u64,
    quotient_lookup_table_ring_vector_count: u64,
    lookup_soundness_numerator: u64,
    lookup_challenge_excludes_base_subfield: bool,
}

impl CompactPublicKeyRelationCatalog {
    #[cfg(test)]
    pub(crate) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(crate) const fn ring_degree(&self) -> u64 {
        self.ring_degree
    }

    #[cfg(test)]
    pub(crate) const fn extension_degree(&self) -> u32 {
        self.extension_degree
    }

    pub(crate) const fn public_input_ring_vector_count(&self) -> u64 {
        self.public_input_ring_vector_count
    }

    #[cfg(test)]
    pub(crate) const fn witness_ring_vector_count(&self) -> u64 {
        self.witness_ring_vector_count
    }

    pub(crate) const fn padded_witness_element_count(&self) -> u64 {
        self.padded_witness_element_count
    }

    #[cfg(test)]
    pub(crate) const fn operative_constraint_count(&self) -> u64 {
        self.operative_constraint_count
    }

    #[cfg(test)]
    pub(crate) const fn padded_constraint_count(&self) -> u64 {
        self.padded_constraint_count
    }

    pub(crate) const fn quotient_vector_count(&self) -> u64 {
        self.ordered_quotient_intervals.len() as u64
    }

    #[cfg(test)]
    pub(crate) const fn shifted_ternary_vector_count(&self) -> u64 {
        self.ordered_private_small_vectors.len().saturating_sub(1) as u64
    }

    #[cfg(test)]
    pub(crate) const fn quotient_lookup_table_ring_vector_count(&self) -> u64 {
        self.quotient_lookup_table_ring_vector_count
    }

    #[cfg(test)]
    pub(crate) const fn structured_public_ring_product_count(&self) -> u64 {
        self.structured_public_ring_product_count
    }

    #[cfg(test)]
    pub(crate) const fn quotient_lookup_table_value_count(&self) -> u64 {
        self.quotient_lookup_table_value_count
    }

    #[cfg(test)]
    pub(crate) fn public_key_share_relation_count(&self) -> usize {
        self.ordered_relations
            .iter()
            .filter(|relation| relation.family == CompactPublicKeyRelationFamily::PublicKeyShare)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn ordinary_anchor_relation_count(&self) -> usize {
        self.ordered_relations
            .iter()
            .filter(|relation| relation.family == CompactPublicKeyRelationFamily::OrdinaryAnchor)
            .count()
    }

    #[cfg(test)]
    pub(crate) fn final_anchor_relation_count(&self) -> usize {
        self.ordered_relations
            .iter()
            .filter(|relation| relation.family == CompactPublicKeyRelationFamily::FinalAnchor)
            .count()
    }

    #[cfg(test)]
    pub(crate) const fn lookup_soundness_numerator(&self) -> u64 {
        self.lookup_soundness_numerator
    }

    /// Hashes the complete ordered relation schema without accepting any
    /// producer-supplied digest or status. Every integer payload uses its
    /// fixed-width little-endian representation, and every field, record, and
    /// closed enum variant is identified by an explicit tag.
    pub(crate) fn canonical_schema_digest(&self) -> Result<[u8; 64], RelationPlanError> {
        let mut digest = CompactRelationSchemaDigestWriter::new(
            compact_relation_schema_digest_part_count(self)?,
        );

        digest.absorb_tagged(
            RELATION_PLAN_VARIANT_HASH_FIELD_TAG,
            &[&self.relation_plan_variant_hash],
        )?;
        digest.absorb_u64(RING_DEGREE_FIELD_TAG, self.ring_degree)?;
        digest.absorb_u32(EXTENSION_DEGREE_FIELD_TAG, self.extension_degree)?;
        digest.absorb_u64(
            STRUCTURED_PUBLIC_RING_PRODUCT_COUNT_FIELD_TAG,
            self.structured_public_ring_product_count,
        )?;

        digest.absorb_u64(
            ORDERED_RELATIONS_FIELD_TAG,
            canonical_collection_length(self.ordered_relations.len())?,
        )?;
        for (relation_ordinal, relation) in self.ordered_relations.iter().enumerate() {
            let relation_ordinal = canonical_collection_length(relation_ordinal)?;
            let relation_ordinal_bytes = relation_ordinal.to_le_bytes();
            let family_bytes = compact_relation_family_tag(relation.family).to_le_bytes();
            let data_modulus_index_bytes = relation.data_modulus_index.to_le_bytes();
            let modulus_bytes = relation.modulus.to_le_bytes();
            let term_count_bytes =
                canonical_collection_length(relation.ordered_terms.len())?.to_le_bytes();
            digest.absorb_tagged(
                STRUCTURED_RELATION_RECORD_TAG,
                &[
                    &relation_ordinal_bytes,
                    &family_bytes,
                    &data_modulus_index_bytes,
                    &modulus_bytes,
                    &term_count_bytes,
                ],
            )?;

            for (term_ordinal, term) in relation.ordered_terms.iter().enumerate() {
                let term_ordinal_bytes = canonical_collection_length(term_ordinal)?.to_le_bytes();
                match term {
                    CompactStructuredLinearTerm::Direct {
                        vector,
                        centered_offset,
                        integer_coefficient,
                    } => {
                        let columns = vector.column_ordinals();
                        let first_column_bytes = columns[0].to_le_bytes();
                        let second_column_bytes = columns[1].to_le_bytes();
                        let centered_offset_bytes = centered_offset.to_le_bytes();
                        let coefficient_bytes = integer_coefficient.to_le_bytes();
                        digest.absorb_tagged(
                            DIRECT_TERM_RECORD_TAG,
                            &[
                                &relation_ordinal_bytes,
                                &term_ordinal_bytes,
                                &first_column_bytes,
                                &second_column_bytes,
                                &centered_offset_bytes,
                                &coefficient_bytes,
                            ],
                        )?;
                    }
                    CompactStructuredLinearTerm::NegacyclicPublicProduct {
                        public_vector,
                        private_vector,
                        private_centered_offset,
                        integer_coefficient,
                    } => {
                        let public_columns = public_vector.column_ordinals();
                        let private_columns = private_vector.column_ordinals();
                        let public_first_column_bytes = public_columns[0].to_le_bytes();
                        let public_second_column_bytes = public_columns[1].to_le_bytes();
                        let private_first_column_bytes = private_columns[0].to_le_bytes();
                        let private_second_column_bytes = private_columns[1].to_le_bytes();
                        let private_centered_offset_bytes = private_centered_offset.to_le_bytes();
                        let coefficient_bytes = integer_coefficient.to_le_bytes();
                        digest.absorb_tagged(
                            NEGACYCLIC_PUBLIC_PRODUCT_TERM_RECORD_TAG,
                            &[
                                &relation_ordinal_bytes,
                                &term_ordinal_bytes,
                                &public_first_column_bytes,
                                &public_second_column_bytes,
                                &private_first_column_bytes,
                                &private_second_column_bytes,
                                &private_centered_offset_bytes,
                                &coefficient_bytes,
                            ],
                        )?;
                    }
                    CompactStructuredLinearTerm::ModulusQuotient {
                        quotient_vector,
                        modulus,
                        integer_coefficient,
                    } => {
                        let columns = quotient_vector.column_ordinals();
                        let first_column_bytes = columns[0].to_le_bytes();
                        let second_column_bytes = columns[1].to_le_bytes();
                        let modulus_bytes = modulus.to_le_bytes();
                        let coefficient_bytes = integer_coefficient.to_le_bytes();
                        digest.absorb_tagged(
                            MODULUS_QUOTIENT_TERM_RECORD_TAG,
                            &[
                                &relation_ordinal_bytes,
                                &term_ordinal_bytes,
                                &first_column_bytes,
                                &second_column_bytes,
                                &modulus_bytes,
                                &coefficient_bytes,
                            ],
                        )?;
                    }
                }
            }
        }

        digest.absorb_u64(
            ORDERED_QUOTIENT_INTERVALS_FIELD_TAG,
            canonical_collection_length(self.ordered_quotient_intervals.len())?,
        )?;
        for (interval_ordinal, interval) in self.ordered_quotient_intervals.iter().enumerate() {
            let interval_ordinal_bytes =
                canonical_collection_length(interval_ordinal)?.to_le_bytes();
            let family_bytes = compact_relation_family_tag(interval.family).to_le_bytes();
            let data_modulus_index_bytes = interval.data_modulus_index.to_le_bytes();
            let modulus_bytes = interval.modulus.to_le_bytes();
            let numerator_minimum_bytes = interval.numerator_minimum.to_le_bytes();
            let numerator_maximum_bytes = interval.numerator_maximum.to_le_bytes();
            let quotient_minimum_bytes = interval.quotient_minimum.to_le_bytes();
            let quotient_maximum_bytes = interval.quotient_maximum.to_le_bytes();
            let codec_minimum_bytes = interval.codec_minimum.to_le_bytes();
            let codec_maximum_bytes = interval.codec_maximum.to_le_bytes();
            let residual_minimum_bytes = interval.residual_minimum.to_le_bytes();
            let residual_maximum_bytes = interval.residual_maximum.to_le_bytes();
            digest.absorb_tagged(
                QUOTIENT_INTERVAL_RECORD_TAG,
                &[
                    &interval_ordinal_bytes,
                    &family_bytes,
                    &data_modulus_index_bytes,
                    &modulus_bytes,
                    &numerator_minimum_bytes,
                    &numerator_maximum_bytes,
                    &quotient_minimum_bytes,
                    &quotient_maximum_bytes,
                    &codec_minimum_bytes,
                    &codec_maximum_bytes,
                    &residual_minimum_bytes,
                    &residual_maximum_bytes,
                ],
            )?;
        }

        digest.absorb_u64(
            ORDERED_PUBLIC_VECTORS_FIELD_TAG,
            canonical_collection_length(self.ordered_public_vectors.len())?,
        )?;
        for (vector_ordinal, vector) in self.ordered_public_vectors.iter().enumerate() {
            let vector_ordinal_bytes = canonical_collection_length(vector_ordinal)?.to_le_bytes();
            let columns = vector.column_ordinals();
            let first_column_bytes = columns[0].to_le_bytes();
            let second_column_bytes = columns[1].to_le_bytes();
            digest.absorb_tagged(
                PUBLIC_VECTOR_RECORD_TAG,
                &[
                    &vector_ordinal_bytes,
                    &first_column_bytes,
                    &second_column_bytes,
                ],
            )?;
        }

        digest.absorb_u64(
            ORDERED_PRIVATE_SMALL_VECTORS_FIELD_TAG,
            canonical_collection_length(self.ordered_private_small_vectors.len())?,
        )?;
        for (vector_ordinal, descriptor) in self.ordered_private_small_vectors.iter().enumerate() {
            let vector_ordinal_bytes = canonical_collection_length(vector_ordinal)?.to_le_bytes();
            let columns = descriptor.vector.column_ordinals();
            let first_column_bytes = columns[0].to_le_bytes();
            let second_column_bytes = columns[1].to_le_bytes();
            let kind_bytes = compact_small_vector_kind_tag(descriptor.kind).to_le_bytes();
            let centered_offset_bytes = descriptor.centered_offset.to_le_bytes();
            digest.absorb_tagged(
                PRIVATE_SMALL_VECTOR_RECORD_TAG,
                &[
                    &vector_ordinal_bytes,
                    &first_column_bytes,
                    &second_column_bytes,
                    &kind_bytes,
                    &centered_offset_bytes,
                ],
            )?;
        }

        digest.absorb_u64(
            ORDERED_WITNESS_SEGMENTS_FIELD_TAG,
            canonical_collection_length(self.ordered_witness_segments.len())?,
        )?;
        for (segment_ordinal, segment) in self.ordered_witness_segments.iter().enumerate() {
            let segment_ordinal_bytes = canonical_collection_length(segment_ordinal)?.to_le_bytes();
            let kind_bytes = compact_witness_segment_kind_tag(segment.kind).to_le_bytes();
            let first_element_bytes = segment.first_element.to_le_bytes();
            let ring_vector_count_bytes = segment.ring_vector_count.to_le_bytes();
            let element_count_bytes = segment.element_count.to_le_bytes();
            digest.absorb_tagged(
                WITNESS_SEGMENT_RECORD_TAG,
                &[
                    &segment_ordinal_bytes,
                    &kind_bytes,
                    &first_element_bytes,
                    &ring_vector_count_bytes,
                    &element_count_bytes,
                ],
            )?;
        }

        digest.absorb_u64(
            ORDERED_CONSTRAINT_SEGMENTS_FIELD_TAG,
            canonical_collection_length(self.ordered_constraint_segments.len())?,
        )?;
        for (segment_ordinal, segment) in self.ordered_constraint_segments.iter().enumerate() {
            let segment_ordinal_bytes = canonical_collection_length(segment_ordinal)?.to_le_bytes();
            let kind_bytes = compact_constraint_kind_tag(segment.kind).to_le_bytes();
            let first_row_bytes = segment.first_row.to_le_bytes();
            let row_count_bytes = segment.row_count.to_le_bytes();
            digest.absorb_tagged(
                CONSTRAINT_SEGMENT_RECORD_TAG,
                &[
                    &segment_ordinal_bytes,
                    &kind_bytes,
                    &first_row_bytes,
                    &row_count_bytes,
                ],
            )?;
        }

        digest.absorb_u64(
            PUBLIC_INPUT_RING_VECTOR_COUNT_FIELD_TAG,
            self.public_input_ring_vector_count,
        )?;
        digest.absorb_u64(
            WITNESS_RING_VECTOR_COUNT_FIELD_TAG,
            self.witness_ring_vector_count,
        )?;
        digest.absorb_u64(
            PADDED_PUBLIC_INPUT_ELEMENT_COUNT_FIELD_TAG,
            self.padded_public_input_element_count,
        )?;
        digest.absorb_u64(
            PADDED_WITNESS_ELEMENT_COUNT_FIELD_TAG,
            self.padded_witness_element_count,
        )?;
        digest.absorb_u64(
            OPERATIVE_CONSTRAINT_COUNT_FIELD_TAG,
            self.operative_constraint_count,
        )?;
        digest.absorb_u64(
            PADDED_CONSTRAINT_COUNT_FIELD_TAG,
            self.padded_constraint_count,
        )?;
        digest.absorb_u64(
            QUOTIENT_LOOKUP_TABLE_VALUE_COUNT_FIELD_TAG,
            self.quotient_lookup_table_value_count,
        )?;
        digest.absorb_u64(
            QUOTIENT_LOOKUP_TABLE_RING_VECTOR_COUNT_FIELD_TAG,
            self.quotient_lookup_table_ring_vector_count,
        )?;
        digest.absorb_u64(
            LOOKUP_SOUNDNESS_NUMERATOR_FIELD_TAG,
            self.lookup_soundness_numerator,
        )?;
        digest.absorb_bool(
            LOOKUP_CHALLENGE_EXCLUDES_BASE_SUBFIELD_FIELD_TAG,
            self.lookup_challenge_excludes_base_subfield,
        )?;
        digest.finalize()
    }

    #[cfg(test)]
    pub(crate) fn lookup_relation_geometry(
        &self,
    ) -> Result<CompactLookupRelationGeometry, RelationPlanError> {
        CompactLookupRelationGeometry::derive(self)
    }

    pub(crate) fn cross_epoch_copy_geometry(
        &self,
    ) -> Result<CompactCrossEpochCopyGeometry, RelationPlanError> {
        CompactCrossEpochCopyGeometry::derive(self)
    }

    pub(crate) fn maximum_residual_interval_width(&self) -> Result<u64, RelationPlanError> {
        self.ordered_quotient_intervals
            .iter()
            .map(|interval| {
                interval
                    .residual_maximum
                    .checked_sub(interval.residual_minimum)
                    .and_then(|width| u64::try_from(width).ok())
                    .ok_or(RelationPlanError::IntegerBoundOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or(RelationPlanError::InvalidConstraint)
    }

    pub(crate) fn check(
        &self,
        input: &PublicKeyShareRelationPlanInput,
        context: &RelationPlanCheckContext,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        if self.relation_plan_variant_hash != variant.canonical_hash()?
            || self.ring_degree != input.ring_degree
            || self.ring_degree
                != u64::try_from(POLYNOMIAL_DEGREE).map_err(|_| RelationPlanError::CountOverflow)?
            || self.extension_degree != QUINTIC_EXTENSION_DEGREE
            || context.base_field_modulus != GOLDILOCKS_BASE_FIELD_MODULUS
            || u32::from(context.challenge_extension_degree) != QUINTIC_EXTENSION_DEGREE
            || usize::try_from(self.extension_degree)
                .map_err(|_| RelationPlanError::CountOverflow)?
                != super::super::PROOF_CHALLENGE_EXTENSION_DEGREE
            || self.ordered_relations.len() != self.ordered_quotient_intervals.len()
            || !self.lookup_challenge_excludes_base_subfield
            || self.structured_public_ring_product_count
                != PUBLIC_KEY_SHARE_PRODUCT_COUNT + ANCHOR_PRODUCT_COUNT
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        check_contiguous_witness_segments(
            &self.ordered_witness_segments,
            self.padded_witness_element_count,
        )?;
        check_contiguous_constraint_segments(
            &self.ordered_constraint_segments,
            self.padded_constraint_count,
        )?;
        check_public_vectors_are_canonical(variant, &self.ordered_public_vectors)?;
        check_private_vectors_are_prover_owned(variant, &self.ordered_private_small_vectors)?;
        validate_compact_authenticated_assignment(self, variant)?;
        structured_r1cs::CompactStructuredR1csCatalog::derive(self)?;
        self.cross_epoch_copy_geometry()?;
        if self.padded_public_input_element_count != self.padded_witness_element_count
            || self.padded_constraint_count != 2 * self.padded_witness_element_count
            || self.operative_constraint_count >= self.padded_constraint_count
            || self.maximum_residual_interval_width()? >= GOLDILOCKS_BASE_FIELD_MODULUS
        {
            return Err(RelationPlanError::NoWrapBoundViolated);
        }
        Ok(())
    }
}

struct CompactRelationSchemaDigestWriter {
    hasher: StreamingHash512,
    expected_part_count: u64,
    absorbed_part_count: u64,
}

impl CompactRelationSchemaDigestWriter {
    fn new(expected_part_count: u64) -> Self {
        Self {
            hasher: StreamingHash512::new(
                COMPACT_RELATION_SCHEMA_DIGEST_DOMAIN,
                expected_part_count,
            ),
            expected_part_count,
            absorbed_part_count: 0,
        }
    }

    fn absorb_tagged(
        &mut self,
        tag: u16,
        payload_chunks: &[&[u8]],
    ) -> Result<(), RelationPlanError> {
        if self.absorbed_part_count >= self.expected_part_count {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let part_byte_length = payload_chunks.iter().try_fold(2_u64, |total, chunk| {
            total
                .checked_add(
                    u64::try_from(chunk.len()).map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::CountOverflow)
        })?;
        self.hasher.begin_part(part_byte_length);
        self.hasher.absorb_raw(&tag.to_le_bytes());
        for chunk in payload_chunks {
            self.hasher.absorb_raw(chunk);
        }
        self.absorbed_part_count = self
            .absorbed_part_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        Ok(())
    }

    fn absorb_u64(&mut self, tag: u16, value: u64) -> Result<(), RelationPlanError> {
        self.absorb_tagged(tag, &[&value.to_le_bytes()])
    }

    fn absorb_u32(&mut self, tag: u16, value: u32) -> Result<(), RelationPlanError> {
        self.absorb_tagged(tag, &[&value.to_le_bytes()])
    }

    fn absorb_bool(&mut self, tag: u16, value: bool) -> Result<(), RelationPlanError> {
        self.absorb_tagged(tag, &[&[u8::from(value)]])
    }

    fn finalize(self) -> Result<[u8; 64], RelationPlanError> {
        if self.absorbed_part_count != self.expected_part_count {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(self.hasher.finalize())
    }
}

fn compact_relation_schema_digest_part_count(
    catalog: &CompactPublicKeyRelationCatalog,
) -> Result<u64, RelationPlanError> {
    let relation_and_term_count =
        catalog
            .ordered_relations
            .iter()
            .try_fold(0_u64, |total, relation| {
                total
                    .checked_add(1)
                    .and_then(|count| {
                        count.checked_add(u64::try_from(relation.ordered_terms.len()).ok()?)
                    })
                    .ok_or(RelationPlanError::CountOverflow)
            })?;
    [
        relation_and_term_count,
        canonical_collection_length(catalog.ordered_quotient_intervals.len())?,
        canonical_collection_length(catalog.ordered_public_vectors.len())?,
        canonical_collection_length(catalog.ordered_private_small_vectors.len())?,
        canonical_collection_length(catalog.ordered_witness_segments.len())?,
        canonical_collection_length(catalog.ordered_constraint_segments.len())?,
    ]
    .into_iter()
    .try_fold(COMPACT_RELATION_SCHEMA_FIXED_PART_COUNT, |total, count| {
        total
            .checked_add(count)
            .ok_or(RelationPlanError::CountOverflow)
    })
}

fn canonical_collection_length(length: usize) -> Result<u64, RelationPlanError> {
    u64::try_from(length).map_err(|_| RelationPlanError::CountOverflow)
}

const fn compact_relation_family_tag(family: CompactPublicKeyRelationFamily) -> u16 {
    match family {
        CompactPublicKeyRelationFamily::PublicKeyShare => 0x0001,
        CompactPublicKeyRelationFamily::OrdinaryAnchor => 0x0002,
        CompactPublicKeyRelationFamily::FinalAnchor => 0x0003,
    }
}

const fn compact_small_vector_kind_tag(kind: CompactSmallVectorKind) -> u16 {
    match kind {
        CompactSmallVectorKind::ShiftedTernary => 0x0001,
        CompactSmallVectorKind::ShiftedEtaTwo => 0x0002,
    }
}

const fn compact_witness_segment_kind_tag(kind: CompactWitnessSegmentKind) -> u16 {
    match kind {
        CompactWitnessSegmentKind::ModularQuotients => 0x0001,
        CompactWitnessSegmentKind::LookupMultiplicities => 0x0002,
        CompactWitnessSegmentKind::ShiftedTernaryValues => 0x0003,
        CompactWitnessSegmentKind::ShiftedEtaTwoValues => 0x0004,
        CompactWitnessSegmentKind::SmallSetProducts => 0x0005,
        CompactWitnessSegmentKind::LookupInverses => 0x0006,
    }
}

const fn compact_constraint_kind_tag(kind: CompactR1csConstraintKind) -> u16 {
    match kind {
        CompactR1csConstraintKind::ExactIntegerLift => 0x0001,
        CompactR1csConstraintKind::LookupInverse => 0x0002,
        CompactR1csConstraintKind::TernaryFirstProduct => 0x0003,
        CompactR1csConstraintKind::TernaryTerminalProduct => 0x0004,
        CompactR1csConstraintKind::EtaTwoFirstProduct => 0x0005,
        CompactR1csConstraintKind::EtaTwoSecondProduct => 0x0006,
        CompactR1csConstraintKind::EtaTwoThirdProduct => 0x0007,
        CompactR1csConstraintKind::EtaTwoTerminalProduct => 0x0008,
        CompactR1csConstraintKind::LookupLogDerivativeEquality => 0x0009,
        CompactR1csConstraintKind::ZeroPadding => 0x000a,
    }
}

fn selected_input_and_context()
-> Result<(PublicKeyShareRelationPlanInput, RelationPlanCheckContext), RelationPlanError> {
    let input = super::super::selected_public_key_share_relation_plan_input()
        .map_err(|_| RelationPlanError::InvalidDomain)?;
    let context = super::super::selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(RelationPlanError::UnsupportedApplicationFamily)?;
    Ok((input, context))
}

pub(crate) fn selected_compact_public_key_relation_catalog()
-> Result<CompactPublicKeyRelationCatalog, RelationPlanError> {
    let (input, context) = selected_input_and_context()?;
    let compiled = compile_public_key_share_relation_with_source_layout(&input, &context)?;
    compiled.relation_plan.check(&context)?;
    let variant = compiled.relation_plan.select_variant(None, None)?;
    let catalog =
        derive_compact_public_key_relation_catalog(&input, variant, &compiled.source_layout)?;
    catalog.check(&input, &context, variant)?;
    Ok(catalog)
}

/// Authenticated production inputs for the compact public-key assignment.
///
/// This is a pre-proof development boundary. It binds the compact relation and
/// exact 202-column request to the retained setup authority, but it neither
/// selects a packing factor nor authorizes or emits proof bytes.
#[cfg(test)]
pub(crate) struct PreparedCompactPublicKeyAssignmentSources {
    pub(crate) relation_plan_variant: RelationPlanVariant,
    pub(crate) relation: CompactPublicKeyRelationCatalog,
    pub(crate) assignment_cursor: CompactAuthenticatedAssignmentCursor,
    pub(crate) source_polynomials: SetupKeyRelationSourcePolynomialAdapter,
}

#[cfg(test)]
pub(crate) struct PreparedCompactPublicKeyBaseAssignment {
    pub(crate) relation: CompactPublicKeyRelationCatalog,
    pub(crate) base_assignment: CompactPublicKeyBaseAssignment,
}

#[cfg(test)]
impl PreparedCompactPublicKeyAssignmentSources {
    pub(crate) fn finish_source_loading(
        self,
    ) -> Result<PreparedCompactPublicKeyBaseAssignment, CommonProofProverError> {
        let Self {
            relation_plan_variant,
            relation,
            assignment_cursor,
            source_polynomials,
        } = self;
        let (input, relation_context) = selected_input_and_context()?;
        let compiled =
            compile_public_key_share_relation_with_source_layout(&input, &relation_context)?;
        compiled.relation_plan.check(&relation_context)?;
        let expected_relation_plan_variant = compiled.relation_plan.select_variant(None, None)?;
        if relation_plan_variant != *expected_relation_plan_variant {
            return Err(CommonProofProverError::InvalidInput);
        }
        relation.check(&input, &relation_context, &relation_plan_variant)?;
        let base_assignment = assignment_cursor.finish(&relation, &relation_plan_variant)?;
        source_polynomials.finish_compact_public_key_assignment_sources()?;
        drop((relation_plan_variant, relation_context));
        Ok(PreparedCompactPublicKeyBaseAssignment {
            relation,
            base_assignment,
        })
    }
}

#[cfg(test)]
pub(crate) fn prepare_compact_public_key_assignment_sources(
    source: &SetupGenerationKeyRelationSource<'_, '_>,
    relation_plan: CommonProofRelationPlanCapability,
) -> Result<PreparedCompactPublicKeyAssignmentSources, CommonProofProverError> {
    if source.family() != SetupKeyRelationProofFamily::PublicKeyShare {
        return Err(CommonProofProverError::InvalidInput);
    }
    let (input, relation_context) = selected_input_and_context()?;
    let compiled = compile_public_key_share_relation_with_source_layout(&input, &relation_context)?;
    compiled.relation_plan.check(&relation_context)?;
    let relation_plan_variant = compiled.relation_plan.select_variant(None, None)?.clone();
    if relation_plan.application_statement_schema_identifier()
        != ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        || relation_plan.relation_plan_hash() != compiled.relation_plan.canonical_hash()?
        || relation_plan.relation_plan_variant_hash() != relation_plan_variant.canonical_hash()?
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let relation = derive_compact_public_key_relation_catalog(
        &input,
        &relation_plan_variant,
        &compiled.source_layout,
    )?;
    relation.check(&input, &relation_context, &relation_plan_variant)?;
    let source_polynomials =
        SetupKeyRelationSourcePolynomialAdapter::new_compact_public_key_assignment(
            source,
            &relation_plan,
            relation_plan_variant.clone(),
            relation_context.clone(),
            usize::try_from(input.ring_degree)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
            compiled.source_layout,
        )?;
    let assignment_cursor = CompactAuthenticatedAssignmentCursor::new(
        &relation,
        &relation_plan_variant,
        source_polynomials.compact_public_key_assignment_request_context()?,
    )?;
    drop(relation_plan);
    Ok(PreparedCompactPublicKeyAssignmentSources {
        relation_plan_variant,
        relation,
        assignment_cursor,
        source_polynomials,
    })
}

#[cfg(test)]
pub(super) fn compact_public_key_authenticated_source_column_ordinals(
    input: &PublicKeyShareRelationPlanInput,
    variant: &RelationPlanVariant,
    source_layout: &PublicKeyShareSourceLayout,
) -> Result<Vec<u32>, RelationPlanError> {
    let relation = derive_compact_public_key_relation_catalog(input, variant, source_layout)?;
    CompactAuthenticatedAssignmentCatalog::derive(&relation, variant)
        .map(|catalog| catalog.source_column_ordinals())
}

pub(crate) fn derive_compact_public_key_relation_catalog(
    input: &PublicKeyShareRelationPlanInput,
    variant: &RelationPlanVariant,
    source_layout: &PublicKeyShareSourceLayout,
) -> Result<CompactPublicKeyRelationCatalog, RelationPlanError> {
    let ring_degree = input.ring_degree;
    if ring_degree == 0
        || source_layout.public_key_share_limbs.len() != input.data_modulus_indices.len()
        || source_layout.public_key_common_reference_limbs.len() != input.data_modulus_indices.len()
        || source_layout.ordered_limbs.len() != input.data_modulus_indices.len()
        || source_layout.ordered_anchors.len() != input.commitment_data_modulus_indices.len()
    {
        return Err(RelationPlanError::InvalidConstraint);
    }

    let common_secret =
        CompactRingVectorReference::from(source_layout.common_secret.source.coefficients);
    let public_key_error =
        CompactRingVectorReference::from(source_layout.public_key_error.coefficients);
    let mut relations = Vec::new();
    let mut quotient_intervals = Vec::new();
    let mut public_vectors = BTreeSet::new();
    let mut private_small_vectors = BTreeMap::new();
    insert_private_small_vector(
        &mut private_small_vectors,
        common_secret,
        CompactSmallVectorKind::ShiftedTernary,
        source_layout.common_secret.source.offset,
    )?;
    insert_private_small_vector(
        &mut private_small_vectors,
        public_key_error,
        CompactSmallVectorKind::ShiftedEtaTwo,
        source_layout.public_key_error.offset,
    )?;

    for (limb_ordinal, limb) in source_layout.ordered_limbs.iter().enumerate() {
        let expected_data_modulus_index = input.data_modulus_indices[limb_ordinal];
        if limb.data_modulus_index != expected_data_modulus_index {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        let modulus = data_modulus(expected_data_modulus_index)?;
        let public_key_share =
            CompactRingVectorReference::from(source_layout.public_key_share_limbs[limb_ordinal]);
        let common_reference = CompactRingVectorReference::from(
            source_layout.public_key_common_reference_limbs[limb_ordinal],
        );
        let quotient = CompactRingVectorReference {
            column_ordinals: limb.quotient_columns,
        };
        public_vectors.extend([public_key_share, common_reference]);
        relations.push(CompactStructuredRelation {
            family: CompactPublicKeyRelationFamily::PublicKeyShare,
            data_modulus_index: expected_data_modulus_index,
            modulus,
            ordered_terms: vec![
                CompactStructuredLinearTerm::Direct {
                    vector: public_key_share,
                    centered_offset: 0,
                    integer_coefficient: 1,
                },
                CompactStructuredLinearTerm::NegacyclicPublicProduct {
                    public_vector: common_reference,
                    private_vector: common_secret,
                    private_centered_offset: source_layout.common_secret.source.offset,
                    integer_coefficient: 1,
                },
                CompactStructuredLinearTerm::Direct {
                    vector: public_key_error,
                    centered_offset: source_layout.public_key_error.offset,
                    integer_coefficient: -i128::from(input.plaintext_modulus),
                },
                CompactStructuredLinearTerm::ModulusQuotient {
                    quotient_vector: quotient,
                    modulus,
                    integer_coefficient: -1,
                },
            ],
        });
        quotient_intervals.push(exact_quotient_interval(
            CompactPublicKeyRelationFamily::PublicKeyShare,
            expected_data_modulus_index,
            modulus,
            ring_degree,
            input.plaintext_modulus,
            1,
        )?);
    }

    for (anchor_ordinal, anchor) in source_layout.ordered_anchors.iter().enumerate() {
        let expected_data_modulus_index = input.commitment_data_modulus_indices[anchor_ordinal];
        if anchor.data_modulus_index != expected_data_modulus_index {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        let modulus = data_modulus(expected_data_modulus_index)?;
        let rank = usize::from(input.commitment_module_rank);
        if anchor.commitments.len() != rank + 1
            || anchor.first_matrix.len() != rank
            || anchor.first_matrix.iter().any(|row| row.len() != rank + 1)
            || anchor.second_matrix.len() != rank
            || anchor.opening.hiding_secrets().len() != rank + 1
            || anchor.opening.hiding_errors().len() != rank
            || anchor.quotients.rows().len() != rank + 1
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        public_vectors.extend(
            anchor
                .commitments
                .iter()
                .copied()
                .map(CompactRingVectorReference::from),
        );
        public_vectors.extend(
            anchor
                .first_matrix
                .iter()
                .flat_map(|row| row.iter().copied())
                .map(CompactRingVectorReference::from),
        );
        public_vectors.extend(
            anchor
                .second_matrix
                .iter()
                .copied()
                .map(CompactRingVectorReference::from),
        );
        for hiding_secret in anchor.opening.hiding_secrets() {
            insert_private_small_vector(
                &mut private_small_vectors,
                CompactRingVectorReference::from(hiding_secret.source.coefficients),
                CompactSmallVectorKind::ShiftedTernary,
                hiding_secret.source.offset,
            )?;
        }
        for hiding_error in anchor.opening.hiding_errors() {
            insert_private_small_vector(
                &mut private_small_vectors,
                CompactRingVectorReference::from(hiding_error.coefficients),
                CompactSmallVectorKind::ShiftedTernary,
                hiding_error.offset,
            )?;
        }

        for row_ordinal in 0..rank {
            let commitment = CompactRingVectorReference::from(anchor.commitments[row_ordinal]);
            let hiding_error = CompactRingVectorReference::from(
                anchor.opening.hiding_errors()[row_ordinal].coefficients,
            );
            let quotient = CompactRingVectorReference {
                column_ordinals: anchor.quotients.rows()[row_ordinal],
            };
            let mut terms = vec![
                CompactStructuredLinearTerm::Direct {
                    vector: commitment,
                    centered_offset: 0,
                    integer_coefficient: 1,
                },
                CompactStructuredLinearTerm::Direct {
                    vector: hiding_error,
                    centered_offset: anchor.opening.hiding_errors()[row_ordinal].offset,
                    integer_coefficient: -1,
                },
            ];
            for column_ordinal in 0..=rank {
                let hiding_secret = &anchor.opening.hiding_secrets()[column_ordinal];
                terms.push(CompactStructuredLinearTerm::NegacyclicPublicProduct {
                    public_vector: CompactRingVectorReference::from(
                        anchor.first_matrix[row_ordinal][column_ordinal],
                    ),
                    private_vector: CompactRingVectorReference::from(
                        hiding_secret.source.coefficients,
                    ),
                    private_centered_offset: hiding_secret.source.offset,
                    integer_coefficient: -1,
                });
            }
            terms.push(CompactStructuredLinearTerm::ModulusQuotient {
                quotient_vector: quotient,
                modulus,
                integer_coefficient: -1,
            });
            relations.push(CompactStructuredRelation {
                family: CompactPublicKeyRelationFamily::OrdinaryAnchor,
                data_modulus_index: expected_data_modulus_index,
                modulus,
                ordered_terms: terms,
            });
            quotient_intervals.push(exact_quotient_interval(
                CompactPublicKeyRelationFamily::OrdinaryAnchor,
                expected_data_modulus_index,
                modulus,
                ring_degree,
                input.plaintext_modulus,
                u64::try_from(rank + 1).map_err(|_| RelationPlanError::CountOverflow)?,
            )?);
        }

        let commitment = CompactRingVectorReference::from(anchor.commitments[rank]);
        let final_hiding_secret = &anchor.opening.hiding_secrets()[rank];
        let quotient = CompactRingVectorReference {
            column_ordinals: anchor.quotients.rows()[rank],
        };
        let mut terms = vec![
            CompactStructuredLinearTerm::Direct {
                vector: commitment,
                centered_offset: 0,
                integer_coefficient: 1,
            },
            CompactStructuredLinearTerm::Direct {
                vector: CompactRingVectorReference::from(final_hiding_secret.source.coefficients),
                centered_offset: final_hiding_secret.source.offset,
                integer_coefficient: -1,
            },
            CompactStructuredLinearTerm::Direct {
                vector: common_secret,
                centered_offset: source_layout.common_secret.source.offset,
                integer_coefficient: -1,
            },
        ];
        for (second_matrix_column, hiding_secret) in anchor
            .second_matrix
            .iter()
            .copied()
            .zip(anchor.opening.hiding_secrets())
        {
            terms.push(CompactStructuredLinearTerm::NegacyclicPublicProduct {
                public_vector: CompactRingVectorReference::from(second_matrix_column),
                private_vector: CompactRingVectorReference::from(hiding_secret.source.coefficients),
                private_centered_offset: hiding_secret.source.offset,
                integer_coefficient: -1,
            });
        }
        terms.push(CompactStructuredLinearTerm::ModulusQuotient {
            quotient_vector: quotient,
            modulus,
            integer_coefficient: -1,
        });
        relations.push(CompactStructuredRelation {
            family: CompactPublicKeyRelationFamily::FinalAnchor,
            data_modulus_index: expected_data_modulus_index,
            modulus,
            ordered_terms: terms,
        });
        quotient_intervals.push(exact_quotient_interval(
            CompactPublicKeyRelationFamily::FinalAnchor,
            expected_data_modulus_index,
            modulus,
            ring_degree,
            input.plaintext_modulus,
            1,
        )?);
    }

    let quotient_vector_count =
        u64::try_from(quotient_intervals.len()).map_err(|_| RelationPlanError::CountOverflow)?;
    let mut ordered_private_small_vectors = private_small_vectors.into_values().collect::<Vec<_>>();
    ordered_private_small_vectors
        .sort_unstable_by_key(|descriptor| (descriptor.kind, descriptor.vector));
    let shifted_ternary_vector_count = u64::try_from(
        ordered_private_small_vectors
            .iter()
            .filter(|descriptor| descriptor.kind == CompactSmallVectorKind::ShiftedTernary)
            .count(),
    )
    .map_err(|_| RelationPlanError::CountOverflow)?;
    let shifted_eta_two_vector_count = u64::try_from(
        ordered_private_small_vectors
            .iter()
            .filter(|descriptor| descriptor.kind == CompactSmallVectorKind::ShiftedEtaTwo)
            .count(),
    )
    .map_err(|_| RelationPlanError::CountOverflow)?;
    let private_small_vector_count = shifted_ternary_vector_count
        .checked_add(shifted_eta_two_vector_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    if private_small_vector_count == 0
        || shifted_ternary_vector_count == 0
        || shifted_eta_two_vector_count != 1
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let lookup_table_ring_vector_count = MODULAR_QUOTIENT_VALUE_COUNT.div_ceil(ring_degree);
    let small_set_product_vector_count = shifted_ternary_vector_count
        .checked_add(3 * shifted_eta_two_vector_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    let witness_vector_counts = [
        (
            CompactWitnessSegmentKind::ModularQuotients,
            quotient_vector_count,
        ),
        (
            CompactWitnessSegmentKind::LookupMultiplicities,
            lookup_table_ring_vector_count,
        ),
        (
            CompactWitnessSegmentKind::ShiftedTernaryValues,
            shifted_ternary_vector_count,
        ),
        (
            CompactWitnessSegmentKind::ShiftedEtaTwoValues,
            shifted_eta_two_vector_count,
        ),
        (
            CompactWitnessSegmentKind::SmallSetProducts,
            small_set_product_vector_count,
        ),
        (
            CompactWitnessSegmentKind::LookupInverses,
            quotient_vector_count,
        ),
    ];
    let (ordered_witness_segments, witness_element_count) =
        witness_segments(ring_degree, &witness_vector_counts)?;
    let witness_ring_vector_count =
        witness_vector_counts
            .iter()
            .try_fold(0_u64, |count, (_, vectors)| {
                count
                    .checked_add(*vectors)
                    .ok_or(RelationPlanError::CountOverflow)
            })?;
    let padded_witness_element_count = witness_element_count
        .checked_next_power_of_two()
        .ok_or(RelationPlanError::CountOverflow)?;
    let public_input_ring_vector_count =
        u64::try_from(public_vectors.len()).map_err(|_| RelationPlanError::CountOverflow)?;
    let public_input_element_count = public_input_ring_vector_count
        .checked_mul(ring_degree)
        .and_then(|count| count.checked_add(1))
        .ok_or(RelationPlanError::CountOverflow)?;
    if public_input_element_count > padded_witness_element_count {
        return Err(RelationPlanError::InvalidConstraint);
    }

    let exact_integer_lift_row_count = quotient_vector_count
        .checked_mul(ring_degree)
        .ok_or(RelationPlanError::CountOverflow)?;
    let lookup_inverse_row_count = exact_integer_lift_row_count;
    let ternary_product_row_count = shifted_ternary_vector_count
        .checked_mul(ring_degree)
        .ok_or(RelationPlanError::CountOverflow)?;
    let eta_two_product_row_count = shifted_eta_two_vector_count
        .checked_mul(ring_degree)
        .ok_or(RelationPlanError::CountOverflow)?;
    let operative_constraint_counts = [
        (
            CompactR1csConstraintKind::ExactIntegerLift,
            exact_integer_lift_row_count,
        ),
        (
            CompactR1csConstraintKind::LookupInverse,
            lookup_inverse_row_count,
        ),
        (
            CompactR1csConstraintKind::TernaryFirstProduct,
            ternary_product_row_count,
        ),
        (
            CompactR1csConstraintKind::TernaryTerminalProduct,
            ternary_product_row_count,
        ),
        (
            CompactR1csConstraintKind::EtaTwoFirstProduct,
            eta_two_product_row_count,
        ),
        (
            CompactR1csConstraintKind::EtaTwoSecondProduct,
            eta_two_product_row_count,
        ),
        (
            CompactR1csConstraintKind::EtaTwoThirdProduct,
            eta_two_product_row_count,
        ),
        (
            CompactR1csConstraintKind::EtaTwoTerminalProduct,
            eta_two_product_row_count,
        ),
        (CompactR1csConstraintKind::LookupLogDerivativeEquality, 1),
    ];
    let padded_constraint_count = padded_witness_element_count
        .checked_mul(2)
        .ok_or(RelationPlanError::CountOverflow)?;
    let (ordered_constraint_segments, operative_constraint_count) =
        constraint_segments(&operative_constraint_counts, padded_constraint_count)?;
    let quotient_entry_count = quotient_vector_count
        .checked_mul(ring_degree)
        .ok_or(RelationPlanError::CountOverflow)?;
    let padded_lookup_table_entry_count = lookup_table_ring_vector_count
        .checked_mul(ring_degree)
        .ok_or(RelationPlanError::CountOverflow)?;

    Ok(CompactPublicKeyRelationCatalog {
        relation_plan_variant_hash: variant.canonical_hash()?,
        ring_degree,
        extension_degree: QUINTIC_EXTENSION_DEGREE,
        structured_public_ring_product_count: relations
            .iter()
            .flat_map(|relation| &relation.ordered_terms)
            .filter(|term| {
                matches!(
                    term,
                    CompactStructuredLinearTerm::NegacyclicPublicProduct { .. }
                )
            })
            .count()
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)?,
        ordered_relations: relations,
        ordered_quotient_intervals: quotient_intervals,
        ordered_public_vectors: public_vectors.into_iter().collect(),
        ordered_private_small_vectors,
        ordered_witness_segments,
        ordered_constraint_segments,
        public_input_ring_vector_count,
        witness_ring_vector_count,
        padded_public_input_element_count: padded_witness_element_count,
        padded_witness_element_count,
        operative_constraint_count,
        padded_constraint_count,
        quotient_lookup_table_value_count: MODULAR_QUOTIENT_VALUE_COUNT,
        quotient_lookup_table_ring_vector_count: lookup_table_ring_vector_count,
        lookup_soundness_numerator: quotient_entry_count
            .checked_add(padded_lookup_table_entry_count)
            .and_then(|count| count.checked_sub(1))
            .ok_or(RelationPlanError::CountOverflow)?,
        lookup_challenge_excludes_base_subfield: true,
    })
}

fn exact_quotient_interval(
    family: CompactPublicKeyRelationFamily,
    data_modulus_index: u16,
    modulus: u64,
    ring_degree: u64,
    plaintext_modulus: u64,
    product_count: u64,
) -> Result<CompactExactQuotientInterval, RelationPlanError> {
    let ring_degree = i128::from(ring_degree);
    let modulus_integer = i128::from(modulus);
    let maximum_residue = modulus_integer - 1;
    let product_bound = ring_degree
        .checked_mul(maximum_residue)
        .and_then(|bound| bound.checked_mul(i128::from(product_count)))
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    let (numerator_minimum, numerator_maximum) = match family {
        CompactPublicKeyRelationFamily::PublicKeyShare => (
            -product_bound - 2 * i128::from(plaintext_modulus),
            maximum_residue + product_bound + 2 * i128::from(plaintext_modulus),
        ),
        CompactPublicKeyRelationFamily::OrdinaryAnchor => {
            (-product_bound - 1, maximum_residue + product_bound + 1)
        }
        CompactPublicKeyRelationFamily::FinalAnchor => {
            (-product_bound - 2, maximum_residue + product_bound + 2)
        }
    };
    let quotient_minimum = -i64::try_from((-numerator_minimum).div_euclid(modulus_integer))
        .map_err(|_| RelationPlanError::IntegerBoundOverflow)?;
    let quotient_maximum = i64::try_from(numerator_maximum.div_euclid(modulus_integer))
        .map_err(|_| RelationPlanError::IntegerBoundOverflow)?;
    if quotient_minimum < MODULAR_QUOTIENT_MINIMUM || quotient_maximum > MODULAR_QUOTIENT_MAXIMUM {
        return Err(RelationPlanError::NoWrapBoundViolated);
    }
    let residual_minimum = numerator_minimum
        .checked_sub(modulus_integer * i128::from(MODULAR_QUOTIENT_MAXIMUM))
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    let residual_maximum = numerator_maximum
        .checked_sub(modulus_integer * i128::from(MODULAR_QUOTIENT_MINIMUM))
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    Ok(CompactExactQuotientInterval {
        family,
        data_modulus_index,
        modulus,
        numerator_minimum,
        numerator_maximum,
        quotient_minimum,
        quotient_maximum,
        codec_minimum: MODULAR_QUOTIENT_MINIMUM,
        codec_maximum: MODULAR_QUOTIENT_MAXIMUM,
        residual_minimum,
        residual_maximum,
    })
}

fn witness_segments(
    ring_degree: u64,
    ordered_counts: &[(CompactWitnessSegmentKind, u64)],
) -> Result<(Vec<CompactWitnessSegment>, u64), RelationPlanError> {
    let mut first_element = 0_u64;
    let mut segments = Vec::with_capacity(ordered_counts.len());
    for (kind, ring_vector_count) in ordered_counts {
        let element_count = ring_vector_count
            .checked_mul(ring_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        segments.push(CompactWitnessSegment {
            kind: *kind,
            first_element,
            ring_vector_count: *ring_vector_count,
            element_count,
        });
        first_element = first_element
            .checked_add(element_count)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok((segments, first_element))
}

#[cfg(test)]
fn unique_witness_segment(
    catalog: &CompactPublicKeyRelationCatalog,
    kind: CompactWitnessSegmentKind,
) -> Result<CompactWitnessSegment, RelationPlanError> {
    let mut matching_segments = catalog
        .ordered_witness_segments
        .iter()
        .copied()
        .filter(|segment| segment.kind == kind);
    let segment = matching_segments
        .next()
        .ok_or(RelationPlanError::InvalidConstraint)?;
    if matching_segments.next().is_some() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(segment)
}

fn constraint_segments(
    operative_counts: &[(CompactR1csConstraintKind, u64)],
    padded_constraint_count: u64,
) -> Result<(Vec<CompactR1csConstraintSegment>, u64), RelationPlanError> {
    let mut first_row = 0_u64;
    let mut segments = Vec::with_capacity(operative_counts.len() + 1);
    for (kind, row_count) in operative_counts {
        segments.push(CompactR1csConstraintSegment {
            kind: *kind,
            first_row,
            row_count: *row_count,
        });
        first_row = first_row
            .checked_add(*row_count)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    let operative_constraint_count = first_row;
    let padding_row_count = padded_constraint_count
        .checked_sub(operative_constraint_count)
        .ok_or(RelationPlanError::InvalidConstraint)?;
    segments.push(CompactR1csConstraintSegment {
        kind: CompactR1csConstraintKind::ZeroPadding,
        first_row,
        row_count: padding_row_count,
    });
    Ok((segments, operative_constraint_count))
}

fn check_contiguous_witness_segments(
    segments: &[CompactWitnessSegment],
    padded_witness_element_count: u64,
) -> Result<(), RelationPlanError> {
    let mut expected_first = 0_u64;
    for segment in segments {
        if segment.first_element != expected_first
            || segment.element_count
                != segment
                    .ring_vector_count
                    .checked_mul(
                        u64::try_from(POLYNOMIAL_DEGREE)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::CountOverflow)?
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        expected_first = expected_first
            .checked_add(segment.element_count)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    if expected_first > padded_witness_element_count {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(())
}

fn check_contiguous_constraint_segments(
    segments: &[CompactR1csConstraintSegment],
    padded_constraint_count: u64,
) -> Result<(), RelationPlanError> {
    let mut expected_first = 0_u64;
    for segment in segments {
        if segment.first_row != expected_first {
            return Err(RelationPlanError::InvalidConstraint);
        }
        expected_first = expected_first
            .checked_add(segment.row_count)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    if expected_first != padded_constraint_count {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(())
}

fn check_public_vectors_are_canonical(
    variant: &RelationPlanVariant,
    vectors: &[CompactRingVectorReference],
) -> Result<(), RelationPlanError> {
    for vector in vectors {
        for column_ordinal in vector.column_ordinals {
            let column = variant
                .ordered_columns()
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::InvalidColumn)?;
            let modulus_reference = column
                .canonical_residue_modulus()
                .ok_or(RelationPlanError::InvalidColumn)?;
            match column.origin() {
                RelationColumnOrigin::BoundTree { .. } => {}
                RelationColumnOrigin::VerifierSequence {
                    verifier_source_ordinal,
                    ..
                } => {
                    let source = variant
                        .verifier_source(*verifier_source_ordinal)
                        .ok_or(RelationPlanError::InvalidSource)?;
                    let value_layout = match source {
                        RelationVerifierSource::ApplicationStatement { value_layout, .. }
                        | RelationVerifierSource::Protocol { value_layout, .. } => value_layout,
                        _ => return Err(RelationPlanError::InvalidSource),
                    };
                    if value_layout.embedding_kind != RelationEmbeddingKind::LeastNonnegative
                        || value_layout.residue_modulus != Some(modulus_reference)
                    {
                        return Err(RelationPlanError::InvalidSource);
                    }
                }
                RelationColumnOrigin::Prover => return Err(RelationPlanError::InvalidColumn),
            }
        }
    }
    Ok(())
}

fn check_private_vectors_are_prover_owned(
    variant: &RelationPlanVariant,
    vectors: &[CompactSmallVectorDescriptor],
) -> Result<(), RelationPlanError> {
    for descriptor in vectors {
        let expected_offset = match descriptor.kind {
            CompactSmallVectorKind::ShiftedTernary => 1,
            CompactSmallVectorKind::ShiftedEtaTwo => 2,
        };
        if descriptor.centered_offset != expected_offset {
            return Err(RelationPlanError::InvalidConstraint);
        }
        for column_ordinal in descriptor.vector.column_ordinals {
            let column = variant
                .ordered_columns()
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::InvalidColumn)?;
            if !matches!(column.origin(), RelationColumnOrigin::Prover) {
                return Err(RelationPlanError::InvalidColumn);
            }
        }
    }
    Ok(())
}

fn insert_private_small_vector(
    vectors: &mut BTreeMap<CompactRingVectorReference, CompactSmallVectorDescriptor>,
    vector: CompactRingVectorReference,
    kind: CompactSmallVectorKind,
    centered_offset: u64,
) -> Result<(), RelationPlanError> {
    let descriptor = CompactSmallVectorDescriptor {
        vector,
        kind,
        centered_offset,
    };
    match vectors.insert(vector, descriptor) {
        None => Ok(()),
        Some(previous) if previous == descriptor => Err(RelationPlanError::DuplicateItem),
        Some(_) => Err(RelationPlanError::InvalidConstraint),
    }
}

fn data_modulus(data_modulus_index: u16) -> Result<u64, RelationPlanError> {
    DATA_PRIMES
        .get(usize::from(data_modulus_index))
        .copied()
        .ok_or(RelationPlanError::MissingModulus)
}

#[cfg(test)]
mod tests {
    use super::super::interpreter::checked_relation_compiler_interpreter_semantics;
    use super::*;

    fn selected_compilation() -> Result<
        (
            PublicKeyShareRelationPlanInput,
            RelationPlanCheckContext,
            super::super::public_key_share::CompiledPublicKeyShareRelation,
        ),
        RelationPlanError,
    > {
        let (input, context) = selected_input_and_context()?;
        let compiled = compile_public_key_share_relation_with_source_layout(&input, &context)?;
        Ok((input, context, compiled))
    }

    #[test]
    fn compact_public_key_relation_catalog_matches_the_checked_production_relation() {
        let (input, context, compiled) = selected_compilation().expect("selected compilation");
        let variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("selected variant");
        let catalog =
            derive_compact_public_key_relation_catalog(&input, variant, &compiled.source_layout)
                .expect("compact public-key catalog");
        catalog
            .check(&input, &context, variant)
            .expect("independently checked compact public-key catalog");
        let interpreter_certificate =
            checked_relation_compiler_interpreter_semantics(variant, &context)
                .expect("independent relation interpreter");
        assert!(interpreter_certificate.is_complete());

        assert_eq!(catalog.ring_degree(), 32_768);
        assert_eq!(catalog.extension_degree(), 5);
        assert_eq!(catalog.quotient_vector_count(), 29);
        assert_eq!(catalog.shifted_ternary_vector_count(), 10);
        assert_eq!(catalog.quotient_lookup_table_ring_vector_count(), 4);
        assert_eq!(catalog.public_input_ring_vector_count(), 61);
        assert_eq!(catalog.witness_ring_vector_count(), 86);
        assert_eq!(catalog.padded_witness_element_count(), 4_194_304);
        assert_eq!(catalog.operative_constraint_count(), 2_686_977);
        assert_eq!(catalog.padded_constraint_count(), 8_388_608);
        assert_eq!(catalog.structured_public_ring_product_count, 32);
        assert_eq!(
            catalog.structured_public_ring_product_count,
            PUBLIC_KEY_SHARE_PRODUCT_COUNT + ANCHOR_PRODUCT_COUNT
        );
        assert_eq!(catalog.lookup_soundness_numerator(), 1_081_343);
        let lookup = catalog
            .lookup_relation_geometry()
            .expect("selected lookup coefficient geometry");
        assert_eq!(lookup.source_first_element(), 0);
        assert_eq!(lookup.source_element_count(), 950_272);
        assert_eq!(lookup.multiplicity_first_element(), 950_272);
        assert_eq!(lookup.table_value_count(), 131_072);
        assert_eq!(lookup.inverse_first_element(), 1_867_776);
        assert_eq!(lookup.inverse_element_count(), 950_272);
        assert_eq!(lookup.pre_challenge_message_element_count(), 2_097_152);
        assert_eq!(lookup.main_message_element_count(), 4_194_304);
        assert_eq!(lookup.soundness_numerator(), 1_081_343);
        assert!(lookup.challenge_excludes_base_subfield());
        assert_eq!(
            catalog.maximum_residual_interval_width(),
            Ok(662_283_957_175_299)
        );
        assert_eq!(catalog.quotient_lookup_table_value_count, 131_072);
        let cross_epoch_copy = catalog
            .cross_epoch_copy_geometry()
            .expect("selected cross-epoch copy geometry");
        assert_eq!(cross_epoch_copy.copied_ring_vector_count(), 33);
        assert_eq!(cross_epoch_copy.copied_element_count(), 1_081_344);
        assert_eq!(
            cross_epoch_copy.pre_challenge_message_element_count(),
            2_097_152
        );
        assert_eq!(cross_epoch_copy.main_message_element_count(), 4_194_304);
        assert_eq!(cross_epoch_copy.point_coordinate_count(), 21);
    }

    #[test]
    fn compact_public_key_relation_schema_digest_binds_nested_fields() {
        let (input, _context, compiled) = selected_compilation().expect("selected compilation");
        let variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("selected variant");
        let catalog =
            derive_compact_public_key_relation_catalog(&input, variant, &compiled.source_layout)
                .expect("compact public-key catalog");
        let digest = catalog
            .canonical_schema_digest()
            .expect("canonical schema digest");
        let mut changed_term = catalog.clone();
        let CompactStructuredLinearTerm::Direct {
            integer_coefficient,
            ..
        } = &mut changed_term.ordered_relations[0].ordered_terms[0]
        else {
            panic!("the first structured term is direct")
        };
        *integer_coefficient += 1;
        assert_ne!(
            digest,
            changed_term
                .canonical_schema_digest()
                .expect("mutated term schema digest")
        );

        let mut changed_scalar = catalog.clone();
        changed_scalar.padded_constraint_count += 1;
        assert_ne!(
            digest,
            changed_scalar
                .canonical_schema_digest()
                .expect("mutated scalar schema digest")
        );
    }

    #[test]
    fn compact_public_key_relation_catalog_rejects_mutated_authority_and_geometry() {
        let (input, context, compiled) = selected_compilation().expect("selected compilation");
        let variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("selected variant");
        let catalog =
            derive_compact_public_key_relation_catalog(&input, variant, &compiled.source_layout)
                .expect("compact public-key catalog");

        let mut wrong_hash = catalog.clone();
        wrong_hash.relation_plan_variant_hash[0] ^= 1;
        assert_eq!(
            wrong_hash.check(&input, &context, variant),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut wrong_extension_boundary = catalog.clone();
        wrong_extension_boundary.extension_degree = 1;
        assert_eq!(
            wrong_extension_boundary.check(&input, &context, variant),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut overlapping_witness = catalog.clone();
        overlapping_witness.ordered_witness_segments[1].first_element -= 1;
        assert_eq!(
            overlapping_witness.check(&input, &context, variant),
            Err(RelationPlanError::InvalidConstraint)
        );

        let mut missing_constraint = catalog.clone();
        missing_constraint.ordered_constraint_segments[0].row_count -= 1;
        assert_eq!(
            missing_constraint.check(&input, &context, variant),
            Err(RelationPlanError::InvalidConstraint)
        );
    }
}
