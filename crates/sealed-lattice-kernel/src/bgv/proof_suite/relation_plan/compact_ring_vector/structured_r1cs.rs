//! Row-addressable structured R1CS matrices for the compact ring-vector relation.
//!
//! The matrices are never materialized densely. Each row instead owns an
//! exact sparse or structured description of its `A`, `B`, and `C` linear
//! forms. Public negacyclic products are matrix bands derived by the verifier
//! from the canonical public input; they are not prover-supplied witness
//! products. The focused semantic test below evaluates every operative row
//! through both the matrix description and an independent relation
//! interpreter.

mod witness_covector;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the compact generation state consumes the release factor-one WHIR primitives at the next integration boundary"
    )
)]
#[path = "production_small_chain.rs"]
mod production_small_chain;

#[cfg(test)]
pub(crate) use witness_covector::compact_structured_witness_covector_geometry;

pub(crate) use witness_covector::{
    CompactStructuredAssignmentTransposeSource, CompactStructuredWitnessCovectorAccumulator,
    CompactStructuredWitnessCovectorAccumulatorPoll,
    CompactStructuredWitnessCovectorAccumulatorStep, StructuredTransposeValueSource,
};
#[cfg(test)]
pub(crate) use witness_covector::{
    CompactStructuredWitnessCovectorHandoff, CompactStructuredWitnessCovectorHandoffPoll,
};

use std::rc::Rc;

#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

use p3_field::PrimeCharacteristicRing;
use zeroize::Zeroizing;

use crate::bgv::proof_suite::{
    PROOF_BASE_FIELD_MODULUS, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofEvaluationDomain,
    compact_cfw::{
        COMPACT_CFW_MATRIX_COUNT, CompactCfwError, CompactCfwMatrixRole, CompactCfwR1csMatrices,
        CompactChallengeField, compact_challenge_from_production,
    },
    compact_cfw_external_prover::CompactCfwExternalRowSource,
    prover::CommonProofProverError,
};

use super::super::key_relation::MODULAR_QUOTIENT_ENCODING_OFFSET;
use super::authenticated_assignment::CompactPublicKeyAssignment;
use super::{
    CompactPublicKeyRelationCatalog, CompactR1csConstraintKind, CompactRingVectorReference,
    CompactSmallVectorKind, CompactStructuredLinearTerm, CompactWitnessSegmentKind,
    RelationPlanError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactStructuredMatrixTerm {
    StaticEntry {
        column_ordinal: u64,
        integer_coefficient: i128,
    },
    LookupChallengeEntry {
        column_ordinal: u64,
    },
    UniformStaticRange {
        first_column_ordinal: u64,
        element_count: u64,
        integer_coefficient: i128,
    },
    NegatedLookupTableReciprocalRange {
        first_column_ordinal: u64,
        table_value_count: u64,
    },
    PublicNegacyclicMatrixBand {
        public_vector_first_column_ordinal: u64,
        private_vector_first_column_ordinal: u64,
        output_coefficient_ordinal: u64,
        centered_offset: u64,
        integer_coefficient: i128,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CompactStructuredLinearForm {
    ordered_terms: Vec<CompactStructuredMatrixTerm>,
}

impl CompactStructuredLinearForm {
    fn static_entry(column_ordinal: u64, integer_coefficient: i128) -> Self {
        Self {
            ordered_terms: vec![CompactStructuredMatrixTerm::StaticEntry {
                column_ordinal,
                integer_coefficient,
            }],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactStructuredR1csRow {
    kind: CompactR1csConstraintKind,
    left: CompactStructuredLinearForm,
    right: CompactStructuredLinearForm,
    output: CompactStructuredLinearForm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactSmallVectorAddress {
    kind: CompactSmallVectorKind,
    vector_ordinal_within_kind: u64,
    centered_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactPublicVectorOrdinal {
    vector: CompactRingVectorReference,
    ordinal: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactPrivateSmallVectorAddress {
    vector: CompactRingVectorReference,
    address: CompactSmallVectorAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactWitnessSegmentAddress {
    kind: CompactWitnessSegmentKind,
    first_element: u64,
    vector_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CompactNegacyclicProductAddress {
    public_vector_first_column_ordinal: u64,
    private_vector_first_column_ordinal: u64,
    centered_offset: u64,
}

type PreparedCompactNegacyclicProduct = (
    CompactNegacyclicProductAddress,
    Zeroizing<Vec<ProofBaseFieldElement>>,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CompactCenteredPrivateVectorAddress {
    private_vector_first_column_ordinal: u64,
    centered_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CompactStructuredR1csRowEvaluation {
    pub(super) left: ProofChallengeExtensionElement,
    pub(super) right: ProofChallengeExtensionElement,
    pub(super) output: ProofChallengeExtensionElement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactStructuredR1csRowSourceGeometry {
    ring_degree: u64,
    negacyclic_product_count: u64,
    distinct_centered_private_vector_count: u64,
    transform_domain_size: u64,
    forward_transform_count: u64,
    inverse_transform_count: u64,
    transform_butterfly_count: u64,
    pointwise_multiplication_count: u64,
    negacyclic_fold_subtraction_count: u64,
    lookup_inverse_element_count: u64,
    lookup_table_value_count: u64,
    lookup_table_batch_extension_multiplication_count: u64,
}

impl CompactStructuredR1csRowSourceGeometry {
    fn derive(
        relation: &CompactPublicKeyRelationCatalog,
        ordered_product_addresses: &[CompactNegacyclicProductAddress],
    ) -> Result<Self, CommonProofProverError> {
        let mut distinct_centered_private_vectors = Vec::new();
        distinct_centered_private_vectors
            .try_reserve_exact(ordered_product_addresses.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for address in ordered_product_addresses {
            let private_vector = CompactCenteredPrivateVectorAddress {
                private_vector_first_column_ordinal: address.private_vector_first_column_ordinal,
                centered_offset: address.centered_offset,
            };
            if !distinct_centered_private_vectors.contains(&private_vector) {
                distinct_centered_private_vectors.push(private_vector);
            }
        }
        let distinct_centered_private_vector_count = distinct_centered_private_vectors
            .len()
            .try_into()
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let negacyclic_product_count: u64 = ordered_product_addresses
            .len()
            .try_into()
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let transform_domain_size = relation
            .ring_degree
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let forward_transform_count = negacyclic_product_count
            .checked_add(distinct_centered_private_vector_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let inverse_transform_count = negacyclic_product_count;
        let transform_count = forward_transform_count
            .checked_add(inverse_transform_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let logarithmic_transform_domain_size = u64::from(transform_domain_size.ilog2());
        let butterflies_per_transform = transform_domain_size
            .checked_div(2)
            .and_then(|count| count.checked_mul(logarithmic_transform_domain_size))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let transform_butterfly_count = transform_count
            .checked_mul(butterflies_per_transform)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let pointwise_multiplication_count = negacyclic_product_count
            .checked_mul(transform_domain_size)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let negacyclic_fold_subtraction_count = negacyclic_product_count
            .checked_mul(relation.ring_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let lookup_inverse_element_count = u64::try_from(relation.ordered_relations.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(relation.ring_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let lookup_table_batch_extension_multiplication_count = relation
            .quotient_lookup_table_value_count
            .checked_mul(4)
            .ok_or(CommonProofProverError::CountOverflow)?;

        Ok(Self {
            ring_degree: relation.ring_degree,
            negacyclic_product_count,
            distinct_centered_private_vector_count,
            transform_domain_size,
            forward_transform_count,
            inverse_transform_count,
            transform_butterfly_count,
            pointwise_multiplication_count,
            negacyclic_fold_subtraction_count,
            lookup_inverse_element_count,
            lookup_table_value_count: relation.quotient_lookup_table_value_count,
            lookup_table_batch_extension_multiplication_count,
        })
    }

    pub(crate) const fn ring_degree(self) -> u64 {
        self.ring_degree
    }

    pub(crate) const fn negacyclic_product_count(self) -> u64 {
        self.negacyclic_product_count
    }

    pub(crate) const fn distinct_centered_private_vector_count(self) -> u64 {
        self.distinct_centered_private_vector_count
    }

    pub(crate) const fn transform_domain_size(self) -> u64 {
        self.transform_domain_size
    }

    pub(crate) const fn forward_transform_count(self) -> u64 {
        self.forward_transform_count
    }

    pub(crate) const fn inverse_transform_count(self) -> u64 {
        self.inverse_transform_count
    }

    pub(crate) const fn transform_butterfly_count(self) -> u64 {
        self.transform_butterfly_count
    }

    pub(crate) const fn pointwise_multiplication_count(self) -> u64 {
        self.pointwise_multiplication_count
    }

    pub(crate) const fn negacyclic_fold_subtraction_count(self) -> u64 {
        self.negacyclic_fold_subtraction_count
    }

    pub(crate) const fn lookup_inverse_element_count(self) -> u64 {
        self.lookup_inverse_element_count
    }

    pub(crate) const fn lookup_table_value_count(self) -> u64 {
        self.lookup_table_value_count
    }

    pub(crate) const fn lookup_table_batch_extension_multiplication_count(self) -> u64 {
        self.lookup_table_batch_extension_multiplication_count
    }
}

pub(crate) fn compact_structured_r1cs_row_source_geometry(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactStructuredR1csRowSourceGeometry, CommonProofProverError> {
    let matrices = CompactStructuredR1csCatalog::derive(relation)?;
    let ordered_product_addresses = matrices.ordered_negacyclic_product_addresses(relation)?;
    CompactStructuredR1csRowSourceGeometry::derive(relation, &ordered_product_addresses)
}

#[derive(Clone, Debug)]
pub(super) struct CompactStructuredR1csCatalog {
    public_input_length: u64,
    witness_length: u64,
    matrix_dimension: u64,
    row_count: u64,
    public_vector_ordinals: Vec<CompactPublicVectorOrdinal>,
    private_small_vector_addresses: Vec<CompactPrivateSmallVectorAddress>,
    witness_segment_addresses: Vec<CompactWitnessSegmentAddress>,
}

impl CompactStructuredR1csCatalog {
    pub(super) fn derive(
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Self, RelationPlanError> {
        let mut public_vector_ordinals = Vec::new();
        public_vector_ordinals
            .try_reserve_exact(relation.ordered_public_vectors.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for (ordinal, vector) in relation.ordered_public_vectors.iter().copied().enumerate() {
            public_vector_ordinals.push(CompactPublicVectorOrdinal {
                vector,
                ordinal: u64::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            });
        }
        public_vector_ordinals.sort_unstable_by_key(|entry| entry.vector);
        if public_vector_ordinals
            .windows(2)
            .any(|pair| pair[0].vector >= pair[1].vector)
        {
            return Err(RelationPlanError::DuplicateItem);
        }

        let mut next_ternary_ordinal = 0_u64;
        let mut next_eta_two_ordinal = 0_u64;
        let mut private_small_vector_addresses = Vec::new();
        private_small_vector_addresses
            .try_reserve_exact(relation.ordered_private_small_vectors.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for descriptor in &relation.ordered_private_small_vectors {
            let vector_ordinal_within_kind = match descriptor.kind {
                CompactSmallVectorKind::ShiftedTernary => {
                    let ordinal = next_ternary_ordinal;
                    next_ternary_ordinal = next_ternary_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                    ordinal
                }
                CompactSmallVectorKind::ShiftedEtaTwo => {
                    let ordinal = next_eta_two_ordinal;
                    next_eta_two_ordinal = next_eta_two_ordinal
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                    ordinal
                }
            };
            private_small_vector_addresses.push(CompactPrivateSmallVectorAddress {
                vector: descriptor.vector,
                address: CompactSmallVectorAddress {
                    kind: descriptor.kind,
                    vector_ordinal_within_kind,
                    centered_offset: descriptor.centered_offset,
                },
            });
        }
        private_small_vector_addresses.sort_unstable_by_key(|entry| entry.vector);
        if private_small_vector_addresses
            .windows(2)
            .any(|pair| pair[0].vector >= pair[1].vector)
        {
            return Err(RelationPlanError::DuplicateItem);
        }

        let mut witness_segment_addresses = Vec::new();
        witness_segment_addresses
            .try_reserve_exact(relation.ordered_witness_segments.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for segment in &relation.ordered_witness_segments {
            witness_segment_addresses.push(CompactWitnessSegmentAddress {
                kind: segment.kind,
                first_element: segment.first_element,
                vector_count: segment.ring_vector_count,
            });
        }
        witness_segment_addresses.sort_unstable_by_key(|entry| entry.kind);
        if witness_segment_addresses
            .windows(2)
            .any(|pair| pair[0].kind >= pair[1].kind)
        {
            return Err(RelationPlanError::DuplicateItem);
        }

        let matrix_dimension = relation
            .padded_public_input_element_count
            .checked_add(relation.padded_witness_element_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        let catalog = Self {
            public_input_length: relation.padded_public_input_element_count,
            witness_length: relation.padded_witness_element_count,
            matrix_dimension,
            row_count: relation.padded_constraint_count,
            public_vector_ordinals,
            private_small_vector_addresses,
            witness_segment_addresses,
        };
        catalog.validate_relation(relation)?;
        Ok(catalog)
    }

    fn validate_relation(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<(), RelationPlanError> {
        if self.public_input_length != self.witness_length
            || self.matrix_dimension != self.row_count
            || self.matrix_dimension
                != self
                    .public_input_length
                    .checked_mul(2)
                    .ok_or(RelationPlanError::CountOverflow)?
            || self.public_vector_ordinals.len() != relation.ordered_public_vectors.len()
            || self.private_small_vector_addresses.len()
                != relation.ordered_private_small_vectors.len()
            || self.witness_segment_addresses.len() != 6
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let relation_count = u64::try_from(relation.ordered_relations.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let ternary_count = relation
            .ordered_private_small_vectors
            .iter()
            .filter(|descriptor| descriptor.kind == CompactSmallVectorKind::ShiftedTernary)
            .count()
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let eta_two_count = relation
            .ordered_private_small_vectors
            .iter()
            .filter(|descriptor| descriptor.kind == CompactSmallVectorKind::ShiftedEtaTwo)
            .count()
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let expected_vector_counts = [
            (CompactWitnessSegmentKind::ModularQuotients, relation_count),
            (
                CompactWitnessSegmentKind::LookupMultiplicities,
                relation.quotient_lookup_table_ring_vector_count,
            ),
            (
                CompactWitnessSegmentKind::ShiftedTernaryValues,
                ternary_count,
            ),
            (
                CompactWitnessSegmentKind::ShiftedEtaTwoValues,
                eta_two_count,
            ),
            (
                CompactWitnessSegmentKind::SmallSetProducts,
                ternary_count
                    .checked_add(
                        eta_two_count
                            .checked_mul(3)
                            .ok_or(RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::CountOverflow)?,
            ),
            (CompactWitnessSegmentKind::LookupInverses, relation_count),
        ];
        for (kind, expected_count) in expected_vector_counts {
            if self
                .witness_segment_address(kind)
                .map(|segment| segment.vector_count)
                != Some(expected_count)
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }

        let used_public_input_count = u64::try_from(self.public_vector_ordinals.len())
            .map_err(|_| RelationPlanError::CountOverflow)?
            .checked_mul(relation.ring_degree)
            .and_then(|count| count.checked_add(1))
            .ok_or(RelationPlanError::CountOverflow)?;
        if used_public_input_count > self.public_input_length {
            return Err(RelationPlanError::InvalidConstraint);
        }

        for relation_ordinal in 0..relation_count {
            let structured_relation = relation
                .ordered_relations
                .get(
                    usize::try_from(relation_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::InvalidConstraint)?;
            let quotient_terms = structured_relation
                .ordered_terms
                .iter()
                .filter(|term| matches!(term, CompactStructuredLinearTerm::ModulusQuotient { .. }))
                .count();
            if quotient_terms != 1 {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }

        for segment in &relation.ordered_constraint_segments {
            if segment.row_count == 0 {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let first = self.row(relation, segment.first_row)?;
            let last_row = segment
                .first_row
                .checked_add(segment.row_count - 1)
                .ok_or(RelationPlanError::CountOverflow)?;
            let last = self.row(relation, last_row)?;
            if first.kind != segment.kind || last.kind != segment.kind {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }
        self.ordered_negacyclic_product_addresses(relation)?;
        Ok(())
    }

    fn row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        row_ordinal: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        if row_ordinal >= self.row_count {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let segment = relation
            .ordered_constraint_segments
            .iter()
            .find(|segment| {
                row_ordinal >= segment.first_row
                    && row_ordinal < segment.first_row.saturating_add(segment.row_count)
            })
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let local_row = row_ordinal
            .checked_sub(segment.first_row)
            .ok_or(RelationPlanError::CountOverflow)?;
        match segment.kind {
            CompactR1csConstraintKind::ExactIntegerLift => {
                self.exact_integer_lift_row(relation, local_row)
            }
            CompactR1csConstraintKind::LookupInverse => {
                self.lookup_inverse_row(relation, local_row)
            }
            CompactR1csConstraintKind::TernaryFirstProduct => {
                self.ternary_first_product_row(relation, local_row)
            }
            CompactR1csConstraintKind::TernaryTerminalProduct => {
                self.ternary_terminal_product_row(relation, local_row)
            }
            CompactR1csConstraintKind::EtaTwoFirstProduct => {
                self.eta_two_product_row(relation, local_row, 0)
            }
            CompactR1csConstraintKind::EtaTwoSecondProduct => {
                self.eta_two_product_row(relation, local_row, 1)
            }
            CompactR1csConstraintKind::EtaTwoThirdProduct => {
                self.eta_two_product_row(relation, local_row, 2)
            }
            CompactR1csConstraintKind::EtaTwoTerminalProduct => {
                self.eta_two_terminal_product_row(relation, local_row)
            }
            CompactR1csConstraintKind::LookupLogDerivativeEquality => {
                self.lookup_log_derivative_row(relation, local_row)
            }
            CompactR1csConstraintKind::ZeroPadding => {
                if local_row >= segment.row_count {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                Ok(CompactStructuredR1csRow {
                    kind: segment.kind,
                    left: CompactStructuredLinearForm::default(),
                    right: CompactStructuredLinearForm::default(),
                    output: CompactStructuredLinearForm::default(),
                })
            }
        }
    }

    fn exact_integer_lift_row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        local_row: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        let relation_ordinal = local_row / relation.ring_degree;
        let coefficient_ordinal = local_row % relation.ring_degree;
        let structured_relation = relation
            .ordered_relations
            .get(usize::try_from(relation_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let mut left = CompactStructuredLinearForm::default();
        let mut quotient_term_count = 0_u8;
        for term in &structured_relation.ordered_terms {
            match term {
                CompactStructuredLinearTerm::Direct {
                    vector,
                    centered_offset,
                    integer_coefficient,
                } => {
                    if let Some(public_vector_ordinal) = self.public_vector_ordinal(*vector) {
                        if *centered_offset != 0 {
                            return Err(RelationPlanError::InvalidConstraint);
                        }
                        left.ordered_terms
                            .push(CompactStructuredMatrixTerm::StaticEntry {
                                column_ordinal: self.public_vector_column(
                                    relation,
                                    public_vector_ordinal,
                                    coefficient_ordinal,
                                )?,
                                integer_coefficient: *integer_coefficient,
                            });
                    } else {
                        let address = self
                            .private_small_vector_address(*vector)
                            .ok_or(RelationPlanError::InvalidConstraint)?;
                        if address.centered_offset != *centered_offset {
                            return Err(RelationPlanError::InvalidConstraint);
                        }
                        let witness_kind = small_vector_witness_kind(address.kind);
                        left.ordered_terms
                            .push(CompactStructuredMatrixTerm::StaticEntry {
                                column_ordinal: self.witness_vector_column(
                                    relation,
                                    witness_kind,
                                    address.vector_ordinal_within_kind,
                                    coefficient_ordinal,
                                )?,
                                integer_coefficient: *integer_coefficient,
                            });
                        push_centering_constant(&mut left, *integer_coefficient, *centered_offset)?;
                    }
                }
                CompactStructuredLinearTerm::NegacyclicPublicProduct {
                    public_vector,
                    private_vector,
                    private_centered_offset,
                    integer_coefficient,
                } => {
                    let public_vector_ordinal = self
                        .public_vector_ordinal(*public_vector)
                        .ok_or(RelationPlanError::InvalidConstraint)?;
                    let private_address = self
                        .private_small_vector_address(*private_vector)
                        .ok_or(RelationPlanError::InvalidConstraint)?;
                    if private_address.centered_offset != *private_centered_offset {
                        return Err(RelationPlanError::InvalidConstraint);
                    }
                    left.ordered_terms.push(
                        CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                            public_vector_first_column_ordinal: self.public_vector_column(
                                relation,
                                public_vector_ordinal,
                                0,
                            )?,
                            private_vector_first_column_ordinal: self.witness_vector_column(
                                relation,
                                small_vector_witness_kind(private_address.kind),
                                private_address.vector_ordinal_within_kind,
                                0,
                            )?,
                            output_coefficient_ordinal: coefficient_ordinal,
                            centered_offset: *private_centered_offset,
                            integer_coefficient: i128::from(*integer_coefficient),
                        },
                    );
                }
                CompactStructuredLinearTerm::ModulusQuotient {
                    modulus,
                    integer_coefficient,
                    ..
                } => {
                    quotient_term_count = quotient_term_count
                        .checked_add(1)
                        .ok_or(RelationPlanError::CountOverflow)?;
                    let scaled_modulus = i128::from(*integer_coefficient)
                        .checked_mul(i128::from(*modulus))
                        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
                    left.ordered_terms
                        .push(CompactStructuredMatrixTerm::StaticEntry {
                            column_ordinal: self.witness_vector_column(
                                relation,
                                CompactWitnessSegmentKind::ModularQuotients,
                                relation_ordinal,
                                coefficient_ordinal,
                            )?,
                            integer_coefficient: scaled_modulus,
                        });
                    push_centering_constant(
                        &mut left,
                        scaled_modulus,
                        MODULAR_QUOTIENT_ENCODING_OFFSET,
                    )?;
                }
            }
        }
        if quotient_term_count != 1 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(CompactStructuredR1csRow {
            kind: CompactR1csConstraintKind::ExactIntegerLift,
            left,
            right: self.one_form(),
            output: CompactStructuredLinearForm::default(),
        })
    }

    fn lookup_inverse_row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        local_row: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        let vector_ordinal = local_row / relation.ring_degree;
        let coefficient_ordinal = local_row % relation.ring_degree;
        let quotient_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::ModularQuotients,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        let inverse_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::LookupInverses,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        Ok(CompactStructuredR1csRow {
            kind: CompactR1csConstraintKind::LookupInverse,
            left: CompactStructuredLinearForm {
                ordered_terms: vec![
                    CompactStructuredMatrixTerm::StaticEntry {
                        column_ordinal: quotient_column,
                        integer_coefficient: 1,
                    },
                    CompactStructuredMatrixTerm::LookupChallengeEntry {
                        column_ordinal: self.public_one_column(),
                    },
                ],
            },
            right: CompactStructuredLinearForm::static_entry(inverse_column, 1),
            output: self.one_form(),
        })
    }

    fn ternary_first_product_row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        local_row: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        let vector_ordinal = local_row / relation.ring_degree;
        let coefficient_ordinal = local_row % relation.ring_degree;
        let value_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::ShiftedTernaryValues,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        let product_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::SmallSetProducts,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        Ok(CompactStructuredR1csRow {
            kind: CompactR1csConstraintKind::TernaryFirstProduct,
            left: CompactStructuredLinearForm::static_entry(value_column, 1),
            right: value_minus_constant_form(value_column, self.public_one_column(), 1),
            output: CompactStructuredLinearForm::static_entry(product_column, 1),
        })
    }

    fn ternary_terminal_product_row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        local_row: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        let vector_ordinal = local_row / relation.ring_degree;
        let coefficient_ordinal = local_row % relation.ring_degree;
        let value_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::ShiftedTernaryValues,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        let product_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::SmallSetProducts,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        Ok(CompactStructuredR1csRow {
            kind: CompactR1csConstraintKind::TernaryTerminalProduct,
            left: CompactStructuredLinearForm::static_entry(product_column, 1),
            right: value_minus_constant_form(value_column, self.public_one_column(), 2),
            output: CompactStructuredLinearForm::default(),
        })
    }

    fn eta_two_product_row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        local_row: u64,
        product_ordinal: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        let vector_ordinal = local_row / relation.ring_degree;
        let coefficient_ordinal = local_row % relation.ring_degree;
        let value_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::ShiftedEtaTwoValues,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        let ternary_product_count = self
            .witness_segment_address(CompactWitnessSegmentKind::ShiftedTernaryValues)
            .ok_or(RelationPlanError::InvalidConstraint)?
            .vector_count;
        let product_vector_ordinal = ternary_product_count
            .checked_add(
                vector_ordinal
                    .checked_mul(3)
                    .and_then(|ordinal| ordinal.checked_add(product_ordinal))
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?;
        let product_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::SmallSetProducts,
            product_vector_ordinal,
            coefficient_ordinal,
        )?;
        let left = if product_ordinal == 0 {
            CompactStructuredLinearForm::static_entry(value_column, 1)
        } else {
            CompactStructuredLinearForm::static_entry(
                self.witness_vector_column(
                    relation,
                    CompactWitnessSegmentKind::SmallSetProducts,
                    product_vector_ordinal - 1,
                    coefficient_ordinal,
                )?,
                1,
            )
        };
        let kind = match product_ordinal {
            0 => CompactR1csConstraintKind::EtaTwoFirstProduct,
            1 => CompactR1csConstraintKind::EtaTwoSecondProduct,
            2 => CompactR1csConstraintKind::EtaTwoThirdProduct,
            _ => return Err(RelationPlanError::InvalidConstraint),
        };
        Ok(CompactStructuredR1csRow {
            kind,
            left,
            right: value_minus_constant_form(
                value_column,
                self.public_one_column(),
                product_ordinal + 1,
            ),
            output: CompactStructuredLinearForm::static_entry(product_column, 1),
        })
    }

    fn eta_two_terminal_product_row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        local_row: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        let vector_ordinal = local_row / relation.ring_degree;
        let coefficient_ordinal = local_row % relation.ring_degree;
        let value_column = self.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::ShiftedEtaTwoValues,
            vector_ordinal,
            coefficient_ordinal,
        )?;
        let ternary_product_count = self
            .witness_segment_address(CompactWitnessSegmentKind::ShiftedTernaryValues)
            .ok_or(RelationPlanError::InvalidConstraint)?
            .vector_count;
        let terminal_product_vector_ordinal = ternary_product_count
            .checked_add(
                vector_ordinal
                    .checked_mul(3)
                    .and_then(|ordinal| ordinal.checked_add(2))
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?;
        Ok(CompactStructuredR1csRow {
            kind: CompactR1csConstraintKind::EtaTwoTerminalProduct,
            left: CompactStructuredLinearForm::static_entry(
                self.witness_vector_column(
                    relation,
                    CompactWitnessSegmentKind::SmallSetProducts,
                    terminal_product_vector_ordinal,
                    coefficient_ordinal,
                )?,
                1,
            ),
            right: value_minus_constant_form(value_column, self.public_one_column(), 4),
            output: CompactStructuredLinearForm::default(),
        })
    }

    fn lookup_log_derivative_row(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        local_row: u64,
    ) -> Result<CompactStructuredR1csRow, RelationPlanError> {
        if local_row != 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let inverse_element_count = u64::try_from(relation.ordered_relations.len())
            .map_err(|_| RelationPlanError::CountOverflow)?
            .checked_mul(relation.ring_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        let multiplicity_element_count = relation
            .quotient_lookup_table_ring_vector_count
            .checked_mul(relation.ring_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        if multiplicity_element_count != relation.quotient_lookup_table_value_count {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(CompactStructuredR1csRow {
            kind: CompactR1csConstraintKind::LookupLogDerivativeEquality,
            left: CompactStructuredLinearForm {
                ordered_terms: vec![
                    CompactStructuredMatrixTerm::UniformStaticRange {
                        first_column_ordinal: self.witness_vector_column(
                            relation,
                            CompactWitnessSegmentKind::LookupInverses,
                            0,
                            0,
                        )?,
                        element_count: inverse_element_count,
                        integer_coefficient: 1,
                    },
                    CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                        first_column_ordinal: self.witness_vector_column(
                            relation,
                            CompactWitnessSegmentKind::LookupMultiplicities,
                            0,
                            0,
                        )?,
                        table_value_count: relation.quotient_lookup_table_value_count,
                    },
                ],
            },
            right: self.one_form(),
            output: CompactStructuredLinearForm::default(),
        })
    }

    fn ordered_negacyclic_product_addresses(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<Vec<CompactNegacyclicProductAddress>, RelationPlanError> {
        let mut ordered_addresses = Vec::new();
        ordered_addresses
            .try_reserve_exact(
                usize::try_from(relation.structured_public_ring_product_count)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for structured_relation in &relation.ordered_relations {
            for term in &structured_relation.ordered_terms {
                let CompactStructuredLinearTerm::NegacyclicPublicProduct {
                    public_vector,
                    private_vector,
                    private_centered_offset,
                    ..
                } = term
                else {
                    continue;
                };
                let public_vector_ordinal = self
                    .public_vector_ordinal(*public_vector)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                let private_address = self
                    .private_small_vector_address(*private_vector)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                if private_address.centered_offset != *private_centered_offset {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let address = CompactNegacyclicProductAddress {
                    public_vector_first_column_ordinal: self.public_vector_column(
                        relation,
                        public_vector_ordinal,
                        0,
                    )?,
                    private_vector_first_column_ordinal: self.witness_vector_column(
                        relation,
                        small_vector_witness_kind(private_address.kind),
                        private_address.vector_ordinal_within_kind,
                        0,
                    )?,
                    centered_offset: private_address.centered_offset,
                };
                if ordered_addresses.contains(&address) {
                    return Err(RelationPlanError::DuplicateItem);
                }
                ordered_addresses.push(address);
            }
        }
        if u64::try_from(ordered_addresses.len()).map_err(|_| RelationPlanError::CountOverflow)?
            != relation.structured_public_ring_product_count
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(ordered_addresses)
    }

    const fn public_one_column(&self) -> u64 {
        0
    }

    fn one_form(&self) -> CompactStructuredLinearForm {
        CompactStructuredLinearForm::static_entry(self.public_one_column(), 1)
    }

    fn public_vector_ordinal(&self, vector: CompactRingVectorReference) -> Option<u64> {
        self.public_vector_ordinals
            .binary_search_by_key(&vector, |entry| entry.vector)
            .ok()
            .and_then(|index| self.public_vector_ordinals.get(index))
            .map(|entry| entry.ordinal)
    }

    fn private_small_vector_address(
        &self,
        vector: CompactRingVectorReference,
    ) -> Option<CompactSmallVectorAddress> {
        self.private_small_vector_addresses
            .binary_search_by_key(&vector, |entry| entry.vector)
            .ok()
            .and_then(|index| self.private_small_vector_addresses.get(index))
            .map(|entry| entry.address)
    }

    fn witness_segment_address(
        &self,
        kind: CompactWitnessSegmentKind,
    ) -> Option<CompactWitnessSegmentAddress> {
        self.witness_segment_addresses
            .binary_search_by_key(&kind, |entry| entry.kind)
            .ok()
            .and_then(|index| self.witness_segment_addresses.get(index))
            .copied()
    }

    fn public_vector_column(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        vector_ordinal: u64,
        coefficient_ordinal: u64,
    ) -> Result<u64, RelationPlanError> {
        if vector_ordinal
            >= u64::try_from(self.public_vector_ordinals.len())
                .map_err(|_| RelationPlanError::CountOverflow)?
            || coefficient_ordinal >= relation.ring_degree
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let column = vector_ordinal
            .checked_mul(relation.ring_degree)
            .and_then(|column| column.checked_add(coefficient_ordinal))
            .and_then(|column| column.checked_add(1))
            .ok_or(RelationPlanError::CountOverflow)?;
        if column >= self.public_input_length {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(column)
    }

    fn witness_vector_column(
        &self,
        relation: &CompactPublicKeyRelationCatalog,
        kind: CompactWitnessSegmentKind,
        vector_ordinal: u64,
        coefficient_ordinal: u64,
    ) -> Result<u64, RelationPlanError> {
        let segment = self
            .witness_segment_address(kind)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        if vector_ordinal >= segment.vector_count || coefficient_ordinal >= relation.ring_degree {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let witness_element = segment
            .first_element
            .checked_add(
                vector_ordinal
                    .checked_mul(relation.ring_degree)
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .and_then(|element| element.checked_add(coefficient_ordinal))
            .ok_or(RelationPlanError::CountOverflow)?;
        if witness_element >= self.witness_length {
            return Err(RelationPlanError::InvalidConstraint);
        }
        self.public_input_length
            .checked_add(witness_element)
            .ok_or(RelationPlanError::CountOverflow)
    }
}

pub(super) trait CompactStructuredAssignmentSource {
    fn padded_public_input_element_count(&self) -> u64;

    fn padded_witness_element_count(&self) -> u64;

    fn lookup_challenge(&self) -> ProofChallengeExtensionElement;

    fn public_input_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError>;

    fn witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError>;

    fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        extension_base_value(self.public_input_value(element_ordinal)?)
    }

    fn base_witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        extension_base_value(self.witness_value(element_ordinal)?)
    }
}

impl CompactStructuredAssignmentSource for CompactPublicKeyAssignment {
    fn padded_public_input_element_count(&self) -> u64 {
        self.memory_geometry().padded_public_input_element_count()
    }

    fn padded_witness_element_count(&self) -> u64 {
        self.memory_geometry().padded_witness_element_count()
    }

    fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
        CompactPublicKeyAssignment::lookup_challenge(self)
    }

    fn public_input_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        CompactPublicKeyAssignment::public_input_value(self, element_ordinal)
    }

    fn witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        CompactPublicKeyAssignment::witness_value(self, element_ordinal)
    }

    fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        CompactPublicKeyAssignment::public_input_base_value(self, element_ordinal)
    }

    fn base_witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        CompactPublicKeyAssignment::base_witness_value(self, element_ordinal)
    }
}

impl<Assignment: CompactStructuredAssignmentSource + ?Sized> CompactStructuredAssignmentSource
    for Rc<Assignment>
{
    fn padded_public_input_element_count(&self) -> u64 {
        Assignment::padded_public_input_element_count(self)
    }

    fn padded_witness_element_count(&self) -> u64 {
        Assignment::padded_witness_element_count(self)
    }

    fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
        Assignment::lookup_challenge(self)
    }

    fn public_input_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        Assignment::public_input_value(self, element_ordinal)
    }

    fn witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        Assignment::witness_value(self, element_ordinal)
    }

    fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        Assignment::public_input_base_value(self, element_ordinal)
    }

    fn base_witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        Assignment::base_witness_value(self, element_ordinal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactLookupLogDerivativeEvaluationCache {
    inverse_first_column_ordinal: u64,
    inverse_element_count: u64,
    inverse_sum: ProofChallengeExtensionElement,
    multiplicity_first_column_ordinal: u64,
    table_value_count: u64,
    negated_weighted_table_reciprocal_sum: ProofChallengeExtensionElement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CompactStructuredR1csRowSourcePreparationStep {
    LookupInverseSum,
    LookupTablePrefixProduct,
    LookupTableProductInversion,
    LookupTableReversePass,
    PrivatePolynomialFill,
    PrivatePolynomialForwardTransform,
    PublicPolynomialFill,
    PublicPolynomialForwardTransform,
    PointwiseProduct,
    ProductPolynomialInverseTransform,
    NegacyclicProductFold,
}

pub(super) enum CompactStructuredR1csRowSourcePreparationPoll<Assignment>
where
    Assignment: CompactStructuredAssignmentSource + Clone,
{
    StepCompleted {
        step: CompactStructuredR1csRowSourcePreparationStep,
        completed_work_unit_count: u64,
    },
    Complete(Box<CompactStructuredR1csRowSource<Assignment>>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactLookupLogDerivativePreparationPhase {
    InverseSum {
        next_element_offset: u64,
        inverse_sum: ProofChallengeExtensionElement,
    },
    TablePrefixProduct {
        next_table_value: u64,
        running_product: ProofChallengeExtensionElement,
    },
    InvertTableProduct {
        total_product: ProofChallengeExtensionElement,
    },
    TableReversePass {
        remaining_table_value_count: u64,
        accumulated_inverse: ProofChallengeExtensionElement,
        negated_weighted_table_reciprocal_sum: ProofChallengeExtensionElement,
    },
    Complete,
}

struct CompactLookupLogDerivativeEvaluationCachePreparation {
    inverse_first_column_ordinal: u64,
    inverse_first_witness_element: u64,
    inverse_element_count: u64,
    inverse_sum: Option<ProofChallengeExtensionElement>,
    multiplicity_first_column_ordinal: u64,
    multiplicity_first_witness_element: u64,
    table_value_count: u64,
    lookup_challenge: ProofChallengeExtensionElement,
    denominator_prefix_products: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    negated_weighted_table_reciprocal_sum: Option<ProofChallengeExtensionElement>,
    phase: CompactLookupLogDerivativePreparationPhase,
}

impl CompactLookupLogDerivativeEvaluationCachePreparation {
    fn new<Assignment: CompactStructuredAssignmentSource + ?Sized>(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        assignment: &Assignment,
    ) -> Result<Self, CommonProofProverError> {
        let inverse_segment = relation
            .ordered_witness_segments
            .iter()
            .find(|segment| segment.kind == CompactWitnessSegmentKind::LookupInverses)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let multiplicity_segment = relation
            .ordered_witness_segments
            .iter()
            .find(|segment| segment.kind == CompactWitnessSegmentKind::LookupMultiplicities)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let expected_inverse_element_count = u64::try_from(relation.ordered_relations.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(relation.ring_degree)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if inverse_segment.element_count != expected_inverse_element_count
            || multiplicity_segment.element_count < relation.quotient_lookup_table_value_count
        {
            return Err(RelationPlanError::InvalidConstraint.into());
        }

        let lookup_challenge = assignment.lookup_challenge();
        if lookup_challenge.canonical_coordinates()[1..]
            .iter()
            .all(|coordinate| *coordinate == 0)
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let table_value_count = relation.quotient_lookup_table_value_count;
        if table_value_count == 0 {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        Ok(Self {
            inverse_first_column_ordinal: matrices
                .public_input_length
                .checked_add(inverse_segment.first_element)
                .ok_or(CommonProofProverError::CountOverflow)?,
            inverse_first_witness_element: inverse_segment.first_element,
            inverse_element_count: inverse_segment.element_count,
            inverse_sum: None,
            multiplicity_first_column_ordinal: matrices
                .public_input_length
                .checked_add(multiplicity_segment.first_element)
                .ok_or(CommonProofProverError::CountOverflow)?,
            multiplicity_first_witness_element: multiplicity_segment.first_element,
            table_value_count,
            lookup_challenge,
            denominator_prefix_products: fallible_extension_vector(table_value_count)?,
            negated_weighted_table_reciprocal_sum: None,
            phase: CompactLookupLogDerivativePreparationPhase::InverseSum {
                next_element_offset: 0,
                inverse_sum: ProofChallengeExtensionElement::ZERO,
            },
        })
    }

    fn advance<Assignment: CompactStructuredAssignmentSource + ?Sized>(
        &mut self,
        assignment: &Assignment,
        maximum_element_count: u64,
    ) -> Result<(CompactStructuredR1csRowSourcePreparationStep, u64), CommonProofProverError> {
        if maximum_element_count == 0 {
            return Err(CommonProofProverError::InvalidInput);
        }
        match self.phase {
            CompactLookupLogDerivativePreparationPhase::InverseSum {
                next_element_offset,
                mut inverse_sum,
            } => {
                let remaining_element_count = self
                    .inverse_element_count
                    .checked_sub(next_element_offset)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if remaining_element_count == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let completed_element_count = remaining_element_count.min(maximum_element_count);
                let end_element_offset = next_element_offset
                    .checked_add(completed_element_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                for element_offset in next_element_offset..end_element_offset {
                    inverse_sum = inverse_sum.add(
                        assignment.witness_value(
                            self.inverse_first_witness_element
                                .checked_add(element_offset)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                        )?,
                    );
                }
                self.phase = if end_element_offset == self.inverse_element_count {
                    CompactLookupLogDerivativePreparationPhase::TablePrefixProduct {
                        next_table_value: 0,
                        running_product: ProofChallengeExtensionElement::ONE,
                    }
                } else {
                    CompactLookupLogDerivativePreparationPhase::InverseSum {
                        next_element_offset: end_element_offset,
                        inverse_sum,
                    }
                };
                if end_element_offset == self.inverse_element_count {
                    self.inverse_sum = Some(inverse_sum);
                }
                Ok((
                    CompactStructuredR1csRowSourcePreparationStep::LookupInverseSum,
                    completed_element_count,
                ))
            }
            CompactLookupLogDerivativePreparationPhase::TablePrefixProduct {
                next_table_value,
                mut running_product,
            } => {
                let remaining_table_value_count = self
                    .table_value_count
                    .checked_sub(next_table_value)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if remaining_table_value_count == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let completed_table_value_count =
                    remaining_table_value_count.min(maximum_element_count);
                let end_table_value = next_table_value
                    .checked_add(completed_table_value_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                for table_value in next_table_value..end_table_value {
                    let denominator =
                        self.lookup_challenge
                            .add(ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)?,
                            ));
                    running_product = running_product.multiply(denominator);
                    self.denominator_prefix_products.push(running_product);
                }
                self.phase = if end_table_value == self.table_value_count {
                    CompactLookupLogDerivativePreparationPhase::InvertTableProduct {
                        total_product: running_product,
                    }
                } else {
                    CompactLookupLogDerivativePreparationPhase::TablePrefixProduct {
                        next_table_value: end_table_value,
                        running_product,
                    }
                };
                Ok((
                    CompactStructuredR1csRowSourcePreparationStep::LookupTablePrefixProduct,
                    completed_table_value_count,
                ))
            }
            CompactLookupLogDerivativePreparationPhase::InvertTableProduct { total_product } => {
                self.phase = CompactLookupLogDerivativePreparationPhase::TableReversePass {
                    remaining_table_value_count: self.table_value_count,
                    accumulated_inverse: total_product.inverse()?,
                    negated_weighted_table_reciprocal_sum: ProofChallengeExtensionElement::ZERO,
                };
                Ok((
                    CompactStructuredR1csRowSourcePreparationStep::LookupTableProductInversion,
                    1,
                ))
            }
            CompactLookupLogDerivativePreparationPhase::TableReversePass {
                remaining_table_value_count,
                mut accumulated_inverse,
                mut negated_weighted_table_reciprocal_sum,
            } => {
                if remaining_table_value_count == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let completed_table_value_count =
                    remaining_table_value_count.min(maximum_element_count);
                let first_table_value = remaining_table_value_count
                    .checked_sub(completed_table_value_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                for table_value in (first_table_value..remaining_table_value_count).rev() {
                    let prefix_before = if table_value == 0 {
                        ProofChallengeExtensionElement::ONE
                    } else {
                        *self
                            .denominator_prefix_products
                            .get(
                                usize::try_from(table_value - 1)
                                    .map_err(|_| CommonProofProverError::CountOverflow)?,
                            )
                            .ok_or(CommonProofProverError::InvalidInput)?
                    };
                    let denominator_inverse = accumulated_inverse.multiply(prefix_before);
                    let denominator =
                        self.lookup_challenge
                            .add(ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)?,
                            ));
                    accumulated_inverse = accumulated_inverse.multiply(denominator);
                    let multiplicity = assignment.base_witness_value(
                        self.multiplicity_first_witness_element
                            .checked_add(table_value)
                            .ok_or(CommonProofProverError::CountOverflow)?,
                    )?;
                    negated_weighted_table_reciprocal_sum = negated_weighted_table_reciprocal_sum
                        .subtract(denominator_inverse.multiply_base(multiplicity));
                }
                if first_table_value == 0 {
                    if accumulated_inverse != ProofChallengeExtensionElement::ONE {
                        return Err(CommonProofProverError::InvalidInput);
                    }
                    self.phase = CompactLookupLogDerivativePreparationPhase::Complete;
                    self.negated_weighted_table_reciprocal_sum =
                        Some(negated_weighted_table_reciprocal_sum);
                } else {
                    self.phase = CompactLookupLogDerivativePreparationPhase::TableReversePass {
                        remaining_table_value_count: first_table_value,
                        accumulated_inverse,
                        negated_weighted_table_reciprocal_sum,
                    };
                }
                Ok((
                    CompactStructuredR1csRowSourcePreparationStep::LookupTableReversePass,
                    completed_table_value_count,
                ))
            }
            CompactLookupLogDerivativePreparationPhase::Complete => {
                Err(CommonProofProverError::InvalidInput)
            }
        }
    }

    fn finish(self) -> Result<CompactLookupLogDerivativeEvaluationCache, CommonProofProverError> {
        if self.phase != CompactLookupLogDerivativePreparationPhase::Complete
            || self.denominator_prefix_products.len()
                != usize::try_from(self.table_value_count)
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(CompactLookupLogDerivativeEvaluationCache {
            inverse_first_column_ordinal: self.inverse_first_column_ordinal,
            inverse_element_count: self.inverse_element_count,
            inverse_sum: self
                .inverse_sum
                .ok_or(CommonProofProverError::InvalidInput)?,
            multiplicity_first_column_ordinal: self.multiplicity_first_column_ordinal,
            table_value_count: self.table_value_count,
            negated_weighted_table_reciprocal_sum: self
                .negated_weighted_table_reciprocal_sum
                .ok_or(CommonProofProverError::InvalidInput)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactNegacyclicProductPreparationPhase {
    FillPrivatePolynomial { next_coefficient_ordinal: u64 },
    ForwardPrivatePolynomial,
    FillPublicPolynomial { next_coefficient_ordinal: u64 },
    ForwardPublicPolynomial,
    MultiplyPointwise { next_evaluation_ordinal: u64 },
    InverseProductPolynomial,
    FoldNegacyclicProduct { next_coefficient_ordinal: u64 },
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactNegacyclicProductPreparationGroup {
    private_address: CompactCenteredPrivateVectorAddress,
    ordered_product_addresses: Vec<CompactNegacyclicProductAddress>,
}

struct CompactNegacyclicProductPreparation {
    ordered_groups: Vec<CompactNegacyclicProductPreparationGroup>,
    next_group_ordinal: usize,
    next_product_ordinal_within_group: usize,
    private_transform: Option<Zeroizing<Vec<ProofBaseFieldElement>>>,
    product_transform: Option<Zeroizing<Vec<ProofBaseFieldElement>>>,
    folded_product: Option<Zeroizing<Vec<ProofBaseFieldElement>>>,
    prepared_products: Vec<PreparedCompactNegacyclicProduct>,
    phase: CompactNegacyclicProductPreparationPhase,
}

impl CompactNegacyclicProductPreparation {
    fn new(
        relation: &CompactPublicKeyRelationCatalog,
        ordered_product_addresses: &[CompactNegacyclicProductAddress],
    ) -> Result<Self, CommonProofProverError> {
        let mut ordered_private_addresses = Vec::new();
        ordered_private_addresses
            .try_reserve_exact(ordered_product_addresses.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for address in ordered_product_addresses {
            ordered_private_addresses.push(CompactCenteredPrivateVectorAddress {
                private_vector_first_column_ordinal: address.private_vector_first_column_ordinal,
                centered_offset: address.centered_offset,
            });
        }
        ordered_private_addresses.sort_unstable();
        ordered_private_addresses.dedup();
        let mut ordered_groups = Vec::new();
        ordered_groups
            .try_reserve_exact(ordered_private_addresses.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for private_address in ordered_private_addresses {
            let product_count = ordered_product_addresses
                .iter()
                .filter(|address| {
                    address.private_vector_first_column_ordinal
                        == private_address.private_vector_first_column_ordinal
                        && address.centered_offset == private_address.centered_offset
                })
                .count();
            let mut group_product_addresses = Vec::new();
            group_product_addresses
                .try_reserve_exact(product_count)
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            group_product_addresses.extend(ordered_product_addresses.iter().copied().filter(
                |address| {
                    address.private_vector_first_column_ordinal
                        == private_address.private_vector_first_column_ordinal
                        && address.centered_offset == private_address.centered_offset
                },
            ));
            ordered_groups.push(CompactNegacyclicProductPreparationGroup {
                private_address,
                ordered_product_addresses: group_product_addresses,
            });
        }
        if ordered_groups.is_empty()
            || ordered_groups
                .iter()
                .any(|group| group.ordered_product_addresses.is_empty())
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let mut prepared_products = Vec::new();
        prepared_products
            .try_reserve_exact(ordered_product_addresses.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(Self {
            ordered_groups,
            next_group_ordinal: 0,
            next_product_ordinal_within_group: 0,
            private_transform: Some(fallible_base_vector(relation.ring_degree)?),
            product_transform: None,
            folded_product: None,
            prepared_products,
            phase: CompactNegacyclicProductPreparationPhase::FillPrivatePolynomial {
                next_coefficient_ordinal: 0,
            },
        })
    }

    fn advance<Assignment: CompactStructuredAssignmentSource + ?Sized>(
        &mut self,
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        assignment: &Assignment,
        maximum_element_count: u64,
    ) -> Result<Option<(CompactStructuredR1csRowSourcePreparationStep, u64)>, CommonProofProverError>
    {
        if maximum_element_count == 0 {
            return Err(CommonProofProverError::InvalidInput);
        }
        let ring_degree = usize::try_from(relation.ring_degree)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        let transform_domain_size = ring_degree
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let transform_domain = ProofEvaluationDomain::new_subgroup(transform_domain_size)?;
        let butterfly_count_per_transform = u64::try_from(transform_domain_size / 2)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(u64::from(transform_domain_size.ilog2()))
            .ok_or(CommonProofProverError::CountOverflow)?;

        match self.phase {
            CompactNegacyclicProductPreparationPhase::FillPrivatePolynomial {
                next_coefficient_ordinal,
            } => {
                let group = self.current_group()?;
                let private_witness_first_element = group
                    .private_address
                    .private_vector_first_column_ordinal
                    .checked_sub(matrices.public_input_length)
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                let centered_offset =
                    ProofBaseFieldElement::from_canonical(group.private_address.centered_offset)?;
                let remaining_coefficient_count = relation
                    .ring_degree
                    .checked_sub(next_coefficient_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if remaining_coefficient_count == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let completed_coefficient_count =
                    remaining_coefficient_count.min(maximum_element_count);
                let end_coefficient_ordinal = next_coefficient_ordinal
                    .checked_add(completed_coefficient_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let private_transform = self
                    .private_transform
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                for coefficient_ordinal in next_coefficient_ordinal..end_coefficient_ordinal {
                    private_transform.push(
                        assignment
                            .base_witness_value(
                                private_witness_first_element
                                    .checked_add(coefficient_ordinal)
                                    .ok_or(CommonProofProverError::CountOverflow)?,
                            )?
                            .subtract(centered_offset),
                    );
                }
                self.phase = if end_coefficient_ordinal == relation.ring_degree {
                    CompactNegacyclicProductPreparationPhase::ForwardPrivatePolynomial
                } else {
                    CompactNegacyclicProductPreparationPhase::FillPrivatePolynomial {
                        next_coefficient_ordinal: end_coefficient_ordinal,
                    }
                };
                Ok(Some((
                    CompactStructuredR1csRowSourcePreparationStep::PrivatePolynomialFill,
                    completed_coefficient_count,
                )))
            }
            CompactNegacyclicProductPreparationPhase::ForwardPrivatePolynomial => {
                let private_transform = self
                    .private_transform
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                transform_domain.evaluate_base_polynomial_in_place(private_transform)?;
                if private_transform.len() != transform_domain_size {
                    return Err(CommonProofProverError::InvalidInput);
                }
                self.product_transform = Some(fallible_base_vector(relation.ring_degree)?);
                self.phase = CompactNegacyclicProductPreparationPhase::FillPublicPolynomial {
                    next_coefficient_ordinal: 0,
                };
                Ok(Some((
                    CompactStructuredR1csRowSourcePreparationStep::PrivatePolynomialForwardTransform,
                    butterfly_count_per_transform,
                )))
            }
            CompactNegacyclicProductPreparationPhase::FillPublicPolynomial {
                next_coefficient_ordinal,
            } => {
                let product_address = self.current_product_address()?;
                let remaining_coefficient_count = relation
                    .ring_degree
                    .checked_sub(next_coefficient_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if remaining_coefficient_count == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let completed_coefficient_count =
                    remaining_coefficient_count.min(maximum_element_count);
                let end_coefficient_ordinal = next_coefficient_ordinal
                    .checked_add(completed_coefficient_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let product_transform = self
                    .product_transform
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                for coefficient_ordinal in next_coefficient_ordinal..end_coefficient_ordinal {
                    product_transform.push(
                        assignment.public_input_base_value(
                            product_address
                                .public_vector_first_column_ordinal
                                .checked_add(coefficient_ordinal)
                                .ok_or(CommonProofProverError::CountOverflow)?,
                        )?,
                    );
                }
                self.phase = if end_coefficient_ordinal == relation.ring_degree {
                    CompactNegacyclicProductPreparationPhase::ForwardPublicPolynomial
                } else {
                    CompactNegacyclicProductPreparationPhase::FillPublicPolynomial {
                        next_coefficient_ordinal: end_coefficient_ordinal,
                    }
                };
                Ok(Some((
                    CompactStructuredR1csRowSourcePreparationStep::PublicPolynomialFill,
                    completed_coefficient_count,
                )))
            }
            CompactNegacyclicProductPreparationPhase::ForwardPublicPolynomial => {
                let product_transform = self
                    .product_transform
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                transform_domain.evaluate_base_polynomial_in_place(product_transform)?;
                if product_transform.len() != transform_domain_size
                    || self
                        .private_transform
                        .as_ref()
                        .is_none_or(|private_transform| {
                            private_transform.len() != transform_domain_size
                        })
                {
                    return Err(CommonProofProverError::InvalidInput);
                }
                self.phase = CompactNegacyclicProductPreparationPhase::MultiplyPointwise {
                    next_evaluation_ordinal: 0,
                };
                Ok(Some((
                    CompactStructuredR1csRowSourcePreparationStep::PublicPolynomialForwardTransform,
                    butterfly_count_per_transform,
                )))
            }
            CompactNegacyclicProductPreparationPhase::MultiplyPointwise {
                next_evaluation_ordinal,
            } => {
                let transform_domain_size_u64 = u64::try_from(transform_domain_size)
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                let remaining_evaluation_count = transform_domain_size_u64
                    .checked_sub(next_evaluation_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if remaining_evaluation_count == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let completed_evaluation_count =
                    remaining_evaluation_count.min(maximum_element_count);
                let end_evaluation_ordinal = next_evaluation_ordinal
                    .checked_add(completed_evaluation_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let private_transform = self
                    .private_transform
                    .as_ref()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                let product_transform = self
                    .product_transform
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                for evaluation_ordinal in next_evaluation_ordinal..end_evaluation_ordinal {
                    let evaluation_ordinal = usize::try_from(evaluation_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?;
                    product_transform[evaluation_ordinal] = product_transform[evaluation_ordinal]
                        .multiply(private_transform[evaluation_ordinal]);
                }
                self.phase = if end_evaluation_ordinal == transform_domain_size_u64 {
                    CompactNegacyclicProductPreparationPhase::InverseProductPolynomial
                } else {
                    CompactNegacyclicProductPreparationPhase::MultiplyPointwise {
                        next_evaluation_ordinal: end_evaluation_ordinal,
                    }
                };
                Ok(Some((
                    CompactStructuredR1csRowSourcePreparationStep::PointwiseProduct,
                    completed_evaluation_count,
                )))
            }
            CompactNegacyclicProductPreparationPhase::InverseProductPolynomial => {
                let product_transform = self
                    .product_transform
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                transform_domain.interpolate_base_polynomial_in_place(product_transform)?;
                if product_transform.len() < transform_domain_size {
                    let missing_element_count = transform_domain_size - product_transform.len();
                    product_transform
                        .try_reserve_exact(missing_element_count)
                        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                    product_transform.resize(transform_domain_size, ProofBaseFieldElement::ZERO);
                }
                self.folded_product = Some(fallible_base_vector(relation.ring_degree)?);
                self.phase = CompactNegacyclicProductPreparationPhase::FoldNegacyclicProduct {
                    next_coefficient_ordinal: 0,
                };
                Ok(Some((
                    CompactStructuredR1csRowSourcePreparationStep::ProductPolynomialInverseTransform,
                    butterfly_count_per_transform,
                )))
            }
            CompactNegacyclicProductPreparationPhase::FoldNegacyclicProduct {
                next_coefficient_ordinal,
            } => {
                let remaining_coefficient_count = relation
                    .ring_degree
                    .checked_sub(next_coefficient_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                if remaining_coefficient_count == 0 {
                    return Err(CommonProofProverError::InvalidInput);
                }
                let completed_coefficient_count =
                    remaining_coefficient_count.min(maximum_element_count);
                let end_coefficient_ordinal = next_coefficient_ordinal
                    .checked_add(completed_coefficient_count)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let product_transform = self
                    .product_transform
                    .as_ref()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                let folded_product = self
                    .folded_product
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                for coefficient_ordinal in next_coefficient_ordinal..end_coefficient_ordinal {
                    let coefficient_index = usize::try_from(coefficient_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?;
                    folded_product.push(
                        product_transform[coefficient_index]
                            .subtract(product_transform[coefficient_index + ring_degree]),
                    );
                }
                if end_coefficient_ordinal == relation.ring_degree {
                    let product_address = self.current_product_address()?;
                    let folded_product = self
                        .folded_product
                        .take()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    if self
                        .prepared_products
                        .iter()
                        .any(|(prepared_address, _)| *prepared_address == product_address)
                    {
                        return Err(RelationPlanError::DuplicateItem.into());
                    }
                    self.prepared_products
                        .push((product_address, folded_product));
                    self.product_transform = None;
                    self.advance_to_next_product_or_group(relation)?;
                } else {
                    self.phase = CompactNegacyclicProductPreparationPhase::FoldNegacyclicProduct {
                        next_coefficient_ordinal: end_coefficient_ordinal,
                    };
                }
                Ok(Some((
                    CompactStructuredR1csRowSourcePreparationStep::NegacyclicProductFold,
                    completed_coefficient_count,
                )))
            }
            CompactNegacyclicProductPreparationPhase::Complete => Ok(None),
        }
    }

    fn current_group(
        &self,
    ) -> Result<&CompactNegacyclicProductPreparationGroup, CommonProofProverError> {
        self.ordered_groups
            .get(self.next_group_ordinal)
            .ok_or(CommonProofProverError::InvalidInput)
    }

    fn current_product_address(
        &self,
    ) -> Result<CompactNegacyclicProductAddress, CommonProofProverError> {
        self.current_group()?
            .ordered_product_addresses
            .get(self.next_product_ordinal_within_group)
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)
    }

    fn advance_to_next_product_or_group(
        &mut self,
        relation: &CompactPublicKeyRelationCatalog,
    ) -> Result<(), CommonProofProverError> {
        self.next_product_ordinal_within_group = self
            .next_product_ordinal_within_group
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if self.next_product_ordinal_within_group
            < self.current_group()?.ordered_product_addresses.len()
        {
            self.product_transform = Some(fallible_base_vector(relation.ring_degree)?);
            self.phase = CompactNegacyclicProductPreparationPhase::FillPublicPolynomial {
                next_coefficient_ordinal: 0,
            };
            return Ok(());
        }

        self.next_group_ordinal = self
            .next_group_ordinal
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.next_product_ordinal_within_group = 0;
        self.private_transform = None;
        if self.next_group_ordinal == self.ordered_groups.len() {
            self.phase = CompactNegacyclicProductPreparationPhase::Complete;
        } else {
            self.private_transform = Some(fallible_base_vector(relation.ring_degree)?);
            self.phase = CompactNegacyclicProductPreparationPhase::FillPrivatePolynomial {
                next_coefficient_ordinal: 0,
            };
        }
        Ok(())
    }

    fn finish(
        mut self,
        expected_product_count: usize,
    ) -> Result<Vec<PreparedCompactNegacyclicProduct>, CommonProofProverError> {
        if self.phase != CompactNegacyclicProductPreparationPhase::Complete
            || self.prepared_products.len() != expected_product_count
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        self.prepared_products
            .sort_unstable_by_key(|(address, _)| *address);
        if self
            .prepared_products
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(RelationPlanError::DuplicateItem.into());
        }
        Ok(self.prepared_products)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactStructuredR1csRowSourcePreparationPhase {
    LookupLogDerivative,
    NegacyclicProducts,
    Complete,
}

pub(super) struct CompactStructuredR1csRowSourcePreparation<Assignment>
where
    Assignment: CompactStructuredAssignmentSource + Clone,
{
    relation: Rc<CompactPublicKeyRelationCatalog>,
    matrices: CompactStructuredR1csCatalog,
    assignment: Assignment,
    ordered_product_addresses: Vec<CompactNegacyclicProductAddress>,
    geometry: CompactStructuredR1csRowSourceGeometry,
    lookup_preparation: Option<CompactLookupLogDerivativeEvaluationCachePreparation>,
    lookup_log_derivative_cache: Option<CompactLookupLogDerivativeEvaluationCache>,
    product_preparation: Option<CompactNegacyclicProductPreparation>,
    negacyclic_products: Option<Vec<PreparedCompactNegacyclicProduct>>,
    phase: CompactStructuredR1csRowSourcePreparationPhase,
}

impl<Assignment> CompactStructuredR1csRowSourcePreparation<Assignment>
where
    Assignment: CompactStructuredAssignmentSource + Clone,
{
    pub(super) fn new(
        relation: Rc<CompactPublicKeyRelationCatalog>,
        assignment: Assignment,
    ) -> Result<Self, CommonProofProverError> {
        let matrices = CompactStructuredR1csCatalog::derive(&relation)?;
        if assignment.padded_public_input_element_count() != matrices.public_input_length
            || assignment.padded_witness_element_count() != matrices.witness_length
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let ordered_product_addresses = matrices.ordered_negacyclic_product_addresses(&relation)?;
        let geometry =
            CompactStructuredR1csRowSourceGeometry::derive(&relation, &ordered_product_addresses)?;
        let lookup_preparation = Some(CompactLookupLogDerivativeEvaluationCachePreparation::new(
            &relation,
            &matrices,
            &assignment,
        )?);
        let product_preparation = Some(CompactNegacyclicProductPreparation::new(
            &relation,
            &ordered_product_addresses,
        )?);
        Ok(Self {
            relation,
            matrices,
            assignment,
            ordered_product_addresses,
            geometry,
            lookup_preparation,
            lookup_log_derivative_cache: None,
            product_preparation,
            negacyclic_products: None,
            phase: CompactStructuredR1csRowSourcePreparationPhase::LookupLogDerivative,
        })
    }

    pub(super) fn advance(
        &mut self,
        maximum_element_count: u64,
    ) -> Result<CompactStructuredR1csRowSourcePreparationPoll<Assignment>, CommonProofProverError>
    {
        if maximum_element_count == 0 {
            return Err(CommonProofProverError::InvalidInput);
        }
        loop {
            match self.phase {
                CompactStructuredR1csRowSourcePreparationPhase::LookupLogDerivative => {
                    let lookup_preparation = self
                        .lookup_preparation
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    if lookup_preparation.phase
                        == CompactLookupLogDerivativePreparationPhase::Complete
                    {
                        self.lookup_log_derivative_cache = Some(
                            self.lookup_preparation
                                .take()
                                .ok_or(CommonProofProverError::InvalidInput)?
                                .finish()?,
                        );
                        self.phase =
                            CompactStructuredR1csRowSourcePreparationPhase::NegacyclicProducts;
                        continue;
                    }
                    let (step, completed_work_unit_count) =
                        lookup_preparation.advance(&self.assignment, maximum_element_count)?;
                    return Ok(
                        CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
                            step,
                            completed_work_unit_count,
                        },
                    );
                }
                CompactStructuredR1csRowSourcePreparationPhase::NegacyclicProducts => {
                    let product_preparation = self
                        .product_preparation
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    let Some((step, completed_work_unit_count)) = product_preparation.advance(
                        &self.relation,
                        &self.matrices,
                        &self.assignment,
                        maximum_element_count,
                    )?
                    else {
                        self.negacyclic_products = Some(
                            self.product_preparation
                                .take()
                                .ok_or(CommonProofProverError::InvalidInput)?
                                .finish(self.ordered_product_addresses.len())?,
                        );
                        self.phase = CompactStructuredR1csRowSourcePreparationPhase::Complete;
                        continue;
                    };
                    return Ok(
                        CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
                            step,
                            completed_work_unit_count,
                        },
                    );
                }
                CompactStructuredR1csRowSourcePreparationPhase::Complete => {
                    let negacyclic_products = self
                        .negacyclic_products
                        .take()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    if negacyclic_products.len() != self.ordered_product_addresses.len()
                        || self
                            .ordered_product_addresses
                            .iter()
                            .zip(&negacyclic_products)
                            .any(|(expected, (actual, _))| expected != actual)
                    {
                        return Err(CommonProofProverError::InvalidInput);
                    }
                    return Ok(CompactStructuredR1csRowSourcePreparationPoll::Complete(
                        Box::new(CompactStructuredR1csRowSource {
                            relation: Rc::clone(&self.relation),
                            matrices: self.matrices.clone(),
                            assignment: self.assignment.clone(),
                            negacyclic_products,
                            lookup_log_derivative_cache: self
                                .lookup_log_derivative_cache
                                .ok_or(CommonProofProverError::InvalidInput)?,
                            geometry: self.geometry,
                        }),
                    ));
                }
            }
        }
    }
}

pub(super) struct CompactStructuredR1csRowSource<Assignment>
where
    Assignment: CompactStructuredAssignmentSource,
{
    relation: Rc<CompactPublicKeyRelationCatalog>,
    matrices: CompactStructuredR1csCatalog,
    assignment: Assignment,
    negacyclic_products: Vec<PreparedCompactNegacyclicProduct>,
    lookup_log_derivative_cache: CompactLookupLogDerivativeEvaluationCache,
    geometry: CompactStructuredR1csRowSourceGeometry,
}

impl<Assignment> CompactStructuredR1csRowSource<Assignment>
where
    Assignment: CompactStructuredAssignmentSource,
{
    pub(super) const fn geometry(&self) -> CompactStructuredR1csRowSourceGeometry {
        self.geometry
    }

    pub(super) const fn witness_length(&self) -> u64 {
        self.matrices.witness_length
    }

    pub(super) const fn row_count(&self) -> u64 {
        self.matrices.row_count
    }

    pub(super) const fn assignment_source(&self) -> &Assignment {
        &self.assignment
    }

    pub(super) fn witness_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        if element_ordinal >= self.matrices.witness_length {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        self.assignment.witness_value(element_ordinal)
    }

    pub(super) fn evaluate_row(
        &self,
        row_ordinal: u64,
    ) -> Result<CompactStructuredR1csRowEvaluation, CommonProofProverError> {
        let row = self.matrices.row(&self.relation, row_ordinal)?;
        Ok(CompactStructuredR1csRowEvaluation {
            left: self.evaluate_form(&row.left)?,
            right: self.evaluate_form(&row.right)?,
            output: self.evaluate_form(&row.output)?,
        })
    }

    fn evaluate_form(
        &self,
        form: &CompactStructuredLinearForm,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        let mut sum = ProofChallengeExtensionElement::ZERO;
        for term in &form.ordered_terms {
            let contribution = match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } => self
                    .value_at_column(column_ordinal)?
                    .multiply_base(base_element_from_signed_integer(integer_coefficient)?),
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal } => self
                    .value_at_column(column_ordinal)?
                    .multiply(self.assignment.lookup_challenge()),
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_sum = if first_column_ordinal
                        == self
                            .lookup_log_derivative_cache
                            .inverse_first_column_ordinal
                        && element_count == self.lookup_log_derivative_cache.inverse_element_count
                    {
                        self.lookup_log_derivative_cache.inverse_sum
                    } else {
                        let mut range_sum = ProofChallengeExtensionElement::ZERO;
                        for element_offset in 0..element_count {
                            range_sum = range_sum.add(
                                self.value_at_column(
                                    first_column_ordinal
                                        .checked_add(element_offset)
                                        .ok_or(CommonProofProverError::CountOverflow)?,
                                )?,
                            );
                        }
                        range_sum
                    };
                    range_sum.multiply_base(base_element_from_signed_integer(integer_coefficient)?)
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    table_value_count,
                } => {
                    if first_column_ordinal
                        != self
                            .lookup_log_derivative_cache
                            .multiplicity_first_column_ordinal
                        || table_value_count != self.lookup_log_derivative_cache.table_value_count
                    {
                        return Err(RelationPlanError::InvalidConstraint.into());
                    }
                    self.lookup_log_derivative_cache
                        .negated_weighted_table_reciprocal_sum
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                    public_vector_first_column_ordinal,
                    private_vector_first_column_ordinal,
                    output_coefficient_ordinal,
                    centered_offset,
                    integer_coefficient,
                } => {
                    let address = CompactNegacyclicProductAddress {
                        public_vector_first_column_ordinal,
                        private_vector_first_column_ordinal,
                        centered_offset,
                    };
                    let product_value = self
                        .negacyclic_product(&address)
                        .and_then(|product| {
                            usize::try_from(output_coefficient_ordinal)
                                .ok()
                                .and_then(|ordinal| product.get(ordinal))
                        })
                        .copied()
                        .ok_or(CommonProofProverError::InvalidInput)?;
                    ProofChallengeExtensionElement::from_base(product_value)
                        .multiply_base(base_element_from_signed_integer(integer_coefficient)?)
                }
            };
            sum = sum.add(contribution);
        }
        Ok(sum)
    }

    fn value_at_column(
        &self,
        column_ordinal: u64,
    ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
        if column_ordinal < self.matrices.public_input_length {
            return self.assignment.public_input_value(column_ordinal);
        }
        if column_ordinal >= self.matrices.matrix_dimension {
            return Err(RelationPlanError::InvalidConstraint.into());
        }
        self.assignment
            .witness_value(column_ordinal - self.matrices.public_input_length)
    }

    fn negacyclic_product(
        &self,
        address: &CompactNegacyclicProductAddress,
    ) -> Option<&Zeroizing<Vec<ProofBaseFieldElement>>> {
        self.negacyclic_products
            .binary_search_by_key(address, |(candidate, _)| *candidate)
            .ok()
            .and_then(|product_ordinal| {
                self.negacyclic_products
                    .get(product_ordinal)
                    .map(|(_, product)| product)
            })
    }

    #[cfg(test)]
    fn negacyclic_product_mut(
        &mut self,
        address: &CompactNegacyclicProductAddress,
    ) -> Option<&mut Zeroizing<Vec<ProofBaseFieldElement>>> {
        self.negacyclic_products
            .binary_search_by_key(address, |(candidate, _)| *candidate)
            .ok()
            .and_then(|product_ordinal| {
                self.negacyclic_products
                    .get_mut(product_ordinal)
                    .map(|(_, product)| product)
            })
    }
}

/// Verifier-owned compact CFW view of the production structured matrices.
///
/// The row source contains caches for one honest assignment, but those caches
/// are not used to evaluate this interface. Every matrix row is instead
/// interpreted against the `public_input` and `witness` slices supplied by the
/// CFW caller. This distinction is load-bearing for knowledge extraction: a
/// candidate witness must be checked against the production matrices rather
/// than against the assignment that happened to prepare the row source.
pub(crate) struct CompactPublicKeyCfwMatrices<'source, 'public_input> {
    row_source: &'source CompactStructuredR1csRowSource<Rc<CompactPublicKeyAssignment>>,
    canonical_public_input: &'public_input [CompactChallengeField],
    witness_length: usize,
    row_count: usize,
    row_point_variable_count: usize,
    lookup_challenge: CompactChallengeField,
}

impl<'source, 'public_input> CompactPublicKeyCfwMatrices<'source, 'public_input> {
    pub(crate) fn new(
        row_source: &'source CompactStructuredR1csRowSource<Rc<CompactPublicKeyAssignment>>,
        canonical_public_input: &'public_input [CompactChallengeField],
    ) -> Result<Self, CompactCfwError> {
        let witness_length = usize::try_from(row_source.witness_length())
            .map_err(|_| CompactCfwError::CountOverflow)?;
        let row_count =
            usize::try_from(row_source.row_count()).map_err(|_| CompactCfwError::CountOverflow)?;
        let expected_row_count = witness_length
            .checked_mul(2)
            .ok_or(CompactCfwError::CountOverflow)?;
        if witness_length == 0
            || row_count != expected_row_count
            || !row_count.is_power_of_two()
            || canonical_public_input.len() != witness_length
            || row_source.matrices.public_input_length
                != u64::try_from(witness_length).map_err(|_| CompactCfwError::CountOverflow)?
            || row_source.matrices.witness_length
                != u64::try_from(witness_length).map_err(|_| CompactCfwError::CountOverflow)?
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        for (element_ordinal, supplied_value) in canonical_public_input.iter().copied().enumerate()
        {
            let expected_value = row_source
                .assignment
                .public_input_value(
                    u64::try_from(element_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .map(compact_challenge_from_production)
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            if supplied_value != expected_value {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
        }
        let row_point_variable_count =
            usize::try_from(row_count.ilog2()).map_err(|_| CompactCfwError::CountOverflow)?;
        Ok(Self {
            row_source,
            canonical_public_input,
            witness_length,
            row_count,
            row_point_variable_count,
            lookup_challenge: compact_challenge_from_production(
                row_source.assignment.lookup_challenge(),
            ),
        })
    }

    fn form_for_role(
        row: &CompactStructuredR1csRow,
        matrix_role: CompactCfwMatrixRole,
    ) -> &CompactStructuredLinearForm {
        match matrix_role {
            CompactCfwMatrixRole::LeftMultiplicand => &row.left,
            CompactCfwMatrixRole::RightMultiplicand => &row.right,
            CompactCfwMatrixRole::Product => &row.output,
        }
    }

    fn little_endian_boolean_weight(
        point: &[CompactChallengeField],
        boolean_ordinal: u64,
    ) -> CompactChallengeField {
        point
            .iter()
            .enumerate()
            .map(|(coordinate_ordinal, coordinate)| {
                if (boolean_ordinal >> coordinate_ordinal) & 1 == 0 {
                    CompactChallengeField::ONE - *coordinate
                } else {
                    *coordinate
                }
            })
            .product()
    }

    fn checked_value_at_column(
        &self,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
        column_ordinal: u64,
    ) -> Result<CompactChallengeField, CompactCfwError> {
        let public_input_length = self.row_source.matrices.public_input_length;
        if column_ordinal < public_input_length {
            return public_input
                .get(usize::try_from(column_ordinal).map_err(|_| CompactCfwError::CountOverflow)?)
                .copied()
                .ok_or(CompactCfwError::InvalidMatrixSource);
        }
        let witness_ordinal = column_ordinal
            .checked_sub(public_input_length)
            .ok_or(CompactCfwError::CountOverflow)?;
        witness
            .get(usize::try_from(witness_ordinal).map_err(|_| CompactCfwError::CountOverflow)?)
            .copied()
            .ok_or(CompactCfwError::InvalidMatrixSource)
    }

    fn evaluate_form(
        &self,
        form: &CompactStructuredLinearForm,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        let mut sum = CompactChallengeField::ZERO;
        for term in &form.ordered_terms {
            let contribution = match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } => {
                    self.checked_value_at_column(public_input, witness, column_ordinal)?
                        * compact_signed_integer(integer_coefficient)?
                }
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal } => {
                    self.checked_value_at_column(public_input, witness, column_ordinal)?
                        * self.lookup_challenge
                }
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_end = first_column_ordinal
                        .checked_add(element_count)
                        .ok_or(CompactCfwError::CountOverflow)?;
                    let coefficient = compact_signed_integer(integer_coefficient)?;
                    let mut range_sum = CompactChallengeField::ZERO;
                    for column_ordinal in first_column_ordinal..range_end {
                        range_sum +=
                            self.checked_value_at_column(public_input, witness, column_ordinal)?
                                * coefficient;
                    }
                    range_sum
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    table_value_count,
                } => {
                    let mut range_sum = CompactChallengeField::ZERO;
                    for table_value in 0..table_value_count {
                        let denominator = self.row_source.assignment.lookup_challenge().add(
                            ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                        let reciprocal = denominator
                            .inverse()
                            .map_err(|_| CompactCfwError::InvalidMatrixSource)?
                            .negate();
                        range_sum += self.checked_value_at_column(
                            public_input,
                            witness,
                            first_column_ordinal
                                .checked_add(table_value)
                                .ok_or(CompactCfwError::CountOverflow)?,
                        )? * compact_challenge_from_production(reciprocal);
                    }
                    range_sum
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                    public_vector_first_column_ordinal,
                    private_vector_first_column_ordinal,
                    output_coefficient_ordinal,
                    centered_offset,
                    integer_coefficient,
                } => self.evaluate_public_negacyclic_matrix_band(
                    public_input,
                    witness,
                    public_vector_first_column_ordinal,
                    private_vector_first_column_ordinal,
                    output_coefficient_ordinal,
                    centered_offset,
                    integer_coefficient,
                )?,
            };
            sum += contribution;
        }
        Ok(sum)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_public_negacyclic_matrix_band(
        &self,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
        public_vector_first_column_ordinal: u64,
        private_vector_first_column_ordinal: u64,
        output_coefficient_ordinal: u64,
        centered_offset: u64,
        integer_coefficient: i128,
    ) -> Result<CompactChallengeField, CompactCfwError> {
        let ring_degree = self.row_source.relation.ring_degree();
        let public_input_length = self.row_source.matrices.public_input_length;
        let matrix_dimension = self.row_source.matrices.matrix_dimension;
        let public_vector_end = public_vector_first_column_ordinal
            .checked_add(ring_degree)
            .filter(|end| *end <= public_input_length)
            .ok_or(CompactCfwError::InvalidMatrixSource)?;
        let private_vector_end = private_vector_first_column_ordinal
            .checked_add(ring_degree)
            .filter(|end| {
                private_vector_first_column_ordinal >= public_input_length
                    && *end <= matrix_dimension
            })
            .ok_or(CompactCfwError::InvalidMatrixSource)?;
        if output_coefficient_ordinal >= ring_degree {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let centered_offset = compact_signed_integer(i128::from(centered_offset))?;
        let mut sum = CompactChallengeField::ZERO;
        for public_column_ordinal in public_vector_first_column_ordinal..public_vector_end {
            let public_coefficient_ordinal = public_column_ordinal
                .checked_sub(public_vector_first_column_ordinal)
                .ok_or(CompactCfwError::CountOverflow)?;
            let (private_coefficient_ordinal, signed_integer_coefficient) =
                if public_coefficient_ordinal <= output_coefficient_ordinal {
                    (
                        output_coefficient_ordinal - public_coefficient_ordinal,
                        integer_coefficient,
                    )
                } else {
                    (
                        ring_degree
                            .checked_add(output_coefficient_ordinal)
                            .and_then(|value| value.checked_sub(public_coefficient_ordinal))
                            .ok_or(CompactCfwError::CountOverflow)?,
                        integer_coefficient
                            .checked_neg()
                            .ok_or(CompactCfwError::InvalidMatrixSource)?,
                    )
                };
            let public_value =
                self.checked_value_at_column(public_input, witness, public_column_ordinal)?;
            let shifted_private_value = self.checked_value_at_column(
                public_input,
                witness,
                private_vector_first_column_ordinal
                    .checked_add(private_coefficient_ordinal)
                    .filter(|column_ordinal| *column_ordinal < private_vector_end)
                    .ok_or(CompactCfwError::InvalidMatrixSource)?,
            )?;
            sum += public_value
                * compact_signed_integer(signed_integer_coefficient)?
                * (shifted_private_value - centered_offset);
        }
        Ok(sum)
    }

    fn public_form_contribution(
        &self,
        form: &CompactStructuredLinearForm,
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        let public_input_length = self.row_source.matrices.public_input_length;
        let mut contribution = CompactChallengeField::ZERO;
        for term in &form.ordered_terms {
            match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } if column_ordinal < public_input_length => {
                    contribution +=
                        self.checked_value_at_column(public_input, &[], column_ordinal)?
                            * compact_signed_integer(integer_coefficient)?;
                }
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal }
                    if column_ordinal < public_input_length =>
                {
                    contribution +=
                        self.checked_value_at_column(public_input, &[], column_ordinal)?
                            * self.lookup_challenge;
                }
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_end = first_column_ordinal
                        .checked_add(element_count)
                        .ok_or(CompactCfwError::CountOverflow)?;
                    let public_range_end = range_end.min(public_input_length);
                    if first_column_ordinal < public_range_end {
                        let coefficient = compact_signed_integer(integer_coefficient)?;
                        for column_ordinal in first_column_ordinal..public_range_end {
                            contribution +=
                                self.checked_value_at_column(public_input, &[], column_ordinal)?
                                    * coefficient;
                        }
                    }
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    ..
                } if first_column_ordinal < public_input_length => {
                    return Err(CompactCfwError::InvalidMatrixSource);
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                    public_vector_first_column_ordinal,
                    output_coefficient_ordinal,
                    centered_offset,
                    integer_coefficient,
                    ..
                } => {
                    let ring_degree = self.row_source.relation.ring_degree();
                    let public_vector_end = public_vector_first_column_ordinal
                        .checked_add(ring_degree)
                        .filter(|end| *end <= public_input_length)
                        .ok_or(CompactCfwError::InvalidMatrixSource)?;
                    if output_coefficient_ordinal >= ring_degree {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                    let mut signed_public_sum = CompactChallengeField::ZERO;
                    for public_column_ordinal in
                        public_vector_first_column_ordinal..public_vector_end
                    {
                        let public_coefficient_ordinal = public_column_ordinal
                            .checked_sub(public_vector_first_column_ordinal)
                            .ok_or(CompactCfwError::CountOverflow)?;
                        let public_value =
                            self.checked_value_at_column(public_input, &[], public_column_ordinal)?;
                        if public_coefficient_ordinal <= output_coefficient_ordinal {
                            signed_public_sum += public_value;
                        } else {
                            signed_public_sum -= public_value;
                        }
                    }
                    let centering_coefficient = integer_coefficient
                        .checked_mul(i128::from(centered_offset))
                        .and_then(i128::checked_neg)
                        .ok_or(CompactCfwError::InvalidMatrixSource)?;
                    contribution +=
                        signed_public_sum * compact_signed_integer(centering_coefficient)?;
                }
                _ => {}
            }
        }
        Ok(contribution)
    }

    fn accumulate_witness_form(
        &self,
        form: &CompactStructuredLinearForm,
        row_weight: CompactChallengeField,
        matrix_role_weight: CompactChallengeField,
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        let public_input_length = self.row_source.matrices.public_input_length;
        let matrix_dimension = self.row_source.matrices.matrix_dimension;
        let weighted_row = row_weight * matrix_role_weight;
        if weighted_row == CompactChallengeField::ZERO {
            return Ok(());
        }
        for term in &form.ordered_terms {
            match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } if column_ordinal >= public_input_length => {
                    add_compact_witness_covector_entry(
                        destination,
                        public_input_length,
                        matrix_dimension,
                        column_ordinal,
                        weighted_row * compact_signed_integer(integer_coefficient)?,
                    )?;
                }
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal }
                    if column_ordinal >= public_input_length =>
                {
                    add_compact_witness_covector_entry(
                        destination,
                        public_input_length,
                        matrix_dimension,
                        column_ordinal,
                        weighted_row * self.lookup_challenge,
                    )?;
                }
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let range_end = first_column_ordinal
                        .checked_add(element_count)
                        .filter(|end| *end <= matrix_dimension)
                        .ok_or(CompactCfwError::InvalidMatrixSource)?;
                    let first_witness_column = first_column_ordinal.max(public_input_length);
                    let coefficient = weighted_row * compact_signed_integer(integer_coefficient)?;
                    for column_ordinal in first_witness_column..range_end {
                        add_compact_witness_covector_entry(
                            destination,
                            public_input_length,
                            matrix_dimension,
                            column_ordinal,
                            coefficient,
                        )?;
                    }
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    table_value_count,
                } => {
                    if first_column_ordinal < public_input_length {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                    for table_value in 0..table_value_count {
                        let denominator = self.row_source.assignment.lookup_challenge().add(
                            ProofChallengeExtensionElement::from_base(
                                ProofBaseFieldElement::from_canonical(table_value)
                                    .map_err(|_| CompactCfwError::InvalidMatrixSource)?,
                            ),
                        );
                        let reciprocal = denominator
                            .inverse()
                            .map_err(|_| CompactCfwError::InvalidMatrixSource)?
                            .negate();
                        add_compact_witness_covector_entry(
                            destination,
                            public_input_length,
                            matrix_dimension,
                            first_column_ordinal
                                .checked_add(table_value)
                                .ok_or(CompactCfwError::CountOverflow)?,
                            weighted_row * compact_challenge_from_production(reciprocal),
                        )?;
                    }
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                    public_vector_first_column_ordinal,
                    private_vector_first_column_ordinal,
                    output_coefficient_ordinal,
                    integer_coefficient,
                    ..
                } => {
                    let ring_degree = self.row_source.relation.ring_degree();
                    let public_vector_end = public_vector_first_column_ordinal
                        .checked_add(ring_degree)
                        .filter(|end| *end <= public_input_length)
                        .ok_or(CompactCfwError::InvalidMatrixSource)?;
                    let private_vector_end = private_vector_first_column_ordinal
                        .checked_add(ring_degree)
                        .filter(|end| {
                            private_vector_first_column_ordinal >= public_input_length
                                && *end <= matrix_dimension
                        })
                        .ok_or(CompactCfwError::InvalidMatrixSource)?;
                    if output_coefficient_ordinal >= ring_degree {
                        return Err(CompactCfwError::InvalidMatrixSource);
                    }
                    for public_column_ordinal in
                        public_vector_first_column_ordinal..public_vector_end
                    {
                        let public_coefficient_ordinal = public_column_ordinal
                            .checked_sub(public_vector_first_column_ordinal)
                            .ok_or(CompactCfwError::CountOverflow)?;
                        let (private_coefficient_ordinal, signed_integer_coefficient) =
                            if public_coefficient_ordinal <= output_coefficient_ordinal {
                                (
                                    output_coefficient_ordinal - public_coefficient_ordinal,
                                    integer_coefficient,
                                )
                            } else {
                                (
                                    ring_degree
                                        .checked_add(output_coefficient_ordinal)
                                        .and_then(|value| {
                                            value.checked_sub(public_coefficient_ordinal)
                                        })
                                        .ok_or(CompactCfwError::CountOverflow)?,
                                    integer_coefficient
                                        .checked_neg()
                                        .ok_or(CompactCfwError::InvalidMatrixSource)?,
                                )
                            };
                        let public_value = self
                            .canonical_public_input
                            .get(
                                usize::try_from(public_column_ordinal)
                                    .map_err(|_| CompactCfwError::CountOverflow)?,
                            )
                            .copied()
                            .ok_or(CompactCfwError::InvalidMatrixSource)?;
                        if public_value == CompactChallengeField::ZERO {
                            continue;
                        }
                        add_compact_witness_covector_entry(
                            destination,
                            public_input_length,
                            matrix_dimension,
                            private_vector_first_column_ordinal
                                .checked_add(private_coefficient_ordinal)
                                .filter(|column_ordinal| *column_ordinal < private_vector_end)
                                .ok_or(CompactCfwError::InvalidMatrixSource)?,
                            weighted_row
                                * public_value
                                * compact_signed_integer(signed_integer_coefficient)?,
                        )?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn check_public_input(
        &self,
        public_input: &[CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        if public_input != self.canonical_public_input {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        Ok(())
    }
}

impl CompactCfwR1csMatrices for CompactPublicKeyCfwMatrices<'_, '_> {
    fn witness_length(&self) -> usize {
        self.witness_length
    }

    fn evaluate_assignment_rows(
        &self,
        matrix_role: CompactCfwMatrixRole,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
        self.check_public_input(public_input)?;
        if witness.len() != self.witness_length {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.row_count)
            .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
        for row_ordinal in 0..self.row_count {
            let row = self
                .row_source
                .matrices
                .row(
                    &self.row_source.relation,
                    u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            rows.push(self.evaluate_form(
                Self::form_for_role(&row, matrix_role),
                public_input,
                witness,
            )?);
        }
        Ok(rows)
    }

    fn public_contribution_at_row_point(
        &self,
        matrix_role: CompactCfwMatrixRole,
        row_point: &[CompactChallengeField],
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        self.check_public_input(public_input)?;
        if row_point.len() != self.row_point_variable_count {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        let mut result = CompactChallengeField::ZERO;
        for row_ordinal in 0..self.row_count {
            let row = self
                .row_source
                .matrices
                .row(
                    &self.row_source.relation,
                    u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            let row_weight = Self::little_endian_boolean_weight(
                row_point,
                u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
            );
            if row_weight != CompactChallengeField::ZERO {
                result += row_weight
                    * self.public_form_contribution(
                        Self::form_for_role(&row, matrix_role),
                        public_input,
                    )?;
            }
        }
        Ok(result)
    }

    fn accumulate_weighted_witness_covector_at_row_point(
        &self,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        if row_point.len() != self.row_point_variable_count
            || destination.len() != self.witness_length
        {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        for row_ordinal in 0..self.row_count {
            let row = self
                .row_source
                .matrices
                .row(
                    &self.row_source.relation,
                    u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
                )
                .map_err(|_| CompactCfwError::InvalidMatrixSource)?;
            let row_weight = Self::little_endian_boolean_weight(
                row_point,
                u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
            );
            for matrix_role in CompactCfwMatrixRole::ALL {
                self.accumulate_witness_form(
                    Self::form_for_role(&row, matrix_role),
                    row_weight,
                    matrix_role_weights[matrix_role.ordinal()],
                    destination,
                )?;
            }
        }
        Ok(())
    }
}

fn compact_signed_integer(value: i128) -> Result<CompactChallengeField, CompactCfwError> {
    base_element_from_signed_integer(value)
        .map(ProofChallengeExtensionElement::from_base)
        .map(compact_challenge_from_production)
        .map_err(|_| CompactCfwError::InvalidMatrixSource)
}

fn add_compact_witness_covector_entry(
    destination: &mut [CompactChallengeField],
    public_input_length: u64,
    matrix_dimension: u64,
    column_ordinal: u64,
    contribution: CompactChallengeField,
) -> Result<(), CompactCfwError> {
    if column_ordinal < public_input_length || column_ordinal >= matrix_dimension {
        return Err(CompactCfwError::InvalidMatrixSource);
    }
    let destination_ordinal = usize::try_from(column_ordinal - public_input_length)
        .map_err(|_| CompactCfwError::CountOverflow)?;
    *destination
        .get_mut(destination_ordinal)
        .ok_or(CompactCfwError::InvalidMatrixSource)? += contribution;
    Ok(())
}

impl<Assignment: CompactStructuredAssignmentSource> CompactCfwExternalRowSource
    for CompactStructuredR1csRowSource<Assignment>
{
    fn witness_length(&self) -> Result<usize, CompactCfwError> {
        usize::try_from(CompactStructuredR1csRowSource::witness_length(self))
            .map_err(|_| CompactCfwError::CountOverflow)
    }

    fn row_count(&self) -> Result<usize, CompactCfwError> {
        usize::try_from(CompactStructuredR1csRowSource::row_count(self))
            .map_err(|_| CompactCfwError::CountOverflow)
    }

    fn evaluate_row(
        &self,
        row_ordinal: usize,
    ) -> Result<[ProofChallengeExtensionElement; COMPACT_CFW_MATRIX_COUNT], CompactCfwError> {
        let evaluation = CompactStructuredR1csRowSource::evaluate_row(
            self,
            u64::try_from(row_ordinal).map_err(|_| CompactCfwError::CountOverflow)?,
        )
        .map_err(|error| match error {
            CommonProofProverError::CountOverflow
            | CommonProofProverError::AllocationLimitExceeded
            | CommonProofProverError::ResidentMemoryLimitExceeded => CompactCfwError::CountOverflow,
            _ => CompactCfwError::InvalidMatrixSource,
        })?;
        Ok([evaluation.left, evaluation.right, evaluation.output])
    }
}

fn extension_base_value(
    value: ProofChallengeExtensionElement,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let coordinates = value.canonical_coordinates();
    if coordinates[1..].iter().any(|coordinate| *coordinate != 0) {
        return Err(CommonProofProverError::InvalidInput);
    }
    ProofBaseFieldElement::from_canonical(coordinates[0]).map_err(Into::into)
}

fn base_element_from_signed_integer(
    value: i128,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let canonical_value = u64::try_from(value.rem_euclid(i128::from(PROOF_BASE_FIELD_MODULUS)))
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    ProofBaseFieldElement::from_canonical(canonical_value).map_err(Into::into)
}

fn fallible_base_vector(
    capacity: u64,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofProverError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(
            usize::try_from(capacity).map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    Ok(Zeroizing::new(values))
}

fn fallible_extension_vector(
    capacity: u64,
) -> Result<Zeroizing<Vec<ProofChallengeExtensionElement>>, CommonProofProverError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(
            usize::try_from(capacity).map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    Ok(Zeroizing::new(values))
}

fn small_vector_witness_kind(kind: CompactSmallVectorKind) -> CompactWitnessSegmentKind {
    match kind {
        CompactSmallVectorKind::ShiftedTernary => CompactWitnessSegmentKind::ShiftedTernaryValues,
        CompactSmallVectorKind::ShiftedEtaTwo => CompactWitnessSegmentKind::ShiftedEtaTwoValues,
    }
}

fn push_centering_constant(
    form: &mut CompactStructuredLinearForm,
    integer_coefficient: i128,
    centered_offset: u64,
) -> Result<(), RelationPlanError> {
    let correction = integer_coefficient
        .checked_mul(i128::from(centered_offset))
        .and_then(i128::checked_neg)
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    if correction != 0 {
        form.ordered_terms
            .push(CompactStructuredMatrixTerm::StaticEntry {
                column_ordinal: 0,
                integer_coefficient: correction,
            });
    }
    Ok(())
}

fn value_minus_constant_form(
    value_column: u64,
    one_column: u64,
    constant: u64,
) -> CompactStructuredLinearForm {
    CompactStructuredLinearForm {
        ordered_terms: vec![
            CompactStructuredMatrixTerm::StaticEntry {
                column_ordinal: value_column,
                integer_coefficient: 1,
            },
            CompactStructuredMatrixTerm::StaticEntry {
                column_ordinal: one_column,
                integer_coefficient: -i128::from(constant),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    #[cfg(not(target_arch = "wasm32"))]
    use core::mem::size_of;

    #[cfg(not(target_arch = "wasm32"))]
    use std::{
        env,
        fs::{self, OpenOptions},
        io::{ErrorKind, Write},
        path::{Path, PathBuf},
        process,
        time::Instant,
    };

    #[cfg(not(target_arch = "wasm32"))]
    use super::super::{
        generation_state::{
            CompactPublicKeyGenerationPoll, CompactPublicKeyGenerationState,
            CompactPublicKeyMainEpochPoll, PreparedCompactPublicKeyMainEpoch,
        },
        prepare_compact_public_key_assignment_sources,
    };
    use super::*;
    use crate::bgv::proof_suite::compact_cfw::{
        COMPACT_CFW_MATRIX_COUNT, CompactCfwGeometry, CompactCfwMaskMaterial,
        compact_challenge_from_production, compact_challenge_to_production,
    };
    use crate::bgv::proof_suite::compact_cfw_external_prover::{
        CompactCfwExternalProverState, CompactCfwExternalRowSource,
    };
    use crate::bgv::proof_suite::external_memory::tests::{FileBackedTestStorage, TestStorage};
    use crate::bgv::proof_suite::field::{
        PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement,
        ProofChallengeExtensionElement,
    };
    #[cfg(not(target_arch = "wasm32"))]
    use crate::{
        bgv::{
            proof_suite::{
                CommonProofRelationPlanCapability, SelectedApplicationStatementContext,
                SourceVerifiedCompactPublicKeyProof, VerifiedCommonProofStatementSource,
                VerifiedCompactPublicKeyStatementAuthority,
                compact_corpus_accounting::{
                    derive_selected_compact_corpus_rollup,
                    derive_selected_public_key_share_emitted_size_evidence,
                    derive_selected_public_key_share_source_verified_size_evidence,
                },
                compact_emitted_cdhz::{
                    CompactEmittedCdhzMeasurement, measure_selected_compact_emission_cdhz,
                    measure_source_verified_compact_emission_cdhz,
                },
                compact_fixed_tape_domain_extension::derive_source_verified_compact_fixed_tape_domain_extension,
                compact_fixed_tape_source_correspondence::verify_source_verified_compact_fixed_tape_correspondence,
                compact_fixed_tape_uniformity::CompactFixedTapeUniformityPremise,
                compact_proof_contract::{CompactPublicKeyProofContract, CompactWhirEpochContract},
                compact_proof_wire::{
                    CompactPublicInputBindings, PROOF_FIXED_HEADER_BYTE_LENGTH,
                    PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH, decode_compact_proof_wire,
                },
                compact_public_key_accepted_verifier::{
                    ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT,
                    ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH,
                    AcceptedCompactPublicKeyVerification, AcceptedCompactPublicKeyVerificationPoll,
                    PreparedAcceptedCompactPublicKeyVerification,
                },
                compact_public_key_algebraic_verifier::{
                    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_SAFE_BOUNDARY_COUNT,
                    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
                    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL,
                    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT,
                    CompactPublicKeyAlgebraicVerification,
                    CompactPublicKeyAlgebraicVerificationError,
                    CompactPublicKeyAlgebraicVerificationPoll,
                    compact_public_key_whir_fold_work_unit_count,
                },
                compact_public_key_verifier::{
                    VerifiedCompactPublicKeyTransport, verify_selected_compact_public_key_transport,
                },
                compact_response_merkle::CompactResponseLeafValueKind,
                compile_public_key_share_relation_with_source_layout,
                decode_selected_public_key_share_statement,
                prover::{
                    CommonProofPrivateCoinCoordinateCapacity,
                    PrivateRandomnessCommonProofCoinSource,
                },
                selected_proof_runtime_limits, verified_application_statement_hash,
            },
            setup::{
                SetupGenerationKeyRelationApplication, SetupKeyRelationGenerationPreparationError,
                SetupKeyRelationProofFamily, VerifiedSetupPolynomialLowDegreePrerequisite,
                populate_compact_public_key_development_evidence_authority,
                resolve_setup_generation_compact_public_key_development_preparation_source,
                with_exclusive_setup_generation_compact_public_key_development_relation,
            },
        },
        foundation::{
            ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessRoot, CanonicalStreamDomain,
            Hash512, PersistentProofCoinInput, ProofApplicationSlot, RefusalReason,
            derive_canonical_stream_descriptor, prepare_exact_same_secret_evidence_attempt,
        },
    };

    #[cfg(not(target_arch = "wasm32"))]
    const COMPACT_PUBLIC_KEY_ALGEBRAIC_CHECKPOINT_CONTEXT_MAGIC: [u8; 8] = *b"SLCAPK01";
    #[cfg(not(target_arch = "wasm32"))]
    const COMPACT_PROOF_EVIDENCE_PROCESS_RECORD_MAGIC: [u8; 8] = *b"SLCPPE01";
    #[cfg(not(target_arch = "wasm32"))]
    const COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER_BYTE_LENGTH: usize = 32;
    #[cfg(not(target_arch = "wasm32"))]
    const COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER_ENVIRONMENT_VARIABLE: &str =
        "SEALED_LATTICE_COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER";

    #[cfg(not(target_arch = "wasm32"))]
    fn compact_public_key_algebraic_checkpoint_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("the kernel crate belongs to the repository workspace")
            .join("temp")
            .join("test-checkpoints")
            .join("compact-public-key-algebraic-verification")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn compact_proof_evidence_run_identifier()
    -> [u8; COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER_BYTE_LENGTH] {
        let identifier = env::var(COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER_ENVIRONMENT_VARIABLE)
            .expect("the compact proof-evidence runner supplies one run identifier");
        assert_eq!(
            identifier.len(),
            COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER_BYTE_LENGTH,
            "the compact proof-evidence run identifier has its fixed length"
        );
        assert!(
            identifier
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "the compact proof-evidence run identifier is lowercase hexadecimal"
        );
        identifier
            .into_bytes()
            .try_into()
            .expect("the validated compact proof-evidence run identifier has its fixed length")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_compact_proof_evidence_producer_process_record(directory: &Path) {
        fs::create_dir_all(directory).expect("the compact evidence directory is available");
        let path = directory.join("producer-process.bin");
        let mut bytes = Vec::with_capacity(
            COMPACT_PROOF_EVIDENCE_PROCESS_RECORD_MAGIC.len()
                + size_of::<u32>()
                + COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER_BYTE_LENGTH,
        );
        bytes.extend_from_slice(&COMPACT_PROOF_EVIDENCE_PROCESS_RECORD_MAGIC);
        bytes.extend_from_slice(&process::id().to_le_bytes());
        bytes.extend_from_slice(&compact_proof_evidence_run_identifier());
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .expect("the compact producer process record opens exclusively for replacement");
        file.write_all(&bytes)
            .expect("the complete compact producer process record is written");
        file.sync_all()
            .expect("the complete compact producer process record is durable");
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_compact_proof_evidence_consumer_is_a_separate_process(directory: &Path) {
        let bytes = fs::read(directory.join("producer-process.bin"))
            .expect("the compact producer process record exists");
        let expected_byte_length = COMPACT_PROOF_EVIDENCE_PROCESS_RECORD_MAGIC.len()
            + size_of::<u32>()
            + COMPACT_PROOF_EVIDENCE_RUN_IDENTIFIER_BYTE_LENGTH;
        assert_eq!(bytes.len(), expected_byte_length);
        assert_eq!(
            &bytes[..COMPACT_PROOF_EVIDENCE_PROCESS_RECORD_MAGIC.len()],
            &COMPACT_PROOF_EVIDENCE_PROCESS_RECORD_MAGIC
        );
        let process_identifier_start = COMPACT_PROOF_EVIDENCE_PROCESS_RECORD_MAGIC.len();
        let process_identifier_end = process_identifier_start + size_of::<u32>();
        let producer_process_identifier = u32::from_le_bytes(
            bytes[process_identifier_start..process_identifier_end]
                .try_into()
                .expect("the producer process identifier is complete"),
        );
        assert_ne!(
            producer_process_identifier,
            process::id(),
            "the compact restoration owner must run in a separate process"
        );
        assert_eq!(
            &bytes[process_identifier_end..],
            &compact_proof_evidence_run_identifier(),
            "producer and restoration processes must belong to the same guarded evidence run"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_or_validate_compact_public_key_algebraic_checkpoint_file(
        directory: &Path,
        file_name: &str,
        expected_bytes: &[u8],
    ) {
        fs::create_dir_all(directory).expect("the algebraic checkpoint directory is available");
        let path = directory.join(file_name);
        match fs::read(&path) {
            Ok(existing_bytes) => assert_eq!(
                existing_bytes, expected_bytes,
                "the existing algebraic checkpoint must match the current deterministic proof"
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .expect("the new algebraic checkpoint file is created exactly once");
                file.write_all(expected_bytes)
                    .expect("the complete algebraic checkpoint file is written");
                file.sync_all()
                    .expect("the complete algebraic checkpoint file is durable");
            }
            Err(error) => panic!("the algebraic checkpoint file can be read: {error}"),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn encode_compact_public_key_algebraic_checkpoint_context(
        public_input_bindings: CompactPublicInputBindings,
        proof_attempt_identifier: [u8; 32],
        compact_construction_identity_hash: [u8; Hash512::BYTE_LENGTH],
        checkpoint_schedule_digest: Hash512,
        source_replay_binding: [u8; Hash512::BYTE_LENGTH],
        private_coin_derivation_binding_hash: Hash512,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            COMPACT_PUBLIC_KEY_ALGEBRAIC_CHECKPOINT_CONTEXT_MAGIC.len()
                + proof_attempt_identifier.len()
                + 8 * Hash512::BYTE_LENGTH,
        );
        bytes.extend_from_slice(&COMPACT_PUBLIC_KEY_ALGEBRAIC_CHECKPOINT_CONTEXT_MAGIC);
        bytes.extend_from_slice(&proof_attempt_identifier);
        for binding in public_input_bindings.ordered_hashes() {
            bytes.extend_from_slice(&binding.into_bytes());
        }
        bytes.extend_from_slice(&compact_construction_identity_hash);
        bytes.extend_from_slice(&checkpoint_schedule_digest.into_bytes());
        bytes.extend_from_slice(&source_replay_binding);
        bytes.extend_from_slice(&private_coin_derivation_binding_hash.into_bytes());
        bytes
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CompactPublicKeyAlgebraicCheckpointContext {
        proof_attempt_identifier: [u8; 32],
        public_input_bindings: CompactPublicInputBindings,
        compact_construction_identity_hash: [u8; Hash512::BYTE_LENGTH],
        checkpoint_schedule_digest: Hash512,
        source_replay_binding: [u8; Hash512::BYTE_LENGTH],
        private_coin_derivation_binding_hash: Hash512,
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn decode_compact_public_key_algebraic_checkpoint_context(
        bytes: &[u8],
    ) -> CompactPublicKeyAlgebraicCheckpointContext {
        const PROOF_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
        const CONTEXT_HASH_COUNT: usize = 8;
        let expected_byte_length = COMPACT_PUBLIC_KEY_ALGEBRAIC_CHECKPOINT_CONTEXT_MAGIC.len()
            + PROOF_ATTEMPT_IDENTIFIER_BYTE_LENGTH
            + CONTEXT_HASH_COUNT * Hash512::BYTE_LENGTH;
        assert_eq!(bytes.len(), expected_byte_length);
        assert_eq!(
            &bytes[..COMPACT_PUBLIC_KEY_ALGEBRAIC_CHECKPOINT_CONTEXT_MAGIC.len()],
            &COMPACT_PUBLIC_KEY_ALGEBRAIC_CHECKPOINT_CONTEXT_MAGIC
        );
        let mut cursor = COMPACT_PUBLIC_KEY_ALGEBRAIC_CHECKPOINT_CONTEXT_MAGIC.len();
        let proof_attempt_identifier: [u8; PROOF_ATTEMPT_IDENTIFIER_BYTE_LENGTH] = bytes
            [cursor..cursor + PROOF_ATTEMPT_IDENTIFIER_BYTE_LENGTH]
            .try_into()
            .expect("the checkpoint context contains one complete proof-attempt identifier");
        assert_ne!(
            proof_attempt_identifier,
            [0_u8; PROOF_ATTEMPT_IDENTIFIER_BYTE_LENGTH]
        );
        cursor += PROOF_ATTEMPT_IDENTIFIER_BYTE_LENGTH;
        let mut context_hashes = Vec::with_capacity(CONTEXT_HASH_COUNT);
        for _ in 0..CONTEXT_HASH_COUNT {
            let hash_bytes: [u8; Hash512::BYTE_LENGTH] = bytes
                [cursor..cursor + Hash512::BYTE_LENGTH]
                .try_into()
                .expect("the checkpoint context contains one complete hash");
            assert_ne!(hash_bytes, [0_u8; Hash512::BYTE_LENGTH]);
            context_hashes.push(Hash512::from_bytes(hash_bytes));
            cursor += Hash512::BYTE_LENGTH;
        }
        assert_eq!(cursor, bytes.len());
        CompactPublicKeyAlgebraicCheckpointContext {
            proof_attempt_identifier,
            public_input_bindings: CompactPublicInputBindings::new(
                context_hashes[0],
                context_hashes[1],
                context_hashes[2],
                context_hashes[3],
            ),
            compact_construction_identity_hash: context_hashes[4].into_bytes(),
            checkpoint_schedule_digest: context_hashes[5],
            source_replay_binding: context_hashes[6].into_bytes(),
            private_coin_derivation_binding_hash: context_hashes[7],
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn verify_compact_public_key_bytes_algebraically(
        public_input_bindings: CompactPublicInputBindings,
        canonical_proof_bytes: Box<[u8]>,
        canonical_public_input_bytes: Box<[u8]>,
    ) -> (VerifiedCompactPublicKeyTransport, u64) {
        let transport = verify_selected_compact_public_key_transport(
            public_input_bindings,
            canonical_proof_bytes,
            canonical_public_input_bytes,
        )
        .expect("the emitted proof passes independent compact transport verification");
        let mut algebraic_verification = CompactPublicKeyAlgebraicVerification::begin(transport)
            .expect("the compact algebraic verifier accepts the transported inputs");
        let mut algebraic_poll_count = 0_u64;
        let algebraic_terminal = loop {
            match algebraic_verification
                .advance(65_536)
                .expect("the compact CFW and WHIR equations verify")
            {
                CompactPublicKeyAlgebraicVerificationPoll::WorkCompleted {
                    completed_work_unit_count,
                    ..
                } => {
                    assert!(completed_work_unit_count > 0);
                    algebraic_poll_count += 1;
                }
                CompactPublicKeyAlgebraicVerificationPoll::ResumeComplete { .. } => {
                    panic!("a fresh compact algebraic verification cannot complete replay")
                }
                CompactPublicKeyAlgebraicVerificationPoll::WhirResumeComplete { .. } => {
                    panic!("a fresh compact WHIR verification cannot complete replay")
                }
                CompactPublicKeyAlgebraicVerificationPoll::WhirWorkCompleted {
                    completed_work_unit_count,
                    ..
                } => {
                    assert!((1..=65_536).contains(&completed_work_unit_count));
                    algebraic_poll_count += 1;
                }
                CompactPublicKeyAlgebraicVerificationPoll::WhirCompleted {
                    completed_work_unit_count,
                    ..
                } => {
                    assert!((1..=65_536).contains(&completed_work_unit_count));
                    algebraic_poll_count += 1;
                }
                CompactPublicKeyAlgebraicVerificationPoll::Complete(terminal) => break *terminal,
            }
        };
        (algebraic_terminal.into_transport(), algebraic_poll_count)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn refuse_transport_valid_equation_invalid_compact_public_key_proof(
        transport: VerifiedCompactPublicKeyTransport,
    ) -> (CompactPublicKeyAlgebraicVerificationError, u64) {
        let mut algebraic_verification = CompactPublicKeyAlgebraicVerification::begin(transport)
            .expect("the equation-invalid proof enters the algebraic verifier after transport");
        let mut algebraic_poll_count = 0_u64;
        loop {
            match algebraic_verification.advance(65_536) {
                Err(error) => return (error, algebraic_poll_count),
                Ok(CompactPublicKeyAlgebraicVerificationPoll::Complete(_)) => {
                    panic!("the equation-invalid witness proof cannot reach positive verification")
                }
                Ok(_) => {
                    algebraic_poll_count = algebraic_poll_count
                        .checked_add(1)
                        .expect("the hostile algebraic poll count fits u64");
                }
            }
        }
    }

    struct CountingCompactCfwExternalRowSource<'source, Source> {
        source: &'source Source,
        evaluated_row_count: Cell<usize>,
    }

    impl<Source: CompactCfwExternalRowSource> CompactCfwExternalRowSource
        for CountingCompactCfwExternalRowSource<'_, Source>
    {
        fn witness_length(&self) -> Result<usize, CompactCfwError> {
            self.source.witness_length()
        }

        fn row_count(&self) -> Result<usize, CompactCfwError> {
            self.source.row_count()
        }

        fn evaluate_row(
            &self,
            row_ordinal: usize,
        ) -> Result<[ProofChallengeExtensionElement; COMPACT_CFW_MATRIX_COUNT], CompactCfwError>
        {
            let values = self.source.evaluate_row(row_ordinal)?;
            self.evaluated_row_count.set(
                self.evaluated_row_count
                    .get()
                    .checked_add(1)
                    .ok_or(CompactCfwError::CountOverflow)?,
            );
            Ok(values)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CompactR1csRowEvaluation {
        left: ProofChallengeExtensionElement,
        right: ProofChallengeExtensionElement,
        output: ProofChallengeExtensionElement,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CompactR1csInterpreterCertificate {
        matrix_dimension: u64,
        compared_operative_row_count: u64,
        covered_padding_row_count: u64,
        compared_constraint_kind_count: u64,
        mismatch_count: u64,
    }

    impl CompactR1csInterpreterCertificate {
        fn is_complete(self, relation: &CompactPublicKeyRelationCatalog) -> bool {
            self.matrix_dimension == relation.padded_constraint_count
                && self.compared_operative_row_count == relation.operative_constraint_count
                && self
                    .compared_operative_row_count
                    .checked_add(self.covered_padding_row_count)
                    == Some(relation.padded_constraint_count)
                && self.compared_constraint_kind_count == 9
                && self.mismatch_count == 0
        }
    }

    struct DeterministicR1csAssignment<'catalog> {
        relation: &'catalog CompactPublicKeyRelationCatalog,
        matrices: &'catalog CompactStructuredR1csCatalog,
        lookup_challenge: ProofChallengeExtensionElement,
    }

    impl<'catalog> DeterministicR1csAssignment<'catalog> {
        fn new(
            relation: &'catalog CompactPublicKeyRelationCatalog,
            matrices: &'catalog CompactStructuredR1csCatalog,
        ) -> Self {
            Self {
                relation,
                matrices,
                lookup_challenge: ProofChallengeExtensionElement::from_canonical_coordinates([
                    7, 1, 2, 3, 4,
                ])
                .expect("deterministic lookup challenge is canonical"),
            }
        }

        fn value_at_column(
            &self,
            column_ordinal: u64,
        ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
            if column_ordinal == 0 {
                return Ok(ProofChallengeExtensionElement::ONE);
            }
            if column_ordinal < self.matrices.public_input_length {
                let logical_ordinal = column_ordinal - 1;
                let vector_ordinal = logical_ordinal / self.relation.ring_degree;
                let coefficient_ordinal = logical_ordinal % self.relation.ring_degree;
                if vector_ordinal
                    >= u64::try_from(self.matrices.public_vector_ordinals.len())
                        .map_err(|_| RelationPlanError::CountOverflow)?
                {
                    return Ok(ProofChallengeExtensionElement::ZERO);
                }
                return self.public_value(vector_ordinal, coefficient_ordinal);
            }
            if column_ordinal >= self.matrices.matrix_dimension {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let witness_element = column_ordinal - self.matrices.public_input_length;
            for segment in &self.relation.ordered_witness_segments {
                let segment_end = segment
                    .first_element
                    .checked_add(segment.element_count)
                    .ok_or(RelationPlanError::CountOverflow)?;
                if witness_element >= segment.first_element && witness_element < segment_end {
                    let local_element = witness_element - segment.first_element;
                    return self.witness_value(
                        segment.kind,
                        local_element / self.relation.ring_degree,
                        local_element % self.relation.ring_degree,
                    );
                }
            }
            Ok(ProofChallengeExtensionElement::ZERO)
        }

        fn public_value(
            &self,
            vector_ordinal: u64,
            coefficient_ordinal: u64,
        ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
            let value = self
                .public_nonzero_entries(vector_ordinal)?
                .into_iter()
                .filter(|(ordinal, _)| *ordinal == coefficient_ordinal)
                .try_fold(0_u64, |sum, (_, value)| {
                    sum.checked_add(value)
                        .ok_or(RelationPlanError::CountOverflow)
                })?
                % PROOF_BASE_FIELD_MODULUS;
            base_extension(value)
        }

        fn public_nonzero_entries(
            &self,
            vector_ordinal: u64,
        ) -> Result<Vec<(u64, u64)>, RelationPlanError> {
            let first = vector_ordinal
                .checked_mul(7_919)
                .and_then(|value| value.checked_add(17))
                .ok_or(RelationPlanError::CountOverflow)?
                % self.relation.ring_degree;
            let second = vector_ordinal
                .checked_mul(104_729)
                .and_then(|value| value.checked_add(12_345))
                .ok_or(RelationPlanError::CountOverflow)?
                % self.relation.ring_degree;
            let first_value = vector_ordinal
                .checked_mul(13)
                .and_then(|value| value.checked_add(3))
                .ok_or(RelationPlanError::CountOverflow)?;
            let second_value = vector_ordinal
                .checked_mul(29)
                .and_then(|value| value.checked_add(5))
                .ok_or(RelationPlanError::CountOverflow)?;
            if first == second {
                Ok(vec![(
                    first,
                    first_value
                        .checked_add(second_value)
                        .ok_or(RelationPlanError::CountOverflow)?,
                )])
            } else {
                Ok(vec![(first, first_value), (second, second_value)])
            }
        }

        fn witness_value(
            &self,
            kind: CompactWitnessSegmentKind,
            vector_ordinal: u64,
            coefficient_ordinal: u64,
        ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
            let seed = vector_ordinal
                .checked_mul(65_537)
                .and_then(|value| value.checked_add(coefficient_ordinal.wrapping_mul(257)))
                .and_then(|value| value.checked_add(kind as u64 * 17))
                .ok_or(RelationPlanError::CountOverflow)?;
            match kind {
                CompactWitnessSegmentKind::ModularQuotients => {
                    base_extension(seed % self.relation.quotient_lookup_table_value_count)
                }
                CompactWitnessSegmentKind::LookupMultiplicities => base_extension(seed % 11),
                CompactWitnessSegmentKind::ShiftedTernaryValues => base_extension(seed % 3),
                CompactWitnessSegmentKind::ShiftedEtaTwoValues => base_extension(seed % 5),
                CompactWitnessSegmentKind::SmallSetProducts => base_extension(seed % 97),
                CompactWitnessSegmentKind::LookupInverses => {
                    ProofChallengeExtensionElement::from_canonical_coordinates([
                        seed % PROOF_BASE_FIELD_MODULUS,
                        (seed + 1) % PROOF_BASE_FIELD_MODULUS,
                        (seed + 3) % PROOF_BASE_FIELD_MODULUS,
                        (seed + 7) % PROOF_BASE_FIELD_MODULUS,
                        (seed + 11) % PROOF_BASE_FIELD_MODULUS,
                    ])
                    .map_err(|_| RelationPlanError::InvalidConstraint)
                }
            }
        }
    }

    impl CompactStructuredAssignmentSource for DeterministicR1csAssignment<'_> {
        fn padded_public_input_element_count(&self) -> u64 {
            self.matrices.public_input_length
        }

        fn padded_witness_element_count(&self) -> u64 {
            self.matrices.witness_length
        }

        fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
            self.lookup_challenge
        }

        fn public_input_value(
            &self,
            element_ordinal: u64,
        ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
            self.value_at_column(element_ordinal)
                .map_err(CommonProofProverError::Relation)
        }

        fn witness_value(
            &self,
            element_ordinal: u64,
        ) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
            self.value_at_column(
                self.matrices
                    .public_input_length
                    .checked_add(element_ordinal)
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .map_err(CommonProofProverError::Relation)
        }
    }

    fn base_extension(value: u64) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        ProofBaseFieldElement::from_canonical(value)
            .map(ProofChallengeExtensionElement::from_base)
            .map_err(|_| RelationPlanError::InvalidConstraint)
    }

    fn signed_extension(value: i128) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let modulus = i128::from(PROOF_BASE_FIELD_MODULUS);
        let canonical = u64::try_from(value.rem_euclid(modulus))
            .map_err(|_| RelationPlanError::IntegerBoundOverflow)?;
        base_extension(canonical)
    }

    fn evaluate_form(
        form: &CompactStructuredLinearForm,
        assignment: &DeterministicR1csAssignment<'_>,
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let mut sum = ProofChallengeExtensionElement::ZERO;
        for term in &form.ordered_terms {
            let contribution = match *term {
                CompactStructuredMatrixTerm::StaticEntry {
                    column_ordinal,
                    integer_coefficient,
                } => assignment
                    .value_at_column(column_ordinal)?
                    .multiply(signed_extension(integer_coefficient)?),
                CompactStructuredMatrixTerm::LookupChallengeEntry { column_ordinal } => assignment
                    .value_at_column(column_ordinal)?
                    .multiply(assignment.lookup_challenge),
                CompactStructuredMatrixTerm::UniformStaticRange {
                    first_column_ordinal,
                    element_count,
                    integer_coefficient,
                } => {
                    let coefficient = signed_extension(integer_coefficient)?;
                    let mut range_sum = ProofChallengeExtensionElement::ZERO;
                    for offset in 0..element_count {
                        range_sum = range_sum.add(
                            assignment
                                .value_at_column(first_column_ordinal + offset)?
                                .multiply(coefficient),
                        );
                    }
                    range_sum
                }
                CompactStructuredMatrixTerm::NegatedLookupTableReciprocalRange {
                    first_column_ordinal,
                    table_value_count,
                } => {
                    let mut range_sum = ProofChallengeExtensionElement::ZERO;
                    for table_value in 0..table_value_count {
                        let denominator = assignment
                            .lookup_challenge
                            .add(base_extension(table_value)?);
                        let reciprocal = denominator
                            .inverse()
                            .map_err(|_| RelationPlanError::InvalidConstraint)?
                            .negate();
                        range_sum = range_sum.add(
                            assignment
                                .value_at_column(first_column_ordinal + table_value)?
                                .multiply(reciprocal),
                        );
                    }
                    range_sum
                }
                CompactStructuredMatrixTerm::PublicNegacyclicMatrixBand {
                    public_vector_first_column_ordinal,
                    private_vector_first_column_ordinal,
                    output_coefficient_ordinal,
                    centered_offset,
                    integer_coefficient,
                } => evaluate_expanded_negacyclic_matrix_band(
                    assignment,
                    public_vector_first_column_ordinal,
                    private_vector_first_column_ordinal,
                    output_coefficient_ordinal,
                    centered_offset,
                    integer_coefficient,
                )?,
            };
            sum = sum.add(contribution);
        }
        Ok(sum)
    }

    fn evaluate_expanded_negacyclic_matrix_band(
        assignment: &DeterministicR1csAssignment<'_>,
        public_vector_first_column_ordinal: u64,
        private_vector_first_column_ordinal: u64,
        output_coefficient_ordinal: u64,
        centered_offset: u64,
        integer_coefficient: i128,
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let public_vector_ordinal = public_vector_first_column_ordinal
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidConstraint)?
            / assignment.relation.ring_degree;
        let mut sum = ProofChallengeExtensionElement::ZERO;
        for (public_coefficient_ordinal, public_value) in
            assignment.public_nonzero_entries(public_vector_ordinal)?
        {
            let (private_coefficient_ordinal, negated) =
                if public_coefficient_ordinal <= output_coefficient_ordinal {
                    (
                        output_coefficient_ordinal - public_coefficient_ordinal,
                        false,
                    )
                } else {
                    (
                        assignment
                            .relation
                            .ring_degree
                            .checked_add(output_coefficient_ordinal)
                            .and_then(|value| value.checked_sub(public_coefficient_ordinal))
                            .ok_or(RelationPlanError::CountOverflow)?,
                        true,
                    )
                };
            let signed_coefficient = if negated {
                integer_coefficient
                    .checked_neg()
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?
            } else {
                integer_coefficient
            };
            let public_value = base_extension(public_value)?;
            let shifted_private = assignment.value_at_column(
                private_vector_first_column_ordinal + private_coefficient_ordinal,
            )?;
            let witness_entry = public_value
                .multiply(signed_extension(signed_coefficient)?)
                .multiply(shifted_private);
            let offset_entry = public_value.multiply(signed_extension(
                signed_coefficient
                    .checked_mul(i128::from(centered_offset))
                    .and_then(i128::checked_neg)
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?,
            )?);
            sum = sum.add(witness_entry).add(offset_entry);
        }
        Ok(sum)
    }

    fn evaluate_matrix_row(
        row: &CompactStructuredR1csRow,
        assignment: &DeterministicR1csAssignment<'_>,
    ) -> Result<CompactR1csRowEvaluation, RelationPlanError> {
        Ok(CompactR1csRowEvaluation {
            left: evaluate_form(&row.left, assignment)?,
            right: evaluate_form(&row.right, assignment)?,
            output: evaluate_form(&row.output, assignment)?,
        })
    }

    fn independently_interpret_row(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        assignment: &DeterministicR1csAssignment<'_>,
        row_ordinal: u64,
    ) -> Result<CompactR1csRowEvaluation, RelationPlanError> {
        let mut first_row = 0_u64;
        let exact_row_count = u64::try_from(relation.ordered_relations.len())
            .map_err(|_| RelationPlanError::CountOverflow)?
            .checked_mul(relation.ring_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        if row_ordinal < first_row + exact_row_count {
            return independently_interpret_exact_row(
                relation,
                matrices,
                assignment,
                row_ordinal - first_row,
            );
        }
        first_row += exact_row_count;
        if row_ordinal < first_row + exact_row_count {
            let local_row = row_ordinal - first_row;
            let vector_ordinal = local_row / relation.ring_degree;
            let coefficient_ordinal = local_row % relation.ring_degree;
            let quotient = assignment.value_at_column(matrices.witness_vector_column(
                relation,
                CompactWitnessSegmentKind::ModularQuotients,
                vector_ordinal,
                coefficient_ordinal,
            )?)?;
            let inverse = assignment.value_at_column(matrices.witness_vector_column(
                relation,
                CompactWitnessSegmentKind::LookupInverses,
                vector_ordinal,
                coefficient_ordinal,
            )?)?;
            return Ok(CompactR1csRowEvaluation {
                left: quotient.add(assignment.lookup_challenge),
                right: inverse,
                output: ProofChallengeExtensionElement::ONE,
            });
        }
        first_row += exact_row_count;

        let ternary_count = matrices
            .witness_segment_address(CompactWitnessSegmentKind::ShiftedTernaryValues)
            .ok_or(RelationPlanError::InvalidConstraint)?
            .vector_count;
        let ternary_rows = ternary_count
            .checked_mul(relation.ring_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        for terminal in [false, true] {
            if row_ordinal < first_row + ternary_rows {
                let local_row = row_ordinal - first_row;
                let vector_ordinal = local_row / relation.ring_degree;
                let coefficient_ordinal = local_row % relation.ring_degree;
                let value = assignment.value_at_column(matrices.witness_vector_column(
                    relation,
                    CompactWitnessSegmentKind::ShiftedTernaryValues,
                    vector_ordinal,
                    coefficient_ordinal,
                )?)?;
                let product = assignment.value_at_column(matrices.witness_vector_column(
                    relation,
                    CompactWitnessSegmentKind::SmallSetProducts,
                    vector_ordinal,
                    coefficient_ordinal,
                )?)?;
                return Ok(if terminal {
                    CompactR1csRowEvaluation {
                        left: product,
                        right: value.add(base_extension(2)?.negate()),
                        output: ProofChallengeExtensionElement::ZERO,
                    }
                } else {
                    CompactR1csRowEvaluation {
                        left: value,
                        right: value.add(ProofChallengeExtensionElement::ONE.negate()),
                        output: product,
                    }
                });
            }
            first_row += ternary_rows;
        }

        let eta_two_count = matrices
            .witness_segment_address(CompactWitnessSegmentKind::ShiftedEtaTwoValues)
            .ok_or(RelationPlanError::InvalidConstraint)?
            .vector_count;
        let eta_rows = eta_two_count
            .checked_mul(relation.ring_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        for product_ordinal in 0..3_u64 {
            if row_ordinal < first_row + eta_rows {
                return independently_interpret_eta_product_row(
                    relation,
                    matrices,
                    assignment,
                    row_ordinal - first_row,
                    product_ordinal,
                );
            }
            first_row += eta_rows;
        }
        if row_ordinal < first_row + eta_rows {
            let local_row = row_ordinal - first_row;
            let vector_ordinal = local_row / relation.ring_degree;
            let coefficient_ordinal = local_row % relation.ring_degree;
            let value = assignment.value_at_column(matrices.witness_vector_column(
                relation,
                CompactWitnessSegmentKind::ShiftedEtaTwoValues,
                vector_ordinal,
                coefficient_ordinal,
            )?)?;
            let product_vector_ordinal = ternary_count
                .checked_add(
                    vector_ordinal
                        .checked_mul(3)
                        .and_then(|value| value.checked_add(2))
                        .ok_or(RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::CountOverflow)?;
            let product = assignment.value_at_column(matrices.witness_vector_column(
                relation,
                CompactWitnessSegmentKind::SmallSetProducts,
                product_vector_ordinal,
                coefficient_ordinal,
            )?)?;
            return Ok(CompactR1csRowEvaluation {
                left: product,
                right: value.add(base_extension(4)?.negate()),
                output: ProofChallengeExtensionElement::ZERO,
            });
        }
        first_row += eta_rows;

        if row_ordinal == first_row {
            let inverse_count = exact_row_count;
            let inverse_first = matrices.witness_vector_column(
                relation,
                CompactWitnessSegmentKind::LookupInverses,
                0,
                0,
            )?;
            let multiplicity_first = matrices.witness_vector_column(
                relation,
                CompactWitnessSegmentKind::LookupMultiplicities,
                0,
                0,
            )?;
            let mut left = ProofChallengeExtensionElement::ZERO;
            for offset in 0..inverse_count {
                left = left.add(assignment.value_at_column(inverse_first + offset)?);
            }
            for table_value in 0..relation.quotient_lookup_table_value_count {
                let reciprocal = assignment
                    .lookup_challenge
                    .add(base_extension(table_value)?)
                    .inverse()
                    .map_err(|_| RelationPlanError::InvalidConstraint)?;
                left = left.add(
                    assignment
                        .value_at_column(multiplicity_first + table_value)?
                        .multiply(reciprocal)
                        .negate(),
                );
            }
            return Ok(CompactR1csRowEvaluation {
                left,
                right: ProofChallengeExtensionElement::ONE,
                output: ProofChallengeExtensionElement::ZERO,
            });
        }
        Err(RelationPlanError::InvalidConstraint)
    }

    fn independently_interpret_exact_row(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        assignment: &DeterministicR1csAssignment<'_>,
        local_row: u64,
    ) -> Result<CompactR1csRowEvaluation, RelationPlanError> {
        let relation_ordinal = local_row / relation.ring_degree;
        let output_coefficient_ordinal = local_row % relation.ring_degree;
        let structured_relation = relation
            .ordered_relations
            .get(usize::try_from(relation_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let mut left = ProofChallengeExtensionElement::ZERO;
        for term in &structured_relation.ordered_terms {
            let contribution = match term {
                CompactStructuredLinearTerm::Direct {
                    vector,
                    centered_offset,
                    integer_coefficient,
                } => {
                    let value = if let Some(public_vector_ordinal) =
                        matrices.public_vector_ordinal(*vector)
                    {
                        assignment.value_at_column(matrices.public_vector_column(
                            relation,
                            public_vector_ordinal,
                            output_coefficient_ordinal,
                        )?)?
                    } else {
                        let address = matrices
                            .private_small_vector_address(*vector)
                            .ok_or(RelationPlanError::InvalidConstraint)?;
                        assignment
                            .value_at_column(matrices.witness_vector_column(
                                relation,
                                small_vector_witness_kind(address.kind),
                                address.vector_ordinal_within_kind,
                                output_coefficient_ordinal,
                            )?)?
                            .add(base_extension(*centered_offset)?.negate())
                    };
                    value.multiply(signed_extension(*integer_coefficient)?)
                }
                CompactStructuredLinearTerm::NegacyclicPublicProduct {
                    public_vector,
                    private_vector,
                    private_centered_offset,
                    integer_coefficient,
                } => independently_interpret_negacyclic_product(
                    relation,
                    matrices,
                    assignment,
                    *public_vector,
                    *private_vector,
                    output_coefficient_ordinal,
                    *private_centered_offset,
                    i128::from(*integer_coefficient),
                )?,
                CompactStructuredLinearTerm::ModulusQuotient {
                    modulus,
                    integer_coefficient,
                    ..
                } => {
                    let encoded_quotient =
                        assignment.value_at_column(matrices.witness_vector_column(
                            relation,
                            CompactWitnessSegmentKind::ModularQuotients,
                            relation_ordinal,
                            output_coefficient_ordinal,
                        )?)?;
                    let quotient = encoded_quotient
                        .add(base_extension(MODULAR_QUOTIENT_ENCODING_OFFSET)?.negate());
                    quotient.multiply(signed_extension(
                        i128::from(*integer_coefficient)
                            .checked_mul(i128::from(*modulus))
                            .ok_or(RelationPlanError::IntegerBoundOverflow)?,
                    )?)
                }
            };
            left = left.add(contribution);
        }
        Ok(CompactR1csRowEvaluation {
            left,
            right: ProofChallengeExtensionElement::ONE,
            output: ProofChallengeExtensionElement::ZERO,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn independently_interpret_negacyclic_product(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        assignment: &DeterministicR1csAssignment<'_>,
        public_vector: CompactRingVectorReference,
        private_vector: CompactRingVectorReference,
        output_coefficient_ordinal: u64,
        centered_offset: u64,
        integer_coefficient: i128,
    ) -> Result<ProofChallengeExtensionElement, RelationPlanError> {
        let public_vector_ordinal = matrices
            .public_vector_ordinal(public_vector)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let private_address = matrices
            .private_small_vector_address(private_vector)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let mut result = ProofChallengeExtensionElement::ZERO;
        for (public_coefficient_ordinal, public_value) in
            assignment.public_nonzero_entries(public_vector_ordinal)?
        {
            let (private_coefficient_ordinal, negative) =
                if public_coefficient_ordinal <= output_coefficient_ordinal {
                    (
                        output_coefficient_ordinal - public_coefficient_ordinal,
                        false,
                    )
                } else {
                    (
                        relation
                            .ring_degree
                            .checked_add(output_coefficient_ordinal)
                            .and_then(|value| value.checked_sub(public_coefficient_ordinal))
                            .ok_or(RelationPlanError::CountOverflow)?,
                        true,
                    )
                };
            let private_value = assignment
                .value_at_column(matrices.witness_vector_column(
                    relation,
                    small_vector_witness_kind(private_address.kind),
                    private_address.vector_ordinal_within_kind,
                    private_coefficient_ordinal,
                )?)?
                .add(base_extension(centered_offset)?.negate());
            let signed_coefficient = if negative {
                integer_coefficient
                    .checked_neg()
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?
            } else {
                integer_coefficient
            };
            result = result.add(
                base_extension(public_value)?
                    .multiply(private_value)
                    .multiply(signed_extension(signed_coefficient)?),
            );
        }
        Ok(result)
    }

    fn independently_interpret_eta_product_row(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
        assignment: &DeterministicR1csAssignment<'_>,
        local_row: u64,
        product_ordinal: u64,
    ) -> Result<CompactR1csRowEvaluation, RelationPlanError> {
        let vector_ordinal = local_row / relation.ring_degree;
        let coefficient_ordinal = local_row % relation.ring_degree;
        let value = assignment.value_at_column(matrices.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::ShiftedEtaTwoValues,
            vector_ordinal,
            coefficient_ordinal,
        )?)?;
        let ternary_count = matrices
            .witness_segment_address(CompactWitnessSegmentKind::ShiftedTernaryValues)
            .ok_or(RelationPlanError::InvalidConstraint)?
            .vector_count;
        let product_vector_ordinal = ternary_count
            .checked_add(
                vector_ordinal
                    .checked_mul(3)
                    .and_then(|value| value.checked_add(product_ordinal))
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?;
        let output = assignment.value_at_column(matrices.witness_vector_column(
            relation,
            CompactWitnessSegmentKind::SmallSetProducts,
            product_vector_ordinal,
            coefficient_ordinal,
        )?)?;
        let left = if product_ordinal == 0 {
            value
        } else {
            assignment.value_at_column(matrices.witness_vector_column(
                relation,
                CompactWitnessSegmentKind::SmallSetProducts,
                product_vector_ordinal - 1,
                coefficient_ordinal,
            )?)?
        };
        Ok(CompactR1csRowEvaluation {
            left,
            right: value.add(base_extension(product_ordinal + 1)?.negate()),
            output,
        })
    }

    fn check_interpreter_correspondence(
        relation: &CompactPublicKeyRelationCatalog,
        matrices: &CompactStructuredR1csCatalog,
    ) -> Result<CompactR1csInterpreterCertificate, RelationPlanError> {
        let assignment = DeterministicR1csAssignment::new(relation, matrices);
        let mut compared_constraint_kinds = std::collections::BTreeSet::new();
        let mut mismatch_count = 0_u64;
        for row_ordinal in 0..relation.operative_constraint_count {
            let matrix_row = matrices.row(relation, row_ordinal)?;
            compared_constraint_kinds.insert(matrix_row.kind as u8);
            let matrix_evaluation = evaluate_matrix_row(&matrix_row, &assignment)?;
            let independent_evaluation =
                independently_interpret_row(relation, matrices, &assignment, row_ordinal)?;
            if matrix_evaluation != independent_evaluation {
                mismatch_count = mismatch_count
                    .checked_add(1)
                    .ok_or(RelationPlanError::CountOverflow)?;
            }
        }
        let padding_row_count = relation
            .padded_constraint_count
            .checked_sub(relation.operative_constraint_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        let first_padding = matrices.row(relation, relation.operative_constraint_count)?;
        let last_padding = matrices.row(relation, relation.padded_constraint_count - 1)?;
        if first_padding.kind != CompactR1csConstraintKind::ZeroPadding
            || last_padding.kind != CompactR1csConstraintKind::ZeroPadding
            || evaluate_matrix_row(&first_padding, &assignment)?
                != (CompactR1csRowEvaluation {
                    left: ProofChallengeExtensionElement::ZERO,
                    right: ProofChallengeExtensionElement::ZERO,
                    output: ProofChallengeExtensionElement::ZERO,
                })
            || evaluate_matrix_row(&last_padding, &assignment)?
                != (CompactR1csRowEvaluation {
                    left: ProofChallengeExtensionElement::ZERO,
                    right: ProofChallengeExtensionElement::ZERO,
                    output: ProofChallengeExtensionElement::ZERO,
                })
        {
            mismatch_count = mismatch_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        Ok(CompactR1csInterpreterCertificate {
            matrix_dimension: matrices.matrix_dimension,
            compared_operative_row_count: relation.operative_constraint_count,
            covered_padding_row_count: padding_row_count,
            compared_constraint_kind_count: u64::try_from(compared_constraint_kinds.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
            mismatch_count,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone, Copy)]
    struct CompletedSelectedWhirPhase {
        next_response_ordinal: u32,
        safe_boundary_ordinal: u32,
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SelectedWhirEpochOwner {
        PreChallenge,
        Main,
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn complete_selected_whir_code_switch(
        prepared_main_epoch: &mut PreparedCompactPublicKeyMainEpoch,
        response_storage: &mut FileBackedTestStorage,
        contract: &CompactPublicKeyProofContract,
        epoch: &CompactWhirEpochContract,
        epoch_owner: SelectedWhirEpochOwner,
        round_ordinal: u8,
        preceding_phase: CompletedSelectedWhirPhase,
    ) -> CompletedSelectedWhirPhase {
        let response_ordinal = contract
            .verifier_inputs()
            .response_component_roles
            .iter()
            .position(|roles| {
                roles.iter().any(|role| {
                    (
                        role.role_tag,
                        role.epoch,
                        role.batch_ordinal,
                        role.round_ordinal,
                    ) == (14, epoch.epoch, 0, u32::from(round_ordinal))
                })
            })
            .and_then(|response_index| u32::try_from(response_index).ok())
            .expect("the selected code-switch response exists");
        assert_eq!(response_ordinal, preceding_phase.next_response_ordinal);
        let response_geometry = &contract.verifier_inputs().response_merkle_geometries
            [usize::try_from(response_ordinal).unwrap()];
        let due_response_ordinals = contract
            .verifier_inputs()
            .response_merkle_geometries
            .iter()
            .enumerate()
            .filter(|(_, geometry)| geometry.last_query_verifier_move_ordinal() == response_ordinal)
            .map(|(response_index, geometry)| {
                assert_eq!(
                    geometry.minimum_queried_leaf_count(),
                    geometry.maximum_queried_leaf_count()
                );
                (
                    u32::try_from(response_index).expect("the response ordinal fits u32"),
                    geometry.minimum_queried_leaf_count(),
                )
            })
            .collect::<Vec<_>>();
        let expected_opened_leaf_count = due_response_ordinals
            .iter()
            .map(|(_, queried_leaf_count)| *queried_leaf_count)
            .sum::<u64>();

        match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => {
                prepared_main_epoch.prepare_pre_challenge_whir_code_switch()
            }
            SelectedWhirEpochOwner::Main => prepared_main_epoch.prepare_main_whir_code_switch(),
        }
        .expect("the completed sumcheck begins its next code switch");
        let mut randomness_poll_count = 0_u64;
        let mut source_poll_count = 0_u64;
        let mut prepared_count = 0_u64;
        let mut response_leaf_count = 0_u64;
        let mut opened_leaf_count = 0_u64;
        loop {
            let poll = match epoch_owner {
                SelectedWhirEpochOwner::PreChallenge => prepared_main_epoch
                    .poll_pre_challenge_whir_code_switch(8_192, response_storage),
                SelectedWhirEpochOwner::Main => {
                    prepared_main_epoch.poll_main_whir_code_switch(8_192, response_storage)
                }
            }
                .unwrap_or_else(|error| {
                    panic!(
                        "the selected code switch failed: round_ordinal={round_ordinal} error={error:?} randomness_poll_count={randomness_poll_count} source_poll_count={source_poll_count} prepared_count={prepared_count} response_leaf_count={response_leaf_count} opened_leaf_count={opened_leaf_count}"
                    )
                });
            match (epoch_owner, poll) {
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted {
                        round_ordinal: observed_round_ordinal,
                        processed_work_unit_count,
                        ..
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted {
                        round_ordinal: observed_round_ordinal,
                        processed_work_unit_count,
                        ..
                    },
                ) => {
                    assert_eq!(observed_round_ordinal, round_ordinal);
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    randomness_poll_count += 1;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared {
                        round_ordinal: observed_round_ordinal,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchPrepared {
                        round_ordinal: observed_round_ordinal,
                    },
                ) => {
                    assert_eq!(observed_round_ordinal, round_ordinal);
                    prepared_count += 1;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted {
                        round_ordinal: observed_round_ordinal,
                        processed_work_unit_count,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted {
                        round_ordinal: observed_round_ordinal,
                        processed_work_unit_count,
                    },
                ) => {
                    assert_eq!(observed_round_ordinal, round_ordinal);
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    source_poll_count += 1;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal }) => {
                    assert_eq!(leaf_ordinal, response_leaf_count);
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    response_leaf_count += 1;
                }
                (
                    _,
                    CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                        response_ordinal: opened_response_ordinal,
                        leaf_ordinal,
                    },
                ) => {
                    assert!(
                        due_response_ordinals
                            .iter()
                            .any(|(response_ordinal, _)| *response_ordinal
                                == opened_response_ordinal)
                    );
                    assert!(
                        leaf_ordinal
                            < contract.verifier_inputs().response_merkle_geometries
                                [usize::try_from(opened_response_ordinal).unwrap()]
                            .merkle_leaf_count()
                    );
                    opened_leaf_count += 1;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
                | (_, CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted) => {}
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady {
                        round_ordinal: observed_round_ordinal,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady {
                        round_ordinal: observed_round_ordinal,
                    },
                ) => {
                    assert_eq!(observed_round_ordinal, round_ordinal);
                    break;
                }
                (_, unexpected) => panic!(
                    "unexpected poll during selected code switch {round_ordinal}: {unexpected:?}"
                ),
            }
        }
        assert_eq!(prepared_count, 1);
        assert!(randomness_poll_count > 0);
        assert!(source_poll_count > 0);
        assert_eq!(response_leaf_count, response_geometry.merkle_leaf_count());
        assert_eq!(opened_leaf_count, expected_opened_leaf_count);
        let (code_switch_ready, code_switch_bound, source_query_masking_verified) =
            match epoch_owner {
                SelectedWhirEpochOwner::PreChallenge => (
                    prepared_main_epoch.pre_challenge_whir_code_switch_ready(round_ordinal),
                    prepared_main_epoch.pre_challenge_whir_code_switch_bound(round_ordinal),
                    prepared_main_epoch
                        .pre_challenge_whir_source_query_masking_verified(round_ordinal),
                ),
                SelectedWhirEpochOwner::Main => (
                    prepared_main_epoch.main_whir_code_switch_ready(round_ordinal),
                    prepared_main_epoch.main_whir_code_switch_bound(round_ordinal),
                    prepared_main_epoch.main_whir_source_query_masking_verified(round_ordinal),
                ),
            };
        assert!(code_switch_ready);
        assert!(code_switch_bound);
        assert!(source_query_masking_verified);
        let checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the selected code switch retains its checkpoint");
        assert_eq!(
            checkpoint.safe_boundary_ordinal(),
            preceding_phase.safe_boundary_ordinal + 1
        );
        assert_eq!(
            u32::from_le_bytes(checkpoint.position()[8..12].try_into().unwrap()),
            response_ordinal + 1
        );
        println!(
            "compact public-key focused owner phase complete: WHIR code switch epoch={} round_ordinal={} randomness_poll_count={} source_poll_count={} response_leaf_count={} opened_leaf_count={}",
            epoch.epoch,
            round_ordinal,
            randomness_poll_count,
            source_poll_count,
            response_leaf_count,
            opened_leaf_count,
        );
        CompletedSelectedWhirPhase {
            next_response_ordinal: response_ordinal + 1,
            safe_boundary_ordinal: checkpoint.safe_boundary_ordinal(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn prepare_selected_whir_sumcheck_after_code_switch(
        prepared_main_epoch: &mut PreparedCompactPublicKeyMainEpoch,
        contract: &CompactPublicKeyProofContract,
        epoch: &CompactWhirEpochContract,
        epoch_owner: SelectedWhirEpochOwner,
        round_ordinal: u8,
    ) {
        let previous_source_contract = contract
            .verifier_inputs()
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == epoch.epoch && fold.batch_ordinal == round_ordinal)
            .expect("the preceding selected source contract exists");
        let next_batch_ordinal = round_ordinal + 1;
        let next_source_contract = contract
            .verifier_inputs()
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == epoch.epoch && fold.batch_ordinal == next_batch_ordinal)
            .expect("the next selected source contract exists");
        let expected_relation_work_unit_count = previous_source_contract
            .query_count
            .checked_mul(
                next_source_contract
                    .message_length
                    .checked_mul(next_source_contract.oracle_width)
                    .and_then(|source_count| {
                        source_count.checked_add(previous_source_contract.hiding_randomness_length)
                    })
                    .expect("the selected code-switch relation width fits u64"),
            )
            .expect("the selected code-switch relation work fits u64");
        match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => {
                prepared_main_epoch.prepare_pre_challenge_whir_next_sumcheck()
            }
            SelectedWhirEpochOwner::Main => prepared_main_epoch.prepare_main_whir_next_sumcheck(),
        }
        .expect("the bound code switch starts its output relation");
        let mut relation_poll_count = 0_u64;
        let mut relation_work_unit_count = 0_u64;
        loop {
            let poll = match epoch_owner {
                SelectedWhirEpochOwner::PreChallenge => {
                    prepared_main_epoch.poll_pre_challenge_whir_next_sumcheck_preparation(8_192)
                }
                SelectedWhirEpochOwner::Main => {
                    prepared_main_epoch.poll_main_whir_next_sumcheck_preparation(8_192)
                }
            }
            .expect("the selected code-switch relation advances");
            match (epoch_owner, poll) {
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted {
                        round_ordinal: observed_round_ordinal,
                        processed_work_unit_count,
                        ..
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted {
                        round_ordinal: observed_round_ordinal,
                        processed_work_unit_count,
                        ..
                    },
                ) => {
                    assert_eq!(observed_round_ordinal, round_ordinal);
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    relation_poll_count += 1;
                    relation_work_unit_count += processed_work_unit_count;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared {
                        batch_ordinal,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { batch_ordinal },
                ) => {
                    assert_eq!(batch_ordinal, next_batch_ordinal);
                    break;
                }
                (_, unexpected) => panic!(
                    "unexpected poll while preparing selected WHIR batch {next_batch_ordinal}: {unexpected:?}"
                ),
            }
        }
        assert!(relation_poll_count > 0);
        assert_eq!(relation_work_unit_count, expected_relation_work_unit_count);
        let sumcheck_output_count = match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => {
                prepared_main_epoch.pre_challenge_whir_sumcheck_output_count(next_batch_ordinal)
            }
            SelectedWhirEpochOwner::Main => {
                prepared_main_epoch.main_whir_sumcheck_output_count(next_batch_ordinal)
            }
        };
        assert_eq!(sumcheck_output_count, Some(1));
        println!(
            "compact public-key focused owner phase complete: code-switch relation epoch={} round_ordinal={} poll_count={} work_unit_count={}",
            epoch.epoch, round_ordinal, relation_poll_count, relation_work_unit_count,
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn complete_selected_whir_sumcheck_batch(
        prepared_main_epoch: &mut PreparedCompactPublicKeyMainEpoch,
        response_storage: &mut FileBackedTestStorage,
        contract: &CompactPublicKeyProofContract,
        epoch: &CompactWhirEpochContract,
        epoch_owner: SelectedWhirEpochOwner,
        batch_ordinal: u8,
        preceding_phase: CompletedSelectedWhirPhase,
    ) -> CompletedSelectedWhirPhase {
        let round_count = usize::try_from(epoch.folding_schedule[usize::from(batch_ordinal)])
            .expect("the selected folding factor fits usize");
        let source_contract = contract
            .verifier_inputs()
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == epoch.epoch && fold.batch_ordinal == batch_ordinal)
            .expect("the selected WHIR source contract exists");
        let source_length = usize::try_from(
            source_contract
                .message_length
                .checked_mul(source_contract.oracle_width)
                .expect("the selected WHIR source length fits u64"),
        )
        .expect("the selected WHIR source length fits usize");
        let expected_residual_length = source_length
            .checked_shr(u32::try_from(round_count).unwrap())
            .expect("the selected residual length exists");
        let maximum_work_unit_count = 8_192_u64;
        let expected_weight_scaling_poll_count =
            u64::try_from(expected_residual_length.saturating_sub(1)).unwrap()
                / maximum_work_unit_count;
        let initial_response_ordinal = contract
            .verifier_inputs()
            .response_component_roles
            .iter()
            .position(|roles| {
                roles.iter().any(|role| {
                    (
                        role.role_tag,
                        role.epoch,
                        role.batch_ordinal,
                        role.round_ordinal,
                    ) == (11, epoch.epoch, batch_ordinal, 0)
                })
            })
            .and_then(|response_index| u32::try_from(response_index).ok())
            .expect("the selected WHIR batch has one mask response");
        assert_eq!(
            initial_response_ordinal,
            preceding_phase.next_response_ordinal
        );
        let response_count = round_count + 1;
        let first_round_response_index = usize::try_from(initial_response_ordinal + 1).unwrap();
        let round_response_geometries = &contract.verifier_inputs().response_merkle_geometries
            [first_round_response_index..first_round_response_index + round_count];
        assert!(round_response_geometries.iter().all(|geometry| {
            geometry.minimum_queried_leaf_count() == geometry.maximum_queried_leaf_count()
        }));
        let expected_opened_leaf_count = round_response_geometries
            .iter()
            .map(|geometry| geometry.minimum_queried_leaf_count())
            .sum::<u64>();
        let response_start_index = usize::try_from(initial_response_ordinal).unwrap();
        let expected_response_leaf_count = contract.verifier_inputs().response_merkle_geometries
            [response_start_index..response_start_index + response_count]
            .iter()
            .map(|geometry| geometry.merkle_leaf_count())
            .sum::<u64>();
        let mut current_response_ordinal = initial_response_ordinal;
        let mut current_response_leaf_ordinal = 0_u64;
        let mut round_polynomial_poll_count = 0_u64;
        let mut bound_round_poll_count = 0_u64;
        let mut weight_scaling_poll_count = 0_u64;
        let mut response_leaf_count = 0_u64;
        let mut opened_leaf_count = 0_u64;
        let mut opened_leaf_counts_by_round = vec![0_u64; round_count];
        let mut completed_round_count = 0_usize;
        loop {
            let poll = match epoch_owner {
                SelectedWhirEpochOwner::PreChallenge => prepared_main_epoch
                    .poll_pre_challenge_whir_sumcheck(maximum_work_unit_count, response_storage),
                SelectedWhirEpochOwner::Main => prepared_main_epoch
                    .poll_main_whir_sumcheck(maximum_work_unit_count, response_storage),
            }
            .expect("the selected WHIR sumcheck advances");
            match (epoch_owner, poll) {
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                        batch_ordinal: observed_batch_ordinal,
                        round_ordinal,
                        ..
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted {
                        batch_ordinal: observed_batch_ordinal,
                        round_ordinal,
                        ..
                    },
                ) => {
                    assert_eq!(observed_batch_ordinal, batch_ordinal);
                    assert_eq!(usize::try_from(round_ordinal).unwrap(), completed_round_count);
                    round_polynomial_poll_count += 1;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                        batch_ordinal: observed_batch_ordinal,
                        round_ordinal,
                        ..
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted {
                        batch_ordinal: observed_batch_ordinal,
                        round_ordinal,
                        ..
                    },
                ) => {
                    assert_eq!(observed_batch_ordinal, batch_ordinal);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap() + 1,
                        completed_round_count
                    );
                    bound_round_poll_count += 1;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                        batch_ordinal: observed_batch_ordinal,
                        ..
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted {
                        batch_ordinal: observed_batch_ordinal,
                        ..
                    },
                ) => {
                    assert_eq!(observed_batch_ordinal, batch_ordinal);
                    weight_scaling_poll_count += 1;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal }) => {
                    assert_eq!(leaf_ordinal, current_response_leaf_ordinal);
                    let geometry = &contract.verifier_inputs().response_merkle_geometries
                        [usize::try_from(current_response_ordinal).unwrap()];
                    assert!(leaf_ordinal < geometry.merkle_leaf_count());
                    current_response_leaf_ordinal += 1;
                    response_leaf_count += 1;
                }
                (
                    _,
                    CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                        response_ordinal,
                        leaf_ordinal,
                    },
                ) => {
                    let round_index = usize::try_from(
                        response_ordinal
                            .checked_sub(initial_response_ordinal + 1)
                            .expect("only the current batch round responses are opened"),
                    )
                    .unwrap();
                    let opened_count = opened_leaf_counts_by_round
                        .get_mut(round_index)
                        .expect("the opened response belongs to the current batch");
                    let geometry = &contract.verifier_inputs().response_merkle_geometries
                        [usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < geometry.merkle_leaf_count());
                    *opened_count += 1;
                    opened_leaf_count += 1;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
                | (_, CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted) => {}
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                        batch_ordinal: observed_batch_ordinal,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady {
                        batch_ordinal: observed_batch_ordinal,
                    },
                ) => {
                    assert_eq!(observed_batch_ordinal, batch_ordinal);
                    assert_eq!(current_response_ordinal, initial_response_ordinal);
                    let geometry = &contract.verifier_inputs().response_merkle_geometries
                        [usize::try_from(current_response_ordinal).unwrap()];
                    assert_eq!(current_response_leaf_ordinal, geometry.merkle_leaf_count());
                    current_response_ordinal += 1;
                    current_response_leaf_ordinal = 0;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                        batch_ordinal: observed_batch_ordinal,
                        round_ordinal,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady {
                        batch_ordinal: observed_batch_ordinal,
                        round_ordinal,
                    },
                ) => {
                    assert_eq!(observed_batch_ordinal, batch_ordinal);
                    assert_eq!(usize::try_from(round_ordinal).unwrap(), completed_round_count);
                    let geometry = &contract.verifier_inputs().response_merkle_geometries
                        [usize::try_from(current_response_ordinal).unwrap()];
                    assert_eq!(current_response_leaf_ordinal, geometry.merkle_leaf_count());
                    completed_round_count += 1;
                    current_response_ordinal += 1;
                    current_response_leaf_ordinal = 0;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete {
                        batch_ordinal: observed_batch_ordinal,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete {
                        batch_ordinal: observed_batch_ordinal,
                    },
                ) => {
                    assert_eq!(observed_batch_ordinal, batch_ordinal);
                    break;
                }
                (_, unexpected) => panic!(
                    "unexpected poll during selected WHIR batch {batch_ordinal}: {unexpected:?}"
                ),
            }
        }
        assert_eq!(completed_round_count, round_count);
        assert_eq!(
            current_response_ordinal,
            initial_response_ordinal + u32::try_from(response_count).unwrap()
        );
        assert_eq!(current_response_leaf_ordinal, 0);
        assert_eq!(response_leaf_count, expected_response_leaf_count);
        assert_eq!(opened_leaf_count, expected_opened_leaf_count);
        for (opened_count, geometry) in opened_leaf_counts_by_round
            .iter()
            .zip(round_response_geometries)
        {
            assert_eq!(*opened_count, geometry.minimum_queried_leaf_count());
        }
        assert!(round_polynomial_poll_count > 0);
        assert!(bound_round_poll_count > 0);
        assert_eq!(
            weight_scaling_poll_count,
            expected_weight_scaling_poll_count
        );
        let (sumcheck_complete, sumcheck_output_count, residual_length) = match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => (
                prepared_main_epoch.pre_challenge_whir_sumcheck_complete(batch_ordinal),
                prepared_main_epoch.pre_challenge_whir_sumcheck_output_count(batch_ordinal),
                prepared_main_epoch.pre_challenge_whir_residual_length(batch_ordinal),
            ),
            SelectedWhirEpochOwner::Main => (
                prepared_main_epoch.main_whir_sumcheck_complete(batch_ordinal),
                prepared_main_epoch.main_whir_sumcheck_output_count(batch_ordinal),
                prepared_main_epoch.main_whir_residual_length(batch_ordinal),
            ),
        };
        assert!(sumcheck_complete);
        assert_eq!(sumcheck_output_count, Some(1 + 2 * round_count));
        assert_eq!(residual_length, Some(expected_residual_length));
        let checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the selected WHIR batch retains its final checkpoint");
        assert_eq!(
            checkpoint.safe_boundary_ordinal(),
            preceding_phase.safe_boundary_ordinal + u32::try_from(response_count).unwrap()
        );
        println!(
            "compact public-key focused owner phase complete: WHIR sumcheck epoch={} batch_ordinal={} round_count={} residual_length={} round_polynomial_poll_count={} bound_round_poll_count={} weight_scaling_poll_count={} response_leaf_count={} opened_leaf_count={}",
            epoch.epoch,
            batch_ordinal,
            round_count,
            expected_residual_length,
            round_polynomial_poll_count,
            bound_round_poll_count,
            weight_scaling_poll_count,
            response_leaf_count,
            opened_leaf_count,
        );
        CompletedSelectedWhirPhase {
            next_response_ordinal: current_response_ordinal,
            safe_boundary_ordinal: checkpoint.safe_boundary_ordinal(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn complete_selected_whir_base_case(
        prepared_main_epoch: &mut PreparedCompactPublicKeyMainEpoch,
        response_storage: &mut FileBackedTestStorage,
        contract: &CompactPublicKeyProofContract,
        epoch: &CompactWhirEpochContract,
        epoch_owner: SelectedWhirEpochOwner,
        preceding_phase: CompletedSelectedWhirPhase,
    ) -> CompletedSelectedWhirPhase {
        let response_ordinal_for_role = |role_tag| {
            contract
                .verifier_inputs()
                .response_component_roles
                .iter()
                .position(|roles| {
                    roles.iter().any(|role| {
                        (
                            role.role_tag,
                            role.epoch,
                            role.batch_ordinal,
                            role.round_ordinal,
                        ) == (role_tag, epoch.epoch, 0, 0)
                    })
                })
                .and_then(|response_index| u32::try_from(response_index).ok())
                .expect("the selected WHIR base response exists")
        };
        let fresh_response_ordinal = response_ordinal_for_role(18);
        assert_eq!(
            fresh_response_ordinal,
            preceding_phase.next_response_ordinal
        );
        let fresh_response_geometry = &contract.verifier_inputs().response_merkle_geometries
            [usize::try_from(fresh_response_ordinal).unwrap()];

        match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => {
                prepared_main_epoch.prepare_pre_challenge_whir_base_case()
            }
            SelectedWhirEpochOwner::Main => prepared_main_epoch.prepare_main_whir_base_case(),
        }
        .expect("the completed selected WHIR folds prepare the base fresh response");
        let (fresh_claim_masking_verified, blinded_response_ready) = match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => (
                prepared_main_epoch.pre_challenge_whir_base_fresh_claim_masking_verified(),
                prepared_main_epoch.pre_challenge_whir_base_blinded_response_ready(),
            ),
            SelectedWhirEpochOwner::Main => (
                prepared_main_epoch.main_whir_base_fresh_claim_masking_verified(),
                prepared_main_epoch.main_whir_base_blinded_response_ready(),
            ),
        };
        assert!(!fresh_claim_masking_verified);
        assert!(!blinded_response_ready);

        let mut base_prepared_count = 0_u64;
        let mut covector_poll_count = 0_u64;
        let mut covector_work_unit_count = 0_u64;
        let mut covectors_prepared_count = 0_u64;
        let mut fresh_source_arithmetic_poll_count = 0_u64;
        let mut fresh_response_leaf_count = 0_u64;
        let mut fresh_response_opened_leaf_count = 0_u64;
        loop {
            let poll = match epoch_owner {
                SelectedWhirEpochOwner::PreChallenge => prepared_main_epoch
                    .poll_pre_challenge_whir_base_fresh_response(8_192, response_storage),
                SelectedWhirEpochOwner::Main => {
                    prepared_main_epoch.poll_main_whir_base_fresh_response(8_192, response_storage)
                }
            }
            .expect("the selected WHIR base fresh response advances");
            match (epoch_owner, poll) {
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorStepCompleted {
                        completed_work_unit_count,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorStepCompleted {
                        completed_work_unit_count,
                    },
                ) => {
                    assert!((1..=8_192).contains(&completed_work_unit_count));
                    covector_poll_count += 1;
                    covector_work_unit_count += completed_work_unit_count;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorsPrepared,
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorsPrepared,
                ) => {
                    let masking_verified = match epoch_owner {
                        SelectedWhirEpochOwner::PreChallenge => prepared_main_epoch
                            .pre_challenge_whir_base_fresh_claim_masking_verified(),
                        SelectedWhirEpochOwner::Main => {
                            prepared_main_epoch.main_whir_base_fresh_claim_masking_verified()
                        }
                    };
                    assert!(masking_verified);
                    covectors_prepared_count += 1;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBasePrepared,
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBasePrepared,
                ) => {
                    base_prepared_count += 1;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted {
                        processed_work_unit_count,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted {
                        processed_work_unit_count,
                    },
                ) => {
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    fresh_source_arithmetic_poll_count += 1;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal }) => {
                    assert_eq!(leaf_ordinal, fresh_response_leaf_count);
                    assert!(leaf_ordinal < fresh_response_geometry.merkle_leaf_count());
                    fresh_response_leaf_count += 1;
                }
                (
                    _,
                    CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                        response_ordinal,
                        leaf_ordinal,
                    },
                ) => {
                    let response_geometry = &contract.verifier_inputs().response_merkle_geometries
                        [usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    fresh_response_opened_leaf_count += 1;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
                | (_, CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted) => {}
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady,
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady,
                ) => break,
                (_, unexpected) => {
                    panic!(
                        "unexpected poll during the selected WHIR base fresh response: {unexpected:?}"
                    )
                }
            }
        }
        assert_eq!(base_prepared_count, 1);
        assert!(covector_poll_count > 0);
        assert!(covector_work_unit_count > 0);
        assert_eq!(covectors_prepared_count, 1);
        assert!(fresh_source_arithmetic_poll_count > 0);
        assert_eq!(
            fresh_response_leaf_count,
            fresh_response_geometry.merkle_leaf_count()
        );
        assert_eq!(
            fresh_response_opened_leaf_count, 0,
            "the combination challenge binds the fresh response root before its final-query opening"
        );
        let (fresh_claim_masking_verified, blinded_response_ready) = match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => (
                prepared_main_epoch.pre_challenge_whir_base_fresh_claim_masking_verified(),
                prepared_main_epoch.pre_challenge_whir_base_blinded_response_ready(),
            ),
            SelectedWhirEpochOwner::Main => (
                prepared_main_epoch.main_whir_base_fresh_claim_masking_verified(),
                prepared_main_epoch.main_whir_base_blinded_response_ready(),
            ),
        };
        assert!(fresh_claim_masking_verified);
        assert!(blinded_response_ready);
        let fresh_response_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the selected WHIR base fresh response retains its checkpoint");
        let fresh_response_safe_boundary_ordinal =
            fresh_response_checkpoint.safe_boundary_ordinal();
        let expected_fresh_response_safe_boundary_ordinal = preceding_phase
            .safe_boundary_ordinal
            .checked_add(1)
            .expect("the selected WHIR base safe-boundary ordinal fits u32");
        let next_response_ordinal = fresh_response_ordinal
            .checked_add(1)
            .expect("the selected WHIR base response ordinal fits u32");
        assert_eq!(
            fresh_response_safe_boundary_ordinal,
            expected_fresh_response_safe_boundary_ordinal
        );
        assert_eq!(
            u32::from_le_bytes(
                fresh_response_checkpoint.position()[8..12]
                    .try_into()
                    .unwrap()
            ),
            next_response_ordinal
        );

        let blinded_response_ordinal = response_ordinal_for_role(19);
        assert_eq!(blinded_response_ordinal, next_response_ordinal);
        let blinded_response_geometry = &contract.verifier_inputs().response_merkle_geometries
            [usize::try_from(blinded_response_ordinal).unwrap()];
        let due_response_ordinals = contract
            .verifier_inputs()
            .response_merkle_geometries
            .iter()
            .enumerate()
            .filter(|(_, geometry)| {
                geometry.last_query_verifier_move_ordinal() == blinded_response_ordinal
            })
            .map(|(response_index, geometry)| {
                (
                    u32::try_from(response_index).expect("the response ordinal fits u32"),
                    geometry.minimum_queried_leaf_count(),
                    geometry.maximum_queried_leaf_count(),
                )
            })
            .collect::<Vec<_>>();
        let (blinded_response_masking_verified, final_query_masking_verified) = match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => (
                prepared_main_epoch.pre_challenge_whir_base_blinded_response_masking_verified(),
                prepared_main_epoch.pre_challenge_whir_base_final_query_masking_verified(),
            ),
            SelectedWhirEpochOwner::Main => (
                prepared_main_epoch.main_whir_base_blinded_response_masking_verified(),
                prepared_main_epoch.main_whir_base_final_query_masking_verified(),
            ),
        };
        assert!(blinded_response_masking_verified);
        assert!(!final_query_masking_verified);

        let mut blinded_response_prepared_count = 0_u64;
        let mut final_query_arithmetic_poll_count = 0_u64;
        let mut final_query_processed_work_unit_count = 0_u64;
        let mut blinded_response_leaf_count = 0_u64;
        let mut final_opened_leaf_count = 0_u64;
        let mut opened_leaf_counts_by_response = vec![0_u64; due_response_ordinals.len()];
        loop {
            let poll = match epoch_owner {
                SelectedWhirEpochOwner::PreChallenge => prepared_main_epoch
                    .poll_pre_challenge_whir_base_blinded_response(8_192, response_storage),
                SelectedWhirEpochOwner::Main => prepared_main_epoch
                    .poll_main_whir_base_blinded_response(8_192, response_storage),
            }
            .expect("the selected WHIR base blinded response and final queries advance");
            match (epoch_owner, poll) {
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponsePrepared,
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponsePrepared,
                ) => {
                    blinded_response_prepared_count += 1;
                }
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted {
                        processed_work_unit_count,
                    },
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted {
                        processed_work_unit_count,
                    },
                ) => {
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    final_query_arithmetic_poll_count += 1;
                    final_query_processed_work_unit_count += processed_work_unit_count;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal }) => {
                    assert_eq!(leaf_ordinal, blinded_response_leaf_count);
                    assert!(leaf_ordinal < blinded_response_geometry.merkle_leaf_count());
                    blinded_response_leaf_count += 1;
                }
                (
                    _,
                    CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                        response_ordinal,
                        leaf_ordinal,
                    },
                ) => {
                    let due_response_index = due_response_ordinals
                        .iter()
                        .position(|(due_response_ordinal, _, _)| {
                            *due_response_ordinal == response_ordinal
                        })
                        .expect("the opened response reaches last use at the base final query");
                    let response_geometry = &contract.verifier_inputs().response_merkle_geometries
                        [usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    opened_leaf_counts_by_response[due_response_index] += 1;
                    final_opened_leaf_count += 1;
                }
                (_, CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
                | (_, CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted) => {}
                (
                    SelectedWhirEpochOwner::PreChallenge,
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady,
                )
                | (
                    SelectedWhirEpochOwner::Main,
                    CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady,
                ) => break,
                (_, unexpected) => {
                    panic!("unexpected poll during the selected WHIR base blinded response: {unexpected:?}")
                }
            }
        }
        assert_eq!(blinded_response_prepared_count, 1);
        assert!(final_query_arithmetic_poll_count > 0);
        assert!(final_query_processed_work_unit_count > 0);
        assert_eq!(
            blinded_response_leaf_count,
            blinded_response_geometry.merkle_leaf_count()
        );
        for (opened_leaf_count, (_, minimum_queried_leaf_count, maximum_queried_leaf_count)) in
            opened_leaf_counts_by_response
                .iter()
                .zip(&due_response_ordinals)
        {
            assert!(
                (*minimum_queried_leaf_count..=*maximum_queried_leaf_count)
                    .contains(opened_leaf_count)
            );
        }
        let final_query_masking_verified = match epoch_owner {
            SelectedWhirEpochOwner::PreChallenge => {
                prepared_main_epoch.pre_challenge_whir_base_final_query_masking_verified()
            }
            SelectedWhirEpochOwner::Main => {
                prepared_main_epoch.main_whir_base_final_query_masking_verified()
            }
        };
        assert!(final_query_masking_verified);
        let blinded_response_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the selected WHIR base blinded response retains its checkpoint");
        let expected_blinded_response_safe_boundary_ordinal = fresh_response_safe_boundary_ordinal
            .checked_add(1)
            .expect("the selected WHIR base safe-boundary ordinal fits u32");
        let completed_response_ordinal = blinded_response_ordinal
            .checked_add(1)
            .expect("the selected WHIR base response ordinal fits u32");
        assert_eq!(
            blinded_response_checkpoint.safe_boundary_ordinal(),
            expected_blinded_response_safe_boundary_ordinal
        );
        assert_eq!(
            u32::from_le_bytes(
                blinded_response_checkpoint.position()[8..12]
                    .try_into()
                    .unwrap()
            ),
            completed_response_ordinal
        );
        println!(
            "compact public-key focused owner phase complete: WHIR base epoch={} covector_poll_count={} covector_work_unit_count={} fresh_source_arithmetic_poll_count={} fresh_response_leaf_count={} final_query_arithmetic_poll_count={} final_query_processed_work_unit_count={} blinded_response_leaf_count={} opened_leaf_count={}",
            epoch.epoch,
            covector_poll_count,
            covector_work_unit_count,
            fresh_source_arithmetic_poll_count,
            fresh_response_leaf_count,
            final_query_arithmetic_poll_count,
            final_query_processed_work_unit_count,
            blinded_response_leaf_count,
            final_opened_leaf_count,
        );
        CompletedSelectedWhirPhase {
            next_response_ordinal: completed_response_ordinal,
            safe_boundary_ordinal: blinded_response_checkpoint.safe_boundary_ordinal(),
        }
    }

    #[test]
    fn complete_structured_matrices_match_the_independent_relation_interpreter() {
        let relation = super::super::selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let matrices = CompactStructuredR1csCatalog::derive(&relation)
            .expect("complete structured R1CS matrices");
        let certificate = check_interpreter_correspondence(&relation, &matrices)
            .expect("independent compact R1CS interpreter correspondence");
        assert!(certificate.is_complete(&relation));
        assert_eq!(certificate.matrix_dimension, 8_388_608);
        assert_eq!(certificate.compared_operative_row_count, 2_686_977);
        assert_eq!(certificate.covered_padding_row_count, 5_701_631);
    }

    #[test]
    fn independent_interpreter_detects_a_changed_matrix_coefficient() {
        let relation = super::super::selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let matrices = CompactStructuredR1csCatalog::derive(&relation)
            .expect("complete structured R1CS matrices");
        let assignment = DeterministicR1csAssignment::new(&relation, &matrices);
        let mut first_row = matrices
            .row(&relation, 0)
            .expect("first exact integer-lift row");
        first_row
            .left
            .ordered_terms
            .push(CompactStructuredMatrixTerm::StaticEntry {
                column_ordinal: matrices.public_one_column(),
                integer_coefficient: 1,
            });
        assert_ne!(
            evaluate_matrix_row(&first_row, &assignment)
                .expect("mutated matrix row remains interpretable"),
            independently_interpret_row(&relation, &matrices, &assignment, 0)
                .expect("independent first-row interpretation"),
        );
    }

    #[test]
    #[ignore = "manual compact public-key proof-evidence producer"]
    fn compact_public_key_proof_evidence_generation_and_verification() {
        run_compact_public_key_proof_evidence_generation(
            CompactPublicKeyProofEvidenceGenerationMode::Positive,
        );
    }

    #[test]
    #[ignore = "manual transport-valid equation-invalid compact public-key proof evidence"]
    fn compact_public_key_transport_valid_equation_invalid_proof_is_refused() {
        run_compact_public_key_proof_evidence_generation(
            CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt,
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CompactPublicKeyProofEvidenceGenerationMode {
        Positive,
        EquationInvalidIndependentAttempt,
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn run_compact_public_key_proof_evidence_generation(
        evidence_mode: CompactPublicKeyProofEvidenceGenerationMode,
    ) {
        let authority = populate_compact_public_key_development_evidence_authority(0x43)
            .expect("standalone production-derived public-key authority populates");
        let authority_action_private_randomness = authority.action_private_randomness;
        let proof_action_private_randomness = match evidence_mode {
            CompactPublicKeyProofEvidenceGenerationMode::Positive => {
                Rc::clone(&authority_action_private_randomness)
            }
            CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt => {
                Rc::new(
                    ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
                        [0x6b; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
                    ))
                    .derive(authority_action_private_randomness.derivation_input())
                    .expect("the independent same-slot proof randomness derives"),
                )
            }
        };
        let authority = authority.authority;
        let execution_started_at = Instant::now();
        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: prepare authenticated assignment");
        let (input, relation_context) = super::super::selected_input_and_context()
            .expect("selected public-key relation input and context");
        let compiled =
            compile_public_key_share_relation_with_source_layout(&input, &relation_context)
                .expect("selected public-key relation compiles");
        let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
            &compiled.relation_plan,
            &relation_context,
            None,
            None,
        )
        .expect("selected public-key relation capability");
        let checkpoint_schedule_digest = relation_plan
            .checkpoint_schedule_digest()
            .expect("selected checkpoint schedule digest");
        let preparation_source =
            resolve_setup_generation_compact_public_key_development_preparation_source(&authority)
                .expect("retained public-key preparation source");
        let statement_schema_identifier =
            SetupKeyRelationProofFamily::PublicKeyShare.statement_schema_identifier();
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(preparation_source.suite_identifier()),
            Hash512::from_bytes(preparation_source.ceremony_context_hash()),
            Hash512::from_bytes(preparation_source.action_context_hash()),
            statement_schema_identifier,
            Some(preparation_source.roster_position()),
            None,
            None,
        )
        .expect("public-key application slot");
        let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
            preparation_source.protocol_version(),
            preparation_source.suite_identifier(),
            statement_schema_identifier,
            preparation_source.canonical_application_statement_bytes(),
        ));
        let proof_coin_input =
            PersistentProofCoinInput::new(application_slot, application_statement_hash)
                .expect("the public-key proof coin input is canonical");
        let authority_private_randomness_attempt_identifier = authority_action_private_randomness
            .persistent_proof_preparation_identifier(&proof_coin_input)
            .expect("the authority-bound public-key private-randomness attempt derives");
        let private_randomness_attempt_identifier = proof_action_private_randomness
            .persistent_proof_preparation_identifier(&proof_coin_input)
            .expect("the selected public-key private-randomness attempt derives");
        match evidence_mode {
            CompactPublicKeyProofEvidenceGenerationMode::Positive => assert_eq!(
                private_randomness_attempt_identifier,
                authority_private_randomness_attempt_identifier,
            ),
            CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt => {
                assert_ne!(
                    private_randomness_attempt_identifier,
                    authority_private_randomness_attempt_identifier,
                );
            }
        }
        let proof_attempt_identifier = *private_randomness_attempt_identifier.as_bytes();
        let prepared_attempt = prepare_exact_same_secret_evidence_attempt(
            &authority_action_private_randomness,
            application_slot,
            application_statement_hash,
            [0x44; 32],
            checkpoint_schedule_digest,
        )
        .expect("authenticated public-key development attempt");
        let decoded_statement = decode_selected_public_key_share_statement(
            preparation_source.canonical_application_statement_bytes(),
            SelectedApplicationStatementContext::new(
                preparation_source.protocol_version(),
                preparation_source.suite_identifier(),
                None,
                None,
            ),
        )
        .expect("retained public-key statement decodes");
        assert_eq!(
            decoded_statement.setup_proof_context_hash(),
            preparation_source.setup_proof_context_hash()
        );
        assert_eq!(
            decoded_statement.participant_identity(),
            preparation_source.participant_identity()
        );
        assert_eq!(
            decoded_statement.roster_position(),
            preparation_source.roster_position()
        );
        let application = SetupGenerationKeyRelationApplication::from_runtime_binding(
            SetupKeyRelationProofFamily::PublicKeyShare,
            prepared_attempt,
            preparation_source.canonical_application_statement_bytes(),
            decoded_statement.setup_proof_context_hash(),
            preparation_source.roster_hash(),
            decoded_statement.participant_identity(),
            decoded_statement.roster_position(),
        );
        let prepared_sources =
            with_exclusive_setup_generation_compact_public_key_development_relation::<
                _,
                SetupKeyRelationGenerationPreparationError,
            >(authority, &application, |source| {
                prepare_compact_public_key_assignment_sources(&source, relation_plan)
                    .map_err(SetupKeyRelationGenerationPreparationError::from)
            })
            .expect("retained authority prepares compact public-key sources");
        assert_eq!(
            prepared_sources
                .source_request_context()
                .expect("compact request context")
                .relation_plan_variant_hash(),
            prepared_sources
                .relation_plan_variant
                .canonical_hash()
                .expect("compact variant hash")
        );
        let provider_memory_accounting = prepared_sources
            .source_provider_memory_accounting()
            .expect("compact retained-source accounting");
        println!(
            "compact public-key focused owner phase complete: prepare authenticated assignment elapsed_milliseconds={} loading_persistent_bytes={} post_source_finish_persistent_bytes={} loading_transient_bytes={} maximum_returned_source_polynomial_bytes={}",
            phase_started_at.elapsed().as_millis(),
            provider_memory_accounting.loading_persistent_resident_byte_length(),
            provider_memory_accounting
                .post_source_polynomial_finish_persistent_resident_byte_length(),
            provider_memory_accounting.additional_loading_transient_byte_length(),
            provider_memory_accounting.maximum_returned_source_polynomial_byte_length(),
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: load 202 authenticated columns");
        let expected_relation_plan_variant_hash = prepared_sources
            .relation_plan_variant
            .canonical_hash()
            .expect("compact variant hash");
        let private_coin_coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(
                &prepared_sources.relation_plan_variant,
            )
            .expect("compact private-coin coordinate capacity derives");
        let mut generation_state = CompactPublicKeyGenerationState::new(prepared_sources);
        let mut loaded_column_ordinals = Vec::new();
        loop {
            match generation_state
                .poll_source_loading(8_192)
                .expect("retained compact source-loading poll")
            {
                CompactPublicKeyGenerationPoll::AuthenticatedSourceReadRequired => {
                    panic!("retained setup authority must not request caller source bytes")
                }
                CompactPublicKeyGenerationPoll::SourceLoaded { column_ordinal } => {
                    loaded_column_ordinals.push(column_ordinal);
                }
                CompactPublicKeyGenerationPoll::SourcesComplete => break,
                unexpected => panic!("unexpected source-loading poll: {unexpected:?}"),
            }
        }
        assert_eq!(loaded_column_ordinals.len(), 202);
        assert!(
            loaded_column_ordinals
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        let injected_witness_equation_fault = match evidence_mode {
            CompactPublicKeyProofEvidenceGenerationMode::Positive => None,
            CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt => {
                Some(
                    generation_state
                        .inject_first_shifted_eta_two_product_equation_fault()
                        .expect(
                            "the test-only equation fault targets one compiler-derived witness coordinate",
                        ),
                )
            }
        };
        let selected_compact_contract =
            crate::bgv::proof_suite::compact_proof_contract::selected_compact_public_key_proof_contract()
                .expect("the frozen compact public-key contract decodes");
        let (
            compact_construction_identity_hash,
            checkpoint_schedule_digest,
            source_replay_binding,
            private_coin_derivation_binding_hash,
        ) = {
            let pre_lookup_material = generation_state
                .pre_lookup_material()
                .expect("loaded compact sources expose bound pre-lookup material");
            let expected_public_input_bindings =
                crate::bgv::proof_suite::compact_proof_wire::CompactPublicInputBindings::new(
                    Hash512::from_bytes(preparation_source.suite_identifier()),
                    application_statement_hash,
                    Hash512::from_bytes(preparation_source.manifest_hash()),
                    Hash512::from_bytes(expected_relation_plan_variant_hash),
                );
            assert_eq!(
                pre_lookup_material.public_input_bindings(),
                expected_public_input_bindings
            );
            assert_eq!(
                pre_lookup_material
                    .public_input_bindings()
                    .relation_plan_hash()
                    .into_bytes(),
                expected_relation_plan_variant_hash
            );
            assert_eq!(
                pre_lookup_material
                    .decoded_public_input()
                    .canonical_byte_length(),
                pre_lookup_material.canonical_public_input_bytes().len()
            );
            assert!(
                !pre_lookup_material
                    .canonical_public_input_bytes()
                    .is_empty()
            );
            assert_eq!(
                pre_lookup_material.proof_wire_geometry(),
                selected_compact_contract
                    .verifier_inputs()
                    .proof_wire_geometry
            );
            assert_eq!(
                pre_lookup_material.response_merkle_geometries(),
                selected_compact_contract
                    .verifier_inputs()
                    .response_merkle_geometries
            );
            let compact_construction_identity_hash =
                pre_lookup_material.compact_construction_identity_hash();
            let checkpoint_schedule_digest = pre_lookup_material.checkpoint_schedule_digest();
            let source_replay_binding = pre_lookup_material.source_replay_binding();
            assert_eq!(
                compact_construction_identity_hash,
                selected_compact_contract
                    .verifier_inputs()
                    .canonical_source_hash()
                    .expect("the frozen compact contract identity derives")
                    .into_bytes()
            );
            assert_eq!(
                checkpoint_schedule_digest,
                selected_compact_contract
                    .verifier_inputs()
                    .checkpoint_schedule
                    .checkpoint_schedule_digest()
            );
            assert_ne!(source_replay_binding, [0_u8; Hash512::BYTE_LENGTH]);

            let [source_response_component] =
                pre_lookup_material.response_merkle_geometries()[0].components()
            else {
                panic!("the selected source response must contain one component")
            };
            assert_eq!(source_response_component.first_leaf_ordinal(), 0);
            assert_eq!(
                source_response_component.leaf_count(),
                pre_lookup_material.response_merkle_geometries()[0].merkle_leaf_count()
            );
            assert!(source_response_component.leaf_count().is_power_of_two());
            assert_eq!(
                source_response_component.value_kind(),
                CompactResponseLeafValueKind::BaseField
            );
            assert_eq!(source_response_component.leaf_count(), 131_072);
            assert_eq!(source_response_component.field_element_count_per_leaf(), 64);
            (
                compact_construction_identity_hash,
                checkpoint_schedule_digest,
                source_replay_binding,
                pre_lookup_material.private_coin_derivation_binding_hash(),
            )
        };
        println!(
            "compact public-key focused owner phase complete: load 202 authenticated columns elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: encode pre-challenge source");
        let mut private_coins = PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&proof_action_private_randomness),
            statement_schema_identifier,
            private_coin_derivation_binding_hash,
            private_randomness_attempt_identifier,
            private_coin_coordinate_capacity,
        )
        .expect("the compact production-private coin source starts");
        let mut response_storage =
            FileBackedTestStorage::new().expect("selected compact response scratch opens");
        assert_eq!(
            generation_state
                .poll(8_192, &mut private_coins, &mut response_storage)
                .expect("the authenticated pre-challenge source encodes through production WHIR"),
            CompactPublicKeyGenerationPoll::PreChallengeSourceEncoded
        );
        println!(
            "compact public-key focused owner phase complete: encode pre-challenge source elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!(
            "compact public-key focused owner phase: commit source response and derive transcript lookup message"
        );
        let mut supplied_response_leaf_count = 0_u64;
        loop {
            match generation_state
                .poll(8_192, &mut private_coins, &mut response_storage)
                .expect("the owned source response advances")
            {
                CompactPublicKeyGenerationPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    assert_eq!(leaf_ordinal, supplied_response_leaf_count);
                    supplied_response_leaf_count += 1;
                }
                CompactPublicKeyGenerationPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyGenerationPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyGenerationPoll::PreChallengeCheckpointReady => break,
                unexpected => panic!("unexpected source-response poll: {unexpected:?}"),
            }
        }
        assert_eq!(supplied_response_leaf_count, 131_072);
        let pre_challenge_checkpoint = generation_state
            .checkpoint_boundary()
            .expect("the source response exposes its authenticated checkpoint boundary");
        let transcript_cursor_digest = pre_challenge_checkpoint
            .canonical_transcript_cursor_digest()
            .expect("the compact response checkpoint carries a transcript cursor digest");
        let randomness_cursor = generation_state
            .canonical_randomness_checkpoint_cursor_bytes()
            .expect("the source response retains its attempt-bound randomness cursor");
        generation_state
            .validate_authenticated_randomness_checkpoint_cursor(&randomness_cursor)
            .expect("the live state accepts its authenticated randomness cursor");
        let mut changed_randomness_cursor = randomness_cursor;
        changed_randomness_cursor[16] ^= 1;
        assert!(
            generation_state
                .validate_authenticated_randomness_checkpoint_cursor(&changed_randomness_cursor)
                .is_err(),
            "a changed proof-attempt binding must fail closed"
        );
        generation_state
            .restore_authenticated_checkpoint_transcript_cursor(
                pre_challenge_checkpoint.canonical_transcript_cursor_bytes(),
                transcript_cursor_digest,
            )
            .expect("the live state accepts its independently decoded checkpoint cursor");
        println!(
            "compact public-key focused owner phase complete: commit source response and derive transcript lookup message elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: materialize lookup and structured rows");
        let mut lookup_materialization_poll_count = 0_u64;
        let mut row_source_preparation_poll_count = 0_u64;
        loop {
            match generation_state
                .poll(8_192, &mut private_coins, &mut response_storage)
                .expect("bounded compact public-key generation poll")
            {
                CompactPublicKeyGenerationPoll::LookupInverseArithmeticStepCompleted {
                    processed_element_count,
                } => {
                    assert!((1..=8_192).contains(&processed_element_count));
                    lookup_materialization_poll_count += 1;
                }
                CompactPublicKeyGenerationPoll::StructuredRowSourceStepCompleted {
                    step,
                    completed_work_unit_count,
                } => {
                    let maximum_work_unit_count = match step {
                            CompactStructuredR1csRowSourcePreparationStep::PrivatePolynomialForwardTransform
                            | CompactStructuredR1csRowSourcePreparationStep::PublicPolynomialForwardTransform
                            | CompactStructuredR1csRowSourcePreparationStep::ProductPolynomialInverseTransform => 524_288,
                            _ => 8_192,
                        };
                    assert!((1..=maximum_work_unit_count).contains(&completed_work_unit_count));
                    row_source_preparation_poll_count += 1;
                }
                CompactPublicKeyGenerationPoll::FamilyMaterializationComplete => break,
                unexpected => panic!("unexpected family-materialization poll: {unexpected:?}"),
            }
        }
        assert_eq!(lookup_materialization_poll_count, 233);
        assert_eq!(row_source_preparation_poll_count, 760);
        let mut prepared_main_epoch = generation_state
            .finish()
            .expect("the compact public-key main epoch is prepared");
        assert_eq!(
            prepared_main_epoch
                .checkpoint_boundary()
                .expect("the prepared main epoch retains the source checkpoint"),
            &pre_challenge_checkpoint
        );
        let family_material = prepared_main_epoch.family_material();
        assert_eq!(
            family_material.public_input_bindings(),
            crate::bgv::proof_suite::compact_proof_wire::CompactPublicInputBindings::new(
                Hash512::from_bytes(preparation_source.suite_identifier()),
                application_statement_hash,
                Hash512::from_bytes(preparation_source.manifest_hash()),
                Hash512::from_bytes(expected_relation_plan_variant_hash),
            )
        );
        assert_eq!(
            family_material
                .decoded_public_input()
                .canonical_byte_length(),
            family_material.canonical_public_input_bytes().len()
        );
        assert_eq!(
            family_material.proof_wire_geometry(),
            selected_compact_contract
                .verifier_inputs()
                .proof_wire_geometry
        );
        assert_eq!(
            family_material.response_merkle_geometries(),
            selected_compact_contract
                .verifier_inputs()
                .response_merkle_geometries
        );
        assert_eq!(
            family_material.compact_construction_identity_hash(),
            compact_construction_identity_hash
        );
        assert_eq!(
            family_material.checkpoint_schedule_digest(),
            checkpoint_schedule_digest
        );
        assert_eq!(
            family_material.source_replay_binding(),
            source_replay_binding
        );
        assert_eq!(
            family_material
                .pre_challenge_material()
                .proof_attempt_identifier(),
            proof_attempt_identifier
        );
        assert_eq!(
            family_material.witness_length(),
            u64::try_from(
                CompactCfwExternalRowSource::witness_length(family_material.row_source())
                    .expect("production witness length fits usize")
            )
            .expect("production witness length fits u64")
        );
        assert_eq!(
            family_material.row_count(),
            u64::try_from(
                CompactCfwExternalRowSource::row_count(family_material.row_source())
                    .expect("production row count fits usize")
            )
            .expect("production row count fits u64")
        );
        let relation = family_material.relation();
        let row_source = family_material.row_source();
        println!(
            "compact public-key focused owner phase complete: materialize lookup and structured rows elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: check relation segment boundaries");
        let mut checked_rows = BTreeSet::new();
        for relation_ordinal in 0..relation.ordered_relations.len() {
            let first_row = u64::try_from(relation_ordinal)
                .expect("relation ordinal fits u64")
                .checked_mul(relation.ring_degree)
                .expect("relation row interval");
            checked_rows.insert(first_row);
            checked_rows.insert(
                first_row
                    .checked_add(relation.ring_degree - 1)
                    .expect("relation final row"),
            );
        }
        for segment in &relation.ordered_constraint_segments {
            checked_rows.insert(segment.first_row);
            checked_rows.insert(
                segment
                    .first_row
                    .checked_add(segment.row_count - 1)
                    .expect("constraint segment final row"),
            );
        }
        checked_rows.insert(relation.operative_constraint_count);
        checked_rows.insert(relation.padded_constraint_count - 1);
        let first_compiler_derived_checked_row = *checked_rows
            .first()
            .expect("the selected relation contributes at least one checked row");
        let mut first_divergent_checked_row = None;
        let mut divergent_checked_row_count = 0_u64;
        for row_ordinal in checked_rows {
            let evaluation = row_source
                .evaluate_row(row_ordinal)
                .expect("selected production row evaluates");
            let evaluated_product = evaluation.left.multiply(evaluation.right);
            if evaluated_product != evaluation.output {
                match evidence_mode {
                    CompactPublicKeyProofEvidenceGenerationMode::Positive => assert_eq!(
                        evaluated_product, evaluation.output,
                        "production assignment violates row {row_ordinal}"
                    ),
                    CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt => {
                        first_divergent_checked_row.get_or_insert((
                            row_ordinal,
                            evaluated_product,
                            evaluation.output,
                        ));
                        divergent_checked_row_count = divergent_checked_row_count
                            .checked_add(1)
                            .expect("the divergent checked-row count fits u64");
                    }
                }
            }
        }
        match evidence_mode {
            CompactPublicKeyProofEvidenceGenerationMode::Positive => {
                assert_eq!(first_divergent_checked_row, None);
            }
            CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt => {
                let (first_divergent_row_ordinal, evaluated_product, expected_output) =
                    first_divergent_checked_row.expect(
                        "the compiler-derived semantic witness fault must violate a checked relation row",
                    );
                assert_eq!(
                    first_divergent_row_ordinal, first_compiler_derived_checked_row,
                    "the selected first eta-two witness fault must diverge at the compiler's first checked relation row",
                );
                println!(
                    "compact public-key equation-invalid preflight detected first_divergent_row_ordinal={} divergent_checked_row_count={} evaluated_product={evaluated_product:?} expected_output={expected_output:?}",
                    first_divergent_row_ordinal, divergent_checked_row_count,
                );
            }
        }
        println!(
            "compact public-key focused owner phase complete: check relation segment boundaries elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: prepare and commit post-lookup response");
        let post_lookup_response_geometry = &selected_compact_contract
            .verifier_inputs()
            .response_merkle_geometries[1];
        assert_eq!(post_lookup_response_geometry.response_ordinal(), 1);
        let expected_post_lookup_response_leaf_count =
            post_lookup_response_geometry.merkle_leaf_count();
        prepared_main_epoch
            .prepare_post_lookup_response()
            .expect("production CFW masks and main WHIR source encode");
        let compact_geometry = CompactCfwGeometry::derive(
            usize::try_from(prepared_main_epoch.family_material().witness_length())
                .expect("production witness length fits CFW"),
        )
        .expect("production row source has compact CFW geometry");
        let compact_mask_material = prepared_main_epoch
            .cfw_mask_material()
            .expect("the post-lookup response retains its CFW masks");
        assert_eq!(
            compact_mask_material
                .auxiliary_target(compact_geometry)
                .expect("the retained masks determine the CFW auxiliary target"),
            prepared_main_epoch
                .cfw_auxiliary_target()
                .expect("the post-lookup response retains the CFW auxiliary target")
        );
        let mut supplied_post_lookup_response_leaf_count = 0_u64;
        let mut supplied_opened_response_leaf_count = 0_u64;
        let mut main_source_arithmetic_poll_count = 0_u64;
        loop {
            match prepared_main_epoch
                .poll_post_lookup_response(8_192, &mut response_storage)
                .expect("the owned post-lookup response advances")
            {
                CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted {
                    processed_work_unit_count,
                } => {
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    main_source_arithmetic_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    assert_eq!(leaf_ordinal, supplied_post_lookup_response_leaf_count);
                    supplied_post_lookup_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    assert!(response_ordinal <= 1);
                    assert!(
                        leaf_ordinal
                            < selected_compact_contract
                                .verifier_inputs()
                                .response_merkle_geometries[usize::try_from(response_ordinal)
                                .expect("response ordinal fits usize")]
                            .merkle_leaf_count()
                    );
                    supplied_opened_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady => break,
                CompactPublicKeyMainEpochPoll::CrossEpochEvaluationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady
                | CompactPublicKeyMainEpochPoll::CfwRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::CfwFinalResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady => {
                    panic!("cross-epoch work cannot precede the post-lookup checkpoint")
                }
            }
        }
        assert_eq!(
            supplied_post_lookup_response_leaf_count,
            expected_post_lookup_response_leaf_count
        );
        assert_eq!(supplied_opened_response_leaf_count, 0);
        assert!(main_source_arithmetic_poll_count > 0);
        assert!(prepared_main_epoch.main_source_encoding_complete());
        let post_lookup_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the post-lookup response exposes its authenticated checkpoint boundary");
        let post_lookup_safe_boundary_ordinal = post_lookup_checkpoint.safe_boundary_ordinal();
        assert_eq!(
            post_lookup_safe_boundary_ordinal,
            pre_challenge_checkpoint.safe_boundary_ordinal() + 1
        );
        let completed_transcript_response_count =
            u32::from_le_bytes(post_lookup_checkpoint.position()[8..12].try_into().unwrap());
        assert_eq!(completed_transcript_response_count, 2);
        let completed_proof_response_count = u32::from_le_bytes(
            post_lookup_checkpoint.position()[12..16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            usize::try_from(completed_proof_response_count).unwrap(),
            selected_compact_contract
                .verifier_inputs()
                .checkpoint_schedule
                .completed_proof_response_count(
                    usize::try_from(completed_transcript_response_count).unwrap()
                )
                .expect("the selected checkpoint schedule owns this transcript boundary")
        );
        assert_eq!(
            completed_proof_response_count, 0,
            "the first two commitments remain behind their later opening boundary"
        );
        let post_lookup_randomness_cursor =
            prepared_main_epoch.canonical_randomness_checkpoint_cursor_bytes();
        prepared_main_epoch
            .validate_authenticated_randomness_checkpoint_cursor(&post_lookup_randomness_cursor)
            .expect("the prepared main epoch accepts its authenticated randomness cursor");
        assert_ne!(post_lookup_randomness_cursor, randomness_cursor);
        let cross_epoch_point = prepared_main_epoch
            .cross_epoch_point()
            .expect("the second transcript message mints the cross-epoch point");
        assert_eq!(cross_epoch_point.len(), 21);
        assert!(cross_epoch_point.iter().any(|coordinate| {
            compact_challenge_to_production(*coordinate)
                .expect("transcript point coordinate is canonical")
                .canonical_coordinates()[1..]
                .iter()
                .any(|value| *value != 0)
        }));
        println!(
            "compact public-key focused owner phase complete: prepare and commit post-lookup response elapsed_milliseconds={} response_leaf_count={} opened_leaf_count={} main_source_arithmetic_poll_count={} maximum_external_storage_bytes={} retained_external_storage_bytes={} retained_secret_object_count={}",
            phase_started_at.elapsed().as_millis(),
            supplied_post_lookup_response_leaf_count,
            supplied_opened_response_leaf_count,
            main_source_arithmetic_poll_count,
            response_storage.maximum_declared_byte_length(),
            response_storage.committed_declared_byte_length(),
            response_storage.retained_secret_object_count(),
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: commit cross-epoch response");
        let cross_epoch_response_geometry = &selected_compact_contract
            .verifier_inputs()
            .response_merkle_geometries[2];
        assert_eq!(cross_epoch_response_geometry.response_ordinal(), 2);
        let expected_cross_epoch_response_leaf_count =
            cross_epoch_response_geometry.merkle_leaf_count();
        let mut supplied_cross_epoch_response_leaf_count = 0_u64;
        let mut supplied_cross_epoch_opened_leaf_count = 0_u64;
        let mut cross_epoch_evaluation_poll_count = 0_u64;
        let mut evaluated_cross_epoch_source_element_count = 0_u64;
        loop {
            match prepared_main_epoch
                .poll_post_lookup_response(8_192, &mut response_storage)
                .expect("the owned cross-epoch response advances")
            {
                CompactPublicKeyMainEpochPoll::CrossEpochEvaluationStepCompleted {
                    processed_work_unit_count,
                    evaluated_source_element_count,
                } => {
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    assert!(evaluated_source_element_count <= processed_work_unit_count);
                    cross_epoch_evaluation_poll_count += 1;
                    evaluated_cross_epoch_source_element_count += evaluated_source_element_count;
                }
                CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    assert_eq!(leaf_ordinal, supplied_cross_epoch_response_leaf_count);
                    supplied_cross_epoch_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    assert!(response_ordinal <= 2);
                    assert!(
                        leaf_ordinal
                            < selected_compact_contract
                                .verifier_inputs()
                                .response_merkle_geometries[usize::try_from(response_ordinal)
                                .expect("response ordinal fits usize")]
                            .merkle_leaf_count()
                    );
                    supplied_cross_epoch_opened_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady => break,
                CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady
                | CompactPublicKeyMainEpochPoll::CfwRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::CfwFinalResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady => {
                    panic!("post-lookup work cannot recur during the cross-epoch response")
                }
            }
        }
        assert_eq!(
            supplied_cross_epoch_response_leaf_count,
            expected_cross_epoch_response_leaf_count
        );
        assert_eq!(
            supplied_cross_epoch_opened_leaf_count,
            expected_cross_epoch_response_leaf_count
        );
        assert!(cross_epoch_evaluation_poll_count > 0);
        assert_eq!(
            evaluated_cross_epoch_source_element_count,
            prepared_main_epoch
                .family_material()
                .relation()
                .cross_epoch_copy_geometry()
                .expect("cross-epoch copy geometry derives")
                .copied_element_count()
        );
        let [masked_pre_challenge, masked_main, mask_difference] = prepared_main_epoch
            .cross_epoch_disclosed_values()
            .expect("the exact masked cross-epoch response is retained");
        assert!(
            prepared_main_epoch.cross_epoch_masking_prefix_verified(),
            "the real response values must pass the compiler-derived conditional-image gate"
        );
        assert_eq!(
            masked_pre_challenge - masked_main - mask_difference,
            CompactChallengeField::ZERO
        );
        assert_eq!(
            prepared_main_epoch
                .cfw_prover_auxiliary_target()
                .expect("the verifier-derived CFW prover is initialized"),
            prepared_main_epoch
                .cfw_auxiliary_target()
                .expect("the committed CFW auxiliary target is retained")
        );
        let cross_epoch_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the cross-epoch response exposes its authenticated checkpoint boundary");
        let cross_epoch_safe_boundary_ordinal = cross_epoch_checkpoint.safe_boundary_ordinal();
        assert_eq!(
            cross_epoch_safe_boundary_ordinal,
            post_lookup_safe_boundary_ordinal + 1
        );
        assert_eq!(
            u32::from_le_bytes(cross_epoch_checkpoint.position()[8..12].try_into().unwrap()),
            3
        );
        println!(
            "compact public-key focused owner phase complete: commit cross-epoch response elapsed_milliseconds={} response_leaf_count={} evaluation_poll_count={} evaluated_source_element_count={} maximum_external_storage_bytes={} retained_external_storage_bytes={} retained_secret_object_count={}",
            phase_started_at.elapsed().as_millis(),
            supplied_cross_epoch_response_leaf_count,
            cross_epoch_evaluation_poll_count,
            evaluated_cross_epoch_source_element_count,
            response_storage.maximum_declared_byte_length(),
            response_storage.committed_declared_byte_length(),
            response_storage.retained_secret_object_count(),
        );

        if evidence_mode
            == CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt
        {
            prepared_main_epoch
                .prepare_test_only_initial_cfw_sumcheck_inconsistency_transcript()
                .expect(
                    "the test-only dishonest prover is enabled before the first CFW polynomial",
                );
            assert!(
                !prepared_main_epoch.test_only_initial_cfw_sumcheck_inconsistency_accepted(),
                "the dishonest-prover seam cannot be consumed before a polynomial is derived",
            );
        }

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: complete verifier-bound compact CFW");
        let mut cfw_storage =
            FileBackedTestStorage::new().expect("selected compact CFW scratch opens");
        let expected_cfw_round_count = compact_geometry.sumcheck_round_count();
        let mut cfw_round_polynomial_poll_count = 0_u64;
        let mut cfw_bound_round_poll_count = 0_u64;
        let mut cfw_response_leaf_count = 0_u64;
        let mut cfw_opened_leaf_count = 0_u64;
        let mut completed_cfw_round_count = 0_usize;
        let mut observed_test_only_initial_cfw_inconsistency = false;
        loop {
            match prepared_main_epoch
                .poll_cfw(&mut response_storage, &mut cfw_storage)
                .expect("the complete verifier-bound production CFW advances")
            {
                CompactPublicKeyMainEpochPoll::CfwRoundPolynomialStepCompleted {
                    round_ordinal,
                    polynomial_ready,
                } => {
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_cfw_round_count
                    );
                    if polynomial_ready
                        && round_ordinal == 0
                        && evidence_mode
                            == CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt
                    {
                        assert!(
                            prepared_main_epoch
                                .test_only_initial_cfw_sumcheck_inconsistency_accepted(),
                            "the equation-invalid witness must diverge at the initial CFW claim",
                        );
                        assert_eq!(
                            prepared_main_epoch
                                .test_only_cfw_masking_inconsistency_round_ordinals(),
                            Some(&[0_u32][..]),
                            "the dishonest polynomial must be outside the initial masking affine image",
                        );
                        observed_test_only_initial_cfw_inconsistency = true;
                    }
                    cfw_round_polynomial_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::CfwBoundRoundStepCompleted {
                    round_ordinal, ..
                } => {
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap() + 1,
                        completed_cfw_round_count
                    );
                    cfw_bound_round_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    let response_ordinal = u32::try_from(completed_cfw_round_count + 3).unwrap();
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries[usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    cfw_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries[usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    cfw_opened_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyMainEpochPoll::CfwRoundResponseCheckpointReady {
                    round_ordinal,
                } => {
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_cfw_round_count
                    );
                    completed_cfw_round_count += 1;
                    assert_eq!(
                        prepared_main_epoch.completed_cfw_round_count(),
                        Some(completed_cfw_round_count)
                    );
                    let checkpoint = prepared_main_epoch
                        .checkpoint_boundary()
                        .expect("each CFW round exposes an authenticated response checkpoint");
                    assert_eq!(
                        u32::from_le_bytes(checkpoint.position()[8..12].try_into().unwrap()),
                        u32::try_from(completed_cfw_round_count + 3).unwrap()
                    );
                }
                CompactPublicKeyMainEpochPoll::CfwFinalResponseCheckpointReady => break,
                CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CrossEpochEvaluationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady
                | CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                    ..
                }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady => {
                    panic!("pre-CFW work cannot recur during the complete CFW reduction")
                }
            }
        }
        assert_eq!(completed_cfw_round_count, expected_cfw_round_count);
        assert_eq!(
            prepared_main_epoch.completed_cfw_round_count(),
            Some(expected_cfw_round_count)
        );
        assert!(prepared_main_epoch.cfw_finish_masking_verified());
        assert!(cfw_round_polynomial_poll_count > 0);
        assert!(cfw_bound_round_poll_count > 0);
        assert!(cfw_response_leaf_count > 0);
        assert!(cfw_opened_leaf_count > 0);
        assert_eq!(
            observed_test_only_initial_cfw_inconsistency,
            evidence_mode
                == CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt,
            "only the test-only hostile producer may emit an initial inconsistent CFW claim",
        );
        let test_only_cfw_masking_inconsistency_round_ordinals = prepared_main_epoch
            .test_only_cfw_masking_inconsistency_round_ordinals()
            .expect("the prepared main epoch retains its test-only CFW diagnostics");
        match evidence_mode {
            CompactPublicKeyProofEvidenceGenerationMode::Positive => {
                assert!(test_only_cfw_masking_inconsistency_round_ordinals.is_empty());
            }
            CompactPublicKeyProofEvidenceGenerationMode::EquationInvalidIndependentAttempt => {
                assert_eq!(
                    test_only_cfw_masking_inconsistency_round_ordinals,
                    (0..u32::try_from(expected_cfw_round_count).unwrap())
                        .collect::<Vec<_>>()
                        .as_slice(),
                    "every dishonest CFW round must be outside the honest masking affine image",
                );
            }
        }
        let cfw_usage = prepared_main_epoch
            .cfw_external_memory_usage()
            .expect("complete CFW retains its exact external-memory usage");
        assert_eq!(cfw_usage.transaction_count(), 4_926);
        assert_eq!(cfw_usage.total_written_byte_length(), 1_006_632_840);
        assert_eq!(cfw_usage.total_read_byte_length(), 2_013_265_440);
        assert_eq!(cfw_usage.peak_stored_byte_length(), 587_202_560);
        assert_eq!(cfw_storage.committed_declared_byte_length(), 0);
        let final_cfw_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the final CFW response exposes an authenticated response checkpoint");
        assert_eq!(
            final_cfw_checkpoint.safe_boundary_ordinal(),
            cross_epoch_safe_boundary_ordinal
                + u32::try_from(expected_cfw_round_count).unwrap()
                + 1
        );
        assert_eq!(
            u32::from_le_bytes(final_cfw_checkpoint.position()[8..12].try_into().unwrap()),
            u32::try_from(expected_cfw_round_count + 4).unwrap()
        );
        let final_cfw_safe_boundary_ordinal = final_cfw_checkpoint.safe_boundary_ordinal();
        println!(
            "compact public-key focused owner phase complete: complete verifier-bound compact CFW elapsed_milliseconds={} round_count={} round_polynomial_poll_count={} bound_round_poll_count={} response_leaf_count={} opened_leaf_count={} external_transaction_count={} external_written_bytes={} external_read_bytes={} peak_external_storage_bytes={} test_only_masking_inconsistency_round_count={}",
            phase_started_at.elapsed().as_millis(),
            expected_cfw_round_count,
            cfw_round_polynomial_poll_count,
            cfw_bound_round_poll_count,
            cfw_response_leaf_count,
            cfw_opened_leaf_count,
            cfw_usage.transaction_count(),
            cfw_usage.total_written_byte_length(),
            cfw_usage.total_read_byte_length(),
            cfw_usage.peak_stored_byte_length(),
            test_only_cfw_masking_inconsistency_round_ordinals.len(),
        );

        let phase_started_at = Instant::now();
        println!(
            "compact public-key focused owner phase: complete initial pre-challenge WHIR sumcheck"
        );
        let [pre_challenge_whir_epoch, _main_whir_epoch] =
            selected_compact_contract.verifier_inputs().whir_epochs
        else {
            panic!("selected compact contract has both WHIR epochs");
        };
        let expected_whir_round_count =
            usize::try_from(pre_challenge_whir_epoch.folding_schedule[0])
                .expect("selected WHIR folding factor fits usize");
        let expected_whir_residual_length = 1_usize
            << usize::try_from(
                pre_challenge_whir_epoch.polynomial_variable_count
                    - pre_challenge_whir_epoch.folding_schedule[0],
            )
            .expect("selected residual dimension fits usize");
        let initial_whir_response_ordinal =
            u32::try_from(expected_cfw_round_count + 4).expect("initial WHIR response ordinal");
        let expected_whir_response_count = expected_whir_round_count + 1;
        let expected_whir_response_leaf_count =
            selected_compact_contract
                .verifier_inputs()
                .response_merkle_geometries[usize::try_from(
                initial_whir_response_ordinal,
            )
            .unwrap()
                ..usize::try_from(initial_whir_response_ordinal).unwrap()
                    + expected_whir_response_count]
                .iter()
                .map(|geometry| geometry.merkle_leaf_count())
                .sum::<u64>();
        prepared_main_epoch
            .prepare_pre_challenge_whir_initial_sumcheck()
            .expect("the retained source begins its verifier-bound initial WHIR sumcheck");
        let mut current_whir_response_ordinal = initial_whir_response_ordinal;
        let mut current_whir_response_leaf_ordinal = 0_u64;
        let mut whir_relation_poll_count = 0_u64;
        let mut whir_round_polynomial_poll_count = 0_u64;
        let mut whir_bound_round_poll_count = 0_u64;
        let mut whir_weight_scaling_poll_count = 0_u64;
        let mut whir_response_leaf_count = 0_u64;
        let mut whir_opened_leaf_count = 0_u64;
        let mut prepared_whir_sumcheck_count = 0_u64;
        let mut completed_whir_round_count = 0_usize;
        loop {
            let poll = prepared_main_epoch
                .poll_pre_challenge_whir_sumcheck(8_192, &mut response_storage)
                .unwrap_or_else(|error| {
                    let completed_response_count = prepared_main_epoch
                        .checkpoint_boundary()
                        .map(|checkpoint| {
                            u32::from_le_bytes(
                                checkpoint.position()[8..12].try_into().unwrap(),
                            )
                        });
                    panic!(
                        "the selected initial WHIR sumcheck failed: error={error:?} relation_polls={whir_relation_poll_count} prepared_count={prepared_whir_sumcheck_count} current_response_ordinal={current_whir_response_ordinal} current_response_leaf_ordinal={current_whir_response_leaf_ordinal} response_leaf_count={whir_response_leaf_count} opened_leaf_count={whir_opened_leaf_count} round_polynomial_polls={whir_round_polynomial_poll_count} bound_round_polls={whir_bound_round_poll_count} weight_scaling_polls={whir_weight_scaling_poll_count} completed_round_count={completed_whir_round_count} checkpoint_completed_response_count={completed_response_count:?}"
                    )
                });
            match poll {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirRelationStepCompleted {
                    processed_work_unit_count,
                    ..
                } => {
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    whir_relation_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared {
                    batch_ordinal,
                } => {
                    assert_eq!(batch_ordinal, 0);
                    prepared_whir_sumcheck_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_whir_round_count
                    );
                    whir_round_polynomial_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap() + 1,
                        completed_whir_round_count
                    );
                    whir_bound_round_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                    batch_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, 0);
                    whir_weight_scaling_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    assert_eq!(leaf_ordinal, current_whir_response_leaf_ordinal);
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(current_whir_response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    current_whir_response_leaf_ordinal += 1;
                    whir_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries[usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    whir_opened_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                    batch_ordinal,
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(current_whir_response_ordinal, initial_whir_response_ordinal);
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(current_whir_response_ordinal).unwrap()];
                    assert_eq!(
                        current_whir_response_leaf_ordinal,
                        response_geometry.merkle_leaf_count()
                    );
                    current_whir_response_ordinal += 1;
                    current_whir_response_leaf_ordinal = 0;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                    batch_ordinal,
                    round_ordinal,
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_whir_round_count
                    );
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(current_whir_response_ordinal).unwrap()];
                    assert_eq!(
                        current_whir_response_leaf_ordinal,
                        response_geometry.merkle_leaf_count()
                    );
                    completed_whir_round_count += 1;
                    current_whir_response_ordinal += 1;
                    current_whir_response_leaf_ordinal = 0;
                    let checkpoint = prepared_main_epoch
                        .checkpoint_boundary()
                        .expect("each initial WHIR response has an authenticated checkpoint");
                    assert_eq!(
                        u32::from_le_bytes(checkpoint.position()[8..12].try_into().unwrap()),
                        current_whir_response_ordinal
                    );
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete {
                    batch_ordinal: 0,
                } => break,
                CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CrossEpochEvaluationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::CfwFinalResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady
                | CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady => {
                    panic!("earlier generation work cannot recur during the initial WHIR sumcheck")
                }
            }
        }
        assert_eq!(prepared_whir_sumcheck_count, 1);
        assert_eq!(completed_whir_round_count, expected_whir_round_count);
        assert_eq!(
            current_whir_response_ordinal,
            initial_whir_response_ordinal + u32::try_from(expected_whir_response_count).unwrap()
        );
        assert_eq!(current_whir_response_leaf_ordinal, 0);
        assert_eq!(whir_response_leaf_count, expected_whir_response_leaf_count);
        assert_eq!(whir_opened_leaf_count, 12);
        assert!(whir_relation_poll_count > 0);
        assert!(whir_round_polynomial_poll_count > 0);
        assert!(whir_bound_round_poll_count > 0);
        assert!(whir_weight_scaling_poll_count > 0);
        assert!(prepared_main_epoch.pre_challenge_whir_sumcheck_complete(0));
        assert_eq!(
            prepared_main_epoch.pre_challenge_whir_sumcheck_output_count(0),
            Some(1 + 2 * expected_whir_round_count)
        );
        assert_eq!(
            prepared_main_epoch.pre_challenge_whir_residual_length(0),
            Some(expected_whir_residual_length)
        );
        let final_whir_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the final initial WHIR sumcheck response retains its checkpoint");
        let final_whir_safe_boundary_ordinal = final_whir_checkpoint.safe_boundary_ordinal();
        assert_eq!(
            final_whir_safe_boundary_ordinal,
            final_cfw_safe_boundary_ordinal + u32::try_from(expected_whir_response_count).unwrap()
        );
        println!(
            "compact public-key focused owner phase complete: complete initial pre-challenge WHIR sumcheck elapsed_milliseconds={} round_count={} residual_length={} relation_poll_count={} round_polynomial_poll_count={} bound_round_poll_count={} weight_scaling_poll_count={} response_leaf_count={} opened_leaf_count={}",
            phase_started_at.elapsed().as_millis(),
            expected_whir_round_count,
            expected_whir_residual_length,
            whir_relation_poll_count,
            whir_round_polynomial_poll_count,
            whir_bound_round_poll_count,
            whir_weight_scaling_poll_count,
            whir_response_leaf_count,
            whir_opened_leaf_count,
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: first pre-challenge WHIR code switch");
        let first_code_switch_response_ordinal = current_whir_response_ordinal;
        let first_code_switch_response_geometry = &selected_compact_contract
            .verifier_inputs()
            .response_merkle_geometries
            [usize::try_from(first_code_switch_response_ordinal).unwrap()];
        let expected_first_code_switch_response_leaf_count =
            first_code_switch_response_geometry.merkle_leaf_count();
        let expected_first_code_switch_opened_leaf_count = selected_compact_contract
            .verifier_inputs()
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == pre_challenge_whir_epoch.epoch && fold.batch_ordinal == 0)
            .expect("the initial pre-challenge WHIR fold exists")
            .query_count;
        prepared_main_epoch
            .prepare_pre_challenge_whir_code_switch()
            .expect("the complete initial sumcheck begins its first code switch");
        let mut code_switch_randomness_poll_count = 0_u64;
        let mut code_switch_source_poll_count = 0_u64;
        let mut code_switch_prepared_count = 0_u64;
        let mut code_switch_response_leaf_count = 0_u64;
        let mut code_switch_opened_leaf_count = 0_u64;
        loop {
            let poll = prepared_main_epoch
                .poll_pre_challenge_whir_code_switch(8_192, &mut response_storage)
                .unwrap_or_else(|error| {
                    panic!(
                        "the first pre-challenge WHIR code switch failed: error={error:?} randomness_polls={code_switch_randomness_poll_count} source_polls={code_switch_source_poll_count} prepared_count={code_switch_prepared_count} response_leaf_count={code_switch_response_leaf_count} opened_leaf_count={code_switch_opened_leaf_count}"
                    )
                });
            match poll {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted {
                    round_ordinal,
                    processed_work_unit_count,
                    ..
                } => {
                    assert_eq!(round_ordinal, 0);
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    code_switch_randomness_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared {
                    round_ordinal,
                } => {
                    assert_eq!(round_ordinal, 0);
                    code_switch_prepared_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted {
                    round_ordinal,
                    processed_work_unit_count,
                } => {
                    assert_eq!(round_ordinal, 0);
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    code_switch_source_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    assert_eq!(leaf_ordinal, code_switch_response_leaf_count);
                    assert!(leaf_ordinal < expected_first_code_switch_response_leaf_count);
                    code_switch_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    assert_eq!(response_ordinal, 0);
                    assert!(
                        leaf_ordinal
                            < selected_compact_contract
                                .verifier_inputs()
                                .response_merkle_geometries[0]
                                .merkle_leaf_count()
                    );
                    code_switch_opened_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady {
                    round_ordinal,
                } => {
                    assert_eq!(round_ordinal, 0);
                    break;
                }
                CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CrossEpochEvaluationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::CfwRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::CfwFinalResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady
                | CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchPrepared { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorsPrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBasePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponsePrepared
                | CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted { .. }
                | CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady => {
                    panic!("earlier generation work cannot recur during the first WHIR code switch")
                }
            }
        }
        assert_eq!(code_switch_prepared_count, 1);
        assert!(code_switch_randomness_poll_count > 0);
        assert!(code_switch_source_poll_count > 0);
        assert_eq!(
            code_switch_response_leaf_count,
            expected_first_code_switch_response_leaf_count
        );
        assert_eq!(
            code_switch_opened_leaf_count,
            expected_first_code_switch_opened_leaf_count
        );
        assert!(prepared_main_epoch.pre_challenge_whir_code_switch_ready(0));
        assert!(prepared_main_epoch.pre_challenge_whir_code_switch_bound(0));
        assert!(prepared_main_epoch.pre_challenge_whir_source_query_masking_verified(0));
        let first_code_switch_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the first code-switch response exposes an authenticated checkpoint");
        let first_code_switch_safe_boundary_ordinal =
            first_code_switch_checkpoint.safe_boundary_ordinal();
        assert_eq!(
            first_code_switch_safe_boundary_ordinal,
            final_whir_safe_boundary_ordinal + 1
        );
        assert_eq!(
            u32::from_le_bytes(
                first_code_switch_checkpoint.position()[8..12]
                    .try_into()
                    .unwrap()
            ),
            first_code_switch_response_ordinal + 1
        );
        println!(
            "compact public-key focused owner phase complete: first pre-challenge WHIR code switch elapsed_milliseconds={} randomness_poll_count={} source_poll_count={} response_leaf_count={} opened_leaf_count={}",
            phase_started_at.elapsed().as_millis(),
            code_switch_randomness_poll_count,
            code_switch_source_poll_count,
            code_switch_response_leaf_count,
            code_switch_opened_leaf_count,
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: first code-switch relation");
        let previous_source_contract = selected_compact_contract
            .verifier_inputs()
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == pre_challenge_whir_epoch.epoch && fold.batch_ordinal == 0)
            .expect("the first pre-challenge source contract exists");
        let next_source_contract = selected_compact_contract
            .verifier_inputs()
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == pre_challenge_whir_epoch.epoch && fold.batch_ordinal == 1)
            .expect("the second pre-challenge source contract exists");
        let expected_relation_work_unit_count = expected_first_code_switch_opened_leaf_count
            .checked_mul(
                next_source_contract
                    .message_length
                    .checked_mul(next_source_contract.oracle_width)
                    .and_then(|source_count| {
                        source_count.checked_add(previous_source_contract.hiding_randomness_length)
                    })
                    .expect("the code-switch relation width fits u64"),
            )
            .expect("the code-switch relation work count fits u64");
        prepared_main_epoch
            .prepare_pre_challenge_whir_next_sumcheck()
            .expect("the bound first code switch starts its output relation");
        let mut relation_poll_count = 0_u64;
        let mut relation_work_unit_count = 0_u64;
        loop {
            match prepared_main_epoch
                .poll_pre_challenge_whir_next_sumcheck_preparation(8_192)
                .expect("the first code-switch relation advances")
            {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted {
                    round_ordinal: 0,
                    processed_work_unit_count,
                    ..
                } => {
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    relation_poll_count += 1;
                    relation_work_unit_count += processed_work_unit_count;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared {
                    batch_ordinal: 1,
                } => break,
                unexpected => {
                    panic!("unexpected poll while preparing the second WHIR sumcheck: {unexpected:?}")
                }
            }
        }
        assert!(relation_poll_count > 1);
        assert_eq!(relation_work_unit_count, expected_relation_work_unit_count);
        assert_eq!(
            prepared_main_epoch.pre_challenge_whir_sumcheck_output_count(1),
            Some(1)
        );
        println!(
            "compact public-key focused owner phase complete: first code-switch relation elapsed_milliseconds={} poll_count={} work_unit_count={}",
            phase_started_at.elapsed().as_millis(),
            relation_poll_count,
            relation_work_unit_count,
        );

        let phase_started_at = Instant::now();
        println!(
            "compact public-key focused owner phase: complete second pre-challenge WHIR sumcheck"
        );
        let second_whir_batch_ordinal = 1_u8;
        let second_whir_round_count = usize::try_from(
            pre_challenge_whir_epoch.folding_schedule[usize::from(second_whir_batch_ordinal)],
        )
        .expect("second selected WHIR folding factor fits usize");
        let second_whir_source_length = usize::try_from(
            next_source_contract
                .message_length
                .checked_mul(next_source_contract.oracle_width)
                .expect("second selected WHIR source length fits u64"),
        )
        .expect("second selected WHIR source length fits usize");
        let expected_second_whir_residual_length = second_whir_source_length
            .checked_shr(u32::try_from(second_whir_round_count).unwrap())
            .expect("second selected WHIR residual length exists");
        let second_whir_maximum_work_unit_count = 8_192_u64;
        let expected_second_whir_weight_scaling_poll_count =
            u64::try_from(expected_second_whir_residual_length.saturating_sub(1))
                .expect("the second WHIR residual length fits u64")
                / second_whir_maximum_work_unit_count;
        let second_whir_initial_response_ordinal = selected_compact_contract
            .verifier_inputs()
            .response_component_roles
            .iter()
            .position(|roles| {
                roles.iter().any(|role| {
                    (
                        role.role_tag,
                        role.epoch,
                        role.batch_ordinal,
                        role.round_ordinal,
                    ) == (
                        11,
                        pre_challenge_whir_epoch.epoch,
                        second_whir_batch_ordinal,
                        0,
                    )
                })
            })
            .and_then(|response_index| u32::try_from(response_index).ok())
            .expect("the second selected WHIR batch has one mask response");
        assert_eq!(
            second_whir_initial_response_ordinal,
            first_code_switch_response_ordinal + 1
        );
        let expected_second_whir_response_count = second_whir_round_count + 1;
        let second_whir_first_round_response_index =
            usize::try_from(second_whir_initial_response_ordinal + 1).unwrap();
        let second_whir_round_response_geometries = &selected_compact_contract
            .verifier_inputs()
            .response_merkle_geometries[second_whir_first_round_response_index
            ..second_whir_first_round_response_index + second_whir_round_count];
        assert!(
            second_whir_round_response_geometries
                .iter()
                .all(|geometry| {
                    geometry.minimum_queried_leaf_count() == geometry.maximum_queried_leaf_count()
                })
        );
        let expected_second_whir_opened_leaf_count = second_whir_round_response_geometries
            .iter()
            .map(|geometry| geometry.minimum_queried_leaf_count())
            .sum::<u64>();
        let expected_second_whir_response_leaf_count = selected_compact_contract
            .verifier_inputs()
            .response_merkle_geometries[usize::try_from(
            second_whir_initial_response_ordinal,
        )
        .unwrap()
            ..usize::try_from(second_whir_initial_response_ordinal).unwrap()
                + expected_second_whir_response_count]
            .iter()
            .map(|geometry| geometry.merkle_leaf_count())
            .sum::<u64>();
        let mut second_whir_response_ordinal = second_whir_initial_response_ordinal;
        let mut second_whir_response_leaf_ordinal = 0_u64;
        let mut second_whir_round_polynomial_poll_count = 0_u64;
        let mut second_whir_bound_round_poll_count = 0_u64;
        let mut second_whir_weight_scaling_poll_count = 0_u64;
        let mut second_whir_response_leaf_count = 0_u64;
        let mut second_whir_opened_leaf_count = 0_u64;
        let mut second_whir_opened_leaf_counts_by_round = vec![0_u64; second_whir_round_count];
        let mut completed_second_whir_round_count = 0_usize;
        loop {
            let poll = prepared_main_epoch
                .poll_pre_challenge_whir_sumcheck(
                    second_whir_maximum_work_unit_count,
                    &mut response_storage,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "the second pre-challenge WHIR sumcheck failed: error={error:?} current_response_ordinal={second_whir_response_ordinal} current_response_leaf_ordinal={second_whir_response_leaf_ordinal} response_leaf_count={second_whir_response_leaf_count} opened_leaf_count={second_whir_opened_leaf_count} round_polynomial_polls={second_whir_round_polynomial_poll_count} bound_round_polls={second_whir_bound_round_poll_count} weight_scaling_polls={second_whir_weight_scaling_poll_count} completed_round_count={completed_second_whir_round_count}"
                    )
                });
            match poll {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, second_whir_batch_ordinal);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_second_whir_round_count
                    );
                    second_whir_round_polynomial_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, second_whir_batch_ordinal);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap() + 1,
                        completed_second_whir_round_count
                    );
                    second_whir_bound_round_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                    batch_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, second_whir_batch_ordinal);
                    second_whir_weight_scaling_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    assert_eq!(leaf_ordinal, second_whir_response_leaf_ordinal);
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(second_whir_response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    second_whir_response_leaf_ordinal += 1;
                    second_whir_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    let round_index = usize::try_from(
                        response_ordinal
                            .checked_sub(second_whir_initial_response_ordinal + 1)
                            .expect("only second-batch round responses are opened"),
                    )
                    .expect("the round response index fits usize");
                    let opened_leaf_count = second_whir_opened_leaf_counts_by_round
                        .get_mut(round_index)
                        .expect("the opened response belongs to a second-batch round");
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries[usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    *opened_leaf_count += 1;
                    second_whir_opened_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                    batch_ordinal,
                } => {
                    assert_eq!(batch_ordinal, second_whir_batch_ordinal);
                    assert_eq!(
                        second_whir_response_ordinal,
                        second_whir_initial_response_ordinal
                    );
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(second_whir_response_ordinal).unwrap()];
                    assert_eq!(
                        second_whir_response_leaf_ordinal,
                        response_geometry.merkle_leaf_count()
                    );
                    second_whir_response_ordinal += 1;
                    second_whir_response_leaf_ordinal = 0;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                    batch_ordinal,
                    round_ordinal,
                } => {
                    assert_eq!(batch_ordinal, second_whir_batch_ordinal);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_second_whir_round_count
                    );
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(second_whir_response_ordinal).unwrap()];
                    assert_eq!(
                        second_whir_response_leaf_ordinal,
                        response_geometry.merkle_leaf_count()
                    );
                    completed_second_whir_round_count += 1;
                    second_whir_response_ordinal += 1;
                    second_whir_response_leaf_ordinal = 0;
                }
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete {
                    batch_ordinal,
                } if batch_ordinal == second_whir_batch_ordinal => break,
                unexpected => {
                    panic!("unexpected poll during the second WHIR sumcheck: {unexpected:?}")
                }
            }
        }
        assert_eq!(completed_second_whir_round_count, second_whir_round_count);
        assert_eq!(
            second_whir_response_ordinal,
            second_whir_initial_response_ordinal
                + u32::try_from(expected_second_whir_response_count).unwrap()
        );
        assert_eq!(second_whir_response_leaf_ordinal, 0);
        assert_eq!(
            second_whir_response_leaf_count,
            expected_second_whir_response_leaf_count
        );
        assert_eq!(
            second_whir_opened_leaf_count,
            expected_second_whir_opened_leaf_count
        );
        for (opened_leaf_count, response_geometry) in second_whir_opened_leaf_counts_by_round
            .iter()
            .zip(second_whir_round_response_geometries)
        {
            assert_eq!(
                *opened_leaf_count,
                response_geometry.minimum_queried_leaf_count()
            );
        }
        assert!(second_whir_round_polynomial_poll_count > 0);
        assert!(second_whir_bound_round_poll_count > 0);
        assert_eq!(
            second_whir_weight_scaling_poll_count,
            expected_second_whir_weight_scaling_poll_count
        );
        assert!(
            prepared_main_epoch.pre_challenge_whir_sumcheck_complete(second_whir_batch_ordinal)
        );
        assert_eq!(
            prepared_main_epoch.pre_challenge_whir_sumcheck_output_count(second_whir_batch_ordinal),
            Some(1 + 2 * second_whir_round_count)
        );
        assert_eq!(
            prepared_main_epoch.pre_challenge_whir_residual_length(second_whir_batch_ordinal),
            Some(expected_second_whir_residual_length)
        );
        let final_second_whir_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the second WHIR sumcheck retains its final checkpoint");
        assert_eq!(
            final_second_whir_checkpoint.safe_boundary_ordinal(),
            first_code_switch_safe_boundary_ordinal
                + u32::try_from(expected_second_whir_response_count).unwrap()
        );
        println!(
            "compact public-key focused owner phase complete: second pre-challenge WHIR sumcheck elapsed_milliseconds={} round_count={} residual_length={} round_polynomial_poll_count={} bound_round_poll_count={} weight_scaling_poll_count={} response_leaf_count={} opened_leaf_count={}",
            phase_started_at.elapsed().as_millis(),
            second_whir_round_count,
            expected_second_whir_residual_length,
            second_whir_round_polynomial_poll_count,
            second_whir_bound_round_poll_count,
            second_whir_weight_scaling_poll_count,
            second_whir_response_leaf_count,
            second_whir_opened_leaf_count,
        );
        let mut completed_phase = CompletedSelectedWhirPhase {
            next_response_ordinal: second_whir_response_ordinal,
            safe_boundary_ordinal: final_second_whir_checkpoint.safe_boundary_ordinal(),
        };
        for round_ordinal in 1_u8..=2 {
            let phase_started_at = Instant::now();
            println!(
                "compact public-key focused owner phase: pre-challenge WHIR code switch round_ordinal={round_ordinal}"
            );
            completed_phase = complete_selected_whir_code_switch(
                &mut prepared_main_epoch,
                &mut response_storage,
                &selected_compact_contract,
                pre_challenge_whir_epoch,
                SelectedWhirEpochOwner::PreChallenge,
                round_ordinal,
                completed_phase,
            );
            println!(
                "compact public-key focused owner phase elapsed_milliseconds={} round_ordinal={round_ordinal}",
                phase_started_at.elapsed().as_millis(),
            );

            prepare_selected_whir_sumcheck_after_code_switch(
                &mut prepared_main_epoch,
                &selected_compact_contract,
                pre_challenge_whir_epoch,
                SelectedWhirEpochOwner::PreChallenge,
                round_ordinal,
            );
            completed_phase = complete_selected_whir_sumcheck_batch(
                &mut prepared_main_epoch,
                &mut response_storage,
                &selected_compact_contract,
                pre_challenge_whir_epoch,
                SelectedWhirEpochOwner::PreChallenge,
                round_ordinal + 1,
                completed_phase,
            );
        }
        assert_eq!(
            prepared_main_epoch.pre_challenge_whir_residual_length(3),
            Some(8)
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: complete pre-challenge WHIR base");
        completed_phase = complete_selected_whir_base_case(
            &mut prepared_main_epoch,
            &mut response_storage,
            &selected_compact_contract,
            pre_challenge_whir_epoch,
            SelectedWhirEpochOwner::PreChallenge,
            completed_phase,
        );
        println!(
            "compact public-key focused owner phase complete: pre-challenge WHIR base elapsed_milliseconds={} next_response_ordinal={} safe_boundary_ordinal={}",
            phase_started_at.elapsed().as_millis(),
            completed_phase.next_response_ordinal,
            completed_phase.safe_boundary_ordinal,
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: prepare initial main WHIR sumcheck");
        let expected_main_source_element_count =
            prepared_main_epoch.family_material().witness_length();
        assert_eq!(expected_main_source_element_count, 4_194_304);
        prepared_main_epoch
            .prepare_main_whir_initial_sumcheck()
            .expect("the completed pre-challenge epoch starts the main-WHIR relation");
        let mut covector_poll_count = 0_u64;
        let mut covector_work_unit_count = 0_u64;
        let mut covector_prepared_count = 0_u64;
        let mut relation_source_poll_count = 0_u64;
        let mut relation_source_element_count = 0_u64;
        let mut relation_completion_poll_count = 0_u64;
        loop {
            match prepared_main_epoch
                .poll_main_whir_initial_sumcheck_preparation(8_192)
                .expect("the selected main-WHIR relation preparation advances")
            {
                CompactPublicKeyMainEpochPoll::MainWhirCovectorStepCompleted {
                    completed_work_unit_count,
                    ..
                } => {
                    assert!(completed_work_unit_count > 0);
                    covector_poll_count += 1;
                    covector_work_unit_count += completed_work_unit_count;
                }
                CompactPublicKeyMainEpochPoll::MainWhirCovectorsPrepared => {
                    covector_prepared_count += 1;
                }
                CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted {
                    processed_work_unit_count,
                    relation_complete,
                } => {
                    assert!((1..=8_192).contains(&processed_work_unit_count));
                    relation_source_poll_count += 1;
                    relation_source_element_count += processed_work_unit_count;
                    relation_completion_poll_count += u64::from(relation_complete);
                }
                CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { batch_ordinal } => {
                    assert_eq!(batch_ordinal, 0);
                    break;
                }
                unexpected => {
                    panic!(
                        "unexpected poll while preparing the initial main-WHIR sumcheck: {unexpected:?}"
                    )
                }
            }
        }
        assert!(covector_poll_count > 0);
        assert!(covector_work_unit_count > 0);
        assert_eq!(covector_prepared_count, 1);
        assert!(relation_source_poll_count > 1);
        assert_eq!(
            relation_source_element_count,
            expected_main_source_element_count
        );
        assert_eq!(relation_completion_poll_count, 1);
        assert!(prepared_main_epoch.main_whir_initial_sumcheck_ready());
        println!(
            "compact public-key focused owner phase complete: prepare initial main WHIR sumcheck elapsed_milliseconds={} covector_poll_count={} covector_work_unit_count={} relation_source_poll_count={} relation_source_element_count={}",
            phase_started_at.elapsed().as_millis(),
            covector_poll_count,
            covector_work_unit_count,
            relation_source_poll_count,
            relation_source_element_count,
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: complete initial main WHIR sumcheck");
        let [_pre_challenge_whir_epoch, main_whir_epoch] =
            selected_compact_contract.verifier_inputs().whir_epochs
        else {
            panic!("selected compact contract has both WHIR epochs");
        };
        let expected_main_whir_round_count = usize::try_from(main_whir_epoch.folding_schedule[0])
            .expect("selected main-WHIR folding factor fits usize");
        let expected_main_whir_residual_length = 1_usize
            << usize::try_from(
                main_whir_epoch.polynomial_variable_count - main_whir_epoch.folding_schedule[0],
            )
            .expect("selected main-WHIR residual dimension fits usize");
        let initial_main_whir_response_ordinal = u32::try_from(
            selected_compact_contract
                .verifier_inputs()
                .response_component_roles
                .iter()
                .position(|roles| {
                    roles.iter().any(|role| {
                        (
                            role.role_tag,
                            role.epoch,
                            role.batch_ordinal,
                            role.round_ordinal,
                        ) == (11, main_whir_epoch.epoch, 0, 0)
                    })
                })
                .expect("the selected response registry contains the initial main-WHIR response"),
        )
        .expect("the initial main-WHIR response ordinal fits u32");
        let expected_main_whir_response_count = expected_main_whir_round_count + 1;
        let expected_main_whir_response_leaf_count = selected_compact_contract
            .verifier_inputs()
            .response_merkle_geometries[usize::try_from(initial_main_whir_response_ordinal)
            .unwrap()
            ..usize::try_from(initial_main_whir_response_ordinal).unwrap()
                + expected_main_whir_response_count]
            .iter()
            .map(|geometry| geometry.merkle_leaf_count())
            .sum::<u64>();
        let main_whir_start_safe_boundary_ordinal = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the completed first epoch retains its authenticated checkpoint")
            .safe_boundary_ordinal();
        let mut current_main_whir_response_ordinal = initial_main_whir_response_ordinal;
        let mut current_main_whir_response_leaf_ordinal = 0_u64;
        let mut main_whir_round_polynomial_poll_count = 0_u64;
        let mut main_whir_bound_round_poll_count = 0_u64;
        let mut main_whir_weight_scaling_poll_count = 0_u64;
        let mut main_whir_response_leaf_count = 0_u64;
        let mut main_whir_opened_leaf_count = 0_u64;
        let mut completed_main_whir_round_count = 0_usize;
        loop {
            let poll = prepared_main_epoch
                .poll_main_whir_sumcheck(8_192, &mut response_storage)
                .unwrap_or_else(|error| {
                    panic!(
                        "the selected initial main-WHIR sumcheck failed: error={error:?} current_response_ordinal={current_main_whir_response_ordinal} current_response_leaf_ordinal={current_main_whir_response_leaf_ordinal} response_leaf_count={main_whir_response_leaf_count} opened_leaf_count={main_whir_opened_leaf_count} round_polynomial_polls={main_whir_round_polynomial_poll_count} bound_round_polls={main_whir_bound_round_poll_count} weight_scaling_polls={main_whir_weight_scaling_poll_count} completed_round_count={completed_main_whir_round_count}"
                    )
                });
            match poll {
                CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_main_whir_round_count
                    );
                    main_whir_round_polynomial_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap() + 1,
                        completed_main_whir_round_count
                    );
                    main_whir_bound_round_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted {
                    batch_ordinal,
                    ..
                } => {
                    assert_eq!(batch_ordinal, 0);
                    main_whir_weight_scaling_poll_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal } => {
                    assert_eq!(leaf_ordinal, current_main_whir_response_leaf_ordinal);
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(current_main_whir_response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    current_main_whir_response_leaf_ordinal += 1;
                    main_whir_response_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                } => {
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries[usize::try_from(response_ordinal).unwrap()];
                    assert!(leaf_ordinal < response_geometry.merkle_leaf_count());
                    main_whir_opened_leaf_count += 1;
                }
                CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted
                | CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted => {}
                CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady {
                    batch_ordinal,
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(
                        current_main_whir_response_ordinal,
                        initial_main_whir_response_ordinal
                    );
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(current_main_whir_response_ordinal).unwrap()];
                    assert_eq!(
                        current_main_whir_response_leaf_ordinal,
                        response_geometry.merkle_leaf_count()
                    );
                    current_main_whir_response_ordinal += 1;
                    current_main_whir_response_leaf_ordinal = 0;
                }
                CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady {
                    batch_ordinal,
                    round_ordinal,
                } => {
                    assert_eq!(batch_ordinal, 0);
                    assert_eq!(
                        usize::try_from(round_ordinal).unwrap(),
                        completed_main_whir_round_count
                    );
                    let response_geometry = &selected_compact_contract
                        .verifier_inputs()
                        .response_merkle_geometries
                        [usize::try_from(current_main_whir_response_ordinal).unwrap()];
                    assert_eq!(
                        current_main_whir_response_leaf_ordinal,
                        response_geometry.merkle_leaf_count()
                    );
                    completed_main_whir_round_count += 1;
                    current_main_whir_response_ordinal += 1;
                    current_main_whir_response_leaf_ordinal = 0;
                    let checkpoint = prepared_main_epoch
                        .checkpoint_boundary()
                        .expect("each initial main-WHIR response has an authenticated checkpoint");
                    assert_eq!(
                        u32::from_le_bytes(checkpoint.position()[8..12].try_into().unwrap()),
                        current_main_whir_response_ordinal
                    );
                }
                CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { batch_ordinal: 0 } => {
                    break;
                }
                unexpected => panic!(
                    "unexpected poll while completing the initial main-WHIR sumcheck: {unexpected:?}"
                ),
            }
        }
        assert_eq!(
            completed_main_whir_round_count,
            expected_main_whir_round_count
        );
        assert_eq!(
            current_main_whir_response_ordinal,
            initial_main_whir_response_ordinal
                + u32::try_from(expected_main_whir_response_count).unwrap()
        );
        assert_eq!(current_main_whir_response_leaf_ordinal, 0);
        assert_eq!(
            main_whir_response_leaf_count,
            expected_main_whir_response_leaf_count
        );
        assert_eq!(
            main_whir_opened_leaf_count,
            u64::try_from(2 * expected_main_whir_round_count).unwrap()
        );
        assert!(main_whir_round_polynomial_poll_count > 0);
        assert!(main_whir_bound_round_poll_count > 0);
        assert!(main_whir_weight_scaling_poll_count > 0);
        assert!(prepared_main_epoch.main_whir_sumcheck_complete(0));
        assert_eq!(
            prepared_main_epoch.main_whir_sumcheck_output_count(0),
            Some(1 + 2 * expected_main_whir_round_count)
        );
        assert_eq!(
            prepared_main_epoch.main_whir_residual_length(0),
            Some(expected_main_whir_residual_length)
        );
        let final_main_whir_checkpoint = prepared_main_epoch
            .checkpoint_boundary()
            .expect("the final initial main-WHIR response retains its checkpoint");
        assert_eq!(
            final_main_whir_checkpoint.safe_boundary_ordinal(),
            main_whir_start_safe_boundary_ordinal
                + u32::try_from(expected_main_whir_response_count).unwrap()
        );
        println!(
            "compact public-key focused owner phase complete: complete initial main WHIR sumcheck elapsed_milliseconds={} round_count={} residual_length={} round_polynomial_poll_count={} bound_round_poll_count={} weight_scaling_poll_count={} response_leaf_count={} opened_leaf_count={}",
            phase_started_at.elapsed().as_millis(),
            expected_main_whir_round_count,
            expected_main_whir_residual_length,
            main_whir_round_polynomial_poll_count,
            main_whir_bound_round_poll_count,
            main_whir_weight_scaling_poll_count,
            main_whir_response_leaf_count,
            main_whir_opened_leaf_count,
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: first main WHIR code switch");
        let mut completed_main_whir_phase = CompletedSelectedWhirPhase {
            next_response_ordinal: current_main_whir_response_ordinal,
            safe_boundary_ordinal: final_main_whir_checkpoint.safe_boundary_ordinal(),
        };
        completed_main_whir_phase = complete_selected_whir_code_switch(
            &mut prepared_main_epoch,
            &mut response_storage,
            &selected_compact_contract,
            main_whir_epoch,
            SelectedWhirEpochOwner::Main,
            0,
            completed_main_whir_phase,
        );
        let expected_main_source_query_count = selected_compact_contract
            .verifier_inputs()
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == main_whir_epoch.epoch && fold.batch_ordinal == 0)
            .expect("the initial main WHIR source contract exists")
            .query_count;
        assert!(prepared_main_epoch.main_source_query_replay_released());
        assert_eq!(
            prepared_main_epoch.main_source_retained_query_count(),
            Some(usize::try_from(expected_main_source_query_count).unwrap())
        );
        println!(
            "compact public-key focused owner phase complete: first main WHIR code switch elapsed_milliseconds={} retained_source_query_count={}",
            phase_started_at.elapsed().as_millis(),
            expected_main_source_query_count,
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: first main code-switch relation");
        prepare_selected_whir_sumcheck_after_code_switch(
            &mut prepared_main_epoch,
            &selected_compact_contract,
            main_whir_epoch,
            SelectedWhirEpochOwner::Main,
            0,
        );
        completed_main_whir_phase = complete_selected_whir_sumcheck_batch(
            &mut prepared_main_epoch,
            &mut response_storage,
            &selected_compact_contract,
            main_whir_epoch,
            SelectedWhirEpochOwner::Main,
            1,
            completed_main_whir_phase,
        );
        println!(
            "compact public-key focused owner phase complete: second main WHIR sumcheck elapsed_milliseconds={} next_response_ordinal={} safe_boundary_ordinal={}",
            phase_started_at.elapsed().as_millis(),
            completed_main_whir_phase.next_response_ordinal,
            completed_main_whir_phase.safe_boundary_ordinal,
        );
        for round_ordinal in 1_u8..=2 {
            let phase_started_at = Instant::now();
            println!(
                "compact public-key focused owner phase: main WHIR code switch round_ordinal={round_ordinal}"
            );
            completed_main_whir_phase = complete_selected_whir_code_switch(
                &mut prepared_main_epoch,
                &mut response_storage,
                &selected_compact_contract,
                main_whir_epoch,
                SelectedWhirEpochOwner::Main,
                round_ordinal,
                completed_main_whir_phase,
            );
            println!(
                "compact public-key focused owner phase elapsed_milliseconds={} round_ordinal={round_ordinal}",
                phase_started_at.elapsed().as_millis(),
            );

            prepare_selected_whir_sumcheck_after_code_switch(
                &mut prepared_main_epoch,
                &selected_compact_contract,
                main_whir_epoch,
                SelectedWhirEpochOwner::Main,
                round_ordinal,
            );
            completed_main_whir_phase = complete_selected_whir_sumcheck_batch(
                &mut prepared_main_epoch,
                &mut response_storage,
                &selected_compact_contract,
                main_whir_epoch,
                SelectedWhirEpochOwner::Main,
                round_ordinal + 1,
                completed_main_whir_phase,
            );
        }
        assert_eq!(prepared_main_epoch.main_whir_residual_length(3), Some(8));
        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: complete main WHIR base");
        completed_main_whir_phase = complete_selected_whir_base_case(
            &mut prepared_main_epoch,
            &mut response_storage,
            &selected_compact_contract,
            main_whir_epoch,
            SelectedWhirEpochOwner::Main,
            completed_main_whir_phase,
        );
        println!(
            "compact public-key focused owner phase complete: main WHIR base elapsed_milliseconds={} next_response_ordinal={} safe_boundary_ordinal={}",
            phase_started_at.elapsed().as_millis(),
            completed_main_whir_phase.next_response_ordinal,
            completed_main_whir_phase.safe_boundary_ordinal,
        );
        let public_input_bindings = prepared_main_epoch
            .family_material()
            .public_input_bindings();
        let canonical_public_input_bytes = prepared_main_epoch
            .family_material()
            .canonical_public_input_bytes()
            .to_vec();
        let response_generation_output = prepared_main_epoch
            .finish()
            .expect("the terminal main-WHIR base emits one complete canonical proof");
        let checkpoint_directory = compact_public_key_algebraic_checkpoint_directory();
        if let Some(injected_witness_equation_fault) = injected_witness_equation_fault {
            let positive_canonical_proof_bytes =
                fs::read(checkpoint_directory.join("generated-proof.bin"))
                    .expect("the preceding positive producer persisted its compact proof");
            let positive_canonical_public_input_bytes =
                fs::read(checkpoint_directory.join("public-input.bin"))
                    .expect("the preceding positive producer persisted its public input");
            let positive_checkpoint_context =
                decode_compact_public_key_algebraic_checkpoint_context(
                    &fs::read(checkpoint_directory.join("binding-and-context.bin"))
                        .expect("the preceding positive producer persisted its binding context"),
                );
            assert_eq!(
                canonical_public_input_bytes, positive_canonical_public_input_bytes,
                "the semantic witness fault cannot alter the canonical public input",
            );
            assert_eq!(
                public_input_bindings,
                positive_checkpoint_context.public_input_bindings,
            );
            assert_eq!(
                compact_construction_identity_hash,
                positive_checkpoint_context.compact_construction_identity_hash,
            );
            assert_eq!(
                checkpoint_schedule_digest,
                positive_checkpoint_context.checkpoint_schedule_digest,
            );
            assert_eq!(
                source_replay_binding,
                positive_checkpoint_context.source_replay_binding,
            );
            assert_eq!(
                private_coin_derivation_binding_hash,
                positive_checkpoint_context.private_coin_derivation_binding_hash,
            );
            assert_ne!(
                proof_attempt_identifier, positive_checkpoint_context.proof_attempt_identifier,
                "the hostile proof must use an independently derived same-slot proof attempt",
            );
            assert_ne!(
                response_generation_output.canonical_proof_bytes(),
                positive_canonical_proof_bytes,
                "the independently derived attempt must emit distinct canonical proof bytes",
            );

            let positive_transport = verify_selected_compact_public_key_transport(
                public_input_bindings,
                positive_canonical_proof_bytes.into_boxed_slice(),
                positive_canonical_public_input_bytes
                    .clone()
                    .into_boxed_slice(),
            )
            .expect("the preceding producer proof remains transport-valid");
            let equation_invalid_transport = verify_selected_compact_public_key_transport(
                public_input_bindings,
                response_generation_output
                    .canonical_proof_bytes()
                    .to_vec()
                    .into_boxed_slice(),
                canonical_public_input_bytes.clone().into_boxed_slice(),
            )
            .expect("the equation-invalid proof remains canonically transport-valid");
            assert_ne!(
                equation_invalid_transport.canonical_proof_binding(),
                positive_transport.canonical_proof_binding(),
            );

            write_or_validate_compact_public_key_algebraic_checkpoint_file(
                &checkpoint_directory,
                "equation-invalid-proof.bin",
                response_generation_output.canonical_proof_bytes(),
            );
            write_or_validate_compact_public_key_algebraic_checkpoint_file(
                &checkpoint_directory,
                "equation-invalid-binding-and-context.bin",
                &encode_compact_public_key_algebraic_checkpoint_context(
                    public_input_bindings,
                    proof_attempt_identifier,
                    compact_construction_identity_hash,
                    checkpoint_schedule_digest,
                    source_replay_binding,
                    private_coin_derivation_binding_hash,
                ),
            );

            let algebraic_verification_started_at = Instant::now();
            let (algebraic_error, algebraic_poll_count) =
                refuse_transport_valid_equation_invalid_compact_public_key_proof(
                    equation_invalid_transport,
                );
            assert_eq!(
                algebraic_error,
                CompactPublicKeyAlgebraicVerificationError::Cfw(
                    CompactCfwError::SumcheckConsistency { round_ordinal: 0 },
                ),
                "the full verifier must localize the semantic fault at the first CFW equation",
            );
            assert_eq!(
                algebraic_error.clone().refusal_reason(),
                RefusalReason::InvalidProof,
                "the semantic equation fault must produce a typed algebraic proof refusal",
            );

            let algebraic_checkpoint_bytes =
                fs::read(checkpoint_directory.join("algebraic-verification-checkpoint.bin"))
                    .expect("the positive producer persisted its algebraic verification cursor");
            let substituted_algebraic_transport = verify_selected_compact_public_key_transport(
                public_input_bindings,
                response_generation_output
                    .canonical_proof_bytes()
                    .to_vec()
                    .into_boxed_slice(),
                canonical_public_input_bytes.clone().into_boxed_slice(),
            )
            .expect("checkpoint substitution starts from transport-valid hostile proof bytes");
            let substituted_checkpoint_error = CompactPublicKeyAlgebraicVerification::resume(
                substituted_algebraic_transport,
                &algebraic_checkpoint_bytes,
            )
            .err()
            .expect("a cursor from the positive proof cannot restore under the hostile attempt");
            assert_eq!(
                substituted_checkpoint_error,
                CompactPublicKeyAlgebraicVerificationError::WrongCheckpoint,
            );
            assert_eq!(
                substituted_checkpoint_error.clone().refusal_reason(),
                RefusalReason::WrongContext,
            );

            let accepted_checkpoint_bytes =
                fs::read(checkpoint_directory.join("accepted-verification-checkpoint.bin"))
                    .expect("the positive producer persisted its accepted/source cursor");
            let substituted_accepted_transport = verify_selected_compact_public_key_transport(
                public_input_bindings,
                response_generation_output
                    .canonical_proof_bytes()
                    .to_vec()
                    .into_boxed_slice(),
                canonical_public_input_bytes.clone().into_boxed_slice(),
            )
            .expect("accepted cursor substitution starts from transport-valid hostile proof bytes");
            assert_eq!(
                PreparedAcceptedCompactPublicKeyVerification::prepare(
                    substituted_accepted_transport,
                    Some(&accepted_checkpoint_bytes),
                )
                .err(),
                Some(RefusalReason::WrongContext),
                "an accepted/source cursor from the positive proof cannot restore under the hostile attempt",
            );

            println!(
                "transport-valid equation-invalid compact public-key proof refused elapsed_milliseconds={} algebraic_poll_count={} algebraic_error={algebraic_error:?} canonical_proof_byte_length={} shifted_eta_two_witness_element_ordinal={} original_shifted_value={} retained_first_product_witness_element_ordinal={} retained_first_product_value={} positive_attempt_checkpoint_refusal={substituted_checkpoint_error:?}",
                algebraic_verification_started_at.elapsed().as_millis(),
                algebraic_poll_count,
                response_generation_output.canonical_proof_bytes().len(),
                injected_witness_equation_fault.shifted_eta_two_witness_element_ordinal,
                injected_witness_equation_fault.original_shifted_value,
                injected_witness_equation_fault.retained_first_product_witness_element_ordinal,
                injected_witness_equation_fault.retained_first_product_value,
            );
            return;
        }
        let checkpoint_context = encode_compact_public_key_algebraic_checkpoint_context(
            public_input_bindings,
            proof_attempt_identifier,
            compact_construction_identity_hash,
            checkpoint_schedule_digest,
            source_replay_binding,
            private_coin_derivation_binding_hash,
        );
        write_or_validate_compact_public_key_algebraic_checkpoint_file(
            &checkpoint_directory,
            "generated-proof.bin",
            response_generation_output.canonical_proof_bytes(),
        );
        write_or_validate_compact_public_key_algebraic_checkpoint_file(
            &checkpoint_directory,
            "public-input.bin",
            &canonical_public_input_bytes,
        );
        write_or_validate_compact_public_key_algebraic_checkpoint_file(
            &checkpoint_directory,
            "binding-and-context.bin",
            &checkpoint_context,
        );
        write_compact_proof_evidence_producer_process_record(&checkpoint_directory);
        let transport_cdhz_measurement = measure_selected_compact_emission_cdhz(
            Some(response_generation_output.canonical_proof_bytes()),
            Some(&canonical_public_input_bytes),
            public_input_bindings,
        )
        .expect("the decoded actual-byte owner accepts and inventories the emitted transport");
        let actual_byte_census = &transport_cdhz_measurement.decoded_actual_byte_census;
        assert_eq!(transport_cdhz_measurement.rounds.len(), 82);
        assert_eq!(actual_byte_census.prover_response_count, 82);
        assert_eq!(actual_byte_census.verifier_message_count, 82);
        assert_eq!(actual_byte_census.response_opening_tuple_count, 82);
        assert_eq!(actual_byte_census.response_commitment_root_count, 82);
        assert_eq!(actual_byte_census.internal_relation_commitment_count, 45);
        assert_eq!(
            actual_byte_census.shared_hash_graph.total_hash_count,
            transport_cdhz_measurement.observed_nrdx_verifier_q_v
        );
        let emitted_size_evidence =
            derive_selected_public_key_share_emitted_size_evidence(&response_generation_output)
                .expect("the completed production generator owns a nonempty proof size");
        let compact_corpus_rollup = derive_selected_compact_corpus_rollup(&[emitted_size_evidence])
            .expect("the emitted production size feeds the selected corpus roll-up");
        let public_key_share_corpus_entry = compact_corpus_rollup
            .families
            .iter()
            .find(|family| {
                family.application_statement_schema_identifier
                    == emitted_size_evidence.application_statement_schema_identifier
            })
            .expect("the selected corpus contains the public-key-share family");
        assert_eq!(
            public_key_share_corpus_entry.candidate_canonical_proof_byte_length,
            Some(emitted_size_evidence.canonical_proof_byte_length),
        );
        assert_eq!(
            public_key_share_corpus_entry.candidate_physical_corpus_byte_length,
            emitted_size_evidence
                .canonical_proof_byte_length
                .checked_mul(u64::from(
                    public_key_share_corpus_entry.physical_proof_count,
                )),
        );
        assert_eq!(
            compact_corpus_rollup.accepted_canonical_corpus_byte_length,
            None,
        );
        let algebraic_verification_started_at = Instant::now();
        let (verified_transport, algebraic_poll_count) =
            verify_compact_public_key_bytes_algebraically(
                public_input_bindings,
                response_generation_output
                    .canonical_proof_bytes()
                    .to_vec()
                    .into_boxed_slice(),
                canonical_public_input_bytes.clone().into_boxed_slice(),
            );
        assert_eq!(
            verified_transport.proof_view().canonical_bytes(),
            response_generation_output.canonical_proof_bytes()
        );
        println!(
            "compact public-key focused owner positive algebraic verification complete elapsed_milliseconds={} cfw_poll_count={}",
            algebraic_verification_started_at.elapsed().as_millis(),
            algebraic_poll_count,
        );
        println!(
            "compact public-key focused owner complete elapsed_milliseconds={} canonical_proof_byte_length={} opened_leaf_count={} frontier_node_count={} verifier_hash_count={} response_storage_transaction_count={} response_storage_written_bytes={} response_storage_read_bytes={} response_storage_peak_bytes={}",
            execution_started_at.elapsed().as_millis(),
            response_generation_output.canonical_proof_bytes().len(),
            actual_byte_census.opened_leaf_count,
            actual_byte_census.frontier_node_count,
            actual_byte_census.shared_hash_graph.total_hash_count,
            response_generation_output
                .external_memory_usage()
                .transaction_count(),
            response_generation_output
                .external_memory_usage()
                .total_written_byte_length(),
            response_generation_output
                .external_memory_usage()
                .total_read_byte_length(),
            response_generation_output
                .external_memory_usage()
                .peak_stored_byte_length(),
        );
        drop(response_generation_output);
        let source_verified_proof = verify_checkpointed_compact_public_key_proof_algebraically(
            &checkpoint_directory,
            CompactPublicKeyCheckpointEvidenceMode::PersistThenRestore,
        );
        assert_source_verified_compact_public_key_emission_evidence(
            &source_verified_proof,
            Some(&transport_cdhz_measurement),
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_selected_compact_transport_refusal(
        category: &str,
        public_input_bindings: CompactPublicInputBindings,
        canonical_proof_bytes: Vec<u8>,
        canonical_public_input_bytes: Vec<u8>,
    ) {
        match verify_selected_compact_public_key_transport(
            public_input_bindings,
            canonical_proof_bytes.into_boxed_slice(),
            canonical_public_input_bytes.into_boxed_slice(),
        ) {
            Err(error) => println!(
                "compact public-key transported hostile input refused category={category} error={error:?}"
            ),
            Ok(_) => panic!(
                "compact public-key transported hostile input was accepted category={category}"
            ),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_selected_compact_public_key_transported_hostile_inputs_are_refused(
        public_input_bindings: CompactPublicInputBindings,
        canonical_proof_bytes: &[u8],
        canonical_public_input_bytes: &[u8],
    ) {
        let contract =
            crate::bgv::proof_suite::compact_proof_contract::selected_compact_public_key_proof_contract()
                .expect("the selected compact public-key contract decodes");
        let proof_geometry = &contract.verifier_inputs().proof_wire_geometry;
        let decoded_proof = decode_compact_proof_wire(proof_geometry, canonical_proof_bytes)
            .expect("the producer proof decodes before hostile mutations");
        let first_response = decoded_proof
            .responses()
            .first()
            .expect("the selected compact proof has a first response");
        let first_response_geometry = proof_geometry
            .responses()
            .first()
            .expect("the selected compact proof geometry has a first response");
        assert!(first_response.queried_base_field_element_count() > 0);
        assert!(first_response.queried_leaf_count() > 0);
        let variable_count_byte_length = if first_response_geometry
            .minimum_queried_base_field_element_count()
            != first_response_geometry.maximum_queried_base_field_element_count()
            || first_response_geometry.minimum_queried_extension_field_element_count()
                != first_response_geometry.maximum_queried_extension_field_element_count()
            || first_response_geometry.minimum_queried_leaf_count()
                != first_response_geometry.maximum_queried_leaf_count()
        {
            3 * size_of::<u32>()
        } else {
            0
        };
        let response_ordinal_offset = PROOF_FIXED_HEADER_BYTE_LENGTH;
        let response_root_offset = response_ordinal_offset + size_of::<u32>();
        let round_salt_offset = response_root_offset + Hash512::BYTE_LENGTH;
        let first_base_field_value_offset = round_salt_offset
            + crate::bgv::proof_suite::compact_proof_wire::COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH
            + variable_count_byte_length;
        let first_leaf_salt_offset = first_base_field_value_offset
            + first_response.queried_base_field_element_count() * size_of::<u64>()
            + first_response.queried_extension_field_element_count()
                * PROOF_CHALLENGE_EXTENSION_DEGREE
                * size_of::<u64>();
        assert_eq!(
            &canonical_proof_bytes
                [first_leaf_salt_offset..first_leaf_salt_offset + Hash512::BYTE_LENGTH * 2],
            first_response
                .leaf_salt(canonical_proof_bytes, 0)
                .expect("the first transported leaf salt is canonical")
                .as_slice()
        );

        let mut wrong_magic = canonical_proof_bytes.to_vec();
        wrong_magic[0] ^= 1;
        assert_selected_compact_transport_refusal(
            "wrong-proof-magic",
            public_input_bindings,
            wrong_magic,
            canonical_public_input_bytes.to_vec(),
        );
        assert_selected_compact_transport_refusal(
            "truncated-proof",
            public_input_bindings,
            canonical_proof_bytes[..canonical_proof_bytes.len() - 1].to_vec(),
            canonical_public_input_bytes.to_vec(),
        );
        let mut trailing_proof = canonical_proof_bytes.to_vec();
        trailing_proof.push(0);
        assert_selected_compact_transport_refusal(
            "trailing-proof",
            public_input_bindings,
            trailing_proof,
            canonical_public_input_bytes.to_vec(),
        );
        let mut reordered_response = canonical_proof_bytes.to_vec();
        reordered_response[response_ordinal_offset] ^= 1;
        assert_selected_compact_transport_refusal(
            "reordered-response",
            public_input_bindings,
            reordered_response,
            canonical_public_input_bytes.to_vec(),
        );
        let mut wrong_root = canonical_proof_bytes.to_vec();
        wrong_root[response_root_offset] ^= 1;
        assert_selected_compact_transport_refusal(
            "wrong-response-root",
            public_input_bindings,
            wrong_root,
            canonical_public_input_bytes.to_vec(),
        );
        let mut wrong_round_salt = canonical_proof_bytes.to_vec();
        wrong_round_salt[round_salt_offset] ^= 1;
        assert_selected_compact_transport_refusal(
            "wrong-transcript-round-salt",
            public_input_bindings,
            wrong_round_salt,
            canonical_public_input_bytes.to_vec(),
        );
        let mut noncanonical_proof_field = canonical_proof_bytes.to_vec();
        noncanonical_proof_field
            [first_base_field_value_offset..first_base_field_value_offset + size_of::<u64>()]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        assert_selected_compact_transport_refusal(
            "noncanonical-proof-field",
            public_input_bindings,
            noncanonical_proof_field,
            canonical_public_input_bytes.to_vec(),
        );
        let mut wrong_opening_salt = canonical_proof_bytes.to_vec();
        wrong_opening_salt[first_leaf_salt_offset] ^= 1;
        assert_selected_compact_transport_refusal(
            "wrong-opening-salt",
            public_input_bindings,
            wrong_opening_salt,
            canonical_public_input_bytes.to_vec(),
        );

        for (binding_ordinal, binding) in public_input_bindings
            .ordered_hashes()
            .into_iter()
            .enumerate()
        {
            let mut changed_hash = binding.into_bytes();
            changed_hash[0] ^= 1;
            let mut changed_bindings = public_input_bindings.ordered_hashes();
            changed_bindings[binding_ordinal] = Hash512::from_bytes(changed_hash);
            assert_selected_compact_transport_refusal(
                &format!("wrong-public-binding-{binding_ordinal}"),
                CompactPublicInputBindings::new(
                    changed_bindings[0],
                    changed_bindings[1],
                    changed_bindings[2],
                    changed_bindings[3],
                ),
                canonical_proof_bytes.to_vec(),
                canonical_public_input_bytes.to_vec(),
            );
        }

        let mut wrong_public_input_magic = canonical_public_input_bytes.to_vec();
        wrong_public_input_magic[0] ^= 1;
        assert_selected_compact_transport_refusal(
            "wrong-public-input-magic",
            public_input_bindings,
            canonical_proof_bytes.to_vec(),
            wrong_public_input_magic,
        );
        let mut noncanonical_public_input_field = canonical_public_input_bytes.to_vec();
        noncanonical_public_input_field[PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH
            ..PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH + size_of::<u64>()]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        assert_selected_compact_transport_refusal(
            "noncanonical-public-input-field",
            public_input_bindings,
            canonical_proof_bytes.to_vec(),
            noncanonical_public_input_field,
        );
        assert_selected_compact_transport_refusal(
            "truncated-public-input",
            public_input_bindings,
            canonical_proof_bytes.to_vec(),
            canonical_public_input_bytes[..canonical_public_input_bytes.len() - 1].to_vec(),
        );
        let mut trailing_public_input = canonical_public_input_bytes.to_vec();
        trailing_public_input.push(0);
        assert_selected_compact_transport_refusal(
            "trailing-public-input",
            public_input_bindings,
            canonical_proof_bytes.to_vec(),
            trailing_public_input,
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn selected_compact_public_key_statement_authority(
        canonical_proof_bytes: &[u8],
    ) -> VerifiedCompactPublicKeyStatementAuthority {
        let evidence_authority = populate_compact_public_key_development_evidence_authority(0x43)
            .expect("the deterministic public-key source authority reconstructs");
        let preparation_source =
            resolve_setup_generation_compact_public_key_development_preparation_source(
                &evidence_authority.authority,
            )
            .expect("the deterministic public-key statement source reconstructs");
        let verified_public_randomness = evidence_authority.verified_public_randomness;
        let (relation_input, relation_context) = super::super::selected_input_and_context()
            .expect("the selected public-key relation input and context derive");
        let compiled_relation = compile_public_key_share_relation_with_source_layout(
            &relation_input,
            &relation_context,
        )
        .expect("the selected public-key relation compiles independently");
        let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
            &compiled_relation.relation_plan,
            &relation_context,
            None,
            None,
        )
        .expect("the selected public-key relation capability derives independently");
        let canonical_application_statement_bytes = preparation_source
            .canonical_application_statement_bytes()
            .to_vec();
        let proof_stream_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::PublicKeyShareProof,
            canonical_proof_bytes,
        )
        .expect("the emitted compact proof has a canonical stream descriptor");
        let runtime_limits =
            selected_proof_runtime_limits(&canonical_application_statement_bytes, &relation_plan)
                .expect("the selected public-key runtime limits derive");
        let statement_source =
            VerifiedCommonProofStatementSource::from_test_verified_public_key_share_statement_source(
                &verified_public_randomness,
                canonical_application_statement_bytes.clone(),
                proof_stream_descriptor,
                relation_plan,
                runtime_limits,
            )
            .expect("the verifier-owned compact public-key statement source derives");
        let verified_context = verified_public_randomness.context();
        let decoded_statement = decode_selected_public_key_share_statement(
            &canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                verified_context.protocol_version(),
                verified_context.suite_identifier().into_bytes(),
                None,
                None,
            ),
        )
        .expect("the verifier-owned public-key statement decodes");
        let setup_polynomial_prerequisite = VerifiedSetupPolynomialLowDegreePrerequisite::for_test(
            verified_context.protocol_version(),
            verified_context.suite_identifier().into_bytes(),
            verified_context.ceremony_context_hash().into_bytes(),
            verified_context.action_context_hash().into_bytes(),
            decoded_statement.setup_proof_context_hash(),
            decoded_statement.participant_identity(),
            decoded_statement.roster_position(),
            decoded_statement.anchor_commitment_roots(),
        );
        VerifiedCompactPublicKeyStatementAuthority::from_verified_accepted_setup_sources(
            statement_source,
            &verified_public_randomness,
            setup_polynomial_prerequisite,
        )
        .expect("the accepted compact public-key statement authority derives")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_selected_accepted_compact_public_key_checkpoint_refusal(
        category: &str,
        expected_refusal: RefusalReason,
        public_input_bindings: CompactPublicInputBindings,
        canonical_proof_bytes: &[u8],
        canonical_public_input_bytes: &[u8],
        canonical_checkpoint_bytes: &[u8],
    ) {
        let transport = verify_selected_compact_public_key_transport(
            public_input_bindings,
            canonical_proof_bytes.to_vec().into_boxed_slice(),
            canonical_public_input_bytes.to_vec().into_boxed_slice(),
        )
        .expect("accepted-checkpoint hostility starts from the exact verified transport");
        match PreparedAcceptedCompactPublicKeyVerification::prepare(
            transport,
            Some(canonical_checkpoint_bytes),
        ) {
            Err(refusal) => {
                assert_eq!(refusal, expected_refusal, "hostile category={category}");
                println!(
                    "compact public-key accepted checkpoint hostile input refused category={category} refusal={refusal:?}"
                );
            }
            Ok(_) => panic!(
                "compact public-key accepted checkpoint hostile input was accepted category={category}"
            ),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_selected_accepted_compact_public_key_checkpoint_hostility(
        public_input_bindings: CompactPublicInputBindings,
        canonical_proof_bytes: &[u8],
        canonical_public_input_bytes: &[u8],
        canonical_checkpoint_bytes: &[u8],
    ) {
        assert_eq!(
            canonical_checkpoint_bytes.len(),
            ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH,
        );
        let binding_start = 8_usize;
        let canonical_proof_binding_start = binding_start + 4 * Hash512::BYTE_LENGTH;
        let canonical_public_input_binding_start =
            canonical_proof_binding_start + Hash512::BYTE_LENGTH;
        let completed_cfw_work_unit_count_start =
            canonical_public_input_binding_start + Hash512::BYTE_LENGTH;
        let completed_whir_work_unit_count_start =
            completed_cfw_work_unit_count_start + size_of::<u64>();
        let completed_correspondence_work_unit_count_start =
            completed_whir_work_unit_count_start + size_of::<u64>();
        assert_eq!(
            completed_correspondence_work_unit_count_start + size_of::<u32>(),
            canonical_checkpoint_bytes.len(),
        );

        let mut wrong_magic = canonical_checkpoint_bytes.to_vec();
        wrong_magic[0] ^= 1;
        assert_selected_accepted_compact_public_key_checkpoint_refusal(
            "wrong-checkpoint-magic",
            RefusalReason::MalformedEncoding,
            public_input_bindings,
            canonical_proof_bytes,
            canonical_public_input_bytes,
            &wrong_magic,
        );
        assert_selected_accepted_compact_public_key_checkpoint_refusal(
            "truncated-checkpoint",
            RefusalReason::MalformedEncoding,
            public_input_bindings,
            canonical_proof_bytes,
            canonical_public_input_bytes,
            &canonical_checkpoint_bytes[..canonical_checkpoint_bytes.len() - 1],
        );
        let mut trailing_checkpoint = canonical_checkpoint_bytes.to_vec();
        trailing_checkpoint.push(0);
        assert_selected_accepted_compact_public_key_checkpoint_refusal(
            "trailing-checkpoint",
            RefusalReason::MalformedEncoding,
            public_input_bindings,
            canonical_proof_bytes,
            canonical_public_input_bytes,
            &trailing_checkpoint,
        );

        for (binding_ordinal, category) in [
            "wrong-suite-identifier-binding",
            "wrong-application-statement-and-action-context-binding",
            "wrong-manifest-binding",
            "wrong-relation-profile-binding",
        ]
        .into_iter()
        .enumerate()
        {
            let mut changed_checkpoint = canonical_checkpoint_bytes.to_vec();
            changed_checkpoint[binding_start + binding_ordinal * Hash512::BYTE_LENGTH] ^= 1;
            assert_selected_accepted_compact_public_key_checkpoint_refusal(
                category,
                RefusalReason::WrongContext,
                public_input_bindings,
                canonical_proof_bytes,
                canonical_public_input_bytes,
                &changed_checkpoint,
            );
        }
        for (binding_start, category) in [
            (
                canonical_proof_binding_start,
                "wrong-attempt-bound-canonical-proof-binding",
            ),
            (
                canonical_public_input_binding_start,
                "wrong-canonical-public-input-source-binding",
            ),
        ] {
            let mut changed_checkpoint = canonical_checkpoint_bytes.to_vec();
            changed_checkpoint[binding_start] ^= 1;
            assert_selected_accepted_compact_public_key_checkpoint_refusal(
                category,
                RefusalReason::WrongContext,
                public_input_bindings,
                canonical_proof_bytes,
                canonical_public_input_bytes,
                &changed_checkpoint,
            );
        }
        for (count_start, category) in [
            (
                completed_cfw_work_unit_count_start,
                "wrong-completed-cfw-work-count",
            ),
            (
                completed_whir_work_unit_count_start,
                "wrong-completed-whir-work-count",
            ),
        ] {
            let mut changed_checkpoint = canonical_checkpoint_bytes.to_vec();
            changed_checkpoint[count_start] ^= 1;
            assert_selected_accepted_compact_public_key_checkpoint_refusal(
                category,
                RefusalReason::MalformedEncoding,
                public_input_bindings,
                canonical_proof_bytes,
                canonical_public_input_bytes,
                &changed_checkpoint,
            );
        }
        let mut excessive_correspondence = canonical_checkpoint_bytes.to_vec();
        excessive_correspondence[completed_correspondence_work_unit_count_start
            ..completed_correspondence_work_unit_count_start + size_of::<u32>()]
            .copy_from_slice(
                &(ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT + 1).to_le_bytes(),
            );
        assert_selected_accepted_compact_public_key_checkpoint_refusal(
            "excessive-source-correspondence-work-count",
            RefusalReason::MalformedEncoding,
            public_input_bindings,
            canonical_proof_bytes,
            canonical_public_input_bytes,
            &excessive_correspondence,
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn complete_selected_accepted_compact_public_key_verification(
        mut verification: AcceptedCompactPublicKeyVerification,
        resume_required: bool,
        completed_correspondence_work_unit_count: &mut u32,
        resume_complete_count: &mut u32,
    ) -> (Box<SourceVerifiedCompactPublicKeyProof>, u64) {
        let mut replayed_work_unit_count = 0_u64;
        loop {
            let maximum_work_unit_count = if resume_required && *resume_complete_count == 0 {
                65_536
            } else {
                1_024
            };
            match verification
                .advance(maximum_work_unit_count)
                .expect("the accepted compact verifier advances through exact source authority")
            {
                AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                    completed_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                } => {
                    assert!((1..=maximum_work_unit_count).contains(&completed_work_unit_count));
                    if resume_required && *resume_complete_count == 0 {
                        assert_eq!(checkpoint_safe_boundary_ordinal, None);
                        replayed_work_unit_count = replayed_work_unit_count
                            .checked_add(u64::from(completed_work_unit_count))
                            .expect("the accepted-verifier replay work count fits u64");
                        continue;
                    }
                    let previous_correspondence_work_unit_count =
                        *completed_correspondence_work_unit_count;
                    *completed_correspondence_work_unit_count =
                        (*completed_correspondence_work_unit_count)
                            .checked_add(completed_work_unit_count)
                            .expect("the selected correspondence work count fits u32");
                    assert_eq!(
                        checkpoint_safe_boundary_ordinal,
                        Some(
                            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT
                                + previous_correspondence_work_unit_count
                                + completed_work_unit_count
                                - 1,
                        ),
                    );
                }
                AcceptedCompactPublicKeyVerificationPoll::ResumeComplete {
                    completed_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                } => {
                    assert!(resume_required);
                    assert_eq!(*resume_complete_count, 0);
                    assert_eq!(completed_work_unit_count, 1);
                    assert_eq!(
                        checkpoint_safe_boundary_ordinal,
                        COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT,
                    );
                    assert_eq!(*completed_correspondence_work_unit_count, 0);
                    *completed_correspondence_work_unit_count = 1;
                    *resume_complete_count += 1;
                }
                AcceptedCompactPublicKeyVerificationPoll::Complete(proof) => {
                    assert_eq!(*resume_complete_count, u32::from(resume_required));
                    return (proof, replayed_work_unit_count);
                }
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_source_verified_compact_public_key_emission_evidence(
        source_verified_proof: &SourceVerifiedCompactPublicKeyProof,
        transport_measurement: Option<&CompactEmittedCdhzMeasurement>,
    ) {
        let source_verified_measurement =
            measure_source_verified_compact_emission_cdhz(source_verified_proof)
                .expect("the source-verified terminal owns a consistent emitted-byte census");
        let fixed_tape_correspondence = verify_source_verified_compact_fixed_tape_correspondence(
            source_verified_proof,
            &source_verified_measurement,
        )
        .expect("the complete fixed-output tape graph matches the source-verified transport");
        let domain_extension_certificate =
            derive_source_verified_compact_fixed_tape_domain_extension(
                &fixed_tape_correspondence,
                &source_verified_measurement,
            )
            .expect("the source-verified graph matches the ideal-QRO simple domain extender");
        let fixed_tape_uniformity =
            CompactFixedTapeUniformityPremise::from_source_verified_domain_extension(
                &domain_extension_certificate,
            )
            .expect("the source-verified domain extender supplies the fixed-tape premise");
        fixed_tape_uniformity
            .validate_measurement(&source_verified_measurement)
            .expect("the fixed-tape premise remains bound to the source-verified transport");
        let (domain_extension_loss_numerator, domain_extension_loss_denominator) =
            domain_extension_certificate.domain_extension_loss_parts();
        println!(
            "compact public-key fixed-tape source correspondence complete logical_round_count={} prefix_hash_count={} output_block_hash_count={} total_tape_byte_length={} maximum_output_block_count_per_round={}",
            fixed_tape_correspondence.logical_round_count,
            fixed_tape_correspondence.prefix_hash_count,
            fixed_tape_correspondence.output_block_hash_count,
            fixed_tape_correspondence.total_fixed_tape_byte_length,
            fixed_tape_correspondence.maximum_output_block_count_per_round,
        );
        println!(
            "compact public-key ideal-QRO domain extension complete theorem_hop_count={} conservative_loss_coefficient={} adversarial_query_budget={} domain_extension_loss_numerator={} domain_extension_loss_denominator={} selected_second_input_count={} minimum_selected_block_preimage_byte_length={} maximum_selected_block_preimage_byte_length={} selected_fixed_register_bit_length={} total_component_output_byte_length={} discarded_component_tail_byte_length={}",
            domain_extension_certificate.theorem_hop_count(),
            domain_extension_certificate.conservative_loss_coefficient(),
            domain_extension_certificate.adversarial_query_budget(),
            domain_extension_loss_numerator,
            domain_extension_loss_denominator,
            domain_extension_certificate.selected_second_input_count(),
            domain_extension_certificate.minimum_selected_block_preimage_byte_length(),
            domain_extension_certificate.maximum_selected_block_preimage_byte_length(),
            domain_extension_certificate.selected_fixed_register_bit_length(),
            domain_extension_certificate.total_component_output_byte_length(),
            domain_extension_certificate.discarded_component_tail_byte_length(),
        );
        if let Some(transport_measurement) = transport_measurement {
            assert_eq!(
                &source_verified_measurement, transport_measurement,
                "positive verification must retain the exact measured canonical transport",
            );
        }
        let source_verified_size_evidence =
            derive_selected_public_key_share_source_verified_size_evidence(source_verified_proof)
                .expect("the source-verified terminal owns a nonempty canonical proof size");
        assert_eq!(
            source_verified_size_evidence.canonical_proof_byte_length,
            source_verified_measurement.canonical_proof_byte_length,
        );
        let compact_corpus_rollup =
            derive_selected_compact_corpus_rollup(&[source_verified_size_evidence])
                .expect("the source-verified size feeds the selected corpus roll-up");
        let public_key_share_corpus_entry = compact_corpus_rollup
            .families
            .iter()
            .find(|family| {
                family.application_statement_schema_identifier
                    == source_verified_size_evidence.application_statement_schema_identifier
            })
            .expect("the selected corpus contains the public-key-share family");

        assert_eq!(
            compact_corpus_rollup
                .blocked_family_schema_identifiers
                .len(),
            11
        );
        assert_eq!(
            compact_corpus_rollup.accepted_canonical_corpus_byte_length,
            None
        );
        assert_eq!(
            public_key_share_corpus_entry.candidate_canonical_proof_byte_length,
            None,
        );
        assert_eq!(
            public_key_share_corpus_entry.accepted_canonical_proof_byte_length,
            Some(source_verified_size_evidence.canonical_proof_byte_length),
        );
        assert_eq!(
            public_key_share_corpus_entry.accepted_physical_corpus_byte_length,
            source_verified_size_evidence
                .canonical_proof_byte_length
                .checked_mul(u64::from(
                    public_key_share_corpus_entry.physical_proof_count,
                )),
        );
        assert_eq!(public_key_share_corpus_entry.blocker, None);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CompactPublicKeyCheckpointEvidenceMode {
        PersistThenRestore,
        RestoreFromProducerProcess,
    }

    #[test]
    #[ignore = "manual compact public-key proof-evidence separate-process restoration"]
    fn compact_public_key_proof_evidence_separate_process_restoration() {
        let checkpoint_directory = compact_public_key_algebraic_checkpoint_directory();
        assert_compact_proof_evidence_consumer_is_a_separate_process(&checkpoint_directory);
        let source_verified_proof = verify_checkpointed_compact_public_key_proof_algebraically(
            &checkpoint_directory,
            CompactPublicKeyCheckpointEvidenceMode::RestoreFromProducerProcess,
        );
        assert_source_verified_compact_public_key_emission_evidence(&source_verified_proof, None);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn verify_checkpointed_compact_public_key_proof_algebraically(
        checkpoint_directory: &Path,
        evidence_mode: CompactPublicKeyCheckpointEvidenceMode,
    ) -> Box<SourceVerifiedCompactPublicKeyProof> {
        let canonical_proof_bytes = fs::read(checkpoint_directory.join("generated-proof.bin"))
            .expect("the generated compact proof checkpoint exists");
        let canonical_public_input_bytes = fs::read(checkpoint_directory.join("public-input.bin"))
            .expect("the compact public-input checkpoint exists");
        let context_bytes = fs::read(checkpoint_directory.join("binding-and-context.bin"))
            .expect("the compact binding-and-context checkpoint exists");
        let checkpoint_context =
            decode_compact_public_key_algebraic_checkpoint_context(&context_bytes);
        let public_input_bindings = checkpoint_context.public_input_bindings;
        let verification_started_at = Instant::now();
        let initial_transport = verify_selected_compact_public_key_transport(
            public_input_bindings,
            canonical_proof_bytes.clone().into_boxed_slice(),
            canonical_public_input_bytes.clone().into_boxed_slice(),
        )
        .expect("the checkpoint source passes independent compact transport verification");
        assert_eq!(
            checkpoint_context.compact_construction_identity_hash,
            initial_transport
                .verifier_inputs()
                .canonical_source_hash()
                .expect("the selected compact construction identity derives")
                .into_bytes()
        );
        assert_eq!(
            checkpoint_context.checkpoint_schedule_digest,
            initial_transport
                .verifier_inputs()
                .checkpoint_schedule
                .checkpoint_schedule_digest()
        );
        assert_ne!(checkpoint_context.proof_attempt_identifier, [0_u8; 32]);
        assert_ne!(
            checkpoint_context.source_replay_binding,
            [0_u8; Hash512::BYTE_LENGTH]
        );
        assert_ne!(
            checkpoint_context
                .private_coin_derivation_binding_hash
                .into_bytes(),
            [0_u8; Hash512::BYTE_LENGTH]
        );
        let expected_whir_work_unit_count =
            compact_public_key_whir_fold_work_unit_count(initial_transport.verifier_inputs())
                .expect("the selected WHIR fold work derives from the verified contract");
        let canonical_verification_checkpoint = match evidence_mode {
            CompactPublicKeyCheckpointEvidenceMode::PersistThenRestore => {
                let mut initial_verification =
                    CompactPublicKeyAlgebraicVerification::begin(initial_transport)
                        .expect("the compact algebraic verifier accepts the checkpoint source");
                let first_completed_work_unit_count = match initial_verification
                    .advance(65_536)
                    .expect("the initial compact algebraic verifier slice succeeds")
                {
                    CompactPublicKeyAlgebraicVerificationPoll::WorkCompleted {
                        completed_work_unit_count,
                        checkpoint_safe_boundary_ordinal,
                    } => {
                        assert_eq!(checkpoint_safe_boundary_ordinal, Some(0));
                        completed_work_unit_count
                    }
                    CompactPublicKeyAlgebraicVerificationPoll::ResumeComplete { .. } => {
                        panic!("a fresh verifier cannot complete checkpoint replay")
                    }
                    CompactPublicKeyAlgebraicVerificationPoll::WhirResumeComplete { .. } => {
                        panic!("a fresh verifier cannot complete WHIR checkpoint replay")
                    }
                    CompactPublicKeyAlgebraicVerificationPoll::WhirWorkCompleted { .. } => {
                        panic!("one bounded slice cannot reach terminal WHIR work")
                    }
                    CompactPublicKeyAlgebraicVerificationPoll::WhirCompleted { .. } => {
                        panic!("one bounded slice cannot reach terminal WHIR verification")
                    }
                    CompactPublicKeyAlgebraicVerificationPoll::Complete(_) => {
                        panic!("one bounded slice cannot complete the selected verifier")
                    }
                };
                assert!(first_completed_work_unit_count > 0);
                let checkpoint = initial_verification
                    .canonical_checkpoint_bytes()
                    .expect("the first safe verifier boundary has a canonical checkpoint");
                write_or_validate_compact_public_key_algebraic_checkpoint_file(
                    checkpoint_directory,
                    "algebraic-verification-checkpoint.bin",
                    &checkpoint,
                );
                checkpoint
            }
            CompactPublicKeyCheckpointEvidenceMode::RestoreFromProducerProcess => {
                assert_selected_compact_public_key_transported_hostile_inputs_are_refused(
                    public_input_bindings,
                    &canonical_proof_bytes,
                    &canonical_public_input_bytes,
                );
                let checkpoint_bytes =
                    fs::read(checkpoint_directory.join("algebraic-verification-checkpoint.bin"))
                        .expect(
                            "the producer process persisted its algebraic verification checkpoint",
                        );
                for changed_byte_offset in [
                    0,
                    8,
                    8 + 4 * Hash512::BYTE_LENGTH,
                    checkpoint_bytes.len() - 1,
                ] {
                    let mut changed_checkpoint_bytes = checkpoint_bytes.clone();
                    changed_checkpoint_bytes[changed_byte_offset] ^= 1;
                    let changed_checkpoint_transport =
                        verify_selected_compact_public_key_transport(
                            public_input_bindings,
                            canonical_proof_bytes.clone().into_boxed_slice(),
                            canonical_public_input_bytes.clone().into_boxed_slice(),
                        )
                        .expect("checkpoint hostility starts from the exact verified transport");
                    assert!(
                        CompactPublicKeyAlgebraicVerification::resume(
                            changed_checkpoint_transport,
                            &changed_checkpoint_bytes,
                        )
                        .is_err(),
                        "changed checkpoint byte offset {changed_byte_offset} must fail closed"
                    );
                }
                checkpoint_bytes.try_into().expect(
                    "the persisted algebraic verification checkpoint has its canonical size",
                )
            }
        };
        if evidence_mode == CompactPublicKeyCheckpointEvidenceMode::RestoreFromProducerProcess {
            let resumed_transport = verify_selected_compact_public_key_transport(
                public_input_bindings,
                canonical_proof_bytes.clone().into_boxed_slice(),
                canonical_public_input_bytes.clone().into_boxed_slice(),
            )
            .expect("cold restoration revalidates the exact compact transport");
            let mut resumed_verification = CompactPublicKeyAlgebraicVerification::resume(
                resumed_transport,
                &canonical_verification_checkpoint,
            )
            .expect("the separate process starts deterministic algebraic replay");
            let mut algebraic_resume_complete = false;
            loop {
                match resumed_verification
                    .advance(65_536)
                    .expect("the separate process replays and continues the algebraic cursor")
                {
                    CompactPublicKeyAlgebraicVerificationPoll::ResumeComplete {
                        completed_work_unit_count,
                        checkpoint_safe_boundary_ordinal,
                    } => {
                        assert_eq!(completed_work_unit_count, 65_536);
                        assert_eq!(checkpoint_safe_boundary_ordinal, 0);
                        assert_eq!(
                            resumed_verification
                                .canonical_checkpoint_bytes()
                                .expect("replayed algebraic state reproduces its safe cursor"),
                            canonical_verification_checkpoint,
                        );
                        algebraic_resume_complete = true;
                    }
                    CompactPublicKeyAlgebraicVerificationPoll::WorkCompleted {
                        completed_work_unit_count,
                        checkpoint_safe_boundary_ordinal,
                    } if algebraic_resume_complete => {
                        assert_eq!(completed_work_unit_count, 65_536);
                        assert_eq!(checkpoint_safe_boundary_ordinal, Some(1));
                        break;
                    }
                    CompactPublicKeyAlgebraicVerificationPoll::WorkCompleted {
                        checkpoint_safe_boundary_ordinal,
                        ..
                    } => assert_eq!(checkpoint_safe_boundary_ordinal, None),
                    _ => panic!(
                        "the first algebraic cursor must restore and continue before WHIR or terminal verification"
                    ),
                }
            }
            assert!(algebraic_resume_complete);
            drop(resumed_verification);

            let accepted_checkpoint_bytes =
                fs::read(checkpoint_directory.join("accepted-verification-checkpoint.bin"))
                    .expect("the producer process persisted its accepted/source checkpoint");
            assert_selected_accepted_compact_public_key_checkpoint_hostility(
                public_input_bindings,
                &canonical_proof_bytes,
                &canonical_public_input_bytes,
                &accepted_checkpoint_bytes,
            );
            let accepted_checkpoint: [u8;
                ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH] =
                accepted_checkpoint_bytes
                    .try_into()
                    .expect("the persisted accepted/source checkpoint has its canonical size");
            let accepted_transport = verify_selected_compact_public_key_transport(
                public_input_bindings,
                canonical_proof_bytes.clone().into_boxed_slice(),
                canonical_public_input_bytes.clone().into_boxed_slice(),
            )
            .expect("accepted/source restoration revalidates the exact compact transport");
            let prepared_accepted_verification =
                PreparedAcceptedCompactPublicKeyVerification::prepare(
                    accepted_transport,
                    Some(&accepted_checkpoint),
                )
                .expect("the accepted/source cursor binds the exact proof and public input");
            let statement_authority =
                selected_compact_public_key_statement_authority(&canonical_proof_bytes);
            let accepted_verification = AcceptedCompactPublicKeyVerification::from_prepared(
                statement_authority,
                prepared_accepted_verification,
            );
            let mut correspondence_work_unit_count = 0_u32;
            let mut accepted_resume_complete_count = 0_u32;
            let (source_verified_proof, replayed_work_unit_count) =
                complete_selected_accepted_compact_public_key_verification(
                    accepted_verification,
                    true,
                    &mut correspondence_work_unit_count,
                    &mut accepted_resume_complete_count,
                );
            assert_eq!(accepted_resume_complete_count, 1);
            assert!(replayed_work_unit_count > 0);
            assert_eq!(
                correspondence_work_unit_count,
                ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT,
            );
            let correspondence = source_verified_proof.correspondence();
            assert_eq!(correspondence.public_ring_vector_count(), 61);
            assert_eq!(correspondence.verified_column_count(), 122);
            assert!(correspondence.verifier_sequence_column_count() > 0);
            assert_eq!(correspondence.statement_tree_count(), 4);
            println!(
                "checkpointed compact public-key accepted/source restoration complete elapsed_milliseconds={} algebraic_checkpoint_byte_length={} accepted_checkpoint_byte_length={} accepted_replayed_work_unit_count={} correspondence_work_unit_count={} accepted_resume_complete_count={} canonical_proof_byte_length={} source_verified_column_count={} source_statement_tree_count={}",
                verification_started_at.elapsed().as_millis(),
                canonical_verification_checkpoint.len(),
                accepted_checkpoint.len(),
                replayed_work_unit_count,
                correspondence_work_unit_count,
                accepted_resume_complete_count,
                canonical_proof_bytes.len(),
                correspondence.verified_column_count(),
                correspondence.statement_tree_count(),
            );
            return source_verified_proof;
        }
        let resumed_transport = verify_selected_compact_public_key_transport(
            public_input_bindings,
            canonical_proof_bytes.clone().into_boxed_slice(),
            canonical_public_input_bytes.clone().into_boxed_slice(),
        )
        .expect("cold restoration revalidates the exact compact transport");
        let mut resumed_verification = CompactPublicKeyAlgebraicVerification::resume(
            resumed_transport,
            &canonical_verification_checkpoint,
        )
        .expect("the source-bound safe cursor starts deterministic replay");
        let mut cfw_verification_poll_count = 0_u64;
        let mut completed_work_unit_count = 0_u64;
        let mut next_safe_boundary_ordinal = 1_u32;
        let mut observed_safe_boundary_count = 1_u32;
        let mut resume_complete_count = 0_u64;
        let mut terminal_cfw_segment_poll_count = 0_u64;
        let mut whir_verification_poll_count = 0_u64;
        let mut completed_whir_work_unit_count = 0_u64;
        let mut whir_checkpoint_restart_count = 0_u64;
        let mut whir_resume_complete_count = 0_u64;
        let mut whir_replay_in_progress = false;
        let mut replayed_cfw_work_unit_count = 0_u64;
        let mut replayed_whir_work_unit_count = 0_u64;
        let mut canonical_whir_checkpoint = None;
        let mut whir_checkpoint_safe_boundary_ordinal = None;
        let algebraically_verified_proof = loop {
            match resumed_verification
                .advance(65_536)
                .expect("bounded replay and continued algebraic verification succeed")
            {
                CompactPublicKeyAlgebraicVerificationPoll::WorkCompleted {
                    completed_work_unit_count: slice_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                } => {
                    assert!(slice_work_unit_count > 0);
                    if whir_replay_in_progress {
                        assert_eq!(checkpoint_safe_boundary_ordinal, None);
                        replayed_cfw_work_unit_count = replayed_cfw_work_unit_count
                            .checked_add(slice_work_unit_count)
                            .expect("the selected CFW replay work count fits u64");
                        continue;
                    }
                    if let Some(safe_boundary_ordinal) = checkpoint_safe_boundary_ordinal {
                        assert_eq!(safe_boundary_ordinal, next_safe_boundary_ordinal);
                        next_safe_boundary_ordinal += 1;
                        observed_safe_boundary_count += 1;
                    } else {
                        terminal_cfw_segment_poll_count += 1;
                        assert_eq!(
                            slice_work_unit_count,
                            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT
                                % COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL,
                        );
                    }
                    completed_work_unit_count = completed_work_unit_count
                        .checked_add(slice_work_unit_count)
                        .expect("the selected verifier work count fits u64");
                    cfw_verification_poll_count += 1;
                }
                CompactPublicKeyAlgebraicVerificationPoll::ResumeComplete {
                    completed_work_unit_count: replayed_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                } => {
                    assert!(replayed_work_unit_count > 0);
                    assert_eq!(checkpoint_safe_boundary_ordinal, 0);
                    completed_work_unit_count = completed_work_unit_count
                        .checked_add(replayed_work_unit_count)
                        .expect("the selected verifier work count fits u64");
                    resume_complete_count += 1;
                    assert_eq!(
                        resumed_verification
                            .canonical_checkpoint_bytes()
                            .expect("replayed state reproduces its safe cursor"),
                        canonical_verification_checkpoint,
                    );
                }
                CompactPublicKeyAlgebraicVerificationPoll::WhirWorkCompleted {
                    completed_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                } => {
                    assert!((1..=65_536).contains(&completed_work_unit_count));
                    if whir_replay_in_progress {
                        assert_eq!(checkpoint_safe_boundary_ordinal, None);
                        replayed_whir_work_unit_count = replayed_whir_work_unit_count
                            .checked_add(completed_work_unit_count)
                            .expect("the selected WHIR replay work count fits u64");
                        continue;
                    }
                    if let Some(safe_boundary_ordinal) = checkpoint_safe_boundary_ordinal {
                        assert_eq!(safe_boundary_ordinal, next_safe_boundary_ordinal);
                        next_safe_boundary_ordinal += 1;
                        observed_safe_boundary_count += 1;
                    }
                    completed_whir_work_unit_count = completed_whir_work_unit_count
                        .checked_add(completed_work_unit_count)
                        .expect("the selected WHIR work count fits u64");
                    whir_verification_poll_count += 1;
                    if checkpoint_safe_boundary_ordinal.is_some()
                        && whir_checkpoint_restart_count == 0
                    {
                        let checkpoint = resumed_verification
                            .canonical_checkpoint_bytes()
                            .expect("the first WHIR fold boundary has a canonical checkpoint");
                        let restored_transport = verify_selected_compact_public_key_transport(
                            public_input_bindings,
                            canonical_proof_bytes.clone().into_boxed_slice(),
                            canonical_public_input_bytes.clone().into_boxed_slice(),
                        )
                        .expect("WHIR cold restoration revalidates the exact compact transport");
                        resumed_verification = CompactPublicKeyAlgebraicVerification::resume(
                            restored_transport,
                            &checkpoint,
                        )
                        .expect("the WHIR safe cursor starts deterministic genesis replay");
                        canonical_whir_checkpoint = Some(checkpoint);
                        whir_checkpoint_safe_boundary_ordinal = checkpoint_safe_boundary_ordinal;
                        whir_checkpoint_restart_count += 1;
                        whir_replay_in_progress = true;
                    }
                }
                CompactPublicKeyAlgebraicVerificationPoll::WhirCompleted {
                    completed_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                } => {
                    assert!((1..=65_536).contains(&completed_work_unit_count));
                    assert_eq!(checkpoint_safe_boundary_ordinal, next_safe_boundary_ordinal);
                    next_safe_boundary_ordinal += 1;
                    observed_safe_boundary_count += 1;
                    completed_whir_work_unit_count = completed_whir_work_unit_count
                        .checked_add(completed_work_unit_count)
                        .expect("the selected WHIR work count fits u64");
                    whir_verification_poll_count += 1;
                }
                CompactPublicKeyAlgebraicVerificationPoll::WhirResumeComplete {
                    completed_work_unit_count,
                    checkpoint_safe_boundary_ordinal,
                } => {
                    assert!(whir_replay_in_progress);
                    replayed_whir_work_unit_count = replayed_whir_work_unit_count
                        .checked_add(completed_work_unit_count)
                        .expect("the selected WHIR replay work count fits u64");
                    assert_eq!(
                        Some(checkpoint_safe_boundary_ordinal),
                        whir_checkpoint_safe_boundary_ordinal
                    );
                    assert_eq!(
                        resumed_verification
                            .canonical_checkpoint_bytes()
                            .expect("replayed WHIR state reproduces its safe cursor"),
                        canonical_whir_checkpoint
                            .expect("the first WHIR checkpoint was retained for comparison"),
                    );
                    whir_replay_in_progress = false;
                    whir_resume_complete_count += 1;
                }
                CompactPublicKeyAlgebraicVerificationPoll::Complete(terminal) => {
                    break *terminal;
                }
            }
        };
        assert_eq!(resume_complete_count, 1);
        assert_eq!(whir_checkpoint_restart_count, 1);
        assert_eq!(whir_resume_complete_count, 1);
        assert!(!whir_replay_in_progress);
        assert_eq!(
            replayed_cfw_work_unit_count,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
        );
        assert_eq!(
            replayed_whir_work_unit_count,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CHECKPOINT_WORK_UNIT_INTERVAL,
        );
        assert_eq!(terminal_cfw_segment_poll_count, 1);
        assert!(whir_verification_poll_count > 1);
        assert_eq!(
            completed_whir_work_unit_count,
            expected_whir_work_unit_count,
        );
        assert_eq!(
            observed_safe_boundary_count,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT,
        );
        assert_eq!(
            next_safe_boundary_ordinal,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT,
        );
        assert_eq!(
            completed_work_unit_count,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
        );
        assert_eq!(
            cfw_verification_poll_count,
            u64::from(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_SAFE_BOUNDARY_COUNT),
        );
        assert_eq!(
            algebraically_verified_proof
                .transport()
                .proof_view()
                .canonical_bytes(),
            canonical_proof_bytes
        );
        let statement_authority =
            selected_compact_public_key_statement_authority(&canonical_proof_bytes);
        let mut accepted_verification =
            AcceptedCompactPublicKeyVerification::from_algebraically_verified(
                statement_authority,
                algebraically_verified_proof,
            )
            .expect("the positive algebraic terminal enters accepted source correspondence");
        let mut correspondence_work_unit_count = match accepted_verification
            .advance(1)
            .expect("the first accepted source-correspondence boundary verifies")
        {
            AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                completed_work_unit_count,
                checkpoint_safe_boundary_ordinal,
            } => {
                assert_eq!(completed_work_unit_count, 1);
                assert_eq!(
                    checkpoint_safe_boundary_ordinal,
                    Some(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT),
                );
                completed_work_unit_count
            }
            _ => panic!("the first accepted source boundary cannot complete the verifier"),
        };
        let accepted_checkpoint = accepted_verification
            .canonical_checkpoint_bytes()
            .expect("the first accepted source boundary has a canonical checkpoint");
        assert_eq!(
            accepted_checkpoint.len(),
            ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH,
        );
        write_or_validate_compact_public_key_algebraic_checkpoint_file(
            checkpoint_directory,
            "accepted-verification-checkpoint.bin",
            &accepted_checkpoint,
        );
        let mut accepted_resume_complete_count = 0_u32;
        let (source_verified_proof, accepted_replayed_work_unit_count) =
            complete_selected_accepted_compact_public_key_verification(
                accepted_verification,
                false,
                &mut correspondence_work_unit_count,
                &mut accepted_resume_complete_count,
            );
        assert_eq!(accepted_resume_complete_count, 0);
        assert_eq!(accepted_replayed_work_unit_count, 0);
        assert_eq!(
            correspondence_work_unit_count,
            ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT,
        );
        let correspondence = source_verified_proof.correspondence();
        assert_eq!(correspondence.public_ring_vector_count(), 61);
        assert_eq!(correspondence.verified_column_count(), 122);
        assert!(correspondence.verifier_sequence_column_count() > 0);
        assert_eq!(correspondence.statement_tree_count(), 4);
        println!(
            "checkpointed compact public-key algebraic and accepted statement verification complete elapsed_milliseconds={} post_resume_work_poll_count={} observed_safe_boundary_count={} terminal_cfw_segment_poll_count={} whir_verification_poll_count={} completed_work_unit_count={} whir_work_unit_count={} correspondence_work_unit_count={} algebraic_resume_complete_count={} accepted_checkpoint_byte_length={} canonical_proof_byte_length={} source_verified_column_count={} source_statement_tree_count={}",
            verification_started_at.elapsed().as_millis(),
            cfw_verification_poll_count,
            observed_safe_boundary_count,
            terminal_cfw_segment_poll_count,
            whir_verification_poll_count,
            completed_work_unit_count,
            completed_whir_work_unit_count,
            correspondence_work_unit_count,
            resume_complete_count,
            accepted_checkpoint.len(),
            canonical_proof_bytes.len(),
            correspondence.verified_column_count(),
            correspondence.statement_tree_count(),
        );
        source_verified_proof
    }

    #[test]
    fn compact_structured_row_source_uses_exact_bounded_transform_products() {
        let relation = Rc::new(
            super::super::selected_compact_public_key_relation_catalog()
                .expect("selected compact public-key relation"),
        );
        let matrices = CompactStructuredR1csCatalog::derive(&relation)
            .expect("complete structured R1CS matrices");
        let assignment = Rc::new(DeterministicR1csAssignment::new(&relation, &matrices));
        let mut preparation = CompactStructuredR1csRowSourcePreparation::new(
            Rc::clone(&relation),
            Rc::clone(&assignment),
        )
        .expect("bounded structured row-source preparation");
        let mut preparation_step_counts = BTreeMap::new();
        let mut preparation_work_unit_counts = BTreeMap::new();
        let mut row_source = loop {
            match preparation
                .advance(8_192)
                .expect("bounded structured row-source preparation step")
            {
                CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
                    step,
                    completed_work_unit_count,
                } => {
                    *preparation_step_counts.entry(step).or_insert(0_u64) += 1;
                    *preparation_work_unit_counts.entry(step).or_insert(0_u64) +=
                        completed_work_unit_count;
                }
                CompactStructuredR1csRowSourcePreparationPoll::Complete(row_source) => {
                    break *row_source;
                }
            }
        };
        drop(preparation);
        assert_eq!(Rc::strong_count(&relation), 2);
        assert_eq!(Rc::strong_count(&assignment), 2);
        let geometry = row_source.geometry();

        assert_eq!(preparation_step_counts.values().sum::<u64>(), 760);
        assert_eq!(
            preparation_step_counts,
            BTreeMap::from([
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupInverseSum,
                    116,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupTablePrefixProduct,
                    16,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupTableProductInversion,
                    1,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupTableReversePass,
                    16,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PrivatePolynomialFill,
                    28,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PrivatePolynomialForwardTransform,
                    7,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PublicPolynomialFill,
                    128,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PublicPolynomialForwardTransform,
                    32,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PointwiseProduct,
                    256,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::ProductPolynomialInverseTransform,
                    32,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::NegacyclicProductFold,
                    128,
                ),
            ])
        );
        assert_eq!(
            preparation_work_unit_counts,
            BTreeMap::from([
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupInverseSum,
                    950_272,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupTablePrefixProduct,
                    131_072,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupTableProductInversion,
                    1,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::LookupTableReversePass,
                    131_072,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PrivatePolynomialFill,
                    229_376,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PrivatePolynomialForwardTransform,
                    3_670_016,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PublicPolynomialFill,
                    1_048_576,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PublicPolynomialForwardTransform,
                    16_777_216,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::PointwiseProduct,
                    2_097_152,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::ProductPolynomialInverseTransform,
                    16_777_216,
                ),
                (
                    CompactStructuredR1csRowSourcePreparationStep::NegacyclicProductFold,
                    1_048_576,
                ),
            ])
        );

        assert_eq!(geometry.ring_degree(), 32_768);
        assert_eq!(geometry.negacyclic_product_count(), 32);
        assert_eq!(geometry.distinct_centered_private_vector_count(), 7);
        assert_eq!(geometry.transform_domain_size(), 65_536);
        assert_eq!(geometry.forward_transform_count(), 39);
        assert_eq!(geometry.inverse_transform_count(), 32);
        assert_eq!(geometry.transform_butterfly_count(), 37_224_448);
        assert_eq!(geometry.pointwise_multiplication_count(), 2_097_152);
        assert_eq!(geometry.negacyclic_fold_subtraction_count(), 1_048_576);
        assert_eq!(geometry.lookup_inverse_element_count(), 950_272);
        assert_eq!(geometry.lookup_table_value_count(), 131_072);
        assert_eq!(
            geometry.lookup_table_batch_extension_multiplication_count(),
            524_288
        );
        assert_eq!(row_source.witness_length(), 4_194_304);
        assert_eq!(row_source.row_count(), 8_388_608);

        let coefficient_ordinals = [0, 1, relation.ring_degree / 2 - 1, relation.ring_degree - 1];
        for relation_ordinal in 0..relation.ordered_relations.len() {
            for coefficient_ordinal in coefficient_ordinals {
                let row_ordinal = u64::try_from(relation_ordinal)
                    .expect("relation ordinal")
                    .checked_mul(relation.ring_degree)
                    .and_then(|ordinal| ordinal.checked_add(coefficient_ordinal))
                    .expect("exact row ordinal");
                let prepared = row_source
                    .evaluate_row(row_ordinal)
                    .expect("prepared exact row");
                let independent = evaluate_matrix_row(
                    &matrices.row(&relation, row_ordinal).expect("matrix row"),
                    &assignment,
                )
                .expect("independently expanded exact row");
                assert_eq!(prepared.left, independent.left);
                assert_eq!(prepared.right, independent.right);
                assert_eq!(prepared.output, independent.output);
            }
        }

        let lookup_log_derivative_row_ordinal = relation
            .ordered_constraint_segments
            .iter()
            .find(|segment| segment.kind == CompactR1csConstraintKind::LookupLogDerivativeEquality)
            .expect("lookup log-derivative segment")
            .first_row;
        let prepared_lookup_log_derivative = row_source
            .evaluate_row(lookup_log_derivative_row_ordinal)
            .expect("prepared lookup log-derivative row");
        let independent_lookup_log_derivative = evaluate_matrix_row(
            &matrices
                .row(&relation, lookup_log_derivative_row_ordinal)
                .expect("lookup log-derivative matrix row"),
            &assignment,
        )
        .expect("independently expanded lookup log-derivative row");
        assert_eq!(
            prepared_lookup_log_derivative.left,
            independent_lookup_log_derivative.left
        );
        assert_eq!(
            prepared_lookup_log_derivative.right,
            independent_lookup_log_derivative.right
        );
        assert_eq!(
            prepared_lookup_log_derivative.output,
            independent_lookup_log_derivative.output
        );

        for padding_row_ordinal in [
            relation.operative_constraint_count,
            relation.padded_constraint_count - 1,
        ] {
            assert_eq!(
                row_source
                    .evaluate_row(padding_row_ordinal)
                    .expect("prepared padding row"),
                CompactStructuredR1csRowEvaluation {
                    left: ProofChallengeExtensionElement::ZERO,
                    right: ProofChallengeExtensionElement::ZERO,
                    output: ProofChallengeExtensionElement::ZERO,
                }
            );
        }
        assert_eq!(
            row_source.evaluate_row(row_source.row_count()),
            Err(CommonProofProverError::Relation(
                RelationPlanError::InvalidConstraint
            ))
        );

        let compact_geometry = CompactCfwGeometry::derive(
            CompactCfwExternalRowSource::witness_length(&row_source)
                .expect("the production row source witness length fits CFW"),
        )
        .expect("the production row source has compact CFW geometry");
        let mut compact_mask_seed = 100_u64;
        let compact_mask_material = CompactCfwMaskMaterial::sample(compact_geometry, || {
            compact_mask_seed += 1;
            compact_challenge_from_production(
                ProofChallengeExtensionElement::from_canonical_coordinates([
                    compact_mask_seed,
                    compact_mask_seed + 1,
                    compact_mask_seed + 2,
                    compact_mask_seed + 3,
                    compact_mask_seed + 4,
                ])
                .expect("the compact mask seed is canonical"),
            )
        })
        .expect("the production row source compact masks derive");
        let equality_point = (0..compact_geometry.sumcheck_round_count())
            .map(|ordinal| {
                compact_challenge_from_production(
                    ProofChallengeExtensionElement::from_canonical_coordinates([
                        1_000 + ordinal as u64,
                        2_000 + ordinal as u64,
                        3_000 + ordinal as u64,
                        4_000 + ordinal as u64,
                        5_000 + ordinal as u64,
                    ])
                    .expect("the compact equality coordinate is canonical"),
                )
            })
            .collect::<Vec<_>>();
        {
            let counting_row_source = CountingCompactCfwExternalRowSource {
                source: &row_source,
                evaluated_row_count: Cell::new(0),
            };
            let mut external_prover = CompactCfwExternalProverState::prepare(
                &counting_row_source,
                compact_mask_material,
                compact_challenge_from_production(
                    ProofChallengeExtensionElement::from_canonical_coordinates([7, 11, 13, 17, 19])
                        .expect("the compact constraint challenge is canonical"),
                ),
                equality_point,
            )
            .expect("the production row source connects to the external CFW prover");
            let mut storage = TestStorage::default();
            assert_eq!(
                external_prover
                    .advance_round_polynomial(&counting_row_source, &mut storage)
                    .expect("one bounded production row-source poll advances"),
                None
            );
            assert_eq!(counting_row_source.evaluated_row_count.get(), 16_384);
            assert_eq!(
                counting_row_source.evaluated_row_count.get() * COMPACT_CFW_MATRIX_COUNT,
                49_152
            );
        }

        let first_product_address = matrices
            .ordered_negacyclic_product_addresses(&relation)
            .expect("ordered product addresses")[0];
        let first_cached_product_value = row_source
            .negacyclic_product_mut(&first_product_address)
            .expect("first cached product")
            .get_mut(0)
            .expect("first cached product coefficient");
        *first_cached_product_value = first_cached_product_value.add(ProofBaseFieldElement::ONE);
        let mutated = row_source
            .evaluate_row(0)
            .expect("row remains structurally evaluable after cache mutation");
        let independent = evaluate_matrix_row(
            &matrices.row(&relation, 0).expect("first matrix row"),
            &assignment,
        )
        .expect("independent first row");
        assert_ne!(mutated.left, independent.left);
    }
}
