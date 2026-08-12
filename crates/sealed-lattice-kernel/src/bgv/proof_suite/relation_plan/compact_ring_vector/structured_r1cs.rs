//! Row-addressable structured R1CS matrices for the compact ring-vector relation.
//!
//! The matrices are never materialized densely. Each row instead owns an
//! exact sparse or structured description of its `A`, `B`, and `C` linear
//! forms. Public negacyclic products are matrix bands derived by the verifier
//! from the canonical public input; they are not prover-supplied witness
//! products. The focused semantic test below evaluates every operative row
//! through both the matrix description and an independent relation
//! interpreter.

#[cfg(test)]
mod witness_covector;

#[cfg(test)]
#[path = "production_small_chain.rs"]
mod production_small_chain;

#[cfg(test)]
pub(crate) use witness_covector::compact_structured_witness_covector_geometry;

#[cfg(test)]
use witness_covector::{
    CompactStructuredWitnessCovectorHandoff, CompactStructuredWitnessCovectorHandoffPoll,
};

#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use p3_field::PrimeCharacteristicRing;
#[cfg(test)]
use zeroize::Zeroizing;

#[cfg(test)]
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
#[cfg(test)]
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

#[cfg(test)]
type PreparedCompactNegacyclicProduct = (
    CompactNegacyclicProductAddress,
    Zeroizing<Vec<ProofBaseFieldElement>>,
);

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CompactCenteredPrivateVectorAddress {
    private_vector_first_column_ordinal: u64,
    centered_offset: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CompactStructuredR1csRowEvaluation {
    pub(super) left: ProofChallengeExtensionElement,
    pub(super) right: ProofChallengeExtensionElement,
    pub(super) output: ProofChallengeExtensionElement,
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactLookupLogDerivativeEvaluationCache {
    inverse_first_column_ordinal: u64,
    inverse_element_count: u64,
    inverse_sum: ProofChallengeExtensionElement,
    multiplicity_first_column_ordinal: u64,
    table_value_count: u64,
    negated_weighted_table_reciprocal_sum: ProofChallengeExtensionElement,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CompactStructuredR1csRowSourcePreparationStep {
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

#[cfg(test)]
pub(super) enum CompactStructuredR1csRowSourcePreparationPoll<
    'source,
    Assignment: CompactStructuredAssignmentSource + ?Sized,
> {
    StepCompleted {
        step: CompactStructuredR1csRowSourcePreparationStep,
        completed_work_unit_count: u64,
    },
    Complete(Box<CompactStructuredR1csRowSource<'source, Assignment>>),
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactNegacyclicProductPreparationGroup {
    private_address: CompactCenteredPrivateVectorAddress,
    ordered_product_addresses: Vec<CompactNegacyclicProductAddress>,
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactStructuredR1csRowSourcePreparationPhase {
    LookupLogDerivative,
    NegacyclicProducts,
    Complete,
}

#[cfg(test)]
pub(super) struct CompactStructuredR1csRowSourcePreparation<
    'source,
    Assignment: CompactStructuredAssignmentSource + ?Sized,
> {
    relation: &'source CompactPublicKeyRelationCatalog,
    matrices: CompactStructuredR1csCatalog,
    assignment: &'source Assignment,
    ordered_product_addresses: Vec<CompactNegacyclicProductAddress>,
    geometry: CompactStructuredR1csRowSourceGeometry,
    lookup_preparation: Option<CompactLookupLogDerivativeEvaluationCachePreparation>,
    lookup_log_derivative_cache: Option<CompactLookupLogDerivativeEvaluationCache>,
    product_preparation: Option<CompactNegacyclicProductPreparation>,
    negacyclic_products: Option<Vec<PreparedCompactNegacyclicProduct>>,
    phase: CompactStructuredR1csRowSourcePreparationPhase,
}

#[cfg(test)]
impl<'source, Assignment: CompactStructuredAssignmentSource + ?Sized>
    CompactStructuredR1csRowSourcePreparation<'source, Assignment>
{
    pub(super) fn new(
        relation: &'source CompactPublicKeyRelationCatalog,
        assignment: &'source Assignment,
    ) -> Result<Self, CommonProofProverError> {
        let matrices = CompactStructuredR1csCatalog::derive(relation)?;
        if assignment.padded_public_input_element_count() != matrices.public_input_length
            || assignment.padded_witness_element_count() != matrices.witness_length
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let ordered_product_addresses = matrices.ordered_negacyclic_product_addresses(relation)?;
        let geometry =
            CompactStructuredR1csRowSourceGeometry::derive(relation, &ordered_product_addresses)?;
        let lookup_preparation = Some(CompactLookupLogDerivativeEvaluationCachePreparation::new(
            relation, &matrices, assignment,
        )?);
        let product_preparation = Some(CompactNegacyclicProductPreparation::new(
            relation,
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
    ) -> Result<
        CompactStructuredR1csRowSourcePreparationPoll<'source, Assignment>,
        CommonProofProverError,
    > {
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
                        lookup_preparation.advance(self.assignment, maximum_element_count)?;
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
                        self.relation,
                        &self.matrices,
                        self.assignment,
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
                            relation: self.relation,
                            matrices: self.matrices.clone(),
                            assignment: self.assignment,
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

#[cfg(test)]
pub(super) struct CompactStructuredR1csRowSource<
    'source,
    Assignment: CompactStructuredAssignmentSource + ?Sized,
> {
    relation: &'source CompactPublicKeyRelationCatalog,
    matrices: CompactStructuredR1csCatalog,
    assignment: &'source Assignment,
    negacyclic_products: Vec<PreparedCompactNegacyclicProduct>,
    lookup_log_derivative_cache: CompactLookupLogDerivativeEvaluationCache,
    geometry: CompactStructuredR1csRowSourceGeometry,
}

#[cfg(test)]
impl<'source, Assignment: CompactStructuredAssignmentSource + ?Sized>
    CompactStructuredR1csRowSource<'source, Assignment>
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

    pub(super) fn evaluate_row(
        &self,
        row_ordinal: u64,
    ) -> Result<CompactStructuredR1csRowEvaluation, CommonProofProverError> {
        let row = self.matrices.row(self.relation, row_ordinal)?;
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
#[cfg(test)]
pub(crate) struct CompactPublicKeyCfwMatrices<'source, 'assignment, 'public_input> {
    row_source: &'source CompactStructuredR1csRowSource<'assignment, CompactPublicKeyAssignment>,
    canonical_public_input: &'public_input [CompactChallengeField],
    witness_length: usize,
    row_count: usize,
    row_point_variable_count: usize,
    lookup_challenge: CompactChallengeField,
}

#[cfg(test)]
impl<'source, 'assignment, 'public_input>
    CompactPublicKeyCfwMatrices<'source, 'assignment, 'public_input>
{
    pub(crate) fn new(
        row_source: &'source CompactStructuredR1csRowSource<
            'assignment,
            CompactPublicKeyAssignment,
        >,
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

#[cfg(test)]
impl CompactCfwR1csMatrices for CompactPublicKeyCfwMatrices<'_, '_, '_> {
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
                    self.row_source.relation,
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
                    self.row_source.relation,
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
                    self.row_source.relation,
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

#[cfg(test)]
fn compact_signed_integer(value: i128) -> Result<CompactChallengeField, CompactCfwError> {
    base_element_from_signed_integer(value)
        .map(ProofChallengeExtensionElement::from_base)
        .map(compact_challenge_from_production)
        .map_err(|_| CompactCfwError::InvalidMatrixSource)
}

#[cfg(test)]
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

#[cfg(test)]
impl<Assignment: CompactStructuredAssignmentSource + ?Sized> CompactCfwExternalRowSource
    for CompactStructuredR1csRowSource<'_, Assignment>
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

#[cfg(test)]
fn extension_base_value(
    value: ProofChallengeExtensionElement,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let coordinates = value.canonical_coordinates();
    if coordinates[1..].iter().any(|coordinate| *coordinate != 0) {
        return Err(CommonProofProverError::InvalidInput);
    }
    ProofBaseFieldElement::from_canonical(coordinates[0]).map_err(Into::into)
}

#[cfg(test)]
fn base_element_from_signed_integer(
    value: i128,
) -> Result<ProofBaseFieldElement, CommonProofProverError> {
    let canonical_value = u64::try_from(value.rem_euclid(i128::from(PROOF_BASE_FIELD_MODULUS)))
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    ProofBaseFieldElement::from_canonical(canonical_value).map_err(Into::into)
}

#[cfg(test)]
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

#[cfg(test)]
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
    use std::time::Instant;

    #[cfg(not(target_arch = "wasm32"))]
    use super::super::{
        PreparedCompactPublicKeyBaseAssignment,
        authenticated_assignment::{
            CompactAuthenticatedAssignmentPoll, CompactLookupInverseMaterializationPoll,
        },
        prepare_compact_public_key_assignment_sources,
    };
    use super::*;
    use crate::bgv::proof_suite::compact_cfw::{
        COMPACT_CFW_MATRIX_COUNT, CompactCfwGeometry, CompactCfwMaskMaterial,
        compact_challenge_from_production,
    };
    use crate::bgv::proof_suite::compact_cfw_external_prover::{
        CompactCfwExternalProverState, CompactCfwExternalRowSource,
    };
    use crate::bgv::proof_suite::external_memory::tests::TestStorage;
    use crate::bgv::proof_suite::field::{
        PROOF_BASE_FIELD_MODULUS, ProofBaseFieldElement, ProofChallengeExtensionElement,
    };
    #[cfg(not(target_arch = "wasm32"))]
    use crate::{
        bgv::{
            proof_suite::{
                CommonProofRelationPlanCapability, CommonProofSourcePolynomialProvider,
                SelectedApplicationStatementContext,
                compile_public_key_share_relation_with_source_layout,
                decode_selected_public_key_share_statement, verified_application_statement_hash,
            },
            setup::{
                SetupGenerationKeyRelationApplication, SetupKeyRelationGenerationPreparationError,
                SetupKeyRelationProofFamily,
                populate_compact_public_key_development_evidence_authority,
                resolve_setup_generation_compact_public_key_development_preparation_source,
                with_exclusive_setup_generation_compact_public_key_development_relation,
            },
        },
        foundation::{Hash512, ProofApplicationSlot, prepare_exact_same_secret_evidence_attempt},
    };

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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore = "manual retained compact public-key assignment gate"]
    fn heavy_rust_kernel_retained_public_key_authority_drives_one_compact_cfw_poll() {
        let authority = populate_compact_public_key_development_evidence_authority(0x43)
            .expect("standalone production-derived public-key authority populates");
        let action_private_randomness = authority.action_private_randomness;
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
        let prepared_attempt = prepare_exact_same_secret_evidence_attempt(
            &action_private_randomness,
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
        let mut prepared_sources =
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
                .source_polynomials
                .compact_public_key_assignment_request_context()
                .expect("compact request context")
                .relation_plan_variant_hash(),
            prepared_sources
                .relation_plan_variant
                .canonical_hash()
                .expect("compact variant hash")
        );
        let provider_memory_accounting = prepared_sources
            .source_polynomials
            .memory_accounting()
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
        let mut loaded_column_ordinals = Vec::new();
        loop {
            match prepared_sources
                .assignment_cursor
                .next_source(
                    &prepared_sources.relation,
                    &prepared_sources.relation_plan_variant,
                    &mut prepared_sources.source_polynomials,
                )
                .expect("retained compact source poll")
            {
                CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired => {
                    panic!("retained setup authority must not request caller source bytes")
                }
                CompactAuthenticatedAssignmentPoll::SourceLoaded { column_ordinal } => {
                    loaded_column_ordinals.push(column_ordinal);
                }
                CompactAuthenticatedAssignmentPoll::Complete => break,
            }
        }
        assert_eq!(loaded_column_ordinals.len(), 202);
        assert!(
            loaded_column_ordinals
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        let PreparedCompactPublicKeyBaseAssignment {
            relation,
            base_assignment,
        } = prepared_sources
            .finish_source_loading()
            .expect("completed compact source loading releases its authority");
        assert_ne!(base_assignment.source_replay_binding(), [0_u8; 64]);
        println!(
            "compact public-key focused owner phase complete: load 202 authenticated columns elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: materialize lookup inverses");
        let lookup_challenge =
            ProofChallengeExtensionElement::from_canonical_coordinates([7, 1, 2, 3, 4])
                .expect("non-base lookup challenge");
        let mut lookup_materializer = base_assignment
            .begin_lookup_inverse_materialization(lookup_challenge)
            .expect("bounded lookup materialization starts");
        let mut lookup_materialization_poll_count = 0_u64;
        while let CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
            processed_element_count,
        } = lookup_materializer
            .advance(8_192)
            .expect("bounded lookup materialization poll")
        {
            assert!((1..=8_192).contains(&processed_element_count));
            lookup_materialization_poll_count += 1;
        }
        assert_eq!(lookup_materialization_poll_count, 233);
        let assignment = lookup_materializer
            .finish()
            .expect("bounded lookup materialization finishes");
        println!(
            "compact public-key focused owner phase complete: materialize lookup inverses elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: prepare structured row source");
        let mut row_source_preparation =
            CompactStructuredR1csRowSourcePreparation::new(&relation, &assignment)
                .expect("production assignment starts structured row preparation");
        let mut row_source_preparation_poll_count = 0_u64;
        let row_source = loop {
            match row_source_preparation
                .advance(8_192)
                .expect("bounded production row-source preparation poll")
            {
                CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
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
                CompactStructuredR1csRowSourcePreparationPoll::Complete(row_source) => {
                    break *row_source;
                }
            }
        };
        assert_eq!(row_source_preparation_poll_count, 760);
        println!(
            "compact public-key focused owner phase complete: prepare structured row source elapsed_milliseconds={}",
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
        for row_ordinal in checked_rows {
            let evaluation = row_source
                .evaluate_row(row_ordinal)
                .expect("selected production row evaluates");
            assert_eq!(
                evaluation.left.multiply(evaluation.right),
                evaluation.output,
                "production assignment violates row {row_ordinal}"
            );
        }
        println!(
            "compact public-key focused owner phase complete: check relation segment boundaries elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );

        let phase_started_at = Instant::now();
        println!("compact public-key focused owner phase: advance one compact CFW poll");
        let compact_geometry = CompactCfwGeometry::derive(
            CompactCfwExternalRowSource::witness_length(&row_source)
                .expect("production witness length fits CFW"),
        )
        .expect("production row source has compact CFW geometry");
        let mut mask_coordinate = 10_000_u64;
        let compact_mask_material = CompactCfwMaskMaterial::sample(compact_geometry, || {
            mask_coordinate += 5;
            compact_challenge_from_production(
                ProofChallengeExtensionElement::from_canonical_coordinates([
                    mask_coordinate,
                    mask_coordinate + 1,
                    mask_coordinate + 2,
                    mask_coordinate + 3,
                    mask_coordinate + 4,
                ])
                .expect("compact mask coordinate is canonical"),
            )
        })
        .expect("compact masks derive");
        let equality_point = (0..compact_geometry.sumcheck_round_count())
            .map(|round_ordinal| {
                let round_ordinal =
                    u64::try_from(round_ordinal).expect("CFW round ordinal fits u64");
                compact_challenge_from_production(
                    ProofChallengeExtensionElement::from_canonical_coordinates([
                        20_000 + round_ordinal,
                        21_000 + round_ordinal,
                        22_000 + round_ordinal,
                        23_000 + round_ordinal,
                        24_000 + round_ordinal,
                    ])
                    .expect("equality coordinate is canonical"),
                )
            })
            .collect::<Vec<_>>();
        let counting_row_source = CountingCompactCfwExternalRowSource {
            source: &row_source,
            evaluated_row_count: Cell::new(0),
        };
        let mut external_prover = CompactCfwExternalProverState::prepare(
            &counting_row_source,
            compact_mask_material,
            compact_challenge_from_production(
                ProofChallengeExtensionElement::from_canonical_coordinates([31, 37, 41, 43, 47])
                    .expect("constraint challenge is canonical"),
            ),
            equality_point,
        )
        .expect("production row source connects to CFW");
        let mut storage = TestStorage::default();
        assert_eq!(
            external_prover
                .advance_round_polynomial(&counting_row_source, &mut storage)
                .expect("one production CFW poll advances"),
            None
        );
        assert_eq!(counting_row_source.evaluated_row_count.get(), 16_384);
        println!(
            "compact public-key focused owner phase complete: advance one compact CFW poll elapsed_milliseconds={}",
            phase_started_at.elapsed().as_millis()
        );
        println!(
            "compact public-key focused owner complete elapsed_milliseconds={}",
            execution_started_at.elapsed().as_millis()
        );
    }

    #[test]
    fn compact_structured_row_source_uses_exact_bounded_transform_products() {
        let relation = super::super::selected_compact_public_key_relation_catalog()
            .expect("selected compact public-key relation");
        let matrices = CompactStructuredR1csCatalog::derive(&relation)
            .expect("complete structured R1CS matrices");
        let assignment = DeterministicR1csAssignment::new(&relation, &matrices);
        let mut preparation =
            CompactStructuredR1csRowSourcePreparation::new(&relation, &assignment)
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
