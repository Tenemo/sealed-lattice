use std::collections::BTreeSet;

use crate::bgv::{
    evaluator::candidate_evidence::EvaluatorCandidateInput,
    key_switch_topology::KeySwitchDecompositionTopology,
    setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
};

use super::key_relation::{
    BoundPolynomialRootUse, ExactRadixDigitColumnCatalog, KeyRelationGeometry,
    KeyRelationPlanBuilder, KeyVerifierSourceKey, RecenteredVerifierVectorWitness,
    ReversibleShiftedSmallVector, ShiftedSmallVector, SplitIntegerVector,
    TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE, TrusteeAnchorOpeningWitness,
    TrusteeKeyRelationGeometryInput, TrusteeRadixThreeQuotientWitness,
    galois_common_reference_source, negacyclic_automorphism_mapping_source,
    nested_statement_root_source, relinearization_common_reference_source, statement_root_source,
    trustee_bdlop_matrix_source,
};
use super::{
    CompiledRelationPlan, RelationPlanCheckContext, RelationPlanChecker, RelationPlanError,
    RelationVerifierSource, SuiteModulusReference,
};

const RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER: u16 = crate::foundation::ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER;
const RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER: u16 = crate::foundation::ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER;
const GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
const ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL: u64 = 4;
const ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL: u64 = 5;
const ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL: u64 = 6;
const AGGREGATE_ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL: u64 = 7;
const AGGREGATE_ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL: u64 = 8;
const ROUND_TWO_ROOT_FIELD_ORDINAL: u64 = 9;
const GALOIS_KEY_SHARE_ROOT_FIELD_ORDINAL: u64 = 5;
const GALOIS_KEY_SHARE_ENTRY_ROOT_FIELD_ORDINAL: u64 = 1;
const SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION: u32 = 0;

pub(crate) const fn selected_galois_key_share_batch_schedule() -> [u32; 1] {
    [SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION]
}

pub(super) fn selected_galois_key_share_relation_schedule()
-> Result<Vec<(u64, usize)>, RelationPlanError> {
    EvaluatorCandidateInput::implemented()
        .map_err(|_| RelationPlanError::InvalidDomain)?
        .galois_key_schedule
        .into_iter()
        .map(|(galois_element, selected_level)| {
            Ok((
                u64::try_from(galois_element).map_err(|_| RelationPlanError::CountOverflow)?,
                selected_level,
            ))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyDecompositionBlock {
    pub(crate) data_modulus_indices: Vec<u16>,
}

/// Exact key-switch basis selected for one evaluator-key catalog level.
///
/// Relinearization and Galois material can live at different levels. This
/// value is therefore derived independently for each family from the selected
/// topology authority rather than copying a family-independent modulus list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyRelationBasis {
    pub(crate) data_moduli: Vec<u64>,
    pub(crate) special_moduli: Vec<u64>,
    pub(crate) decomposition_blocks: Vec<TrusteeEvaluationKeyDecompositionBlock>,
}

pub(crate) fn trustee_evaluation_key_relation_basis_for_catalog_level(
    evaluator_candidate: &EvaluatorCandidateInput,
    catalog_level: usize,
) -> Result<TrusteeEvaluationKeyRelationBasis, RelationPlanError> {
    let topology = KeySwitchDecompositionTopology::for_level(catalog_level)
        .map_err(|_| RelationPlanError::InvalidDomain)?;
    let data_modulus_count = topology.data_prime_count();
    let candidate_data_moduli = evaluator_candidate
        .data_primes
        .get(..data_modulus_count)
        .ok_or(RelationPlanError::InvalidDomain)?;
    let topology_special_moduli = topology
        .extended_moduli()
        .get(data_modulus_count..)
        .ok_or(RelationPlanError::InvalidDomain)?;
    if candidate_data_moduli != topology.active_data_moduli()
        || evaluator_candidate.special_primes.as_slice() != topology_special_moduli
    {
        return Err(RelationPlanError::InvalidModulus);
    }
    let decomposition_blocks = (0..topology.data_block_count())
        .map(|block_index| {
            Ok(TrusteeEvaluationKeyDecompositionBlock {
                data_modulus_indices: topology
                    .data_block_range(block_index)
                    .map_err(|_| RelationPlanError::InvalidDomain)?
                    .map(|modulus_index| {
                        u16::try_from(modulus_index).map_err(|_| RelationPlanError::CountOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, RelationPlanError>>()?;

    Ok(TrusteeEvaluationKeyRelationBasis {
        data_moduli: candidate_data_moduli.to_vec(),
        special_moduli: topology_special_moduli.to_vec(),
        decomposition_blocks,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrusteeEvaluationKeyRelationGeometry {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) data_moduli: Vec<u64>,
    pub(crate) special_moduli: Vec<u64>,
    pub(crate) plaintext_modulus: u64,
    pub(crate) decomposition_blocks: Vec<TrusteeEvaluationKeyDecompositionBlock>,
    pub(crate) commitment_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_module_rank: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelinearizationRoundOneRelationPlanInput {
    pub(crate) schedule_position: u32,
    pub(crate) geometry: TrusteeEvaluationKeyRelationGeometry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelinearizationRoundTwoRelationPlanInput {
    pub(crate) schedule_position: u32,
    pub(crate) geometry: TrusteeEvaluationKeyRelationGeometry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GaloisKeyShareRelationEntryInput {
    pub(crate) schedule_position: u32,
    pub(crate) galois_element: u64,
    pub(crate) selected_level: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GaloisKeyShareRelationPlanInput {
    pub(crate) batch_schedule_position: u32,
    pub(crate) ordered_entries: Vec<GaloisKeyShareRelationEntryInput>,
    pub(crate) geometry: TrusteeEvaluationKeyRelationGeometry,
}

pub(crate) struct CompiledGaloisKeyShareRelation {
    pub(crate) relation_plan: CompiledRelationPlan,
    pub(crate) source_layout: GaloisKeyShareSourceLayout,
}

pub(crate) struct CompiledRelinearizationRoundOneRelation {
    pub(crate) relation_plan: CompiledRelationPlan,
    pub(crate) source_layout: RelinearizationRoundOneSourceLayout,
}

pub(crate) struct CompiledRelinearizationRoundTwoRelation {
    pub(crate) relation_plan: CompiledRelationPlan,
    pub(crate) source_layout: RelinearizationRoundTwoSourceLayout,
}

pub(crate) struct RelinearizationRoundOneSourceLayout {
    pub(super) common_secret: ReversibleShiftedSmallVector,
    pub(super) ephemeral_secret: ReversibleShiftedSmallVector,
    pub(super) round_one_left_rows: Box<[SplitIntegerVector]>,
    pub(super) round_one_right_rows: Box<[SplitIntegerVector]>,
    pub(super) errors_by_block: Box<[RelinearizationRoundOneErrorSourceLayout]>,
    pub(super) quotients_by_row: Box<[RelinearizationRoundOneQuotientSourceLayout]>,
    pub(super) ordered_anchors: Box<[GaloisKeyShareAnchorSourceLayout]>,
    pub(super) exact_radix_digits_by_column: ExactRadixDigitColumnCatalog,
}

pub(crate) struct RelinearizationRoundTwoSourceLayout {
    pub(super) common_secret: ReversibleShiftedSmallVector,
    pub(super) ephemeral_secret: ReversibleShiftedSmallVector,
    pub(super) round_one_left_rows: Box<[SplitIntegerVector]>,
    pub(super) round_one_right_rows: Box<[SplitIntegerVector]>,
    pub(super) aggregate_round_one_left_rows: Box<[SplitIntegerVector]>,
    pub(super) aggregate_round_one_right_rows: Box<[SplitIntegerVector]>,
    pub(super) round_two_rows: Box<[SplitIntegerVector]>,
    pub(super) round_one_errors_by_block: Box<[RelinearizationRoundOneErrorSourceLayout]>,
    pub(super) round_one_quotients_by_row: Box<[RelinearizationRoundOneQuotientSourceLayout]>,
    pub(super) aggregate_rows: Box<[RelinearizationRoundTwoAggregateRowSourceLayout]>,
    pub(super) round_two_errors_by_block: Box<[ShiftedSmallVector]>,
    pub(super) round_two_quotients_by_row: Box<[TrusteeRadixThreeQuotientWitness]>,
    pub(super) ordered_anchors: Box<[GaloisKeyShareAnchorSourceLayout]>,
    pub(super) exact_radix_digits_by_column: ExactRadixDigitColumnCatalog,
}

pub(crate) struct RelinearizationRoundOneErrorSourceLayout {
    pub(super) left: ShiftedSmallVector,
    pub(super) right: ShiftedSmallVector,
}

#[derive(Clone, Copy)]
pub(crate) struct RelinearizationRoundOneQuotientSourceLayout {
    pub(super) left: TrusteeRadixThreeQuotientWitness,
    pub(super) right: TrusteeRadixThreeQuotientWitness,
}

pub(crate) struct RelinearizationRoundTwoAggregateRowSourceLayout {
    pub(super) left: RecenteredVerifierVectorWitness,
    pub(super) right: RecenteredVerifierVectorWitness,
}

pub(crate) struct GaloisKeyShareSourceLayout {
    pub(super) common_secret: ReversibleShiftedSmallVector,
    pub(super) ordered_entries: Box<[GaloisKeyShareEntrySourceLayout]>,
    pub(super) ordered_anchors: Box<[GaloisKeyShareAnchorSourceLayout]>,
    pub(super) exact_radix_digits_by_column: ExactRadixDigitColumnCatalog,
}

pub(crate) struct GaloisKeyShareEntrySourceLayout {
    pub(super) schedule_position: u32,
    pub(super) galois_element: u64,
    pub(super) selected_level: usize,
    pub(super) relation_geometry: TrusteeEvaluationKeyRelationGeometry,
    pub(super) automorphed_secret: ShiftedSmallVector,
    pub(super) bound_rows: Box<[SplitIntegerVector]>,
    pub(super) errors_by_block: Box<[ShiftedSmallVector]>,
    pub(super) quotients_by_row: Box<[TrusteeRadixThreeQuotientWitness]>,
}

pub(crate) struct GaloisKeyShareAnchorSourceLayout {
    pub(super) data_modulus_index: u16,
    pub(super) opening: TrusteeAnchorOpeningWitness,
    pub(super) commitments: Box<[SplitIntegerVector]>,
    pub(super) first_matrix: Box<[Box<[RecenteredVerifierVectorWitness]>]>,
    pub(super) second_matrix: Box<[RecenteredVerifierVectorWitness]>,
    pub(super) quotients: Box<[TrusteeRadixThreeQuotientWitness]>,
}

impl TrusteeEvaluationKeyRelationGeometry {
    pub(crate) fn selected_catalog_prefix(
        &self,
        catalog_level: usize,
    ) -> Result<Self, RelationPlanError> {
        let topology = KeySwitchDecompositionTopology::for_level(catalog_level)
            .map_err(|_| RelationPlanError::InvalidDomain)?;
        let data_modulus_count = topology.data_prime_count();
        let selected_data_moduli = self
            .data_moduli
            .get(..data_modulus_count)
            .ok_or(RelationPlanError::InvalidModulus)?;
        let selected_special_moduli = topology
            .extended_moduli()
            .get(data_modulus_count..)
            .ok_or(RelationPlanError::InvalidModulus)?;
        if selected_data_moduli != topology.active_data_moduli()
            || self.special_moduli != selected_special_moduli
        {
            return Err(RelationPlanError::InvalidModulus);
        }
        let decomposition_blocks = (0..topology.data_block_count())
            .map(|block_index| {
                Ok(TrusteeEvaluationKeyDecompositionBlock {
                    data_modulus_indices: topology
                        .data_block_range(block_index)
                        .map_err(|_| RelationPlanError::InvalidDomain)?
                        .map(|modulus_index| {
                            u16::try_from(modulus_index)
                                .map_err(|_| RelationPlanError::CountOverflow)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                })
            })
            .collect::<Result<Vec<_>, RelationPlanError>>()?;
        Ok(Self {
            ring_degree: self.ring_degree,
            evaluation_domain_size: self.evaluation_domain_size,
            opening_degree_bound_exclusive: self.opening_degree_bound_exclusive,
            public_polynomial_column_degree_bound_exclusive: self
                .public_polynomial_column_degree_bound_exclusive,
            data_moduli: selected_data_moduli.to_vec(),
            special_moduli: self.special_moduli.clone(),
            plaintext_modulus: self.plaintext_modulus,
            decomposition_blocks,
            commitment_data_modulus_indices: self.commitment_data_modulus_indices.clone(),
            commitment_module_rank: self.commitment_module_rank,
        })
    }

    fn validate_common(
        &self,
        check_context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        RelationPlanChecker::new(check_context).check_context()?;
        if self.ring_degree < 4
            || !self.ring_degree.is_power_of_two()
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.public_polynomial_column_degree_bound_exclusive == 0
            || self.public_polynomial_column_degree_bound_exclusive
                > self.opening_degree_bound_exclusive
            || self.data_moduli.is_empty()
            || self.special_moduli.is_empty()
            || self.plaintext_modulus < 3
            || self.plaintext_modulus.is_multiple_of(2)
            || self.decomposition_blocks.is_empty()
            || self.commitment_data_modulus_indices.is_empty()
            || usize::from(self.commitment_module_rank) != SETUP_COMMITMENT_MODULE_RANK
        {
            return Err(RelationPlanError::InvalidDomain);
        }

        let opening_degree_domain = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(RelationPlanError::CountOverflow)?;
        if !self
            .evaluation_domain_size
            .is_multiple_of(opening_degree_domain)
            || !(check_context.base_field_modulus - 1).is_multiple_of(self.evaluation_domain_size)
            || super::modular_power(
                check_context.evaluation_domain_generator,
                self.evaluation_domain_size,
                check_context.base_field_modulus,
            ) != 1
            || super::modular_power(
                check_context.evaluation_domain_generator,
                self.evaluation_domain_size / 2,
                check_context.base_field_modulus,
            ) == 1
            || super::modular_power(
                check_context.evaluation_coset_offset,
                self.ring_degree / 2,
                check_context.base_field_modulus,
            ) == 1
        {
            return Err(RelationPlanError::InvalidDomain);
        }

        validate_modulus_catalog(
            &self.data_moduli,
            SuiteModulusReference::data,
            check_context,
        )?;
        validate_modulus_catalog(
            &self.special_moduli,
            SuiteModulusReference::special,
            check_context,
        )?;
        if check_context.resolved_modulus(SuiteModulusReference::plaintext())?
            != self.plaintext_modulus
        {
            return Err(RelationPlanError::InvalidModulus);
        }

        let mut distinct_moduli = BTreeSet::new();
        for modulus in self.data_moduli.iter().chain(&self.special_moduli).copied() {
            if modulus <= self.ring_degree
                || modulus >= check_context.base_field_modulus
                || modulus.is_multiple_of(2)
                || self.plaintext_modulus >= modulus
                || !distinct_moduli.insert(modulus)
            {
                return Err(RelationPlanError::InvalidModulus);
            }
        }
        if !distinct_moduli.insert(self.plaintext_modulus) {
            return Err(RelationPlanError::InvalidModulus);
        }

        let expected_data_modulus_indices = (0..self.data_moduli.len())
            .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        let flattened_block_indices = self
            .decomposition_blocks
            .iter()
            .flat_map(|block| block.data_modulus_indices.iter().copied())
            .collect::<Vec<_>>();
        if self
            .decomposition_blocks
            .iter()
            .any(|block| block.data_modulus_indices.is_empty())
            || flattened_block_indices != expected_data_modulus_indices
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }

        let expected_commitment_data_modulus_indices = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .copied()
            .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
            .collect::<Result<Vec<_>, _>>()?;
        if self.commitment_data_modulus_indices != expected_commitment_data_modulus_indices
            || !super::strictly_sorted_unique(&self.commitment_data_modulus_indices)
            || self
                .commitment_data_modulus_indices
                .iter()
                .any(|index| usize::from(*index) >= self.data_moduli.len())
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }

        self.validate_round_one_quotient_bounds()?;
        self.validate_anchor_quotient_bounds()?;
        Ok(())
    }

    fn validate_round_one_quotient_bounds(&self) -> Result<(), RelationPlanError> {
        for modulus in self.data_moduli.iter().chain(&self.special_moduli).copied() {
            let modulus_minus_one = u128::from(modulus - 1);
            let numerator_bound = u128::from(self.ring_degree)
                .checked_add(2)
                .and_then(|factor| factor.checked_mul(modulus_minus_one))
                .and_then(|bound| bound.checked_add(2_u128 * u128::from(self.plaintext_modulus)))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            validate_quotient_capacity(numerator_bound, modulus)?;
        }
        Ok(())
    }

    fn validate_round_two_quotient_bounds(&self) -> Result<(), RelationPlanError> {
        for modulus in self.data_moduli.iter().chain(&self.special_moduli).copied() {
            let centered_product_bound = u128::from(self.ring_degree)
                .checked_mul(u128::from((modulus - 1) / 2))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            let numerator_bound = centered_product_bound
                .checked_mul(3)
                .and_then(|bound| bound.checked_add(u128::from(modulus - 1)))
                .and_then(|bound| bound.checked_add(2_u128 * u128::from(self.plaintext_modulus)))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            validate_quotient_capacity(numerator_bound, modulus)?;
        }
        Ok(())
    }

    fn validate_anchor_quotient_bounds(&self) -> Result<(), RelationPlanError> {
        let product_count = u128::from(self.commitment_module_rank)
            .checked_add(1)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        for data_modulus_index in self.commitment_data_modulus_indices.iter().copied() {
            let modulus = self.data_moduli[usize::from(data_modulus_index)];
            let product_bound = u128::from(self.ring_degree)
                .checked_mul(u128::from((modulus - 1) / 2))
                .and_then(|bound| bound.checked_mul(product_count))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            let numerator_bound = product_bound
                .checked_add(u128::from(modulus - 1))
                .and_then(|bound| bound.checked_add(2))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            validate_quotient_capacity(numerator_bound, modulus)?;
        }
        Ok(())
    }

    pub(super) fn ordered_modulus_references(
        &self,
    ) -> Result<Vec<SuiteModulusReference>, RelationPlanError> {
        let mut references = Vec::with_capacity(
            self.data_moduli
                .len()
                .checked_add(self.special_moduli.len())
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        for index in 0..self.data_moduli.len() {
            references.push(SuiteModulusReference::data(
                u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
        for index in 0..self.special_moduli.len() {
            references.push(SuiteModulusReference::special(
                u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
        Ok(references)
    }

    fn ordered_root_row_modulus_references(
        &self,
    ) -> Result<Vec<SuiteModulusReference>, RelationPlanError> {
        let ordered_modulus_references = self.ordered_modulus_references()?;
        let capacity = self
            .decomposition_blocks
            .len()
            .checked_mul(ordered_modulus_references.len())
            .ok_or(RelationPlanError::CountOverflow)?;
        let mut rows = Vec::with_capacity(capacity);
        for _ in &self.decomposition_blocks {
            rows.extend(ordered_modulus_references.iter().copied());
        }
        Ok(rows)
    }

    pub(super) fn gadget_coefficient(
        &self,
        decomposition_block_index: usize,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u64, RelationPlanError> {
        if modulus_reference.catalog != super::ModulusCatalog::Data
            || !self.decomposition_blocks[decomposition_block_index]
                .data_modulus_indices
                .contains(&modulus_reference.modulus_index)
        {
            return Ok(0);
        }
        let modulus = self.data_moduli[usize::from(modulus_reference.modulus_index)];
        self.special_moduli
            .iter()
            .copied()
            .try_fold(1_u64, |product, special_modulus| {
                let reduced_product =
                    (u128::from(product) * u128::from(special_modulus)) % u128::from(modulus);
                u64::try_from(reduced_product).map_err(|_| RelationPlanError::IntegerBoundOverflow)
            })
    }

    fn key_relation_geometry(
        &self,
        schedule_position: u32,
    ) -> Result<KeyRelationGeometry, RelationPlanError> {
        KeyRelationGeometry::for_trustee(TrusteeKeyRelationGeometryInput {
            schedule_position,
            ring_degree: self.ring_degree,
            evaluation_domain_size: self.evaluation_domain_size,
            opening_degree_bound_exclusive: self.opening_degree_bound_exclusive,
            public_polynomial_column_degree_bound_exclusive: self
                .public_polynomial_column_degree_bound_exclusive,
            data_modulus_count: self.data_moduli.len(),
            special_modulus_count: self.special_moduli.len(),
            commitment_data_modulus_indices: self.commitment_data_modulus_indices.clone(),
            commitment_module_rank: self.commitment_module_rank,
            plaintext_modulus: self.plaintext_modulus,
        })
    }
}

fn validate_modulus_catalog(
    moduli: &[u64],
    reference: impl Fn(u16) -> SuiteModulusReference,
    check_context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    for (index, expected_modulus) in moduli.iter().copied().enumerate() {
        let index = u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow)?;
        if check_context.resolved_modulus(reference(index))? != expected_modulus {
            return Err(RelationPlanError::InvalidModulus);
        }
    }
    Ok(())
}

fn validate_quotient_capacity(
    numerator_bound: u128,
    modulus: u64,
) -> Result<(), RelationPlanError> {
    let modulus = u128::from(modulus);
    let quotient_bound = numerator_bound
        .checked_add(modulus - 1)
        .ok_or(RelationPlanError::IntegerBoundOverflow)?
        / modulus;
    if quotient_bound > u128::from(TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE) {
        Err(RelationPlanError::IntegerBoundOverflow)
    } else {
        Ok(())
    }
}

fn append_anchor_relation_sources(
    sources: &mut Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
) -> Result<(), RelationPlanError> {
    let rank = usize::from(geometry.commitment_module_rank);
    for (root_ordinal, data_modulus_index) in geometry
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        sources.push(statement_root_source(
            ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
            Some(u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?),
        ));
        for row_ordinal in 0..rank {
            for column_ordinal in 0..=rank {
                sources.push(trustee_bdlop_matrix_source(
                    geometry.ring_degree,
                    data_modulus_index,
                    1,
                    u16::try_from(row_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                    u16::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ));
            }
        }
        for column_ordinal in 0..rank {
            sources.push(trustee_bdlop_matrix_source(
                geometry.ring_degree,
                data_modulus_index,
                2,
                0,
                u16::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
    }
    Ok(())
}

fn append_relation_sources(
    sources: &mut Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    schedule_position: u32,
) -> Result<(), RelationPlanError> {
    append_anchor_relation_sources(sources, geometry)?;
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        for modulus_reference in ordered_modulus_references.iter().copied() {
            sources.push(relinearization_common_reference_source(
                geometry.ring_degree,
                schedule_position,
                u16::try_from(decomposition_block_index)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                modulus_reference,
            ));
        }
    }
    Ok(())
}

fn append_galois_relation_sources(
    sources: &mut Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    schedule_position: u32,
    galois_element: u64,
) -> Result<(), RelationPlanError> {
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        for modulus_reference in ordered_modulus_references.iter().copied() {
            sources.push(galois_common_reference_source(
                geometry.ring_degree,
                schedule_position,
                u16::try_from(decomposition_block_index)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                modulus_reference,
            ));
        }
    }
    sources.push(negacyclic_automorphism_mapping_source(
        geometry.ring_degree,
        galois_element,
    ));
    Ok(())
}

fn statement_root_key(field_ordinal: u64) -> KeyVerifierSourceKey {
    KeyVerifierSourceKey::StatementRoot {
        field_ordinal,
        list_ordinal: None,
    }
}

fn nested_statement_root_key(
    field_ordinal: u64,
    list_ordinal: u64,
    nested_field_ordinal: u64,
) -> KeyVerifierSourceKey {
    KeyVerifierSourceKey::NestedStatementRoot {
        field_ordinal,
        list_ordinal,
        nested_field_ordinal,
    }
}

fn add_statement_root_rows(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    source_key: &KeyVerifierSourceKey,
    root_use: BoundPolynomialRootUse,
) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
    builder.add_setup_polynomial_rows_root(
        source_key,
        &geometry.ordered_root_row_modulus_references()?,
        root_use,
    )
}

type RelinearizationRoundOneRelationLayouts = (
    Box<[RelinearizationRoundOneErrorSourceLayout]>,
    Box<[RelinearizationRoundOneQuotientSourceLayout]>,
);

type RelinearizationRoundTwoRelationLayouts = (
    Box<[RelinearizationRoundTwoAggregateRowSourceLayout]>,
    Box<[ShiftedSmallVector]>,
    Box<[TrusteeRadixThreeQuotientWitness]>,
);

type GaloisKeyRelationLayouts = (
    Box<[ShiftedSmallVector]>,
    Box<[TrusteeRadixThreeQuotientWitness]>,
);

#[allow(clippy::too_many_arguments)]
fn add_round_one_relations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    schedule_position: u32,
    round_one_left_rows: &[SplitIntegerVector],
    round_one_right_rows: &[SplitIntegerVector],
    secret: &ReversibleShiftedSmallVector,
    ephemeral_secret: &ReversibleShiftedSmallVector,
    check_context: &RelationPlanCheckContext,
) -> Result<RelinearizationRoundOneRelationLayouts, RelationPlanError> {
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    let expected_row_count = geometry
        .decomposition_blocks
        .len()
        .checked_mul(ordered_modulus_references.len())
        .ok_or(RelationPlanError::CountOverflow)?;
    if round_one_left_rows.len() != expected_row_count
        || round_one_right_rows.len() != expected_row_count
    {
        return Err(RelationPlanError::InvalidRoot);
    }

    let mut errors_by_block = Vec::with_capacity(geometry.decomposition_blocks.len());
    let mut quotients_by_row = Vec::with_capacity(expected_row_count);
    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        let round_one_left_error = builder.add_signed_eta_two_vector()?;
        let round_one_right_error = builder.add_signed_eta_two_vector()?;
        errors_by_block.push(RelinearizationRoundOneErrorSourceLayout {
            left: round_one_left_error.clone(),
            right: round_one_right_error.clone(),
        });
        for (limb_ordinal, modulus_reference) in
            ordered_modulus_references.iter().copied().enumerate()
        {
            let row_ordinal = decomposition_block_index
                .checked_mul(ordered_modulus_references.len())
                .and_then(|start| start.checked_add(limb_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            let source_key = KeyVerifierSourceKey::RelinearizationCommonReference {
                schedule_position,
                decomposition_block_index: u16::try_from(decomposition_block_index)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                modulus_reference,
            };
            let common_reference =
                builder.add_split_verifier_vector(&source_key, modulus_reference)?;
            let left_quotient = builder.add_trustee_radix_three_quotient_witness()?;
            let right_quotient = builder.add_trustee_radix_three_quotient_witness()?;
            quotients_by_row.push(RelinearizationRoundOneQuotientSourceLayout {
                left: left_quotient,
                right: right_quotient,
            });
            let gadget_coefficient =
                geometry.gadget_coefficient(decomposition_block_index, modulus_reference)?;
            for challenge_ordinal in 0..check_context.non_native_theta_repetition_count {
                builder.add_relinearization_round_one_equations(
                    modulus_reference,
                    challenge_ordinal,
                    &round_one_left_rows[row_ordinal],
                    &round_one_right_rows[row_ordinal],
                    common_reference,
                    secret,
                    ephemeral_secret,
                    &round_one_left_error,
                    &round_one_right_error,
                    gadget_coefficient,
                    left_quotient,
                    right_quotient,
                )?;
            }
        }
    }
    Ok((
        errors_by_block.into_boxed_slice(),
        quotients_by_row.into_boxed_slice(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn add_round_two_relations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    round_two_rows: &[SplitIntegerVector],
    aggregate_round_one_left_rows: &[SplitIntegerVector],
    aggregate_round_one_right_rows: &[SplitIntegerVector],
    secret: &ReversibleShiftedSmallVector,
    ephemeral_secret: &ReversibleShiftedSmallVector,
    check_context: &RelationPlanCheckContext,
) -> Result<RelinearizationRoundTwoRelationLayouts, RelationPlanError> {
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    let expected_row_count = geometry
        .decomposition_blocks
        .len()
        .checked_mul(ordered_modulus_references.len())
        .ok_or(RelationPlanError::CountOverflow)?;
    if round_two_rows.len() != expected_row_count
        || aggregate_round_one_left_rows.len() != expected_row_count
        || aggregate_round_one_right_rows.len() != expected_row_count
    {
        return Err(RelationPlanError::InvalidRoot);
    }

    let mut aggregate_rows = Vec::with_capacity(expected_row_count);
    let mut errors_by_block = Vec::with_capacity(geometry.decomposition_blocks.len());
    let mut quotients_by_row = Vec::with_capacity(expected_row_count);
    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        let round_two_error = builder.add_signed_eta_two_vector()?;
        errors_by_block.push(round_two_error.clone());
        for (limb_ordinal, modulus_reference) in
            ordered_modulus_references.iter().copied().enumerate()
        {
            let row_ordinal = decomposition_block_index
                .checked_mul(ordered_modulus_references.len())
                .and_then(|start| start.checked_add(limb_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            let aggregate_round_one_left = builder.add_recentered_vector(
                aggregate_round_one_left_rows[row_ordinal],
                modulus_reference,
            )?;
            let aggregate_round_one_right = builder.add_recentered_vector(
                aggregate_round_one_right_rows[row_ordinal],
                modulus_reference,
            )?;
            let quotient = builder.add_trustee_radix_three_quotient_witness()?;
            aggregate_rows.push(RelinearizationRoundTwoAggregateRowSourceLayout {
                left: aggregate_round_one_left.clone(),
                right: aggregate_round_one_right.clone(),
            });
            quotients_by_row.push(quotient);
            for challenge_ordinal in 0..check_context.non_native_theta_repetition_count {
                builder.add_relinearization_round_two_equation(
                    modulus_reference,
                    challenge_ordinal,
                    &round_two_rows[row_ordinal],
                    &aggregate_round_one_left.centered,
                    &aggregate_round_one_right.centered,
                    secret,
                    ephemeral_secret,
                    &round_two_error,
                    quotient,
                )?;
            }
        }
    }
    Ok((
        aggregate_rows.into_boxed_slice(),
        errors_by_block.into_boxed_slice(),
        quotients_by_row.into_boxed_slice(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn add_galois_relations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    schedule_position: u32,
    galois_key_share_rows: &[SplitIntegerVector],
    secret: &ReversibleShiftedSmallVector,
    automorphed_secret: &super::key_relation::ShiftedSmallVector,
    check_context: &RelationPlanCheckContext,
) -> Result<GaloisKeyRelationLayouts, RelationPlanError> {
    let ordered_modulus_references = geometry.ordered_modulus_references()?;
    let expected_row_count = geometry
        .decomposition_blocks
        .len()
        .checked_mul(ordered_modulus_references.len())
        .ok_or(RelationPlanError::CountOverflow)?;
    if galois_key_share_rows.len() != expected_row_count {
        return Err(RelationPlanError::InvalidRoot);
    }
    let mut errors_by_block = Vec::with_capacity(geometry.decomposition_blocks.len());
    let mut quotients_by_row = Vec::with_capacity(expected_row_count);
    for decomposition_block_index in 0..geometry.decomposition_blocks.len() {
        let error = builder.add_signed_eta_two_vector()?;
        errors_by_block.push(error.clone());
        for (limb_ordinal, modulus_reference) in
            ordered_modulus_references.iter().copied().enumerate()
        {
            let row_ordinal = decomposition_block_index
                .checked_mul(ordered_modulus_references.len())
                .and_then(|start| start.checked_add(limb_ordinal))
                .ok_or(RelationPlanError::CountOverflow)?;
            let common_reference = builder.add_split_verifier_vector(
                &KeyVerifierSourceKey::GaloisCommonReference {
                    schedule_position,
                    decomposition_block_index: u16::try_from(decomposition_block_index)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    modulus_reference,
                },
                modulus_reference,
            )?;
            let quotient = builder.add_trustee_radix_three_quotient_witness()?;
            quotients_by_row.push(quotient);
            let gadget_coefficient =
                geometry.gadget_coefficient(decomposition_block_index, modulus_reference)?;
            for challenge_ordinal in 0..check_context.non_native_theta_repetition_count {
                builder.add_galois_key_equation(
                    modulus_reference,
                    challenge_ordinal,
                    &galois_key_share_rows[row_ordinal],
                    common_reference,
                    secret,
                    automorphed_secret,
                    &error,
                    gadget_coefficient,
                    quotient,
                )?;
            }
        }
    }
    Ok((
        errors_by_block.into_boxed_slice(),
        quotients_by_row.into_boxed_slice(),
    ))
}

fn add_anchor_relations(
    builder: &mut KeyRelationPlanBuilder<'_>,
    geometry: &TrusteeEvaluationKeyRelationGeometry,
    secret: &ReversibleShiftedSmallVector,
    check_context: &RelationPlanCheckContext,
) -> Result<Vec<GaloisKeyShareAnchorSourceLayout>, RelationPlanError> {
    let rank = usize::from(geometry.commitment_module_rank);
    let mut source_layouts = Vec::with_capacity(geometry.commitment_data_modulus_indices.len());
    for (root_ordinal, data_modulus_index) in geometry
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        let modulus_reference = SuiteModulusReference::data(data_modulus_index);
        let opening = builder.add_trustee_anchor_opening_witness()?;
        let commitments = builder.add_setup_polynomial_root(
            &KeyVerifierSourceKey::StatementRoot {
                field_ordinal: ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
                list_ordinal: Some(
                    u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ),
            },
            modulus_reference,
            rank.checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
            BoundPolynomialRootUse::Input,
        )?;
        let first_matrix_witnesses = (0..rank)
            .map(|row_ordinal| {
                (0..=rank)
                    .map(|column_ordinal| {
                        builder.add_recentered_split_verifier_vector_with_witness(
                            &KeyVerifierSourceKey::TrusteeBdlopMatrix {
                                data_modulus_index,
                                matrix_part: 1,
                                row: u16::try_from(row_ordinal)
                                    .map_err(|_| RelationPlanError::CountOverflow)?,
                                column: u16::try_from(column_ordinal)
                                    .map_err(|_| RelationPlanError::CountOverflow)?,
                            },
                            modulus_reference,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let second_matrix_witnesses = (0..rank)
            .map(|column_ordinal| {
                builder.add_recentered_split_verifier_vector_with_witness(
                    &KeyVerifierSourceKey::TrusteeBdlopMatrix {
                        data_modulus_index,
                        matrix_part: 2,
                        row: 0,
                        column: u16::try_from(column_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                    modulus_reference,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let first_matrix = first_matrix_witnesses
            .iter()
            .map(|row| {
                row.iter()
                    .map(|witness| witness.centered.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let second_matrix = second_matrix_witnesses
            .iter()
            .map(|witness| witness.centered.clone())
            .collect::<Vec<_>>();
        let quotients = (0..=rank)
            .map(|_| builder.add_trustee_radix_three_quotient_witness())
            .collect::<Result<Vec<_>, _>>()?;
        for challenge_ordinal in 0..check_context.non_native_theta_repetition_count {
            builder.add_trustee_anchor_equations(
                modulus_reference,
                challenge_ordinal,
                &commitments,
                &first_matrix,
                &second_matrix,
                &opening,
                &secret.source,
                &quotients,
            )?;
        }
        source_layouts.push(GaloisKeyShareAnchorSourceLayout {
            data_modulus_index,
            opening,
            commitments: commitments.into_boxed_slice(),
            first_matrix: first_matrix_witnesses
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            second_matrix: second_matrix_witnesses.into_boxed_slice(),
            quotients: quotients.into_boxed_slice(),
        });
    }
    Ok(source_layouts)
}

pub(crate) fn compile_relinearization_round_one_relation_plan(
    input: &RelinearizationRoundOneRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    compile_relinearization_round_one_relation_with_source_layout(input, check_context)
        .map(|compiled| compiled.relation_plan)
}

pub(crate) fn compile_relinearization_round_one_relation_with_source_layout(
    input: &RelinearizationRoundOneRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelinearizationRoundOneRelation, RelationPlanError> {
    input.geometry.validate_common(check_context)?;
    let mut sources = vec![
        statement_root_source(ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL, None),
    ];
    append_relation_sources(&mut sources, &input.geometry, input.schedule_position)?;
    let geometry = input
        .geometry
        .key_relation_geometry(input.schedule_position)?;
    let mut builder = KeyRelationPlanBuilder::new(
        RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        check_context,
        sources,
    )?;
    let secret = builder.add_reversible_signed_ternary_vector()?;
    let ephemeral_secret = builder.add_reversible_signed_ternary_vector()?;
    let round_one_left_source_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        &statement_root_key(ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL),
        BoundPolynomialRootUse::Output,
    )?;
    let round_one_right_source_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        &statement_root_key(ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL),
        BoundPolynomialRootUse::Output,
    )?;
    let (errors_by_block, quotients_by_row) = add_round_one_relations(
        &mut builder,
        &input.geometry,
        input.schedule_position,
        &round_one_left_source_rows,
        &round_one_right_source_rows,
        &secret,
        &ephemeral_secret,
        check_context,
    )?;
    let ordered_anchors =
        add_anchor_relations(&mut builder, &input.geometry, &secret, check_context)?;
    let exact_radix_digits_by_column = builder
        .exact_radix_digits_by_column()
        .iter()
        .map(|(column_ordinal, digit_column_ordinals)| {
            (
                *column_ordinal,
                digit_column_ordinals.clone().into_boxed_slice(),
            )
        })
        .collect();
    let relation_plan = builder.finish()?;
    Ok(CompiledRelinearizationRoundOneRelation {
        relation_plan,
        source_layout: RelinearizationRoundOneSourceLayout {
            common_secret: secret,
            ephemeral_secret,
            round_one_left_rows: round_one_left_source_rows.into_boxed_slice(),
            round_one_right_rows: round_one_right_source_rows.into_boxed_slice(),
            errors_by_block,
            quotients_by_row,
            ordered_anchors: ordered_anchors.into_boxed_slice(),
            exact_radix_digits_by_column,
        },
    })
}

pub(crate) fn compile_relinearization_round_two_relation_plan(
    input: &RelinearizationRoundTwoRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    compile_relinearization_round_two_relation_with_source_layout(input, check_context)
        .map(|compiled| compiled.relation_plan)
}

pub(crate) fn compile_relinearization_round_two_relation_with_source_layout(
    input: &RelinearizationRoundTwoRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelinearizationRoundTwoRelation, RelationPlanError> {
    input.geometry.validate_common(check_context)?;
    input.geometry.validate_round_two_quotient_bounds()?;
    let mut sources = vec![
        statement_root_source(ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(AGGREGATE_ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(AGGREGATE_ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL, None),
        statement_root_source(ROUND_TWO_ROOT_FIELD_ORDINAL, None),
    ];
    append_relation_sources(&mut sources, &input.geometry, input.schedule_position)?;
    let geometry = input
        .geometry
        .key_relation_geometry(input.schedule_position)?;
    let mut builder = KeyRelationPlanBuilder::new(
        RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        check_context,
        sources,
    )?;
    let secret = builder.add_reversible_signed_ternary_vector()?;
    let ephemeral_secret = builder.add_reversible_signed_ternary_vector()?;
    let round_one_left_source_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        &statement_root_key(ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL),
        BoundPolynomialRootUse::Input,
    )?;
    let round_one_right_source_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        &statement_root_key(ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL),
        BoundPolynomialRootUse::Input,
    )?;
    let aggregate_round_one_left_source_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        &statement_root_key(AGGREGATE_ROUND_ONE_LEFT_ROOT_FIELD_ORDINAL),
        BoundPolynomialRootUse::Input,
    )?;
    let aggregate_round_one_right_source_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        &statement_root_key(AGGREGATE_ROUND_ONE_RIGHT_ROOT_FIELD_ORDINAL),
        BoundPolynomialRootUse::Input,
    )?;
    let round_two_source_rows = add_statement_root_rows(
        &mut builder,
        &input.geometry,
        &statement_root_key(ROUND_TWO_ROOT_FIELD_ORDINAL),
        BoundPolynomialRootUse::Output,
    )?;
    let (round_one_errors_by_block, round_one_quotients_by_row) = add_round_one_relations(
        &mut builder,
        &input.geometry,
        input.schedule_position,
        &round_one_left_source_rows,
        &round_one_right_source_rows,
        &secret,
        &ephemeral_secret,
        check_context,
    )?;
    let (aggregate_rows, round_two_errors_by_block, round_two_quotients_by_row) =
        add_round_two_relations(
            &mut builder,
            &input.geometry,
            &round_two_source_rows,
            &aggregate_round_one_left_source_rows,
            &aggregate_round_one_right_source_rows,
            &secret,
            &ephemeral_secret,
            check_context,
        )?;
    let ordered_anchors =
        add_anchor_relations(&mut builder, &input.geometry, &secret, check_context)?;
    let exact_radix_digits_by_column = builder
        .exact_radix_digits_by_column()
        .iter()
        .map(|(column_ordinal, digit_column_ordinals)| {
            (
                *column_ordinal,
                digit_column_ordinals.clone().into_boxed_slice(),
            )
        })
        .collect();
    let relation_plan = builder.finish()?;
    Ok(CompiledRelinearizationRoundTwoRelation {
        relation_plan,
        source_layout: RelinearizationRoundTwoSourceLayout {
            common_secret: secret,
            ephemeral_secret,
            round_one_left_rows: round_one_left_source_rows.into_boxed_slice(),
            round_one_right_rows: round_one_right_source_rows.into_boxed_slice(),
            aggregate_round_one_left_rows: aggregate_round_one_left_source_rows.into_boxed_slice(),
            aggregate_round_one_right_rows: aggregate_round_one_right_source_rows
                .into_boxed_slice(),
            round_two_rows: round_two_source_rows.into_boxed_slice(),
            round_one_errors_by_block,
            round_one_quotients_by_row,
            aggregate_rows,
            round_two_errors_by_block,
            round_two_quotients_by_row,
            ordered_anchors: ordered_anchors.into_boxed_slice(),
            exact_radix_digits_by_column,
        },
    })
}

pub(crate) fn compile_galois_key_share_relation_plan(
    input: &GaloisKeyShareRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    compile_galois_key_share_relation_with_source_layout(input, check_context)
        .map(|compiled| compiled.relation_plan)
}

pub(crate) fn compile_galois_key_share_relation_with_source_layout(
    input: &GaloisKeyShareRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledGaloisKeyShareRelation, RelationPlanError> {
    let expected_entries = selected_galois_key_share_relation_schedule()?
        .into_iter()
        .enumerate()
        .map(|(schedule_position, (galois_element, selected_level))| {
            Ok((
                u32::try_from(schedule_position).map_err(|_| RelationPlanError::CountOverflow)?,
                galois_element,
                selected_level,
            ))
        })
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    compile_galois_key_share_relation_batch(
        input,
        check_context,
        SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION,
        &expected_entries,
    )
}

fn compile_galois_key_share_relation_batch(
    input: &GaloisKeyShareRelationPlanInput,
    check_context: &RelationPlanCheckContext,
    expected_batch_schedule_position: u32,
    expected_entries: &[(u32, u64, usize)],
) -> Result<CompiledGaloisKeyShareRelation, RelationPlanError> {
    input.geometry.validate_common(check_context)?;
    input.geometry.validate_round_one_quotient_bounds()?;
    if input.batch_schedule_position != expected_batch_schedule_position
        || input.ordered_entries.len() != expected_entries.len()
        || expected_entries.is_empty()
    {
        return Err(RelationPlanError::NonCanonicalOrder);
    }
    let automorphism_modulus = input
        .geometry
        .ring_degree
        .checked_mul(2)
        .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    for entry in &input.ordered_entries {
        if entry.galois_element <= 1
            || entry.galois_element >= automorphism_modulus
            || entry.galois_element.is_multiple_of(2)
        {
            return Err(RelationPlanError::InvalidDomain);
        }
    }
    for (entry, expected_entry) in input.ordered_entries.iter().zip(expected_entries) {
        if entry.schedule_position != expected_entry.0 || entry.galois_element != expected_entry.1 {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        if entry.selected_level != expected_entry.2 {
            return Err(RelationPlanError::InvalidDomain);
        }
    }
    let maximum_selected_level = input
        .ordered_entries
        .iter()
        .map(|entry| entry.selected_level)
        .max()
        .ok_or(RelationPlanError::InvalidDomain)?;
    if input
        .geometry
        .selected_catalog_prefix(maximum_selected_level)?
        != input.geometry
    {
        return Err(RelationPlanError::InvalidDomain);
    }
    let entry_geometries = input
        .ordered_entries
        .iter()
        .map(|entry| {
            let geometry = input
                .geometry
                .selected_catalog_prefix(entry.selected_level)?;
            geometry.validate_common(check_context)?;
            geometry.validate_round_one_quotient_bounds()?;
            Ok(geometry)
        })
        .collect::<Result<Vec<_>, RelationPlanError>>()?;

    let mut sources = Vec::new();
    for (entry_ordinal, (entry, entry_geometry)) in input
        .ordered_entries
        .iter()
        .zip(&entry_geometries)
        .enumerate()
    {
        let entry_ordinal =
            u64::try_from(entry_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        sources.push(nested_statement_root_source(
            GALOIS_KEY_SHARE_ROOT_FIELD_ORDINAL,
            entry_ordinal,
            GALOIS_KEY_SHARE_ENTRY_ROOT_FIELD_ORDINAL,
        ));
        append_galois_relation_sources(
            &mut sources,
            entry_geometry,
            entry.schedule_position,
            entry.galois_element,
        )?;
    }
    append_anchor_relation_sources(&mut sources, &input.geometry)?;
    let geometry = input
        .geometry
        .key_relation_geometry(input.batch_schedule_position)?;
    let mut builder = KeyRelationPlanBuilder::new(
        GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        check_context,
        sources,
    )?;
    #[cfg(test)]
    let relation_started = std::time::Instant::now();
    let secret = builder.add_reversible_signed_ternary_vector()?;
    let mut entry_source_layouts = Vec::with_capacity(input.ordered_entries.len());
    for (entry_ordinal, (entry, entry_geometry)) in input
        .ordered_entries
        .iter()
        .zip(entry_geometries)
        .enumerate()
    {
        #[cfg(test)]
        let entry_started = std::time::Instant::now();
        let automorphed_secret = builder.add_signed_ternary_vector()?;
        builder.add_negacyclic_automorphism_permutation(
            &KeyVerifierSourceKey::NegacyclicAutomorphismMapping {
                ring_degree: input.geometry.ring_degree,
                galois_element: entry.galois_element,
            },
            entry.galois_element,
            &secret,
            &automorphed_secret,
        )?;
        let galois_key_share_source_rows = add_statement_root_rows(
            &mut builder,
            &entry_geometry,
            &nested_statement_root_key(
                GALOIS_KEY_SHARE_ROOT_FIELD_ORDINAL,
                u64::try_from(entry_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                GALOIS_KEY_SHARE_ENTRY_ROOT_FIELD_ORDINAL,
            ),
            BoundPolynomialRootUse::Output,
        )?;
        let (errors_by_block, quotients_by_row) = add_galois_relations(
            &mut builder,
            &entry_geometry,
            entry.schedule_position,
            &galois_key_share_source_rows,
            &secret,
            &automorphed_secret,
            check_context,
        )?;
        entry_source_layouts.push(GaloisKeyShareEntrySourceLayout {
            schedule_position: entry.schedule_position,
            galois_element: entry.galois_element,
            selected_level: entry.selected_level,
            relation_geometry: entry_geometry,
            automorphed_secret,
            bound_rows: galois_key_share_source_rows.into_boxed_slice(),
            errors_by_block,
            quotients_by_row,
        });
        #[cfg(test)]
        eprintln!(
            "key relation Galois entry {entry_ordinal}: {:?}",
            entry_started.elapsed()
        );
    }
    #[cfg(test)]
    let anchor_started = std::time::Instant::now();
    let anchor_source_layouts =
        add_anchor_relations(&mut builder, &input.geometry, &secret, check_context)?;
    #[cfg(test)]
    eprintln!(
        "key relation Galois anchors: {:?}; relations before finish: {:?}",
        anchor_started.elapsed(),
        relation_started.elapsed()
    );
    let exact_radix_digits_by_column = builder
        .exact_radix_digits_by_column()
        .iter()
        .map(|(column_ordinal, digit_column_ordinals)| {
            (
                *column_ordinal,
                digit_column_ordinals.clone().into_boxed_slice(),
            )
        })
        .collect();
    let relation_plan = builder.finish()?;
    Ok(CompiledGaloisKeyShareRelation {
        relation_plan,
        source_layout: GaloisKeyShareSourceLayout {
            common_secret: secret,
            ordered_entries: entry_source_layouts.into_boxed_slice(),
            ordered_anchors: anchor_source_layouts.into_boxed_slice(),
            exact_radix_digits_by_column,
        },
    })
}

#[cfg(test)]
pub(crate) fn compile_galois_key_share_relation_topology_comparison(
    input: &GaloisKeyShareRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledGaloisKeyShareRelation, RelationPlanError> {
    let expected_entries = input
        .ordered_entries
        .iter()
        .map(|entry| {
            (
                entry.schedule_position,
                entry.galois_element,
                entry.selected_level,
            )
        })
        .collect::<Vec<_>>();
    compile_galois_key_share_relation_batch(
        input,
        check_context,
        input.batch_schedule_position,
        &expected_entries,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use num_bigint::BigInt;

    use super::super::key_relation::{
        EXACT_INTEGER_LIFT_RADIX, TRUSTEE_QUOTIENT_HIGH_RADIX, TRUSTEE_QUOTIENT_LOW_TRIT_COUNT,
    };
    use super::super::same_secret_anchor::tests::{
        TEST_EVALUATION_DOMAIN_SIZE, TEST_OPENING_DEGREE_BOUND_EXCLUSIVE, TEST_RING_DEGREE,
        check_context as key_relation_check_context,
    };
    use super::super::{
        BoundTreeRootUse, ModulusCatalog, RelationBoundCertificate, RelationColumnOrigin,
        RelationEmbeddingKind, RelationIntegerLiftCoefficient, RelationMaskKind,
        RelationMaskTargetClass, RelationSelectorPathStep, RelationTreeDescriptor,
        RelationVerifierSource, ResolvedSuiteModulus, SelectorPathStepKind, SignedIntegerInterval,
        apply_negacyclic_automorphism, negacyclic_automorphism_mapping_values,
        negacyclic_automorphism_semantics_match,
    };
    use super::*;
    use crate::bgv::{
        evaluator::top_k::{SCATTER_KEY_LEVEL, TRACE_KEY_LEVEL},
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
    };
    fn check_context() -> RelationPlanCheckContext {
        let mut context = key_relation_check_context(true);
        context.resolved_moduli.insert(
            3,
            ResolvedSuiteModulus::new(SuiteModulusReference::special(0), SPECIAL_PRIMES[0]),
        );
        context
    }

    fn geometry() -> TrusteeEvaluationKeyRelationGeometry {
        TrusteeEvaluationKeyRelationGeometry {
            ring_degree: TEST_RING_DEGREE,
            evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
            public_polynomial_column_degree_bound_exclusive: TEST_RING_DEGREE,
            data_moduli: vec![DATA_PRIMES[0], DATA_PRIMES[1], DATA_PRIMES[2]],
            special_moduli: vec![SPECIAL_PRIMES[0]],
            plaintext_modulus: 257,
            decomposition_blocks: vec![TrusteeEvaluationKeyDecompositionBlock {
                data_modulus_indices: vec![0, 1, 2],
            }],
            commitment_data_modulus_indices: vec![0, 1, 2],
            commitment_module_rank: 1,
        }
    }

    fn round_one_input() -> RelinearizationRoundOneRelationPlanInput {
        RelinearizationRoundOneRelationPlanInput {
            schedule_position: 3,
            geometry: geometry(),
        }
    }

    fn round_two_input() -> RelinearizationRoundTwoRelationPlanInput {
        RelinearizationRoundTwoRelationPlanInput {
            schedule_position: 3,
            geometry: geometry(),
        }
    }

    fn selected_galois_relation_geometry_level(
        evaluator_candidate: &EvaluatorCandidateInput,
    ) -> usize {
        evaluator_candidate
            .galois_key_schedule
            .iter()
            .map(|(_, catalog_level)| *catalog_level)
            .max()
            .expect("the selected Galois catalog is nonempty")
    }

    fn galois_input() -> GaloisKeyShareRelationPlanInput {
        let evaluator_candidate = EvaluatorCandidateInput::implemented()
            .expect("selected evaluator candidate is canonical");
        let selected_level = selected_galois_relation_geometry_level(&evaluator_candidate);
        assert_eq!(selected_level, TRACE_KEY_LEVEL);
        let relation_basis = trustee_evaluation_key_relation_basis_for_catalog_level(
            &evaluator_candidate,
            selected_level,
        )
        .expect("selected Galois key-share relation basis");
        GaloisKeyShareRelationPlanInput {
            batch_schedule_position: SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION,
            ordered_entries: evaluator_candidate
                .galois_key_schedule
                .iter()
                .copied()
                .enumerate()
                .map(|(schedule_position, (galois_element, selected_level))| {
                    GaloisKeyShareRelationEntryInput {
                        schedule_position: u32::try_from(schedule_position)
                            .expect("selected Galois schedule position fits u32"),
                        galois_element: u64::try_from(galois_element)
                            .expect("selected Galois element fits u64"),
                        selected_level,
                    }
                })
                .collect(),
            geometry: TrusteeEvaluationKeyRelationGeometry {
                ring_degree: u64::try_from(POLYNOMIAL_DEGREE)
                    .expect("selected ring degree fits u64"),
                evaluation_domain_size:
                    crate::bgv::proof_suite::selected_profile::SELECTED_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: crate::bgv::proof_suite::selected_profile::SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
                public_polynomial_column_degree_bound_exclusive: crate::bgv::proof_suite::selected_profile::SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
                data_moduli: relation_basis.data_moduli,
                special_moduli: relation_basis.special_moduli,
                plaintext_modulus: evaluator_candidate.plaintext_modulus,
                decomposition_blocks: relation_basis.decomposition_blocks,
                commitment_data_modulus_indices: SETUP_COMMITMENT_MODULUS_LIMB_INDICES
                    .iter()
                    .copied()
                    .map(|modulus_index| {
                        u16::try_from(modulus_index)
                            .expect("selected commitment-modulus index fits u16")
                    })
                    .collect(),
                commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
                    .expect("selected commitment rank fits u16"),
            },
        }
    }

    #[test]
    fn selected_family_bases_follow_the_exact_catalog_levels_and_galois_order() {
        let evaluator_candidate = EvaluatorCandidateInput::implemented()
            .expect("selected evaluator candidate is canonical");
        let [relinearization_catalog_level] = evaluator_candidate.relinearization_levels.as_slice()
        else {
            panic!("the selected suite has exactly one relinearization catalog position");
        };
        assert_eq!(evaluator_candidate.galois_key_schedule.len(), 6);
        assert_eq!(
            evaluator_candidate
                .galois_key_schedule
                .iter()
                .map(|(_, level)| *level)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([SCATTER_KEY_LEVEL, TRACE_KEY_LEVEL]),
        );
        assert_eq!(
            evaluator_candidate
                .galois_key_schedule
                .iter()
                .map(|(galois_element, _)| *galois_element)
                .collect::<BTreeSet<_>>()
                .len(),
            evaluator_candidate.galois_key_schedule.len(),
            "the selected Galois catalog must not repeat an automorphism"
        );

        let relinearization_basis = trustee_evaluation_key_relation_basis_for_catalog_level(
            &evaluator_candidate,
            *relinearization_catalog_level,
        )
        .expect("selected relinearization relation basis");
        let mut family_bases = vec![(*relinearization_catalog_level, relinearization_basis)];
        family_bases.extend(
            evaluator_candidate
                .galois_key_schedule
                .iter()
                .map(|(_, catalog_level)| *catalog_level)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|catalog_level| {
                    (
                        catalog_level,
                        trustee_evaluation_key_relation_basis_for_catalog_level(
                            &evaluator_candidate,
                            catalog_level,
                        )
                        .expect("selected Galois relation basis"),
                    )
                }),
        );
        for (catalog_level, basis) in family_bases {
            assert_eq!(basis.data_moduli.len(), catalog_level + 1);
            assert_eq!(
                basis.data_moduli,
                evaluator_candidate.data_primes[..=catalog_level]
            );
            assert_eq!(basis.special_moduli, evaluator_candidate.special_primes);
            assert_eq!(
                basis
                    .decomposition_blocks
                    .iter()
                    .flat_map(|block| block.data_modulus_indices.iter().copied())
                    .collect::<Vec<_>>(),
                (0..=catalog_level)
                    .map(|modulus_index| u16::try_from(modulus_index)
                        .expect("selected modulus index fits u16"))
                    .collect::<Vec<_>>()
            );
        }

        assert_eq!(
            selected_galois_key_share_relation_schedule()
                .expect("selected Galois relation schedule"),
            evaluator_candidate
                .galois_key_schedule
                .iter()
                .map(|(galois_element, catalog_level)| {
                    (
                        u64::try_from(*galois_element).expect("Galois element fits u64"),
                        *catalog_level,
                    )
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(selected_galois_key_share_batch_schedule(), [0]);
    }

    fn semantic_cells_by_column(
        variant: &super::super::RelationPlanVariant,
    ) -> BTreeMap<u32, &super::super::SemanticCellDescriptor> {
        variant
            .ordered_semantic_cells
            .iter()
            .map(|cell| (cell.column_ordinal, cell))
            .collect()
    }

    fn assert_radix_three_quotients(variant: &super::super::RelationPlanVariant) {
        let semantic_cells = semantic_cells_by_column(variant);
        let mut component_count = 0_usize;
        let mut low_quotient_columns = BTreeSet::new();
        let mut high_carry_columns = BTreeSet::new();
        let mut outgoing_recurrence_carry_counts = BTreeMap::new();
        let mut positive_unit_term_counts = BTreeMap::new();
        for batch in &variant.ordered_integer_lift_batches {
            for component in &batch.ordered_components {
                component_count += 1;
                for term in &component.ordered_linear_terms {
                    match term.coefficient {
                        RelationIntegerLiftCoefficient::Modulus { .. } => {
                            panic!("wide modulus coefficients must be radix-expanded")
                        }
                        RelationIntegerLiftCoefficient::ModulusRadixDigit {
                            modulus_reference,
                            multiplier,
                            radix,
                            ..
                        } if term.negative
                            && modulus_reference == batch.modulus_reference
                            && radix == EXACT_INTEGER_LIFT_RADIX =>
                        {
                            let semantic_cell = semantic_cells
                                .get(&term.column_ordinal)
                                .expect("exact quotient semantic cell");
                            if multiplier == 1
                                && matches!(
                                    &semantic_cell.bound_certificate,
                                    RelationBoundCertificate::ShiftedRadixRecomposition {
                                        radix: 3,
                                        ordered_digit_column_ordinals,
                                        ..
                                    } if ordered_digit_column_ordinals.len()
                                        == TRUSTEE_QUOTIENT_LOW_TRIT_COUNT
                                )
                            {
                                low_quotient_columns.insert(term.column_ordinal);
                            } else if multiplier == TRUSTEE_QUOTIENT_HIGH_RADIX {
                                assert_eq!(
                                    semantic_cell.claimed_interval,
                                    SignedIntegerInterval::new(-2, 2)
                                );
                                assert!(matches!(
                                    &semantic_cell.bound_certificate,
                                    RelationBoundCertificate::FiniteIntegerSet {
                                        ordered_values,
                                        ..
                                    } if ordered_values
                                        == &(-2..=2).map(BigInt::from).collect::<Vec<_>>()
                                ));
                                high_carry_columns.insert(term.column_ordinal);
                            }
                        }
                        RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
                            if term.negative =>
                        {
                            *outgoing_recurrence_carry_counts
                                .entry(term.column_ordinal)
                                .or_insert(0_usize) += 1;
                        }
                        RelationIntegerLiftCoefficient::Constant(1) if !term.negative => {
                            *positive_unit_term_counts
                                .entry(term.column_ordinal)
                                .or_insert(0_usize) += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
        assert!(component_count > 0);
        assert!(!low_quotient_columns.is_empty());
        assert!(!high_carry_columns.is_empty());
        assert!(!outgoing_recurrence_carry_counts.is_empty());
        for (carry_column_ordinal, outgoing_count) in outgoing_recurrence_carry_counts {
            assert_eq!(
                positive_unit_term_counts.get(&carry_column_ordinal),
                Some(&outgoing_count),
                "each outgoing radix carry must recur as the next limb's incoming carry"
            );
        }
    }

    #[test]
    fn round_one_plan_covers_all_limbs_with_shared_small_witnesses() {
        let context = check_context();
        let input = round_one_input();
        let plan = compile_relinearization_round_one_relation_plan(&input, &context)
            .expect("round-one relation plan");
        assert_eq!(
            plan.application_statement_schema_identifier(),
            RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
        );
        let variant = plan
            .select_variant(Some(3), None)
            .expect("scheduled round-one variant");
        for (tree_ordinal, expected_root_use) in
            [BoundTreeRootUse::Output, BoundTreeRootUse::Output]
                .into_iter()
                .enumerate()
        {
            let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                root_use,
                ..
            } = &variant.ordered_trees()[tree_ordinal]
            else {
                panic!("round-one component roots must be statement-bound trees");
            };
            assert_eq!(
                *expected_root_source_ordinal,
                u32::try_from(tree_ordinal).expect("root source ordinal fits u32")
            );
            assert_eq!(*root_use, expected_root_use);
        }
        let batch_moduli = variant
            .ordered_integer_lift_batches
            .iter()
            .map(|batch| batch.modulus_reference)
            .collect::<BTreeSet<_>>();
        let expected_batch_moduli =
            input
                .geometry
                .data_moduli
                .iter()
                .enumerate()
                .map(|(modulus_index, _)| {
                    SuiteModulusReference::data(
                        u16::try_from(modulus_index).expect("test data-modulus index fits u16"),
                    )
                })
                .chain(input.geometry.special_moduli.iter().enumerate().map(
                    |(modulus_index, _)| {
                        SuiteModulusReference::special(
                            u16::try_from(modulus_index)
                                .expect("test special-modulus index fits u16"),
                        )
                    },
                ))
                .collect::<BTreeSet<_>>();
        assert_eq!(batch_moduli, expected_batch_moduli);
        for source in &variant.ordered_verifier_sources {
            if let RelationVerifierSource::Protocol {
                protocol_source_kind: 5 | 7,
                value_layout,
                ..
            } = source
            {
                assert_eq!(
                    value_layout.embedding_kind,
                    RelationEmbeddingKind::LeastNonnegative
                );
            }
        }

        let mut round_one_small_multiplier_columns = BTreeSet::new();
        let mut anchor_multiplicands_by_modulus = BTreeMap::new();
        for batch in &variant.ordered_integer_lift_batches {
            let mut anchor_multiplicands = BTreeSet::new();
            for product in batch
                .ordered_components
                .iter()
                .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            {
                if product.multiplier_low_offset == 0 {
                    round_one_small_multiplier_columns
                        .insert(product.multiplier_low_column_ordinal);
                } else {
                    anchor_multiplicands.insert(product.multiplicand_low_column_ordinal);
                }
            }
            if batch.modulus_reference.catalog == ModulusCatalog::Data {
                assert_eq!(anchor_multiplicands.len(), 2);
                anchor_multiplicands_by_modulus
                    .insert(batch.modulus_reference, anchor_multiplicands);
            } else {
                assert!(anchor_multiplicands.is_empty());
            }
        }
        assert_eq!(round_one_small_multiplier_columns.len(), 2);
        assert_eq!(
            anchor_multiplicands_by_modulus.len(),
            input.geometry.data_moduli.len(),
            "every data modulus must have its own pair of anchor openings"
        );
        let data_modulus_anchor_multiplicands =
            anchor_multiplicands_by_modulus.values().collect::<Vec<_>>();
        for (left_index, left_multiplicands) in data_modulus_anchor_multiplicands.iter().enumerate()
        {
            for right_multiplicands in data_modulus_anchor_multiplicands
                .iter()
                .skip(left_index + 1)
            {
                assert!(
                    left_multiplicands.is_disjoint(right_multiplicands),
                    "each data modulus must bind a distinct pair of anchor openings"
                );
            }
        }
        assert_radix_three_quotients(variant);
    }

    #[test]
    fn round_two_plan_reproves_round_one_and_reuses_both_small_witnesses() {
        let context = check_context();
        let plan = compile_relinearization_round_two_relation_plan(&round_two_input(), &context)
            .expect("round-two relation plan");
        assert_eq!(
            plan.application_statement_schema_identifier(),
            RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER
        );
        let variant = plan
            .select_variant(Some(3), None)
            .expect("scheduled round-two variant");
        for (tree_ordinal, expected_root_use) in [
            BoundTreeRootUse::Input,
            BoundTreeRootUse::Input,
            BoundTreeRootUse::Input,
            BoundTreeRootUse::Input,
            BoundTreeRootUse::Output,
        ]
        .into_iter()
        .enumerate()
        {
            let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                root_use,
                ..
            } = &variant.ordered_trees()[tree_ordinal]
            else {
                panic!("round-two cross-round roots must be statement-bound trees");
            };
            assert_eq!(
                *expected_root_source_ordinal,
                u32::try_from(tree_ordinal).expect("root source ordinal fits u32")
            );
            assert_eq!(*root_use, expected_root_use);
        }
        let special_batch = variant
            .ordered_integer_lift_batches
            .iter()
            .find(|batch| batch.modulus_reference == SuiteModulusReference::special(0))
            .expect("special-limb batch");
        assert_eq!(
            special_batch.ordered_components.len(),
            24,
            "six exact special-modulus equations each expand into four radix limbs"
        );
        let round_one_small_columns = special_batch
            .ordered_components
            .iter()
            .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            .filter(|product| product.multiplier_low_offset == 0)
            .map(|product| product.multiplier_low_column_ordinal)
            .collect::<BTreeSet<_>>();
        let round_two_small_columns = special_batch
            .ordered_components
            .iter()
            .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            .filter(|product| product.multiplier_low_offset != 0)
            .map(|product| product.multiplicand_low_column_ordinal)
            .collect::<BTreeSet<_>>();
        assert_eq!(round_one_small_columns.len(), 2);
        assert_eq!(round_two_small_columns, round_one_small_columns);

        let semantic_cells = semantic_cells_by_column(variant);
        for product in special_batch
            .ordered_components
            .iter()
            .flat_map(|component| &component.ordered_full_ring_negacyclic_products)
            .filter(|product| product.multiplier_low_offset != 0)
        {
            assert!(matches!(
                semantic_cells
                    .get(&product.multiplier_low_column_ordinal)
                    .map(|cell| &cell.bound_certificate),
                Some(RelationBoundCertificate::UnsignedRadixRecomposition {
                    radix: 3,
                    ordered_digit_column_ordinals,
                    ..
                }) if !ordered_digit_column_ordinals.is_empty()
            ));
        }
        assert_radix_three_quotients(variant);
    }

    #[test]
    fn relation_inputs_reject_basis_and_quotient_bound_mutations() {
        let context = check_context();
        let mut repeated_data_limb = round_one_input();
        repeated_data_limb.geometry.decomposition_blocks[0].data_modulus_indices = vec![0, 0, 1];
        assert_eq!(
            compile_relinearization_round_one_relation_plan(&repeated_data_limb, &context,),
            Err(RelationPlanError::NonCanonicalOrder)
        );

        let mut wrong_special_modulus = round_one_input();
        wrong_special_modulus.geometry.special_moduli[0] -= 2;
        assert_eq!(
            compile_relinearization_round_one_relation_plan(&wrong_special_modulus, &context,),
            Err(RelationPlanError::InvalidModulus)
        );

        let mut unsupported_anchor_rank = round_one_input();
        unsupported_anchor_rank.geometry.commitment_module_rank = 2;
        assert_eq!(
            compile_relinearization_round_one_relation_plan(&unsupported_anchor_rank, &context,),
            Err(RelationPlanError::InvalidDomain)
        );
    }

    #[test]
    fn galois_relation_batches_the_exact_selected_schedule_with_one_shared_anchor() {
        let context = crate::bgv::proof_suite::selected_relation_plan_check_context(
            GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("selected Galois-key-share proof context");
        let input = galois_input();
        let selected_galois_elements = selected_galois_key_share_relation_schedule()
            .expect("selected Galois-key-share relation schedule")
            .into_iter()
            .map(|(galois_element, _)| galois_element)
            .collect::<Vec<_>>();
        let compiled = compile_galois_key_share_relation_with_source_layout(&input, &context)
            .expect("exact Galois-key-share relation plan");
        let plan = compiled.relation_plan;
        assert_eq!(
            compiled
                .source_layout
                .ordered_entries
                .iter()
                .map(|entry| (
                    entry.selected_level,
                    entry.relation_geometry.data_moduli.len(),
                    entry.relation_geometry.decomposition_blocks.len(),
                ))
                .collect::<Vec<_>>(),
            input
                .ordered_entries
                .iter()
                .map(|entry| {
                    let entry_geometry = input
                        .geometry
                        .selected_catalog_prefix(entry.selected_level)
                        .expect("selected entry geometry");
                    (
                        entry.selected_level,
                        entry_geometry.data_moduli.len(),
                        entry_geometry.decomposition_blocks.len(),
                    )
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(
            plan.application_statement_schema_identifier(),
            GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        );
        let variant = plan
            .select_variant(Some(input.batch_schedule_position), None)
            .expect("scheduled Galois-key-share variant");
        let mut tree_roles_by_column = BTreeMap::new();
        for tree in variant.ordered_trees() {
            let role = match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role, ..
                } => format!("proof-created-{proof_tree_role}"),
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    root_use,
                    ..
                } => format!("bound-{construction_kind:?}-{root_use:?}"),
            };
            for column_ordinal in tree.ordered_column_ordinals() {
                tree_roles_by_column.insert(*column_ordinal, role.clone());
            }
        }
        let mut column_groups = BTreeMap::new();
        let mut relation_column_catalog_byte_length = 0_u64;
        for (column_ordinal, column) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal =
                u32::try_from(column_ordinal).expect("relation column ordinal fits u32");
            let origin = match column.origin() {
                RelationColumnOrigin::VerifierSequence { .. } => "verifier-sequence",
                RelationColumnOrigin::BoundTree { .. } => "bound-tree",
                RelationColumnOrigin::Prover => "prover",
            };
            let role = tree_roles_by_column
                .get(&column_ordinal)
                .map(String::as_str)
                .unwrap_or("no-tree");
            *column_groups
                .entry((
                    format!("{:?}", column.value_type()),
                    column.source_degree_bound_exclusive(),
                    origin,
                    role.to_owned(),
                ))
                .or_insert(0_usize) += 1;
            relation_column_catalog_byte_length += column.source_degree_bound_exclusive() * 8;
        }
        eprintln!("selected 0x1217 column groups: {column_groups:#?}");
        eprintln!(
            "selected 0x1217 relation column catalog byte length: {relation_column_catalog_byte_length}"
        );
        let prover_column_ordinals = variant
            .ordered_columns()
            .iter()
            .enumerate()
            .filter_map(|(column_ordinal, column)| {
                matches!(column.origin(), RelationColumnOrigin::Prover).then_some(
                    u32::try_from(column_ordinal).expect("prover column ordinal fits u32"),
                )
            })
            .collect::<Vec<_>>();
        let expected_prover_column_count = prover_column_ordinals.len();
        assert!(expected_prover_column_count > 0);
        let quotient_component_count = usize::try_from(context.quotient_component_count)
            .expect("quotient component count fits usize");
        assert_eq!(
            variant.ordered_masks().len(),
            expected_prover_column_count + quotient_component_count
        );
        for (trace_mask_ordinal, (mask, expected_column_ordinal)) in variant.ordered_masks()
            [..expected_prover_column_count]
            .iter()
            .zip(prover_column_ordinals)
            .enumerate()
        {
            assert_eq!(mask.mask_kind(), RelationMaskKind::Trace);
            assert_eq!(
                mask.mask_coordinate().purpose_class(),
                RelationMaskKind::Trace as u16
            );
            assert_eq!(
                mask.mask_coordinate().mask_ordinal(),
                u32::try_from(trace_mask_ordinal).expect("trace-mask ordinal fits u32")
            );
            assert_eq!(mask.target_class(), RelationMaskTargetClass::Column);
            assert_eq!(mask.target_ordinal(), expected_column_ordinal);
        }
        for (quotient_ordinal, mask) in variant.ordered_masks()[expected_prover_column_count
            ..expected_prover_column_count + quotient_component_count - 1]
            .iter()
            .enumerate()
        {
            assert_eq!(mask.mask_kind(), RelationMaskKind::Telescoping);
            assert_eq!(
                mask.mask_coordinate().purpose_class(),
                RelationMaskKind::Telescoping as u16
            );
            assert_eq!(
                mask.mask_coordinate().mask_ordinal(),
                u32::try_from(quotient_ordinal).expect("telescoping-mask ordinal fits u32")
            );
            assert_eq!(
                mask.target_class(),
                RelationMaskTargetClass::QuotientComponent
            );
            assert_eq!(
                mask.target_ordinal(),
                u32::try_from(quotient_ordinal).expect("quotient ordinal fits u32")
            );
        }
        let opening_mask = variant
            .ordered_masks()
            .last()
            .expect("Galois relation opening-batch mask");
        assert_eq!(opening_mask.mask_kind(), RelationMaskKind::OpeningBatch);
        assert_eq!(
            opening_mask.mask_coordinate().purpose_class(),
            RelationMaskKind::OpeningBatch as u16
        );
        assert_eq!(opening_mask.mask_coordinate().mask_ordinal(), 0);
        assert_eq!(opening_mask.target_class(), RelationMaskTargetClass::Batch);
        assert_eq!(opening_mask.target_ordinal(), 0);
        for batch in &variant.ordered_integer_lift_batches {
            assert_eq!(
                batch.ordered_negacyclic_automorphism_permutations.len(),
                selected_galois_elements.len()
                    * usize::from(batch.modulus_reference == SuiteModulusReference::data(0))
            );
        }
        let permutations = &variant
            .ordered_integer_lift_batches
            .iter()
            .find(|batch| batch.modulus_reference == SuiteModulusReference::data(0))
            .expect("first data-limb batch")
            .ordered_negacyclic_automorphism_permutations;
        assert_eq!(
            permutations
                .iter()
                .map(|permutation| {
                    (
                        permutation.source_low_column_ordinal,
                        permutation.source_high_column_ordinal,
                    )
                })
                .collect::<BTreeSet<_>>()
                .len(),
            1,
            "every Galois entry must reuse one trustee secret witness"
        );
        assert_eq!(
            permutations
                .iter()
                .map(|permutation| {
                    (
                        permutation.target_low_column_ordinal,
                        permutation.target_high_column_ordinal,
                    )
                })
                .collect::<BTreeSet<_>>()
                .len(),
            selected_galois_elements.len(),
            "every Galois entry must have a distinct automorphed-secret witness"
        );
        let mapping_sources = variant
            .ordered_verifier_sources
            .iter()
            .filter_map(|source| {
                if let RelationVerifierSource::NegacyclicAutomorphismMapping {
                    ring_degree,
                    galois_element,
                } = source
                    && *ring_degree == input.geometry.ring_degree
                {
                    Some(*galois_element)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            mapping_sources.iter().copied().collect::<BTreeSet<_>>(),
            selected_galois_elements
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            "canonical verifier-source order must retain every selected automorphism",
        );
        assert_eq!(
            mapping_sources.len(),
            selected_galois_elements.len(),
            "the canonical verifier-source catalog must not repeat an automorphism",
        );
        let entry_count = input.ordered_entries.len();
        let anchor_count = input.geometry.commitment_data_modulus_indices.len();
        let bound_tree_count = entry_count + anchor_count;
        assert_eq!(
            variant
                .ordered_trees()
                .iter()
                .filter(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
                .count(),
            bound_tree_count
        );
        for (bound_tree_ordinal, tree) in variant.ordered_trees()[..bound_tree_count]
            .iter()
            .enumerate()
        {
            let RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                root_use,
                ordered_column_ordinals,
                ..
            } = tree
            else {
                panic!("the leading Galois trees must be statement-bound");
            };
            if bound_tree_ordinal < entry_count {
                let entry_geometry = input
                    .geometry
                    .selected_catalog_prefix(
                        input.ordered_entries[bound_tree_ordinal].selected_level,
                    )
                    .expect("selected entry geometry");
                assert_eq!(
                    *expected_root_source_ordinal,
                    u32::try_from(bound_tree_ordinal + anchor_count)
                        .expect("Galois source ordinal fits u32")
                );
                assert_eq!(*root_use, BoundTreeRootUse::Output);
                assert_eq!(
                    ordered_column_ordinals.len(),
                    2 * entry_geometry.decomposition_blocks.len()
                        * (entry_geometry.data_moduli.len() + entry_geometry.special_moduli.len())
                );
            } else {
                assert_eq!(
                    *expected_root_source_ordinal,
                    u32::try_from(bound_tree_ordinal - entry_count)
                        .expect("anchor source ordinal fits u32")
                );
                assert_eq!(*root_use, BoundTreeRootUse::Input);
                assert_eq!(
                    ordered_column_ordinals.len(),
                    2 * (usize::from(input.geometry.commitment_module_rank) + 1)
                );
            }
        }
        let nested_root_paths = variant
            .ordered_verifier_sources
            .iter()
            .filter_map(|source| match source {
                RelationVerifierSource::ApplicationStatement { value_path, .. }
                    if value_path.len() == 3 =>
                {
                    Some(value_path)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(nested_root_paths.len(), entry_count);
        for (entry_ordinal, value_path) in nested_root_paths.into_iter().enumerate() {
            assert_eq!(
                value_path,
                &vec![
                    RelationSelectorPathStep::tuple_field(GALOIS_KEY_SHARE_ROOT_FIELD_ORDINAL),
                    RelationSelectorPathStep {
                        step_kind: SelectorPathStepKind::LiteralListIndex,
                        argument: u64::try_from(entry_ordinal)
                            .expect("Galois entry ordinal fits u64"),
                    },
                    RelationSelectorPathStep::tuple_field(
                        GALOIS_KEY_SHARE_ENTRY_ROOT_FIELD_ORDINAL,
                    ),
                ]
            );
        }
        let mut common_reference_count_by_schedule_position = vec![0_usize; entry_count];
        for source in &variant.ordered_verifier_sources {
            if let RelationVerifierSource::Protocol {
                protocol_source_kind: 8,
                source_coordinates,
                ..
            } = source
            {
                assert_eq!(source_coordinates.len(), 4);
                let schedule_position = usize::try_from(source_coordinates[0])
                    .expect("Galois source schedule position fits usize");
                assert!(schedule_position < entry_count);
                common_reference_count_by_schedule_position[schedule_position] += 1;
            }
        }
        assert_eq!(
            common_reference_count_by_schedule_position,
            input
                .ordered_entries
                .iter()
                .map(|entry| {
                    let entry_geometry = input
                        .geometry
                        .selected_catalog_prefix(entry.selected_level)
                        .expect("selected entry geometry");
                    entry_geometry.decomposition_blocks.len()
                        * entry_geometry
                            .ordered_modulus_references()
                            .expect("selected modulus order")
                            .len()
                })
                .collect::<Vec<_>>()
        );

        let mut even_automorphism = input.clone();
        even_automorphism.ordered_entries[0].galois_element = 4;
        assert_eq!(
            compile_galois_key_share_relation_plan(&even_automorphism, &context,),
            Err(RelationPlanError::InvalidDomain)
        );

        let mut reordered = input.clone();
        reordered.ordered_entries.swap(1, 2);
        assert_eq!(
            compile_galois_key_share_relation_plan(&reordered, &context),
            Err(RelationPlanError::NonCanonicalOrder)
        );

        let mut wrong_level = input;
        wrong_level.ordered_entries[2].selected_level = wrong_level.ordered_entries[2]
            .selected_level
            .checked_add(1)
            .expect("selected level increment fits usize");
        assert_eq!(
            compile_galois_key_share_relation_plan(&wrong_level, &context),
            Err(RelationPlanError::InvalidDomain)
        );

        let mut wrong_batch_schedule = galois_input();
        wrong_batch_schedule.batch_schedule_position += 1;
        assert_eq!(
            compile_galois_key_share_relation_plan(&wrong_batch_schedule, &context),
            Err(RelationPlanError::NonCanonicalOrder)
        );

        let mut incomplete = galois_input();
        incomplete.ordered_entries.pop();
        assert_eq!(
            compile_galois_key_share_relation_plan(&incomplete, &context),
            Err(RelationPlanError::NonCanonicalOrder)
        );

        let mut out_of_domain = galois_input();
        let out_of_domain_galois_element = out_of_domain
            .geometry
            .ring_degree
            .checked_mul(2)
            .and_then(|automorphism_modulus| automorphism_modulus.checked_add(1))
            .expect("selected out-of-domain Galois element fits u64");
        let out_of_domain_entry = out_of_domain
            .ordered_entries
            .last_mut()
            .expect("selected Galois schedule is not empty");
        out_of_domain_entry.galois_element = out_of_domain_galois_element;
        assert_eq!(
            compile_galois_key_share_relation_plan(&out_of_domain, &context),
            Err(RelationPlanError::InvalidDomain)
        );
    }

    #[test]
    fn negacyclic_automorphism_semantics_match_an_independent_coefficient_oracle() {
        let mapping = negacyclic_automorphism_mapping_values(8, 3)
            .expect("deterministic automorphism mapping");
        assert_eq!(
            mapping,
            vec![
                0, 3, 6, 1, 0, 0, 0, 1, 4, 7, 2, 5, 1, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7,
            ]
        );
        let source = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let expected = vec![1, -4, 7, 2, -5, 8, 3, -6];
        assert_eq!(
            apply_negacyclic_automorphism(&source, 3).expect("coefficient automorphism"),
            expected
        );
        assert!(
            negacyclic_automorphism_semantics_match(&source, &expected, 3)
                .expect("matching automorphism")
        );
        let mut mutated = expected;
        mutated[5] += 1;
        assert!(
            !negacyclic_automorphism_semantics_match(&source, &mutated, 3)
                .expect("mutated automorphism")
        );
    }
}
