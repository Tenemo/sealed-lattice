use std::collections::{BTreeMap, BTreeSet};

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::poly::Poly;

use super::super::{
    RowCodeWhirAggregateColumnRole, RowCodeWhirBoundLowDegreeMode, RowCodeWhirConstructionPlan,
    RowCodeWhirOpenedPolynomialSource, RowCodeWhirSelectedParameters, RowCodeWhirTracePhasePlan,
};
use crate::bgv::proof_suite::relation_plan::{
    ProofPrivacyMode, RelationMaskKind, RelationMaskTargetClass, RelationOpeningSourceClass,
};
use crate::bgv::proof_suite::row_code_whir::{
    ChallengeField, algebra::polynomial_extension_opening_reduction,
    opening_schedule::divide_polynomial_opening,
    same_secret_source_manifest::SameSecretAuthenticatedSourceManifest,
};
use crate::bgv::proof_suite::{
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofTreeRole, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor,
};

const INDEPENDENT_BASIS_POINT_COUNT: usize = 3;
const SYNTHETIC_DIVISION_IDENTITY_COUNT: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProductionExtractorCorrespondenceFault {
    None,
    DropFirstRelationPhasePolynomial,
    ChangeFirstAggregateOpeningColumn,
    ChangeScalarOpeningCount,
    PermitProofSuppliedPoint,
    ChangeFirstPolynomialBasisIdentity,
    ChangeFirstSelectorBasisIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProductionPolynomialProtocolExtractorCertificate {
    construction_plan_identity_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    authenticated_source_manifest_hash: [u8; 64],
    authenticated_source_polynomial_count: u64,
    raw_authenticated_source_coefficient_position_count: u64,
    persisted_pre_challenge_source_coefficient_position_count: u64,
    deterministic_reversed_column_count: u64,
    stored_pre_challenge_column_count: u64,
    logical_polynomial_coefficient_count: usize,
    logical_polynomials_per_physical_row: usize,
    challenge_extension_degree: usize,
    relation_phase_presence: [bool; 3],
    relation_phase_row_counts: [usize; 3],
    relation_phase_polynomial_counts: [usize; 3],
    quotient_component_count: usize,
    quotient_component_degree_bound_exclusive: u64,
    opening_batch_mask_degree_bound_exclusive: Option<u64>,
    quotient_component_chunk_coordinate_count: usize,
    opening_batch_mask_chunk_coordinate_count: usize,
    bound_tree_counts_by_mode: [usize; 3],
    bound_polynomial_count: usize,
    bound_reduction_block_count: usize,
    bound_reduction_tree_coverage_count: usize,
    whir_epoch_codeword_count: usize,
    whir_fold_transition_count: usize,
    whir_code_state_count: usize,
    whir_epoch_query_counts: Vec<usize>,
    opening_batch_count: usize,
    scalar_opening_count: usize,
    polynomial_coefficient_variable_count: usize,
    polynomial_basis_identity_count: usize,
    synthetic_division_identity_count: usize,
    actual_pole_rejection_count: usize,
}

impl ProductionPolynomialProtocolExtractorCertificate {
    pub(super) fn is_complete(&self) -> bool {
        let expected_stored_column_count = self
            .authenticated_source_polynomial_count
            .checked_add(self.deterministic_reversed_column_count);
        let expected_quotient_coordinate_count = checked_coefficient_chunk_count(
            self.quotient_component_degree_bound_exclusive,
            self.logical_polynomial_coefficient_count,
        )
        .and_then(|chunk_count| chunk_count.checked_mul(self.quotient_component_count))
        .and_then(|coordinate_count| coordinate_count.checked_mul(self.challenge_extension_degree));
        let expected_mask_coordinate_count = match self.opening_batch_mask_degree_bound_exclusive {
            Some(degree_bound_exclusive) => checked_coefficient_chunk_count(
                degree_bound_exclusive,
                self.logical_polynomial_coefficient_count,
            )
            .and_then(|chunk_count| chunk_count.checked_mul(self.challenge_extension_degree)),
            None => Some(0),
        };
        let expected_bound_tree_count = self
            .bound_tree_counts_by_mode
            .iter()
            .try_fold(0_usize, |total, count| total.checked_add(*count));
        let expected_epoch_count = self.whir_epoch_query_counts.len();
        let phase_rows_are_complete = self
            .relation_phase_presence
            .iter()
            .zip(self.relation_phase_row_counts)
            .zip(self.relation_phase_polynomial_counts)
            .enumerate()
            .all(
                |(phase_index, ((is_present, row_count), polynomial_count))| {
                    if *is_present {
                        row_count > 0 && polynomial_count > 0
                    } else {
                        phase_index != 2 && row_count == 0 && polynomial_count == 0
                    }
                },
            );
        self.construction_plan_identity_hash != [0_u8; 64]
            && self.relation_plan_variant_hash != [0_u8; 64]
            && self.authenticated_source_manifest_hash != [0_u8; 64]
            && self.authenticated_source_polynomial_count > 0
            && self.raw_authenticated_source_coefficient_position_count > 0
            && self.persisted_pre_challenge_source_coefficient_position_count
                >= self.raw_authenticated_source_coefficient_position_count
            && expected_stored_column_count == Some(self.stored_pre_challenge_column_count)
            && self.logical_polynomial_coefficient_count.is_power_of_two()
            && self.logical_polynomials_per_physical_row.is_power_of_two()
            && self.challenge_extension_degree == PROOF_CHALLENGE_EXTENSION_DEGREE
            && self.relation_phase_presence[2]
            && phase_rows_are_complete
            && expected_quotient_coordinate_count
                == Some(self.quotient_component_chunk_coordinate_count)
            && expected_mask_coordinate_count
                == Some(self.opening_batch_mask_chunk_coordinate_count)
            && self
                .quotient_component_chunk_coordinate_count
                .checked_add(self.opening_batch_mask_chunk_coordinate_count)
                == Some(self.relation_phase_polynomial_counts[2])
            && expected_bound_tree_count == Some(self.bound_reduction_tree_coverage_count)
            && (self.bound_reduction_tree_coverage_count == 0) == (self.bound_polynomial_count == 0)
            && if self.bound_reduction_tree_coverage_count == 0 {
                self.bound_reduction_block_count == 0
            } else {
                self.bound_reduction_block_count > 0
            }
            && self.whir_epoch_codeword_count == expected_epoch_count
            && self.whir_epoch_codeword_count > 0
            && self.whir_fold_transition_count
                == self.whir_epoch_codeword_count.checked_mul(3).unwrap_or(0)
            && self.whir_code_state_count
                == self.whir_epoch_codeword_count.checked_mul(4).unwrap_or(0)
            && self.whir_epoch_query_counts.iter().all(|count| *count > 0)
            && self
                .whir_epoch_query_counts
                .windows(2)
                .all(|pair| pair[1] <= pair[0])
            && self.opening_batch_count > 0
            && self.scalar_opening_count >= self.opening_batch_count
            && self.polynomial_coefficient_variable_count
                == self.logical_polynomial_coefficient_count.ilog2() as usize
            && self.polynomial_basis_identity_count
                == INDEPENDENT_BASIS_POINT_COUNT
                    .checked_mul(self.logical_polynomial_coefficient_count)
                    .unwrap_or(0)
            && self.synthetic_division_identity_count == SYNTHETIC_DIVISION_IDENTITY_COUNT
            && self.actual_pole_rejection_count == 1
    }

    pub(super) const fn construction_plan_identity_hash(&self) -> [u8; 64] {
        self.construction_plan_identity_hash
    }

    pub(super) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(super) const fn relation_phase_row_counts(&self) -> [usize; 3] {
        self.relation_phase_row_counts
    }

    pub(super) const fn relation_phase_polynomial_counts(&self) -> [usize; 3] {
        self.relation_phase_polynomial_counts
    }

    pub(super) const fn bound_polynomial_count(&self) -> usize {
        self.bound_polynomial_count
    }

    pub(super) const fn opening_batch_count(&self) -> usize {
        self.opening_batch_count
    }

    pub(super) const fn scalar_opening_count(&self) -> usize {
        self.scalar_opening_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ProductionPointCoordinateAuthority {
    TranscriptOpeningPoint,
    TranscriptRowSelector,
    PolynomialOpeningReduction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProductionPointConstraintExtractorCertificate {
    construction_plan_identity_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    proof_privacy_mode: ProofPrivacyMode,
    explicit_point_count: usize,
    explicit_point_variable_count: usize,
    fixed_aggregate_selector_coordinate_count: usize,
    row_selector_coordinate_count: usize,
    coefficient_reduction_coordinate_count: usize,
    logical_polynomials_per_physical_row: usize,
    logical_polynomial_coefficient_count: usize,
    coordinate_authorities: BTreeSet<ProductionPointCoordinateAuthority>,
    proof_supplied_point_coordinate_count: usize,
    opening_point_aggregate_columns: Vec<u32>,
    quotient_active_point_count: usize,
    proof_created_tree_opening_claim_count: usize,
    bound_tree_opening_claim_count: usize,
    quotient_opening_claim_count: usize,
    opening_batch_mask_claim_count: usize,
    relation_opening_claim_count: usize,
    selector_equality_identity_count: usize,
}

impl ProductionPointConstraintExtractorCertificate {
    pub(super) fn is_complete(&self) -> bool {
        let expected_opening_point_columns = (0..self.explicit_point_count)
            .map(u32::try_from)
            .collect::<Result<Vec<_>, _>>()
            .ok();
        let expected_claim_count = self
            .proof_created_tree_opening_claim_count
            .checked_add(self.bound_tree_opening_claim_count)
            .and_then(|count| count.checked_add(self.quotient_opening_claim_count))
            .and_then(|count| count.checked_add(self.opening_batch_mask_claim_count));
        let expected_mask_claim_count = match self.proof_privacy_mode {
            ProofPrivacyMode::PublicOnly => 0,
            ProofPrivacyMode::SecretBearing => 1,
        };
        self.construction_plan_identity_hash != [0_u8; 64]
            && self.relation_plan_variant_hash != [0_u8; 64]
            && self.explicit_point_count > 0
            && self.explicit_point_variable_count
                == self
                    .fixed_aggregate_selector_coordinate_count
                    .checked_add(self.row_selector_coordinate_count)
                    .and_then(|count| {
                        count.checked_add(self.coefficient_reduction_coordinate_count)
                    })
                    .unwrap_or(usize::MAX)
            && self.fixed_aggregate_selector_coordinate_count == 1
            && self.logical_polynomials_per_physical_row.is_power_of_two()
            && self.logical_polynomial_coefficient_count.is_power_of_two()
            && self.row_selector_coordinate_count
                == self.logical_polynomials_per_physical_row.ilog2() as usize
            && self.coefficient_reduction_coordinate_count
                == self.logical_polynomial_coefficient_count.ilog2() as usize
            && self.coordinate_authorities
                == BTreeSet::from([
                    ProductionPointCoordinateAuthority::TranscriptOpeningPoint,
                    ProductionPointCoordinateAuthority::TranscriptRowSelector,
                    ProductionPointCoordinateAuthority::PolynomialOpeningReduction,
                ])
            && self.proof_supplied_point_coordinate_count == 0
            && expected_opening_point_columns == Some(self.opening_point_aggregate_columns.clone())
            && self.quotient_active_point_count > 0
            && self.quotient_active_point_count <= self.explicit_point_count
            && self.proof_created_tree_opening_claim_count > 0
            && self.quotient_opening_claim_count > 0
            && self.opening_batch_mask_claim_count == expected_mask_claim_count
            && expected_claim_count == Some(self.relation_opening_claim_count)
            && self.selector_equality_identity_count
                == INDEPENDENT_BASIS_POINT_COUNT
                    .checked_mul(self.logical_polynomials_per_physical_row)
                    .unwrap_or(0)
    }

    pub(super) const fn construction_plan_identity_hash(&self) -> [u8; 64] {
        self.construction_plan_identity_hash
    }

    pub(super) const fn relation_plan_variant_hash(&self) -> [u8; 64] {
        self.relation_plan_variant_hash
    }

    pub(super) const fn explicit_point_count(&self) -> usize {
        self.explicit_point_count
    }

    pub(super) const fn row_selector_coordinate_count(&self) -> usize {
        self.row_selector_coordinate_count
    }

    pub(super) const fn proof_supplied_point_coordinate_count(&self) -> usize {
        self.proof_supplied_point_coordinate_count
    }
}

fn checked_coefficient_chunk_count(
    degree_bound_exclusive: u64,
    logical_polynomial_coefficient_count: usize,
) -> Option<usize> {
    let chunk_size = u64::try_from(logical_polynomial_coefficient_count).ok()?;
    if degree_bound_exclusive == 0 || !logical_polynomial_coefficient_count.is_power_of_two() {
        return None;
    }
    usize::try_from(degree_bound_exclusive.checked_add(chunk_size - 1)? / chunk_size).ok()
}

fn expected_column_opening_points(
    variant: &RelationPlanVariant,
    column_ordinal: u32,
) -> Result<Vec<u32>, String> {
    let mut points = variant
        .ordered_opening_claims()
        .iter()
        .filter(|claim| {
            claim.source_class() == RelationOpeningSourceClass::TreeColumn
                && claim.column_ordinal() == Some(column_ordinal)
        })
        .map(|claim| claim.opening_point_ordinal())
        .collect::<Vec<_>>();
    points.sort_unstable();
    points.dedup();
    if points.is_empty() {
        return Err("production relation column has no opening point".to_owned());
    }
    Ok(points)
}

fn checked_trace_phase_polynomial_mapping(
    phase: &RowCodeWhirTracePhasePlan,
    variant: &RelationPlanVariant,
    parameters: RowCodeWhirSelectedParameters,
    expected_tree_role: ProofTreeRole,
    drop_first_polynomial: bool,
) -> Result<usize, String> {
    if phase.tree_role != expected_tree_role {
        return Err("production trace phase changes its proof-tree role".to_owned());
    }
    let mut expected_coordinates = BTreeSet::new();
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::ProofCreated {
            proof_tree_role,
            ordered_column_ordinals,
        } = tree
        else {
            continue;
        };
        if *proof_tree_role != expected_tree_role as u16 {
            continue;
        }
        for column_ordinal in ordered_column_ordinals {
            let column =
                variant
                    .ordered_columns()
                    .get(usize::try_from(*column_ordinal).map_err(|_| {
                        "production relation column ordinal exceeds usize".to_owned()
                    })?)
                    .ok_or_else(|| "production proof tree names an absent column".to_owned())?;
            let chunk_count = checked_coefficient_chunk_count(
                column.source_degree_bound_exclusive(),
                parameters.logical_polynomial_coefficient_count,
            )
            .ok_or_else(|| "production relation column chunk count is invalid".to_owned())?;
            for chunk_ordinal in 0..chunk_count {
                if !expected_coordinates.insert((
                    *column_ordinal,
                    u32::try_from(chunk_ordinal)
                        .map_err(|_| "production coefficient chunk exceeds u32".to_owned())?,
                )) {
                    return Err("production proof-created polynomial is duplicated".to_owned());
                }
            }
        }
    }
    if expected_coordinates.is_empty() {
        return Err("production trace phase has no relation polynomial".to_owned());
    }

    let mut observed_coordinates = BTreeSet::new();
    for row in &phase.rows {
        if row.logical_polynomial_chunks[parameters.logical_polynomials_per_physical_row..]
            .iter()
            .any(Option::is_some)
        {
            return Err("production trace phase uses a lane outside its selected width".to_owned());
        }
        let mut row_has_polynomial = false;
        for chunk in row.logical_polynomial_chunks
            [..parameters.logical_polynomials_per_physical_row]
            .iter()
            .flatten()
        {
            row_has_polynomial = true;
            if chunk.coefficient_chunk_ordinal != row.coefficient_chunk_ordinal
                || !observed_coordinates
                    .insert((chunk.column_ordinal, chunk.coefficient_chunk_ordinal))
            {
                return Err(
                    "production trace phase does not define a polynomial bijection".to_owned(),
                );
            }
            if expected_column_opening_points(variant, chunk.column_ordinal)?
                != row.opening_point_ordinals
            {
                return Err("production trace phase changes a column opening pattern".to_owned());
            }
        }
        if !row_has_polynomial {
            return Err("production trace phase contains an empty row".to_owned());
        }
    }
    if drop_first_polynomial {
        let first = observed_coordinates
            .first()
            .copied()
            .ok_or_else(|| "production trace phase has no polynomial to remove".to_owned())?;
        observed_coordinates.remove(&first);
    }
    if observed_coordinates != expected_coordinates {
        return Err("production trace phase omits or invents a relation polynomial".to_owned());
    }
    Ok(observed_coordinates.len())
}

fn opening_points_by_source(
    variant: &RelationPlanVariant,
    source_class: RelationOpeningSourceClass,
) -> Result<BTreeMap<u32, Vec<u32>>, String> {
    let mut points_by_source = BTreeMap::<u32, Vec<u32>>::new();
    for claim in variant.ordered_opening_claims() {
        if claim.source_class() != source_class {
            continue;
        }
        let points = points_by_source.entry(claim.source_ordinal()).or_default();
        if points.contains(&claim.opening_point_ordinal()) {
            return Err("production opening claim is duplicated".to_owned());
        }
        points.push(claim.opening_point_ordinal());
    }
    for points in points_by_source.values_mut() {
        points.sort_unstable();
    }
    Ok(points_by_source)
}

fn checked_quotient_phase_polynomial_mapping(
    plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(usize, usize), String> {
    if plan.quotient_phase.quotient_component_count != context.quotient_component_count
        || plan
            .quotient_phase
            .quotient_component_degree_bound_exclusive
            != context.quotient_component_degree_bound_exclusive
        || usize::from(context.challenge_extension_degree) != PROOF_CHALLENGE_EXTENSION_DEGREE
    {
        return Err("production quotient phase changes its checked relation geometry".to_owned());
    }
    let quotient_points = opening_points_by_source(variant, RelationOpeningSourceClass::Quotient)?;
    let mask_points = opening_points_by_source(variant, RelationOpeningSourceClass::BatchMask)?;
    let quotient_chunk_count = checked_coefficient_chunk_count(
        context.quotient_component_degree_bound_exclusive,
        plan.parameters.logical_polynomial_coefficient_count,
    )
    .ok_or_else(|| "production quotient chunk count is invalid".to_owned())?;
    let mut expected_quotient_coordinates = BTreeSet::new();
    for component_ordinal in 0..context.quotient_component_count {
        if !quotient_points.contains_key(&component_ordinal) {
            return Err("production quotient component has no opening claim".to_owned());
        }
        for chunk_ordinal in 0..quotient_chunk_count {
            for extension_coordinate_ordinal in 0..context.challenge_extension_degree {
                expected_quotient_coordinates.insert((
                    component_ordinal,
                    u32::try_from(chunk_ordinal)
                        .map_err(|_| "production quotient chunk exceeds u32".to_owned())?,
                    extension_coordinate_ordinal,
                ));
            }
        }
    }

    let opening_batch_masks = variant
        .ordered_masks()
        .iter()
        .copied()
        .filter(|mask| mask.mask_kind() == RelationMaskKind::OpeningBatch)
        .collect::<Vec<_>>();
    let mut expected_mask_coordinates = BTreeSet::new();
    match variant.proof_privacy_mode() {
        ProofPrivacyMode::PublicOnly => {
            if !opening_batch_masks.is_empty()
                || !mask_points.is_empty()
                || plan
                    .quotient_phase
                    .opening_batch_mask_degree_bound_exclusive
                    .is_some()
            {
                return Err("public production quotient phase contains a private mask".to_owned());
            }
        }
        ProofPrivacyMode::SecretBearing => {
            let [mask] = opening_batch_masks.as_slice() else {
                return Err("secret production quotient phase lacks one opening mask".to_owned());
            };
            if mask.target_class() != RelationMaskTargetClass::Batch
                || mask.target_ordinal() != 0
                || plan
                    .quotient_phase
                    .opening_batch_mask_degree_bound_exclusive
                    != Some(mask.mask_degree_bound_exclusive())
            {
                return Err("production opening mask changes its target or degree".to_owned());
            }
            let mask_ordinal = mask.mask_coordinate().mask_ordinal();
            if !mask_points.contains_key(&mask_ordinal) {
                return Err("production opening mask has no opening claim".to_owned());
            }
            let mask_chunk_count = checked_coefficient_chunk_count(
                mask.mask_degree_bound_exclusive(),
                plan.parameters.logical_polynomial_coefficient_count,
            )
            .ok_or_else(|| "production opening-mask chunk count is invalid".to_owned())?;
            for chunk_ordinal in 0..mask_chunk_count {
                for extension_coordinate_ordinal in 0..context.challenge_extension_degree {
                    expected_mask_coordinates.insert((
                        mask_ordinal,
                        u32::try_from(chunk_ordinal)
                            .map_err(|_| "production mask chunk exceeds u32".to_owned())?,
                        extension_coordinate_ordinal,
                    ));
                }
            }
        }
    }

    let mut observed_quotient_coordinates = BTreeSet::new();
    let mut observed_mask_coordinates = BTreeSet::new();
    for row in &plan.quotient_phase.rows {
        if usize::from(row.extension_coordinate_ordinal) >= PROOF_CHALLENGE_EXTENSION_DEGREE
            || row.logical_polynomial_chunks[plan.parameters.logical_polynomials_per_physical_row..]
                .iter()
                .any(Option::is_some)
        {
            return Err("production quotient row exceeds its selected geometry".to_owned());
        }
        let mut row_has_polynomial = false;
        for chunk in row.logical_polynomial_chunks
            [..plan.parameters.logical_polynomials_per_physical_row]
            .iter()
            .flatten()
        {
            row_has_polynomial = true;
            match chunk.source {
                RowCodeWhirOpenedPolynomialSource::QuotientComponent { component_ordinal } => {
                    if row.source_class != RelationOpeningSourceClass::Quotient
                        || quotient_points.get(&component_ordinal)
                            != Some(&row.opening_point_ordinals)
                        || !observed_quotient_coordinates.insert((
                            component_ordinal,
                            chunk.coefficient_chunk_ordinal,
                            row.extension_coordinate_ordinal,
                        ))
                    {
                        return Err(
                            "production quotient coordinate map is not bijective".to_owned()
                        );
                    }
                }
                RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { mask_ordinal } => {
                    if row.source_class != RelationOpeningSourceClass::BatchMask
                        || mask_points.get(&mask_ordinal) != Some(&row.opening_point_ordinals)
                        || !observed_mask_coordinates.insert((
                            mask_ordinal,
                            chunk.coefficient_chunk_ordinal,
                            row.extension_coordinate_ordinal,
                        ))
                    {
                        return Err(
                            "production opening-mask coordinate map is not bijective".to_owned()
                        );
                    }
                }
            }
        }
        if !row_has_polynomial {
            return Err("production quotient phase contains an empty row".to_owned());
        }
    }
    if observed_quotient_coordinates != expected_quotient_coordinates
        || observed_mask_coordinates != expected_mask_coordinates
    {
        return Err(
            "production quotient phase omits or invents a polynomial coordinate".to_owned(),
        );
    }
    Ok((
        observed_quotient_coordinates.len(),
        observed_mask_coordinates.len(),
    ))
}

fn checked_bound_polynomial_mapping(
    plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
) -> Result<([usize; 3], usize, usize, usize), String> {
    let mut observed_relation_tree_ordinals = BTreeSet::new();
    let mut observed_columns = BTreeSet::new();
    let mut counts_by_mode = [0_usize; 3];
    for (expected_bound_tree_ordinal, tree) in plan.bound_trees.iter().enumerate() {
        if tree.bound_tree_ordinal
            != u32::try_from(expected_bound_tree_ordinal)
                .map_err(|_| "production bound-tree ordinal exceeds u32".to_owned())?
            || !observed_relation_tree_ordinals.insert(tree.relation_tree_ordinal)
        {
            return Err("production bound-tree ordinal map is not bijective".to_owned());
        }
        let relation_tree = variant
            .ordered_trees()
            .get(
                usize::try_from(tree.relation_tree_ordinal)
                    .map_err(|_| "production relation-tree ordinal exceeds usize".to_owned())?,
            )
            .ok_or_else(|| "production bound tree has no relation owner".to_owned())?;
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            expected_root_source_ordinal,
            root_use,
            ordered_column_ordinals,
        } = relation_tree
        else {
            return Err("production bound tree maps to a proof-created relation tree".to_owned());
        };
        if tree.construction_kind != *construction_kind
            || tree.expected_root_source_ordinal != *expected_root_source_ordinal
            || tree.root_use != *root_use
            || tree.ordered_columns.len() != ordered_column_ordinals.len()
        {
            return Err("production bound tree changes its relation geometry".to_owned());
        }
        let mode_index = match tree.low_degree_mode {
            RowCodeWhirBoundLowDegreeMode::PriorVssProofRequired => 0,
            RowCodeWhirBoundLowDegreeMode::PriorSetupPolynomialProofRequired => 1,
            RowCodeWhirBoundLowDegreeMode::Direct => 2,
        };
        counts_by_mode[mode_index] = counts_by_mode[mode_index]
            .checked_add(1)
            .ok_or_else(|| "production bound-tree count overflowed".to_owned())?;
        for (column, expected_column_ordinal) in
            tree.ordered_columns.iter().zip(ordered_column_ordinals)
        {
            let relation_column = variant
                .ordered_columns()
                .get(
                    usize::try_from(*expected_column_ordinal)
                        .map_err(|_| "production bound column ordinal exceeds usize".to_owned())?,
                )
                .ok_or_else(|| "production bound relation column is absent".to_owned())?;
            if column.column_ordinal != *expected_column_ordinal
                || column.value_type != relation_column.value_type()
                || column.source_degree_bound_exclusive
                    != relation_column.source_degree_bound_exclusive()
                || column.opening_point_ordinals
                    != expected_column_opening_points(variant, *expected_column_ordinal)?
                || !observed_columns.insert(column.column_ordinal)
            {
                return Err("production bound polynomial map is not bijective".to_owned());
            }
        }
    }
    let expected_relation_tree_ordinals = variant
        .ordered_trees()
        .iter()
        .enumerate()
        .filter(|(_, tree)| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
        .map(|(tree_index, _)| u32::try_from(tree_index))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| "production relation-tree ordinal exceeds u32".to_owned())?;
    if observed_relation_tree_ordinals != expected_relation_tree_ordinals {
        return Err("production bound tree extraction omits a relation tree".to_owned());
    }

    let mut reduction_tree_ordinals = BTreeSet::new();
    for block in &plan.bound_reduction_blocks {
        if block.ordered_bound_tree_ordinals.is_empty() {
            return Err("production bound-reduction block is empty".to_owned());
        }
        for bound_tree_ordinal in &block.ordered_bound_tree_ordinals {
            let tree = plan
                .bound_trees
                .get(usize::try_from(*bound_tree_ordinal).map_err(|_| {
                    "production bound-tree reduction ordinal exceeds usize".to_owned()
                })?)
                .ok_or_else(|| "production bound reduction names an absent tree".to_owned())?;
            if tree.low_degree_mode != block.low_degree_mode
                || !reduction_tree_ordinals.insert(*bound_tree_ordinal)
            {
                return Err("production bound reduction does not partition its trees".to_owned());
            }
        }
    }
    let expected_bound_tree_ordinals = (0..plan.bound_trees.len())
        .map(u32::try_from)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| "production bound-tree count exceeds u32".to_owned())?;
    if reduction_tree_ordinals != expected_bound_tree_ordinals {
        return Err("production bound reductions omit a bound tree".to_owned());
    }
    Ok((
        counts_by_mode,
        observed_columns.len(),
        plan.bound_reduction_blocks.len(),
        reduction_tree_ordinals.len(),
    ))
}

fn expected_opening_batches(
    plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
) -> Result<(Vec<Vec<u32>>, Vec<u32>), String> {
    let mut opening_point_columns = Vec::new();
    let mut bound_reduction_column = None;
    for (column_index, role) in plan.aggregate_column_roles.iter().enumerate() {
        let column_ordinal = u32::try_from(column_index)
            .map_err(|_| "production aggregate column exceeds u32".to_owned())?;
        match role {
            RowCodeWhirAggregateColumnRole::OpeningPoint {
                opening_point_ordinal,
            } => {
                if usize::try_from(*opening_point_ordinal).ok() != Some(opening_point_columns.len())
                {
                    return Err("production aggregate opening-point roles are reordered".to_owned());
                }
                opening_point_columns.push(column_ordinal);
            }
            RowCodeWhirAggregateColumnRole::BoundReduction => {
                if bound_reduction_column.replace(column_ordinal).is_some() {
                    return Err("production aggregate has two bound-reduction columns".to_owned());
                }
            }
        }
    }
    if opening_point_columns.len() != variant.ordered_opening_points().len() {
        return Err("production aggregate omits an explicit opening point".to_owned());
    }
    if bound_reduction_column.is_some() == plan.bound_reduction_blocks.is_empty() {
        return Err("production aggregate bound-reduction role is inconsistent".to_owned());
    }
    let mut expected = opening_point_columns
        .iter()
        .map(|column| vec![*column])
        .collect::<Vec<_>>();
    expected.extend((0..plan.parameters.outer_query_count).map(|_| opening_point_columns.clone()));
    if let Some(bound_column) = bound_reduction_column {
        for block in &plan.bound_reduction_blocks {
            let query_batch_count = block
                .query_count
                .checked_mul(2)
                .ok_or_else(|| "production bound opening count overflowed".to_owned())?;
            expected.extend((0..query_batch_count).map(|_| vec![bound_column]));
            expected.extend((0..=block.degree_suffix_prefixes.len()).map(|_| vec![bound_column]));
        }
    }
    Ok((expected, opening_point_columns))
}

fn checked_opening_batch_mapping(
    plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
    change_first_column: bool,
) -> Result<(usize, usize, Vec<u32>), String> {
    let (expected, opening_point_columns) = expected_opening_batches(plan, variant)?;
    let mut observed = plan
        .opening_batches()
        .iter()
        .map(|batch| batch.requested_aggregate_column_ordinals.clone())
        .collect::<Vec<_>>();
    if change_first_column {
        let first = observed
            .first_mut()
            .and_then(|columns| columns.first_mut())
            .ok_or_else(|| "production opening catalog is empty".to_owned())?;
        *first = first.wrapping_add(1);
    }
    if observed != expected
        || plan
            .opening_batches()
            .iter()
            .enumerate()
            .any(|(index, batch)| u32::try_from(index).ok() != Some(batch.point_ordinal))
    {
        return Err("production aggregate-wide opening catalog changed".to_owned());
    }
    let scalar_opening_count = observed.iter().try_fold(0_usize, |count, columns| {
        count
            .checked_add(columns.len())
            .ok_or_else(|| "production scalar opening count overflowed".to_owned())
    })?;
    Ok((observed.len(), scalar_opening_count, opening_point_columns))
}

fn independent_multilinear_equality_weight(
    point: &[ChallengeField],
    table_index: usize,
) -> ChallengeField {
    point.iter().copied().enumerate().fold(
        ChallengeField::ONE,
        |weight, (coordinate_index, coordinate)| {
            let bit_ordinal = point.len() - 1 - coordinate_index;
            if table_index & (1 << bit_ordinal) == 0 {
                weight * (ChallengeField::ONE - coordinate)
            } else {
                weight * coordinate
            }
        },
    )
}

fn checked_polynomial_basis_identities(
    parameters: RowCodeWhirSelectedParameters,
    change_first_identity: bool,
) -> Result<(usize, usize, usize), String> {
    let coefficient_variable_count =
        parameters.logical_polynomial_coefficient_count.ilog2() as usize;
    let points = [
        ChallengeField::from_u64(2),
        ChallengeField::from_u64(7),
        ChallengeField::new([
            Goldilocks::from_u64(11),
            Goldilocks::from_u64(13),
            Goldilocks::from_u64(17),
            Goldilocks::from_u64(19),
            Goldilocks::from_u64(23),
        ]),
    ];
    let mut identity_count = 0_usize;
    for (point_ordinal, evaluation_point) in points.into_iter().enumerate() {
        let reduction =
            polynomial_extension_opening_reduction(evaluation_point, coefficient_variable_count)?;
        let mut expected_power = ChallengeField::ONE;
        for coefficient_ordinal in 0..parameters.logical_polynomial_coefficient_count {
            let mut observed_power = independent_multilinear_equality_weight(
                reduction.multilinear_point.as_slice(),
                coefficient_ordinal,
            ) * reduction.multilinear_to_polynomial_scale;
            if change_first_identity && point_ordinal == 0 && coefficient_ordinal == 0 {
                observed_power += ChallengeField::ONE;
            }
            if observed_power != expected_power {
                return Err(
                    "production polynomial-to-multilinear basis identity changed".to_owned(),
                );
            }
            expected_power *= evaluation_point;
            identity_count = identity_count
                .checked_add(1)
                .ok_or_else(|| "production polynomial basis count overflowed".to_owned())?;
        }
    }
    let actual_pole_rejection_count = usize::from(
        polynomial_extension_opening_reduction(-ChallengeField::ONE, coefficient_variable_count)
            .is_err(),
    );
    Ok((
        coefficient_variable_count,
        identity_count,
        actual_pole_rejection_count,
    ))
}

fn checked_selector_equality_identities(
    parameters: RowCodeWhirSelectedParameters,
    change_first_identity: bool,
) -> Result<usize, String> {
    let selector_variable_count = parameters.logical_polynomials_per_physical_row.ilog2() as usize;
    let selector_cases = (0..INDEPENDENT_BASIS_POINT_COUNT)
        .map(|case_ordinal| {
            (0..selector_variable_count)
                .map(|selector_ordinal| {
                    if case_ordinal == 2 && selector_ordinal == 0 {
                        ChallengeField::new([
                            Goldilocks::from_u64(17),
                            Goldilocks::from_u64(19),
                            Goldilocks::from_u64(23),
                            Goldilocks::from_u64(29),
                            Goldilocks::from_u64(31),
                        ])
                    } else {
                        ChallengeField::from_u64(
                            2 + 5 * case_ordinal as u64 + 3 * selector_ordinal as u64,
                        )
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut identity_count = 0_usize;
    for (case_ordinal, selectors) in selector_cases.iter().enumerate() {
        let production_weights = Poly::new_from_point(selectors, ChallengeField::ONE);
        if production_weights.as_slice().len() != parameters.logical_polynomials_per_physical_row {
            return Err("production selector basis has the wrong width".to_owned());
        }
        for (selector_index, production_weight) in
            production_weights.as_slice().iter().copied().enumerate()
        {
            let mut observed_weight = production_weight;
            if change_first_identity && case_ordinal == 0 && selector_index == 0 {
                observed_weight += ChallengeField::ONE;
            }
            if observed_weight != independent_multilinear_equality_weight(selectors, selector_index)
            {
                return Err("production selector equality-weight ordering changed".to_owned());
            }
            identity_count = identity_count
                .checked_add(1)
                .ok_or_else(|| "production selector identity count overflowed".to_owned())?;
        }
    }
    Ok(identity_count)
}

fn evaluate_challenge_polynomial(
    coefficients: &[ChallengeField],
    point: ChallengeField,
) -> ChallengeField {
    coefficients
        .iter()
        .rev()
        .fold(ChallengeField::ZERO, |value, coefficient| {
            value * point + *coefficient
        })
}

fn checked_synthetic_division_identities() -> Result<usize, String> {
    let opening_points = [
        ChallengeField::from_u64(3),
        ChallengeField::new([
            Goldilocks::from_u64(5),
            Goldilocks::from_u64(7),
            Goldilocks::from_u64(11),
            Goldilocks::from_u64(13),
            Goldilocks::from_u64(17),
        ]),
    ];
    let mut identity_count = 0_usize;
    for coefficient_count in [1_usize, 2, 17, 257] {
        let coefficients = (0..coefficient_count)
            .map(|coefficient_ordinal| {
                ChallengeField::new(core::array::from_fn(|coordinate_ordinal| {
                    Goldilocks::from_u64(
                        (coefficient_ordinal as u64 + 2) * (coordinate_ordinal as u64 + 3) + 1,
                    )
                }))
            })
            .collect::<Vec<_>>();
        for opening_point in opening_points {
            let actual_evaluation = evaluate_challenge_polynomial(&coefficients, opening_point);
            for claimed_value in [actual_evaluation, actual_evaluation + ChallengeField::ONE] {
                let (quotient, remainder) = divide_polynomial_opening(
                    coefficients.len(),
                    |coefficient_ordinal| coefficients[coefficient_ordinal],
                    opening_point,
                    claimed_value,
                )?;
                if remainder != actual_evaluation - claimed_value
                    || quotient.len() + 1 != coefficients.len()
                {
                    return Err(
                        "production synthetic division changed its remainder identity".to_owned(),
                    );
                }
                for coefficient_ordinal in 0..coefficients.len() {
                    let mut reconstructed = if coefficient_ordinal == 0 {
                        remainder
                    } else {
                        quotient[coefficient_ordinal - 1]
                    };
                    if coefficient_ordinal < quotient.len() {
                        reconstructed -= opening_point * quotient[coefficient_ordinal];
                    }
                    let expected = if coefficient_ordinal == 0 {
                        coefficients[0] - claimed_value
                    } else {
                        coefficients[coefficient_ordinal]
                    };
                    if reconstructed != expected {
                        return Err(
                            "production synthetic division changed its polynomial identity"
                                .to_owned(),
                        );
                    }
                }
                identity_count = identity_count
                    .checked_add(1)
                    .ok_or_else(|| "production synthetic-division count overflowed".to_owned())?;
            }
        }
    }
    Ok(identity_count)
}

fn opening_claim_partition(
    variant: &RelationPlanVariant,
) -> Result<(usize, usize, usize, usize), String> {
    let mut proof_created_columns = BTreeSet::new();
    let mut bound_columns = BTreeSet::new();
    for tree in variant.ordered_trees() {
        match tree {
            RelationTreeDescriptor::ProofCreated {
                ordered_column_ordinals,
                ..
            } => proof_created_columns.extend(ordered_column_ordinals.iter().copied()),
            RelationTreeDescriptor::BoundPublic {
                ordered_column_ordinals,
                ..
            } => bound_columns.extend(ordered_column_ordinals.iter().copied()),
        }
    }
    let mut proof_created_claim_count = 0_usize;
    let mut bound_claim_count = 0_usize;
    let mut quotient_claim_count = 0_usize;
    let mut mask_claim_count = 0_usize;
    for claim in variant.ordered_opening_claims() {
        match claim.source_class() {
            RelationOpeningSourceClass::TreeColumn => {
                let column = claim
                    .column_ordinal()
                    .ok_or_else(|| "production tree opening claim has no column".to_owned())?;
                if proof_created_columns.contains(&column) {
                    proof_created_claim_count += 1;
                } else if bound_columns.contains(&column) {
                    bound_claim_count += 1;
                } else {
                    return Err(
                        "production tree opening claim has no authenticated owner".to_owned()
                    );
                }
            }
            RelationOpeningSourceClass::Quotient => quotient_claim_count += 1,
            RelationOpeningSourceClass::BatchMask => mask_claim_count += 1,
        }
    }
    Ok((
        proof_created_claim_count,
        bound_claim_count,
        quotient_claim_count,
        mask_claim_count,
    ))
}

pub(super) fn checked_production_extractor_correspondence_with_fault(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    expected_relation_plan_hash: [u8; 64],
    expected_relation_plan_variant_hash: [u8; 64],
    fault: ProductionExtractorCorrespondenceFault,
) -> Result<
    (
        ProductionPolynomialProtocolExtractorCertificate,
        ProductionPointConstraintExtractorCertificate,
    ),
    String,
> {
    let relation_plan_variant_hash = relation_variant
        .canonical_hash()
        .map_err(|error| format!("derive production relation identity: {error:?}"))?;
    if construction_plan.relation_plan_hash != expected_relation_plan_hash
        || construction_plan.relation_plan_variant_hash != expected_relation_plan_variant_hash
        || relation_plan_variant_hash != expected_relation_plan_variant_hash
        || construction_plan.application_statement_schema_identifier == 0
        || construction_plan.schedule_position != relation_variant.schedule_position()
        || construction_plan.top_count != relation_variant.top_count()
        || construction_plan.trace_domain_size != relation_variant.trace_domain_size()
        || construction_plan.evaluation_domain_size != relation_variant.evaluation_domain_size()
        || construction_plan.opening_degree_bound_exclusive
            != relation_variant.opening_degree_bound_exclusive()
        || construction_plan.proof_privacy_mode != relation_variant.proof_privacy_mode()
    {
        return Err("production extractor changes the checked relation identity".to_owned());
    }
    let parameters = construction_plan.parameters;
    let construction_plan_identity_hash = construction_plan
        .canonical_identity_hash()
        .map_err(|error| format!("derive production construction identity: {error:?}"))?;
    let source_manifest = SameSecretAuthenticatedSourceManifest::derive(
        construction_plan,
        relation_variant,
        relation_context,
    )
    .map_err(|error| format!("derive production source manifest: {error:?}"))?;
    if source_manifest.construction_identity() != construction_plan_identity_hash {
        return Err("production source manifest changes the construction identity".to_owned());
    }

    let mut relation_phase_presence = [false; 3];
    let mut relation_phase_row_counts = [0_usize; 3];
    let mut relation_phase_polynomial_counts = [0_usize; 3];
    let mut drop_first_polynomial =
        fault == ProductionExtractorCorrespondenceFault::DropFirstRelationPhasePolynomial;
    for (phase_index, phase, role) in [
        (
            0,
            construction_plan.base_phase.as_ref(),
            ProofTreeRole::BaseOracle,
        ),
        (
            1,
            construction_plan.auxiliary_phase.as_ref(),
            ProofTreeRole::AuxiliaryOracle,
        ),
    ] {
        if let Some(phase) = phase {
            relation_phase_presence[phase_index] = true;
            relation_phase_row_counts[phase_index] = phase.rows.len();
            relation_phase_polynomial_counts[phase_index] = checked_trace_phase_polynomial_mapping(
                phase,
                relation_variant,
                parameters,
                role,
                drop_first_polynomial,
            )?;
            drop_first_polynomial = false;
        }
    }
    if drop_first_polynomial {
        return Err("production extractor has no trace polynomial to remove".to_owned());
    }
    relation_phase_presence[2] = true;
    relation_phase_row_counts[2] = construction_plan.quotient_phase.rows.len();
    let (quotient_component_chunk_coordinate_count, opening_batch_mask_chunk_coordinate_count) =
        checked_quotient_phase_polynomial_mapping(
            construction_plan,
            relation_variant,
            relation_context,
        )?;
    relation_phase_polynomial_counts[2] = quotient_component_chunk_coordinate_count
        .checked_add(opening_batch_mask_chunk_coordinate_count)
        .ok_or_else(|| "production quotient polynomial count overflowed".to_owned())?;

    let (
        bound_tree_counts_by_mode,
        bound_polynomial_count,
        bound_reduction_block_count,
        bound_reduction_tree_coverage_count,
    ) = checked_bound_polynomial_mapping(construction_plan, relation_variant)?;
    let (opening_batch_count, mut scalar_opening_count, opening_point_aggregate_columns) =
        checked_opening_batch_mapping(
            construction_plan,
            relation_variant,
            fault == ProductionExtractorCorrespondenceFault::ChangeFirstAggregateOpeningColumn,
        )?;
    if fault == ProductionExtractorCorrespondenceFault::ChangeScalarOpeningCount {
        scalar_opening_count = scalar_opening_count
            .checked_add(1)
            .ok_or_else(|| "faulted production scalar opening count overflowed".to_owned())?;
        let expected_scalar_opening_count = construction_plan
            .opening_batches()
            .iter()
            .try_fold(0_usize, |count, batch| {
                count.checked_add(batch.requested_aggregate_column_ordinals.len())
            })
            .ok_or_else(|| "production scalar opening count overflowed".to_owned())?;
        if scalar_opening_count != expected_scalar_opening_count {
            return Err("production scalar opening count changed".to_owned());
        }
    }
    let (
        polynomial_coefficient_variable_count,
        polynomial_basis_identity_count,
        actual_pole_rejection_count,
    ) = checked_polynomial_basis_identities(
        parameters,
        fault == ProductionExtractorCorrespondenceFault::ChangeFirstPolynomialBasisIdentity,
    )?;
    let selector_equality_identity_count = checked_selector_equality_identities(
        parameters,
        fault == ProductionExtractorCorrespondenceFault::ChangeFirstSelectorBasisIdentity,
    )?;
    let synthetic_division_identity_count = checked_synthetic_division_identities()?;

    let whir_epoch_query_counts = construction_plan
        .whir
        .rounds
        .iter()
        .map(|round| round.query_epoch.query_count)
        .chain(std::iter::once(
            construction_plan.whir.final_round.query_epoch.query_count,
        ))
        .collect::<Vec<_>>();
    let whir_epoch_codeword_count = whir_epoch_query_counts.len();
    let whir_fold_transition_count = whir_epoch_codeword_count
        .checked_mul(parameters.folding_factor)
        .ok_or_else(|| "production WHIR fold count overflowed".to_owned())?;
    let whir_code_state_count = whir_epoch_codeword_count
        .checked_mul(
            parameters
                .folding_factor
                .checked_add(1)
                .ok_or_else(|| "production WHIR code-state factor overflowed".to_owned())?,
        )
        .ok_or_else(|| "production WHIR code-state count overflowed".to_owned())?;

    let polynomial_protocol = ProductionPolynomialProtocolExtractorCertificate {
        construction_plan_identity_hash,
        relation_plan_variant_hash,
        authenticated_source_manifest_hash: source_manifest.catalog_hash(),
        authenticated_source_polynomial_count: source_manifest
            .authenticated_source_polynomial_count()
            .map_err(|error| format!("count production authenticated sources: {error:?}"))?,
        raw_authenticated_source_coefficient_position_count: source_manifest
            .raw_authenticated_source_coefficient_position_count()
            .map_err(|error| format!("count production raw source positions: {error:?}"))?,
        persisted_pre_challenge_source_coefficient_position_count: source_manifest
            .persisted_pre_challenge_source_coefficient_position_count()
            .map_err(|error| format!("count production persisted source positions: {error:?}"))?,
        deterministic_reversed_column_count: source_manifest
            .deterministic_reversed_column_count()
            .map_err(|error| format!("count production reversed columns: {error:?}"))?,
        stored_pre_challenge_column_count: source_manifest
            .stored_pre_challenge_column_count()
            .map_err(|error| format!("count production stored columns: {error:?}"))?,
        logical_polynomial_coefficient_count: parameters.logical_polynomial_coefficient_count,
        logical_polynomials_per_physical_row: parameters.logical_polynomials_per_physical_row,
        challenge_extension_degree: usize::from(relation_context.challenge_extension_degree),
        relation_phase_presence,
        relation_phase_row_counts,
        relation_phase_polynomial_counts,
        quotient_component_count: usize::try_from(relation_context.quotient_component_count)
            .map_err(|_| "production quotient component count exceeds usize".to_owned())?,
        quotient_component_degree_bound_exclusive: relation_context
            .quotient_component_degree_bound_exclusive,
        opening_batch_mask_degree_bound_exclusive: construction_plan
            .quotient_phase
            .opening_batch_mask_degree_bound_exclusive,
        quotient_component_chunk_coordinate_count,
        opening_batch_mask_chunk_coordinate_count,
        bound_tree_counts_by_mode,
        bound_polynomial_count,
        bound_reduction_block_count,
        bound_reduction_tree_coverage_count,
        whir_epoch_codeword_count,
        whir_fold_transition_count,
        whir_code_state_count,
        whir_epoch_query_counts,
        opening_batch_count,
        scalar_opening_count,
        polynomial_coefficient_variable_count,
        polynomial_basis_identity_count,
        synthetic_division_identity_count,
        actual_pole_rejection_count,
    };

    let row_selector_coordinate_count =
        parameters.logical_polynomials_per_physical_row.ilog2() as usize;
    let coefficient_reduction_coordinate_count =
        parameters.logical_polynomial_coefficient_count.ilog2() as usize;
    let fixed_aggregate_selector_coordinate_count = parameters
        .table_variable_count
        .checked_sub(row_selector_coordinate_count)
        .and_then(|count| count.checked_sub(coefficient_reduction_coordinate_count))
        .ok_or_else(|| "production explicit-point coordinate partition underflowed".to_owned())?;
    let (
        proof_created_tree_opening_claim_count,
        bound_tree_opening_claim_count,
        quotient_opening_claim_count,
        opening_batch_mask_claim_count,
    ) = opening_claim_partition(relation_variant)?;
    let point_constraints = ProductionPointConstraintExtractorCertificate {
        construction_plan_identity_hash,
        relation_plan_variant_hash,
        proof_privacy_mode: relation_variant.proof_privacy_mode(),
        explicit_point_count: relation_variant.ordered_opening_points().len(),
        explicit_point_variable_count: parameters.table_variable_count,
        fixed_aggregate_selector_coordinate_count,
        row_selector_coordinate_count,
        coefficient_reduction_coordinate_count,
        logical_polynomials_per_physical_row: parameters.logical_polynomials_per_physical_row,
        logical_polynomial_coefficient_count: parameters.logical_polynomial_coefficient_count,
        coordinate_authorities: BTreeSet::from([
            ProductionPointCoordinateAuthority::TranscriptOpeningPoint,
            ProductionPointCoordinateAuthority::TranscriptRowSelector,
            ProductionPointCoordinateAuthority::PolynomialOpeningReduction,
        ]),
        proof_supplied_point_coordinate_count: usize::from(
            fault == ProductionExtractorCorrespondenceFault::PermitProofSuppliedPoint,
        ),
        opening_point_aggregate_columns,
        quotient_active_point_count: construction_plan
            .quotient_phase
            .rows
            .iter()
            .flat_map(|row| row.opening_point_ordinals.iter().copied())
            .collect::<BTreeSet<_>>()
            .len(),
        proof_created_tree_opening_claim_count,
        bound_tree_opening_claim_count,
        quotient_opening_claim_count,
        opening_batch_mask_claim_count,
        relation_opening_claim_count: relation_variant.ordered_opening_claims().len(),
        selector_equality_identity_count,
    };
    if !polynomial_protocol.is_complete() || !point_constraints.is_complete() {
        return Err("production polynomial extractor correspondence is incomplete".to_owned());
    }
    Ok((polynomial_protocol, point_constraints))
}

pub(super) fn checked_production_extractor_correspondence(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    expected_relation_plan_hash: [u8; 64],
    expected_relation_plan_variant_hash: [u8; 64],
) -> Result<
    (
        ProductionPolynomialProtocolExtractorCertificate,
        ProductionPointConstraintExtractorCertificate,
    ),
    String,
> {
    checked_production_extractor_correspondence_with_fault(
        construction_plan,
        relation_variant,
        relation_context,
        expected_relation_plan_hash,
        expected_relation_plan_variant_hash,
        ProductionExtractorCorrespondenceFault::None,
    )
}
