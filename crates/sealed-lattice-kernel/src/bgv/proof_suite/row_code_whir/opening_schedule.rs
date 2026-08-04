//! Construction-derived aggregate batching and opening coordinates.
//!
//! Every selected relation uses the same physical aggregate table. The
//! relation plan decides which logical columns are populated, while the
//! remaining physical columns are canonical zeros. All batching weights,
//! query coordinates, and bound-reduction points are verifier challenges.

use std::collections::{BTreeMap, BTreeSet};

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::{point::Point, poly::Poly};

use super::algebra::{
    coset_point, polynomial_extension_opening_reduction, polynomial_opening_reduction,
};
use super::construction_plan::{
    RowCodeWhirAggregateColumnRole, RowCodeWhirConstructionPlan, RowCodeWhirPhase,
};
use super::{ChallengeField, ExtensionFieldChallenger};
use crate::bgv::proof_suite::relation_plan::{
    ProofPrivacyMode, RelationColumnOrigin, RelationOpeningSourceClass, RelationPlanCheckContext,
    RelationPlanVariant,
};
use crate::bgv::proof_suite::transcript::{RowCodeWhirChallenge, RowCodeWhirTracePhase};
use crate::bgv::proof_suite::{ProofChallengeExtensionElement, ProofEvaluationDomain};

const CHALLENGE_FIELD_BASE_DIMENSION: usize =
    <ChallengeField as BasedVectorSpace<Goldilocks>>::DIMENSION;

#[derive(Clone, Copy)]
pub(super) struct RowCodeWhirBoundOpeningClaim {
    pub(super) column_ordinal: u32,
    pub(super) opening_point: ChallengeField,
    pub(super) claimed_value: ChallengeField,
    pub(super) batching_weight: ChallengeField,
    pub(super) reduction_block_ordinal: usize,
}

#[derive(Clone)]
pub(super) struct RowCodeWhirPointRowWeights {
    selectors: Vec<ChallengeField>,
    phase_rows: [Vec<ChallengeField>; 3],
}

impl RowCodeWhirPointRowWeights {
    pub(super) fn selectors(&self) -> &[ChallengeField] {
        &self.selectors
    }

    pub(super) fn phase_rows(&self, phase: RowCodeWhirPhase) -> &[ChallengeField] {
        &self.phase_rows[phase_index(phase)]
    }
}

pub(super) struct RowCodeWhirOpeningScheduleContinuation {
    construction_identity_hash: [u8; 64],
    evaluation_domain_generator: u64,
    evaluation_coset_offset: u64,
    point_row_weights: Vec<RowCodeWhirPointRowWeights>,
}

pub(super) struct RowCodeWhirOpeningSchedule {
    points: Vec<Point<ChallengeField>>,
    requested_columns_by_point: Vec<Vec<usize>>,
    point_row_weights: Vec<RowCodeWhirPointRowWeights>,
    outer_traversal_query_indices: Vec<usize>,
    accepted_bound_query_indices: Vec<usize>,
    bound_tree_traversal_query_indices: Vec<Vec<usize>>,
}

impl RowCodeWhirOpeningSchedule {
    pub(super) fn points(&self) -> &[Point<ChallengeField>] {
        &self.points
    }

    pub(super) fn requested_columns_by_point(&self) -> &[Vec<usize>] {
        &self.requested_columns_by_point
    }

    pub(super) fn point_row_weights(&self) -> &[RowCodeWhirPointRowWeights] {
        &self.point_row_weights
    }

    pub(super) fn outer_traversal_query_indices(&self) -> &[usize] {
        &self.outer_traversal_query_indices
    }

    pub(super) fn bound_tree_traversal_query_indices(
        &self,
        bound_tree_ordinal: usize,
    ) -> Result<&[usize], String> {
        self.bound_tree_traversal_query_indices
            .get(bound_tree_ordinal)
            .map(Vec::as_slice)
            .ok_or_else(|| "bound tree ordinal is outside the opening schedule".to_owned())
    }

    pub(super) fn accepted_bound_query_ordinal(
        &self,
        construction_plan: &RowCodeWhirConstructionPlan,
        bound_tree_ordinal: usize,
        leaf_index: usize,
    ) -> Result<usize, String> {
        let query_count = construction_plan
            .bound_trees
            .get(bound_tree_ordinal)
            .ok_or_else(|| "bound tree ordinal is outside the construction".to_owned())?
            .query_count;
        self.accepted_bound_query_indices
            .get(..query_count)
            .ok_or_else(|| "accepted bound query vector is too short".to_owned())?
            .iter()
            .position(|accepted_leaf_index| *accepted_leaf_index == leaf_index)
            .ok_or_else(|| "bound traversal index is absent from accepted query order".to_owned())
    }
}

pub(super) fn challenge_from_production(value: ProofChallengeExtensionElement) -> ChallengeField {
    ChallengeField::new(value.canonical_coordinates().map(Goldilocks::new))
}

pub(super) fn divide_polynomial_opening(
    coefficient_count: usize,
    mut coefficient_at: impl FnMut(usize) -> ChallengeField,
    opening_point: ChallengeField,
    claimed_value: ChallengeField,
) -> Result<(Vec<ChallengeField>, ChallengeField), String> {
    if coefficient_count == 0 {
        return Err("synthetic division requires a nonempty polynomial".to_owned());
    }
    let mut quotient = vec![ChallengeField::ZERO; coefficient_count - 1];
    if let Some(last_quotient) = quotient.last_mut() {
        *last_quotient = coefficient_at(coefficient_count - 1);
        for coefficient_ordinal in (1..quotient.len()).rev() {
            quotient[coefficient_ordinal - 1] =
                coefficient_at(coefficient_ordinal) + opening_point * quotient[coefficient_ordinal];
        }
    }
    let remainder = coefficient_at(0) - claimed_value
        + quotient.first().copied().unwrap_or(ChallengeField::ZERO) * opening_point;
    Ok((quotient, remainder))
}

fn opening_claim_key(
    source_class: RelationOpeningSourceClass,
    source_ordinal: u32,
    column_ordinal: Option<u32>,
    opening_point_ordinal: u32,
) -> Result<(u16, u32, u32), String> {
    let source_identifier = match source_class {
        RelationOpeningSourceClass::TreeColumn => {
            column_ordinal.ok_or_else(|| "tree opening claim has no column ordinal".to_owned())?
        }
        RelationOpeningSourceClass::Quotient | RelationOpeningSourceClass::BatchMask => {
            if column_ordinal.is_some() {
                return Err("non-tree opening claim carries a column ordinal".to_owned());
            }
            source_ordinal
        }
    };
    Ok((
        source_class as u16,
        source_identifier,
        opening_point_ordinal,
    ))
}

fn out_of_domain_evaluation_catalog(
    relation_variant: &RelationPlanVariant,
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
) -> Result<BTreeMap<(u16, u32, u32), ProofChallengeExtensionElement>, String> {
    if relation_variant.ordered_opening_claims().len() != out_of_domain_evaluations.len() {
        return Err("out-of-domain evaluation count does not match the relation".to_owned());
    }
    let mut catalog = BTreeMap::new();
    for (claim, evaluation) in relation_variant
        .ordered_opening_claims()
        .iter()
        .zip(out_of_domain_evaluations)
    {
        let key = opening_claim_key(
            claim.source_class(),
            claim.source_ordinal(),
            claim.column_ordinal(),
            claim.opening_point_ordinal(),
        )?;
        if catalog.insert(key, *evaluation).is_some() {
            return Err("relation contains a duplicate opening claim".to_owned());
        }
    }
    Ok(catalog)
}

pub(super) fn verify_opening_batch_mask_chunk_evaluations(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    chunk_evaluations: &[ProofChallengeExtensionElement],
) -> Result<(), String> {
    let expected_chunk_count = construction_plan
        .opening_batch_mask_chunk_evaluation_count()
        .map_err(|_| "opening-batch mask geometry is invalid".to_owned())?;
    if chunk_evaluations.len() != expected_chunk_count {
        return Err("opening-batch mask chunk count does not match the construction".to_owned());
    }
    let mask_claims = relation_variant
        .ordered_opening_claims()
        .iter()
        .filter(|claim| claim.source_class() == RelationOpeningSourceClass::BatchMask)
        .collect::<Vec<_>>();
    if expected_chunk_count == 0 {
        return if mask_claims.is_empty() {
            Ok(())
        } else {
            Err("public relation contains an opening-batch mask claim".to_owned())
        };
    }
    let [mask_claim] = mask_claims.as_slice() else {
        return Err(
            "secret relation does not have exactly one opening-batch mask claim".to_owned(),
        );
    };
    let opening_point_index = usize::try_from(mask_claim.opening_point_ordinal())
        .map_err(|_| "opening-batch mask point ordinal does not fit this platform".to_owned())?;
    let opening_point = opening_points
        .get(opening_point_index)
        .copied()
        .ok_or_else(|| "opening-batch mask claim references an absent point".to_owned())?;
    let catalog = out_of_domain_evaluation_catalog(relation_variant, out_of_domain_evaluations)?;
    let claimed_evaluation = catalog
        .get(&opening_claim_key(
            RelationOpeningSourceClass::BatchMask,
            mask_claim.source_ordinal(),
            None,
            mask_claim.opening_point_ordinal(),
        )?)
        .copied()
        .ok_or_else(|| {
            "opening-batch mask claim is absent from the evaluation catalog".to_owned()
        })?;
    let opening_point = challenge_from_production(opening_point);
    let chunk_power = opening_point.exp_u64(
        u64::try_from(
            construction_plan
                .selected_parameters()
                .logical_polynomial_coefficient_count,
        )
        .map_err(|_| "logical polynomial coefficient count exceeds u64".to_owned())?,
    );
    let mut recombined_evaluation = ChallengeField::ZERO;
    let mut current_chunk_power = ChallengeField::ONE;
    for chunk_evaluation in chunk_evaluations {
        recombined_evaluation += current_chunk_power * challenge_from_production(*chunk_evaluation);
        current_chunk_power *= chunk_power;
    }
    if recombined_evaluation != challenge_from_production(claimed_evaluation) {
        return Err("opening-batch mask chunks do not recombine to the claimed value".to_owned());
    }
    Ok(())
}

pub(super) fn expected_out_of_domain_aggregate_evaluations(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    opening_batch_mask_chunk_evaluations: &[ProofChallengeExtensionElement],
    point_row_weights: &[RowCodeWhirPointRowWeights],
) -> Result<Vec<ChallengeField>, String> {
    if opening_points.len() != point_row_weights.len() {
        return Err("opening points and row weights have different lengths".to_owned());
    }
    verify_opening_batch_mask_chunk_evaluations(
        construction_plan,
        relation_variant,
        opening_points,
        out_of_domain_evaluations,
        opening_batch_mask_chunk_evaluations,
    )?;
    let catalog = out_of_domain_evaluation_catalog(relation_variant, out_of_domain_evaluations)?;
    let mut expected = Vec::with_capacity(opening_points.len());
    for (opening_point_index, (opening_point, point_weights)) in opening_points
        .iter()
        .copied()
        .zip(point_row_weights)
        .enumerate()
    {
        let opening_point_ordinal = u32::try_from(opening_point_index)
            .map_err(|_| "opening-point ordinal exceeds u32".to_owned())?;
        let selector_weights = Poly::new_from_point(point_weights.selectors(), ChallengeField::ONE);
        let mut aggregate_evaluation = ChallengeField::ZERO;
        for (phase, phase_plan) in [
            (
                RowCodeWhirPhase::Base,
                construction_plan.base_phase.as_ref(),
            ),
            (
                RowCodeWhirPhase::Auxiliary,
                construction_plan.auxiliary_phase.as_ref(),
            ),
        ] {
            let Some(phase_plan) = phase_plan else {
                continue;
            };
            let mut consumed_column_groups = BTreeSet::new();
            for (row_index, row) in phase_plan.rows.iter().enumerate() {
                if row.coefficient_chunk_ordinal != 0
                    || !row.opening_point_ordinals.contains(&opening_point_ordinal)
                {
                    continue;
                }
                if !consumed_column_groups.insert(row.column_group_ordinal) {
                    return Err("trace column group has more than one leading row".to_owned());
                }
                let row_weight = *point_weights
                    .phase_rows(phase)
                    .get(row_index)
                    .ok_or_else(|| "trace row weight is absent".to_owned())?;
                for (logical_column_index, chunk) in
                    row.logical_polynomial_chunks.iter().enumerate()
                {
                    let Some(chunk) = chunk else { continue };
                    let claim = catalog
                        .get(&opening_claim_key(
                            RelationOpeningSourceClass::TreeColumn,
                            0,
                            Some(chunk.column_ordinal),
                            opening_point_ordinal,
                        )?)
                        .copied()
                        .ok_or_else(|| {
                            format!(
                                "relation column {} has no opening at point {opening_point_ordinal}",
                                chunk.column_ordinal
                            )
                        })?;
                    aggregate_evaluation += row_weight
                        * selector_weights.as_slice()[logical_column_index]
                        * challenge_from_production(claim);
                }
            }
        }

        for (row_index, row) in construction_plan.quotient_phase.rows.iter().enumerate() {
            if row.extension_coordinate_ordinal != 0
                || !row.opening_point_ordinals.contains(&opening_point_ordinal)
            {
                continue;
            }
            let row_weight = *point_weights
                .phase_rows(RowCodeWhirPhase::Quotient)
                .get(row_index)
                .ok_or_else(|| "quotient row weight is absent".to_owned())?;
            match row.source_class {
                RelationOpeningSourceClass::Quotient => {
                    if row.coefficient_chunk_group_start_ordinal != 0 {
                        continue;
                    }
                    for (logical_column_index, chunk) in
                        row.logical_polynomial_chunks.iter().enumerate()
                    {
                        let Some(chunk) = chunk else { continue };
                        let super::construction_plan::RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                            component_ordinal,
                        } = chunk.source
                        else {
                            return Err("quotient row contains a non-quotient source".to_owned());
                        };
                        let claim = catalog
                            .get(&opening_claim_key(
                                RelationOpeningSourceClass::Quotient,
                                component_ordinal,
                                None,
                                opening_point_ordinal,
                            )?)
                            .copied()
                            .ok_or_else(|| {
                                format!(
                                    "quotient component {component_ordinal} has no opening at point {opening_point_ordinal}"
                                )
                            })?;
                        aggregate_evaluation += row_weight
                            * selector_weights.as_slice()[logical_column_index]
                            * challenge_from_production(claim);
                    }
                }
                RelationOpeningSourceClass::BatchMask => {
                    for (logical_column_index, chunk) in
                        row.logical_polynomial_chunks.iter().enumerate()
                    {
                        let Some(chunk) = chunk else { continue };
                        let super::construction_plan::RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
                            ..
                        } = chunk.source
                        else {
                            return Err("opening-batch row contains a non-mask source".to_owned());
                        };
                        let coefficient_chunk_ordinal =
                            usize::try_from(chunk.coefficient_chunk_ordinal).map_err(|_| {
                                "opening-batch chunk ordinal does not fit this platform".to_owned()
                            })?;
                        let chunk_evaluation = opening_batch_mask_chunk_evaluations
                            .get(coefficient_chunk_ordinal)
                            .copied()
                            .ok_or_else(|| "opening-batch chunk evaluation is absent".to_owned())?;
                        aggregate_evaluation += row_weight
                            * selector_weights.as_slice()[logical_column_index]
                            * challenge_from_production(chunk_evaluation);
                    }
                }
                RelationOpeningSourceClass::TreeColumn => {
                    return Err("tree column appeared in the quotient phase".to_owned());
                }
            }
        }
        let logical_polynomial_variable_count = construction_plan
            .selected_parameters()
            .logical_polynomial_coefficient_count
            .ilog2() as usize;
        let reduction = polynomial_extension_opening_reduction(
            challenge_from_production(opening_point),
            logical_polynomial_variable_count,
        )?;
        expected.push(aggregate_evaluation * reduction.multilinear_to_polynomial_scale.inverse());
    }
    Ok(expected)
}

pub(super) fn derive_point_row_weights(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<RowCodeWhirPointRowWeights>, String> {
    let parameters = construction_plan.selected_parameters();
    let logical_polynomial_count = parameters.logical_polynomials_per_physical_row;
    if !logical_polynomial_count.is_power_of_two() {
        return Err("logical polynomial row width is not a power of two".to_owned());
    }
    let selector_count = logical_polynomial_count.ilog2() as usize;
    let logical_opening_point_count = construction_plan
        .aggregate_opening_point_count()
        .map_err(|error| format!("derive aggregate opening layout: {error:?}"))?;
    if logical_opening_point_count != opening_points.len()
        || opening_points.len() != relation_variant.ordered_opening_points().len()
        || construction_plan.aggregate_logical_column_count()
            > construction_plan.aggregate_table_width()
    {
        return Err("aggregate opening-point geometry does not match the relation".to_owned());
    }

    let mut all_weights = Vec::with_capacity(opening_points.len());
    for (opening_point_index, opening_point) in opening_points.iter().copied().enumerate() {
        let opening_point_ordinal = u16::try_from(opening_point_index)
            .map_err(|_| "opening-point ordinal exceeds u16".to_owned())?;
        let opening_point_ordinal_u32 = u32::try_from(opening_point_index)
            .map_err(|_| "opening-point ordinal exceeds u32".to_owned())?;
        let selectors = (0..selector_count)
            .map(|selector_index| {
                challenger.sample_exact_challenge(RowCodeWhirChallenge::PointSelectorWeight {
                    opening_point_ordinal,
                    selector_ordinal: u16::try_from(selector_index)
                        .map_err(|_| "selector ordinal exceeds u16".to_owned())?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let opening_point = challenge_from_production(opening_point);
        let logical_chunk_power = opening_point.exp_u64(
            u64::try_from(parameters.logical_polynomial_coefficient_count)
                .map_err(|_| "logical polynomial coefficient count exceeds u64".to_owned())?,
        );

        let mut phase_rows: [Vec<ChallengeField>; 3] = std::array::from_fn(|_| Vec::new());
        for (phase, phase_plan, transcript_phase) in [
            (
                RowCodeWhirPhase::Base,
                construction_plan.base_phase.as_ref(),
                RowCodeWhirTracePhase::Base,
            ),
            (
                RowCodeWhirPhase::Auxiliary,
                construction_plan.auxiliary_phase.as_ref(),
                RowCodeWhirTracePhase::Auxiliary,
            ),
        ] {
            let Some(phase_plan) = phase_plan else {
                continue;
            };
            let mut column_group_weights = BTreeMap::new();
            for row in &phase_plan.rows {
                if row
                    .opening_point_ordinals
                    .contains(&opening_point_ordinal_u32)
                    && !column_group_weights.contains_key(&row.column_group_ordinal)
                {
                    let weight = challenger.sample_exact_challenge(
                        RowCodeWhirChallenge::TraceColumnGroupWeight {
                            opening_point_ordinal,
                            phase: transcript_phase,
                            column_group_ordinal: row.column_group_ordinal,
                        },
                    )?;
                    column_group_weights.insert(row.column_group_ordinal, weight);
                }
            }
            let weights = &mut phase_rows[phase_index(phase)];
            weights
                .try_reserve_exact(phase_plan.rows.len())
                .map_err(|_| {
                    "trace phase row-weight allocation exceeded the resident limit".to_owned()
                })?;
            for row in &phase_plan.rows {
                weights.push(
                    if row
                        .opening_point_ordinals
                        .contains(&opening_point_ordinal_u32)
                    {
                        column_group_weights
                            .get(&row.column_group_ordinal)
                            .copied()
                            .ok_or_else(|| {
                                "trace row has no sampled column-group weight".to_owned()
                            })?
                            * logical_chunk_power.exp_u64(u64::from(row.coefficient_chunk_ordinal))
                    } else {
                        ChallengeField::ZERO
                    },
                );
            }
        }

        let quotient_rows = &construction_plan.quotient_phase.rows;
        let mut quotient_group_weights = BTreeMap::new();
        for row in quotient_rows {
            if row
                .opening_point_ordinals
                .contains(&opening_point_ordinal_u32)
                && !quotient_group_weights.contains_key(&row.source_group_ordinal)
            {
                let weight = challenger.sample_exact_challenge(
                    RowCodeWhirChallenge::QuotientGroupWeight {
                        opening_point_ordinal,
                        source_group_ordinal: row.source_group_ordinal,
                    },
                )?;
                quotient_group_weights.insert(row.source_group_ordinal, weight);
            }
        }
        let opening_batch_mask_weight = if construction_plan
            .quotient_phase
            .opening_batch_mask_degree_bound_exclusive
            .is_some()
            && !quotient_group_weights.is_empty()
        {
            Some(challenger.sample_exact_challenge(
                RowCodeWhirChallenge::OpeningBatchMaskWeight {
                    opening_point_ordinal,
                },
            )?)
        } else {
            None
        };
        let quotient_weights = &mut phase_rows[phase_index(RowCodeWhirPhase::Quotient)];
        quotient_weights
            .try_reserve_exact(quotient_rows.len())
            .map_err(|_| "quotient row-weight allocation exceeded the resident limit".to_owned())?;
        for row in quotient_rows {
            if !row
                .opening_point_ordinals
                .contains(&opening_point_ordinal_u32)
            {
                quotient_weights.push(ChallengeField::ZERO);
                continue;
            }
            let source_weight = match row.source_class {
                RelationOpeningSourceClass::Quotient => quotient_group_weights
                    .get(&row.source_group_ordinal)
                    .copied()
                    .ok_or_else(|| "quotient row has no sampled group weight".to_owned())?,
                RelationOpeningSourceClass::BatchMask => opening_batch_mask_weight
                    .ok_or_else(|| "opening-batch row has no sampled mask weight".to_owned())?,
                RelationOpeningSourceClass::TreeColumn => {
                    return Err("tree column appeared in the quotient phase".to_owned());
                }
            };
            let chunk_weight =
                logical_chunk_power.exp_u64(u64::from(row.coefficient_chunk_group_start_ordinal));
            quotient_weights.push(
                source_weight
                    * chunk_weight
                    * challenge_extension_basis(usize::from(row.extension_coordinate_ordinal))?,
            );
        }
        all_weights.push(RowCodeWhirPointRowWeights {
            selectors,
            phase_rows,
        });
    }

    Ok(all_weights)
}

pub(super) fn derive_bound_opening_claims(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    opening_points: &[ProofChallengeExtensionElement],
    out_of_domain_evaluations: &[ProofChallengeExtensionElement],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<RowCodeWhirBoundOpeningClaim>, String> {
    if relation_variant.ordered_opening_claims().len() != out_of_domain_evaluations.len() {
        return Err("bound opening reduction has the wrong claim count".to_owned());
    }
    let mut column_locations = BTreeMap::new();
    for tree in &construction_plan.bound_trees {
        for column in &tree.ordered_columns {
            if column_locations
                .insert(column.column_ordinal, tree.bound_tree_ordinal)
                .is_some()
            {
                return Err("bound column occurs in more than one tree".to_owned());
            }
        }
    }
    let mut claims = Vec::new();
    for (claim, claimed_value) in relation_variant
        .ordered_opening_claims()
        .iter()
        .zip(out_of_domain_evaluations)
    {
        if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
            continue;
        }
        let column_ordinal = claim
            .column_ordinal()
            .ok_or_else(|| "tree opening claim has no column ordinal".to_owned())?;
        let column_index = usize::try_from(column_ordinal)
            .map_err(|_| "bound opening column ordinal does not fit this platform".to_owned())?;
        let descriptor = relation_variant
            .ordered_columns()
            .get(column_index)
            .ok_or_else(|| "bound opening references an absent column".to_owned())?;
        if !matches!(descriptor.origin(), RelationColumnOrigin::BoundTree { .. }) {
            continue;
        }
        let bound_tree_ordinal = *column_locations
            .get(&column_ordinal)
            .ok_or_else(|| "bound opening column is absent from the construction".to_owned())?;
        let reduction_block_ordinal = construction_plan
            .bound_reduction_blocks
            .iter()
            .position(|block| {
                block
                    .ordered_bound_tree_ordinals
                    .contains(&bound_tree_ordinal)
            })
            .ok_or_else(|| "bound opening tree has no reduction block".to_owned())?;
        let opening_point_index = usize::try_from(claim.opening_point_ordinal())
            .map_err(|_| "bound opening point ordinal does not fit this platform".to_owned())?;
        let opening_point = opening_points
            .get(opening_point_index)
            .copied()
            .ok_or_else(|| "bound opening references an absent point".to_owned())?;
        claims.push(RowCodeWhirBoundOpeningClaim {
            column_ordinal,
            opening_point: challenge_from_production(opening_point),
            claimed_value: challenge_from_production(*claimed_value),
            batching_weight: challenger.sample_exact_challenge(
                RowCodeWhirChallenge::BoundOpeningWeight { column_ordinal },
            )?,
            reduction_block_ordinal,
        });
    }
    if claims.len() != construction_plan.bound_opening_column_ordinals.len() {
        return Err("bound opening claim catalog does not match the construction".to_owned());
    }
    Ok(claims)
}

pub(super) fn opening_schedule_continuation(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_context: &RelationPlanCheckContext,
    point_row_weights: Vec<RowCodeWhirPointRowWeights>,
) -> Result<RowCodeWhirOpeningScheduleContinuation, String> {
    Ok(RowCodeWhirOpeningScheduleContinuation {
        construction_identity_hash: construction_plan
            .canonical_identity_hash()
            .map_err(|error| format!("derive construction identity: {error:?}"))?,
        evaluation_domain_generator: relation_context.evaluation_domain_generator,
        evaluation_coset_offset: relation_context.evaluation_coset_offset,
        point_row_weights,
    })
}

pub(super) fn derive_opening_schedule_after_observed_commitment(
    continuation: RowCodeWhirOpeningScheduleContinuation,
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_context: &RelationPlanCheckContext,
    opening_points: &[ProofChallengeExtensionElement],
    challenger: &mut ExtensionFieldChallenger,
) -> Result<RowCodeWhirOpeningSchedule, String> {
    if construction_plan
        .canonical_identity_hash()
        .map_err(|error| format!("derive construction identity: {error:?}"))?
        != continuation.construction_identity_hash
        || relation_context.evaluation_domain_generator != continuation.evaluation_domain_generator
        || relation_context.evaluation_coset_offset != continuation.evaluation_coset_offset
        || continuation.point_row_weights.len() != opening_points.len()
    {
        return Err("opening schedule continuation has the wrong binding".to_owned());
    }

    let degree_test_points = derive_bound_degree_test_points(construction_plan, challenger)?;
    let outer_encoded_column_count = construction_plan
        .quotient_phase
        .geometry
        .encoded_column_count;
    let accepted_outer_indices = challenger.sample_exact_distinct_indices(
        RowCodeWhirChallenge::OuterQueryVector,
        outer_encoded_column_count,
        construction_plan.parameters.outer_query_count,
    )?;
    let mut outer_traversal_query_indices = accepted_outer_indices.clone();
    outer_traversal_query_indices.sort_unstable();

    let (accepted_bound_indices, bound_tree_traversal_query_indices) =
        derive_bound_query_indices(construction_plan, challenger)?;
    let mut points = Vec::with_capacity(construction_plan.opening_batches.len());
    let parameters = construction_plan.selected_parameters();
    let logical_polynomial_variable_count =
        parameters.logical_polynomial_coefficient_count.ilog2() as usize;
    let selector_count = parameters.logical_polynomials_per_physical_row.ilog2() as usize;
    let fixed_zero_count = parameters
        .table_variable_count
        .checked_sub(selector_count)
        .and_then(|count| count.checked_sub(logical_polynomial_variable_count))
        .ok_or_else(|| "aggregate point variable geometry underflowed".to_owned())?;
    if !construction_plan
        .uses_opening_claim_quotient_batch()
        .map_err(|error| format!("derive aggregate opening layout: {error:?}"))?
    {
        for (opening_point, row_weights) in opening_points
            .iter()
            .copied()
            .zip(&continuation.point_row_weights)
        {
            let reduction = polynomial_extension_opening_reduction(
                challenge_from_production(opening_point),
                logical_polynomial_variable_count,
            )?;
            let mut coordinates = vec![ChallengeField::ZERO; fixed_zero_count];
            coordinates.extend_from_slice(row_weights.selectors());
            coordinates.extend_from_slice(reduction.multilinear_point.as_slice());
            if coordinates.len() != parameters.table_variable_count {
                return Err("aggregate out-of-domain point has the wrong width".to_owned());
            }
            points.push(Point::new(coordinates));
        }
    }
    let encoded_column_variable_count = outer_encoded_column_count.ilog2() as usize;
    for column_index in outer_traversal_query_indices.iter().copied() {
        points.push(
            polynomial_opening_reduction(
                coset_point(encoded_column_variable_count, column_index)?,
                parameters.table_variable_count,
            )?
            .multilinear_point,
        );
    }
    append_bound_reduction_query_points(
        &mut points,
        construction_plan,
        relation_context,
        &accepted_bound_indices,
    )?;
    points.extend(degree_test_points);

    let requested_columns_by_point = construction_plan
        .opening_batches()
        .iter()
        .map(|batch| {
            batch
                .requested_aggregate_column_ordinals
                .iter()
                .map(|column_ordinal| {
                    let column_index = usize::try_from(*column_ordinal).map_err(|_| {
                        "aggregate column ordinal does not fit this platform".to_owned()
                    })?;
                    if column_index >= construction_plan.aggregate_logical_column_count() {
                        return Err(
                            "opening batch requests an unpopulated aggregate column".to_owned()
                        );
                    }
                    Ok(column_index)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    if points.len() != construction_plan.opening_batches.len()
        || requested_columns_by_point.len() != points.len()
        || requested_columns_by_point.iter().any(Vec::is_empty)
    {
        return Err("aggregate opening batches do not match derived points".to_owned());
    }
    Ok(RowCodeWhirOpeningSchedule {
        points,
        requested_columns_by_point,
        point_row_weights: continuation.point_row_weights,
        outer_traversal_query_indices,
        accepted_bound_query_indices: accepted_bound_indices,
        bound_tree_traversal_query_indices,
    })
}

fn challenge_extension_basis(coordinate_ordinal: usize) -> Result<ChallengeField, String> {
    if coordinate_ordinal >= CHALLENGE_FIELD_BASE_DIMENSION {
        return Err("extension coordinate ordinal is outside the challenge field".to_owned());
    }
    Ok(ChallengeField::new(core::array::from_fn(|coordinate| {
        if coordinate == coordinate_ordinal {
            Goldilocks::ONE
        } else {
            Goldilocks::ZERO
        }
    })))
}

fn derive_bound_degree_test_points(
    construction_plan: &RowCodeWhirConstructionPlan,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<Point<ChallengeField>>, String> {
    let mut points = Vec::new();
    for (block_ordinal, block) in construction_plan.bound_reduction_blocks.iter().enumerate() {
        let mut boundary_coordinates = prefix_coordinates(&block.selector_prefix)?;
        boundary_coordinates.extend(binary_coordinates(
            block.quotient_degree_bound_exclusive,
            block.polynomial_variable_count,
        )?);
        if boundary_coordinates.len() != construction_plan.parameters.table_variable_count {
            return Err("bound reduction boundary point has the wrong width".to_owned());
        }
        points.push(Point::new(boundary_coordinates));
        for (suffix_index, suffix_prefix) in block.degree_suffix_prefixes.iter().enumerate() {
            let mut coordinates = prefix_coordinates(&block.selector_prefix)?;
            coordinates.extend(prefix_coordinates(suffix_prefix)?);
            while coordinates.len() < construction_plan.parameters.table_variable_count {
                coordinates.push(
                    challenger.sample_exact_challenge(
                        RowCodeWhirChallenge::BoundDegreeCoordinate {
                            block_ordinal: u16::try_from(block_ordinal)
                                .map_err(|_| "bound block ordinal exceeds u16".to_owned())?,
                            degree_test_ordinal: u16::try_from(suffix_index + 1)
                                .map_err(|_| "bound degree-test ordinal exceeds u16".to_owned())?,
                            coordinate_ordinal: u16::try_from(coordinates.len())
                                .map_err(|_| "bound coordinate ordinal exceeds u16".to_owned())?,
                        },
                    )?,
                );
            }
            points.push(Point::new(coordinates));
        }
    }
    Ok(points)
}

fn derive_bound_query_indices(
    construction_plan: &RowCodeWhirConstructionPlan,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(Vec<usize>, Vec<Vec<usize>>), String> {
    if construction_plan.bound_trees.is_empty() {
        if !construction_plan.bound_reduction_blocks.is_empty() {
            return Err("bound reduction blocks exist without bound trees".to_owned());
        }
        return Ok((Vec::new(), Vec::new()));
    }
    let leaf_count = construction_plan.bound_trees[0].leaf_count;
    if construction_plan
        .bound_trees
        .iter()
        .any(|tree| tree.leaf_count != leaf_count)
    {
        return Err("bound trees do not share one leaf domain".to_owned());
    }
    let maximum_query_count = construction_plan
        .bound_reduction_blocks
        .iter()
        .map(|block| block.query_count)
        .max()
        .ok_or_else(|| "bound trees have no reduction block".to_owned())?;
    let accepted = challenger.sample_exact_distinct_indices(
        RowCodeWhirChallenge::BoundQueryVector,
        leaf_count,
        maximum_query_count,
    )?;
    let traversals = construction_plan
        .bound_trees
        .iter()
        .map(|tree| {
            let mut indices = accepted
                .get(..tree.query_count)
                .ok_or_else(|| "bound query vector is too short".to_owned())?
                .to_vec();
            indices.sort_unstable();
            Ok(indices)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((accepted, traversals))
}

fn append_bound_reduction_query_points(
    points: &mut Vec<Point<ChallengeField>>,
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_context: &RelationPlanCheckContext,
    accepted_bound_indices: &[usize],
) -> Result<(), String> {
    for block in &construction_plan.bound_reduction_blocks {
        let representative_tree = block
            .ordered_bound_tree_ordinals
            .first()
            .and_then(|ordinal| {
                usize::try_from(*ordinal)
                    .ok()
                    .and_then(|ordinal| construction_plan.bound_trees.get(ordinal))
            })
            .ok_or_else(|| "bound reduction block has no tree".to_owned())?;
        if block.ordered_bound_tree_ordinals.iter().any(|ordinal| {
            usize::try_from(*ordinal)
                .ok()
                .and_then(|ordinal| construction_plan.bound_trees.get(ordinal))
                .is_none_or(|tree| tree.leaf_count != representative_tree.leaf_count)
        }) {
            return Err("bound reduction block mixes leaf domains".to_owned());
        }
        let evaluation_domain_size = usize::try_from(representative_tree.evaluation_domain_size)
            .map_err(|_| "bound evaluation domain does not fit this platform".to_owned())?;
        let evaluation_domain = ProofEvaluationDomain::new(
            evaluation_domain_size,
            relation_context.evaluation_coset_offset,
        )
        .map_err(|error| format!("construct bound evaluation domain: {error:?}"))?;
        if evaluation_domain.generator().canonical() != relation_context.evaluation_domain_generator
        {
            return Err("bound evaluation-domain generator changed".to_owned());
        }
        for leaf_index in accepted_bound_indices
            .get(..block.query_count)
            .ok_or_else(|| "bound query vector is too short for a reduction block".to_owned())?
        {
            for evaluation_position in [
                *leaf_index,
                leaf_index
                    .checked_add(representative_tree.leaf_count)
                    .ok_or_else(|| "bound evaluation position overflowed".to_owned())?,
            ] {
                let evaluation_point = evaluation_domain
                    .point(evaluation_position)
                    .map_err(|error| format!("derive bound evaluation point: {error:?}"))?;
                let reduction = polynomial_opening_reduction(
                    Goldilocks::new(evaluation_point.canonical()),
                    block.polynomial_variable_count,
                )?;
                let mut coordinates = prefix_coordinates(&block.selector_prefix)?;
                coordinates.extend_from_slice(reduction.multilinear_point.as_slice());
                if coordinates.len() != construction_plan.parameters.table_variable_count {
                    return Err("bound reduction query point has the wrong width".to_owned());
                }
                points.push(Point::new(coordinates));
            }
        }
    }
    Ok(())
}

fn binary_coordinates(value: u64, bit_count: usize) -> Result<Vec<ChallengeField>, String> {
    if bit_count >= u64::BITS as usize || value >= (1_u64 << bit_count) {
        return Err("binary coordinate value is outside its width".to_owned());
    }
    Ok((0..bit_count)
        .map(|bit_ordinal| {
            if value & (1_u64 << (bit_count - 1 - bit_ordinal)) == 0 {
                ChallengeField::ZERO
            } else {
                ChallengeField::ONE
            }
        })
        .collect())
}

fn prefix_coordinates(prefix: &[u8]) -> Result<Vec<ChallengeField>, String> {
    prefix
        .iter()
        .map(|bit| match bit {
            0 => Ok(ChallengeField::ZERO),
            1 => Ok(ChallengeField::ONE),
            _ => Err("binary prefix contains a non-bit".to_owned()),
        })
        .collect()
}

pub(super) fn aggregate_column_index_for_opening_point(
    construction_plan: &RowCodeWhirConstructionPlan,
    opening_point_ordinal: usize,
) -> Result<usize, String> {
    let opening_point_ordinal = u32::try_from(opening_point_ordinal)
        .map_err(|_| "opening-point ordinal exceeds u32".to_owned())?;
    construction_plan
        .aggregate_column_roles
        .iter()
        .position(|role| {
            *role
                == RowCodeWhirAggregateColumnRole::OpeningPoint {
                    opening_point_ordinal,
                }
        })
        .ok_or_else(|| "opening point has no aggregate column".to_owned())
}

pub(super) fn aggregate_bound_reduction_column_index(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<Option<usize>, String> {
    let matching = construction_plan
        .aggregate_column_roles
        .iter()
        .enumerate()
        .filter_map(|(index, role)| {
            matches!(role, RowCodeWhirAggregateColumnRole::BoundReduction).then_some(index)
        })
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(*index)),
        _ => Err("aggregate has more than one bound-reduction column".to_owned()),
    }
}

pub(super) fn reduction_block_coefficient_start(
    construction_plan: &RowCodeWhirConstructionPlan,
    block_ordinal: usize,
) -> Result<usize, String> {
    let block = construction_plan
        .bound_reduction_blocks
        .get(block_ordinal)
        .ok_or_else(|| "bound reduction block ordinal is outside the construction".to_owned())?;
    let prefix_value = block
        .selector_prefix
        .iter()
        .try_fold(0_usize, |value, bit| {
            value
                .checked_mul(2)
                .and_then(|value| value.checked_add(usize::from(*bit)))
                .filter(|_| *bit <= 1)
                .ok_or_else(|| "bound selector prefix is not canonical".to_owned())
        })?;
    prefix_value
        .checked_shl(
            u32::try_from(block.polynomial_variable_count)
                .map_err(|_| "bound polynomial variable count exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "bound reduction coefficient start overflowed".to_owned())
}

pub(super) fn bound_reduction_evaluation_count(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<usize, String> {
    construction_plan
        .bound_reduction_blocks
        .iter()
        .try_fold(0_usize, |count, block| {
            block
                .query_count
                .checked_mul(2)
                .and_then(|block_count| count.checked_add(block_count))
                .ok_or_else(|| "bound reduction evaluation count overflowed".to_owned())
        })
}

pub(super) fn bound_degree_test_count(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<usize, String> {
    construction_plan
        .bound_reduction_blocks
        .iter()
        .try_fold(0_usize, |count, block| {
            block
                .degree_suffix_prefixes
                .len()
                .checked_add(1)
                .and_then(|block_count| count.checked_add(block_count))
                .ok_or_else(|| "bound degree-test count overflowed".to_owned())
        })
}

pub(super) fn ensure_bound_opening_points_are_outside_evaluation_domains(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_context: &RelationPlanCheckContext,
    bound_claims: &[RowCodeWhirBoundOpeningClaim],
) -> Result<(), String> {
    for claim in bound_claims {
        let bound_tree = construction_plan
            .bound_trees
            .iter()
            .find(|tree| {
                tree.ordered_columns
                    .iter()
                    .any(|column| column.column_ordinal == claim.column_ordinal)
            })
            .ok_or_else(|| "bound opening claim has no authenticated tree".to_owned())?;
        let domain_constant =
            ChallengeField::from(Goldilocks::new(relation_context.evaluation_coset_offset))
                .exp_u64(bound_tree.evaluation_domain_size);
        if claim
            .opening_point
            .exp_u64(bound_tree.evaluation_domain_size)
            == domain_constant
        {
            return Err(
                "bound opening point lies in an authenticated evaluation domain".to_owned(),
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn accumulate_phase_query_column_evaluations(
    construction_plan: &RowCodeWhirConstructionPlan,
    phase: RowCodeWhirPhase,
    traversal_query_ordinal: usize,
    authenticated_column_index: usize,
    opened_values: &[Goldilocks],
    point_row_weights: &[RowCodeWhirPointRowWeights],
    expected: &mut [Vec<ChallengeField>],
) -> Result<(), String> {
    let encoded_column_count = construction_plan
        .phase_encoded_column_count(phase)
        .ok_or_else(|| "authenticated phase is absent from the construction".to_owned())?;
    let expected_row_count = construction_plan
        .phase_row_count(phase)
        .ok_or_else(|| "authenticated phase has no row plan".to_owned())?;
    if traversal_query_ordinal >= construction_plan.outer_query_count()
        || authenticated_column_index >= encoded_column_count
        || opened_values.len() != expected_row_count
        || expected.len() != construction_plan.outer_query_count()
        || expected
            .iter()
            .any(|point_evaluations| point_evaluations.len() != point_row_weights.len())
    {
        return Err("authenticated phase query accumulator has the wrong shape".to_owned());
    }
    let encoded_column_variable_count = usize::try_from(encoded_column_count.ilog2())
        .map_err(|_| "encoded column variable count exceeds usize".to_owned())?;
    let reduction = polynomial_opening_reduction(
        coset_point(encoded_column_variable_count, authenticated_column_index)?,
        construction_plan.selected_parameters().table_variable_count,
    )?;
    let scale_inverse = reduction.multilinear_to_polynomial_scale.inverse();
    for (point_ordinal, point_weights) in point_row_weights.iter().enumerate() {
        let phase_weights = point_weights.phase_rows(phase);
        if phase_weights.len() != opened_values.len() {
            return Err("authenticated phase values do not match their row weights".to_owned());
        }
        let codeword_value = opened_values
            .iter()
            .zip(phase_weights)
            .fold(ChallengeField::ZERO, |sum, (value, weight)| {
                sum + ChallengeField::from(*value) * *weight
            });
        *expected
            .get_mut(traversal_query_ordinal)
            .and_then(|evaluations| evaluations.get_mut(point_ordinal))
            .ok_or_else(|| {
                "authenticated phase query offset is outside the schedule".to_owned()
            })? += codeword_value * scale_inverse;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn accumulate_bound_leaf_reduction_evaluations(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_context: &RelationPlanCheckContext,
    bound_tree_ordinal: usize,
    accepted_query_ordinal: usize,
    leaf_index: usize,
    first_point_values: &[crate::bgv::proof_suite::ProofBaseFieldElement],
    opposite_point_values: &[crate::bgv::proof_suite::ProofBaseFieldElement],
    bound_claims: &[RowCodeWhirBoundOpeningClaim],
    expected: &mut [ChallengeField],
) -> Result<(), String> {
    if expected.len() != bound_reduction_evaluation_count(construction_plan)? {
        return Err("bound reduction accumulator has the wrong shape".to_owned());
    }
    let bound_tree = construction_plan
        .bound_trees
        .get(bound_tree_ordinal)
        .ok_or_else(|| "bound tree ordinal is outside the construction".to_owned())?;
    let reduction_block_ordinal = construction_plan
        .bound_reduction_blocks
        .iter()
        .position(|block| {
            block
                .ordered_bound_tree_ordinals
                .contains(&bound_tree.bound_tree_ordinal)
        })
        .ok_or_else(|| "bound tree has no reduction block".to_owned())?;
    let reduction_block = &construction_plan.bound_reduction_blocks[reduction_block_ordinal];
    if accepted_query_ordinal >= reduction_block.query_count
        || leaf_index >= bound_tree.leaf_count
        || first_point_values.len() != bound_tree.ordered_columns.len()
        || opposite_point_values.len() != first_point_values.len()
    {
        return Err("bound leaf reduction has the wrong shape".to_owned());
    }
    let evaluation_domain_size = usize::try_from(bound_tree.evaluation_domain_size)
        .map_err(|_| "bound evaluation domain does not fit this platform".to_owned())?;
    let evaluation_domain = ProofEvaluationDomain::new(
        evaluation_domain_size,
        relation_context.evaluation_coset_offset,
    )
    .map_err(|error| format!("construct bound evaluation domain: {error:?}"))?;
    if evaluation_domain.generator().canonical() != relation_context.evaluation_domain_generator {
        return Err("bound evaluation domain has the wrong generator".to_owned());
    }
    let block_offset = construction_plan
        .bound_reduction_blocks
        .iter()
        .take(reduction_block_ordinal)
        .try_fold(0_usize, |offset, block| {
            block
                .query_count
                .checked_mul(2)
                .and_then(|count| offset.checked_add(count))
                .ok_or_else(|| "bound reduction block offset overflowed".to_owned())
        })?;
    for (opposite_ordinal, (values, evaluation_position)) in [
        (first_point_values, leaf_index),
        (
            opposite_point_values,
            leaf_index
                .checked_add(bound_tree.leaf_count)
                .ok_or_else(|| "bound opposite evaluation position overflowed".to_owned())?,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let evaluation_point = evaluation_domain
            .point(evaluation_position)
            .map_err(|error| format!("derive bound evaluation point: {error:?}"))?;
        let evaluation_point_challenge =
            ChallengeField::from(Goldilocks::new(evaluation_point.canonical()));
        let mut polynomial_value = ChallengeField::ZERO;
        for claim in bound_claims
            .iter()
            .filter(|claim| claim.reduction_block_ordinal == reduction_block_ordinal)
        {
            let Some(column_position) = bound_tree
                .ordered_columns
                .iter()
                .position(|column| column.column_ordinal == claim.column_ordinal)
            else {
                continue;
            };
            let denominator = evaluation_point_challenge - claim.opening_point;
            if denominator == ChallengeField::ZERO {
                return Err("bound opening reduction sampled a pole".to_owned());
            }
            let value = values
                .get(column_position)
                .ok_or_else(|| "bound opening column position is absent".to_owned())?;
            polynomial_value += claim.batching_weight
                * (ChallengeField::from(Goldilocks::new(value.canonical())) - claim.claimed_value)
                * denominator.inverse();
        }
        let reduction = polynomial_opening_reduction(
            Goldilocks::new(evaluation_point.canonical()),
            reduction_block.polynomial_variable_count,
        )?;
        let expected_index = block_offset
            .checked_add(
                accepted_query_ordinal
                    .checked_mul(2)
                    .and_then(|offset| offset.checked_add(opposite_ordinal))
                    .ok_or_else(|| "bound reduction query offset overflowed".to_owned())?,
            )
            .ok_or_else(|| "bound reduction evaluation offset overflowed".to_owned())?;
        *expected.get_mut(expected_index).ok_or_else(|| {
            "bound reduction evaluation offset is outside the schedule".to_owned()
        })? += polynomial_value * reduction.multilinear_to_polynomial_scale.inverse();
    }
    Ok(())
}

pub(super) const fn phase_index(phase: RowCodeWhirPhase) -> usize {
    match phase {
        RowCodeWhirPhase::Base => 0,
        RowCodeWhirPhase::Auxiliary => 1,
        RowCodeWhirPhase::Quotient => 2,
    }
}

pub(super) fn phase_has_private_row_padding(relation_variant: &RelationPlanVariant) -> bool {
    relation_variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing
}
