//! Structural zero-knowledge checks for generated secret-bearing relations.
//!
//! These checks are part of suite generation. They are not proof fields and
//! do not turn a verifier result into an assurance claim. Their purpose is to
//! prevent a generated plan from committing a secret polynomial with too few
//! fresh mask coefficients for the complete verifier-visible opening set.

use std::collections::BTreeMap;

use super::relation_plan::{
    ProofPrivacyMode, RelationColumnOrigin, RelationMaskKind,
    RelationMaskTargetClass, RelationOpeningSourceClass,
};
use super::{RelationPlanCheckContext, RelationPlanError, RelationPlanVariant};

/// Checks the Vandermonde image dimensions required by the common masking
/// grammar. All counts come from the checked plan and field schedule.
pub(crate) fn validate_zero_knowledge_mask_image(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<(), RelationPlanError> {
    if variant.proof_privacy_mode() == ProofPrivacyMode::PublicOnly {
        return Ok(());
    }

    let phase_pair_query_coordinate_count = u64::from(context.unique_query_count)
        .checked_mul(2)
        .ok_or(RelationPlanError::CountOverflow)?;
    let extension_degree = u64::from(context.challenge_extension_degree);
    let trace_mask_degree_by_column = variant
        .ordered_masks()
        .iter()
        .filter(|mask| {
            mask.mask_kind() == RelationMaskKind::Trace
                && mask.target_class() == RelationMaskTargetClass::Column
        })
        .map(|mask| (mask.target_ordinal(), mask.mask_degree_bound_exclusive()))
        .collect::<BTreeMap<_, _>>();

    for (column_ordinal, column) in variant.ordered_columns().iter().enumerate() {
        if !matches!(column.origin(), RelationColumnOrigin::Prover) {
            continue;
        }
        let column_ordinal = u32::try_from(column_ordinal)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let deep_opening_count = u64::try_from(
            variant
                .ordered_opening_claims()
                .iter()
                .filter(|claim| {
                    claim.source_class() == RelationOpeningSourceClass::TreeColumn
                        && claim.column_ordinal() == Some(column_ordinal)
                })
                .count(),
        )
        .map_err(|_| RelationPlanError::CountOverflow)?;
        if deep_opening_count == 0 {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let deep_base_coordinate_count = deep_opening_count
            .checked_mul(extension_degree)
            .ok_or(RelationPlanError::CountOverflow)?;
        let complete_view_coordinate_count = deep_base_coordinate_count
            .checked_add(phase_pair_query_coordinate_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        let minimum_trace_mask_degree = complete_view_coordinate_count
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?;
        let actual_trace_mask_degree = trace_mask_degree_by_column
            .get(&column_ordinal)
            .copied()
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        if actual_trace_mask_degree < minimum_trace_mask_degree
            || actual_trace_mask_degree > variant.trace_domain_size()
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
    }

    let minimum_telescoping_mask_degree = u64::from(context.deep_point_count)
        .checked_add(phase_pair_query_coordinate_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut telescoping_mask_count = 0_u32;
    for mask in variant.ordered_masks().iter().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::Telescoping
            && mask.target_class()
                == RelationMaskTargetClass::QuotientComponent
    }) {
        if mask.mask_degree_bound_exclusive() < minimum_telescoping_mask_degree {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        telescoping_mask_count = telescoping_mask_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    if telescoping_mask_count + 1 != context.quotient_component_count {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }

    let minimum_opening_batch_mask_degree = phase_pair_query_coordinate_count
        .checked_add(1)
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut opening_batch_masks = variant.ordered_masks().iter().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::OpeningBatch
            && mask.target_class() == RelationMaskTargetClass::Batch
    });
    let opening_batch_mask = opening_batch_masks
        .next()
        .ok_or(RelationPlanError::InvalidMaskGrammar)?;
    if opening_batch_masks.next().is_some()
        || opening_batch_mask.mask_degree_bound_exclusive()
            < minimum_opening_batch_mask_degree
    {
        return Err(RelationPlanError::InvalidMaskGrammar);
    }
    Ok(())
}

