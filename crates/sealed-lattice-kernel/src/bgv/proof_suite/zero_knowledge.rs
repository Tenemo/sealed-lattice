//! Structural zero-knowledge checks for generated secret-bearing relations.
//!
//! These checks are part of suite generation. They are not proof fields and
//! do not turn a verifier result into an assurance claim. Their purpose is to
//! prevent a generated plan from committing a secret polynomial with too few
//! fresh mask coefficients for the complete verifier-visible opening set.

use std::collections::{BTreeMap, BTreeSet};

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
        let mut deep_opening_count = 0_u64;
        let mut required_rotations = BTreeSet::new();
        for claim in variant.ordered_opening_claims().iter().filter(|claim| {
            claim.source_class() == RelationOpeningSourceClass::TreeColumn
                && claim.column_ordinal() == Some(column_ordinal)
        }) {
            deep_opening_count = deep_opening_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
            let opening_point = variant
                .ordered_opening_points()
                .get(
                    usize::try_from(claim.opening_point_ordinal())
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .copied()
                .ok_or(RelationPlanError::InvalidMaskGrammar)?;
            required_rotations.insert(opening_point.trace_rotation());
        }
        if deep_opening_count == 0 {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let minimum_trace_mask_degree = required_trace_mask_coefficient_count(
            deep_opening_count,
            extension_degree,
            phase_pair_query_coordinate_count,
            &required_rotations,
        )?;
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

fn required_trace_mask_coefficient_count(
    deep_opening_count: u64,
    extension_degree: u64,
    phase_pair_query_coordinate_count: u64,
    required_rotations: &BTreeSet<(bool, u64)>,
) -> Result<u64, RelationPlanError> {
    // Habock-Al Kindi's DEEP count is a count of sampled centers before the
    // relation-specific neighboring-row expansion. The checked opening-claim
    // list already contains that complete expansion, so each claim contributes
    // one extension-field value here and must not receive another factor two.
    let deep_base_coordinate_count = deep_opening_count
        .checked_mul(extension_degree)
        .ok_or(RelationPlanError::CountOverflow)?;
    let direct_tree_rotation = (false, 0);
    let query_rotation_count = u64::try_from(required_rotations.len())
        .map_err(|_| RelationPlanError::CountOverflow)?
        .checked_add(u64::from(!required_rotations.contains(&direct_tree_rotation)))
        .ok_or(RelationPlanError::CountOverflow)?;
    let query_base_coordinate_count = phase_pair_query_coordinate_count
        .checked_mul(query_rotation_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    deep_base_coordinate_count
        .checked_add(query_base_coordinate_count)
        .ok_or(RelationPlanError::CountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rotation_set(rotations: &[(bool, u64)]) -> BTreeSet<(bool, u64)> {
        rotations.iter().copied().collect()
    }

    #[test]
    fn one_direct_rotation_counts_each_deep_opening_once() {
        let required = required_trace_mask_coefficient_count(
            3,
            5,
            14,
            &rotation_set(&[(false, 0)]),
        )
        .expect("mask-image count must fit");

        assert_eq!(required, 3 * 5 + 14);
    }

    #[test]
    fn one_translated_rotation_also_counts_direct_query_openings() {
        let required = required_trace_mask_coefficient_count(
            3,
            5,
            14,
            &rotation_set(&[(false, 1)]),
        )
        .expect("mask-image count must fit");

        assert_eq!(required, 3 * 5 + 2 * 14);
    }

    #[test]
    fn two_rotation_deep_claims_are_not_expanded_twice() {
        let deep_point_count = 3;
        let extension_degree = 5;
        let phase_pair_query_coordinate_count = 14;
        let required = required_trace_mask_coefficient_count(
            deep_point_count * 2,
            extension_degree,
            phase_pair_query_coordinate_count,
            &rotation_set(&[(false, 0), (false, 1)]),
        )
        .expect("mask-image count must fit");

        assert_eq!(
            required,
            deep_point_count * 2 * extension_degree
                + 2 * phase_pair_query_coordinate_count
        );
        assert_ne!(
            required,
            (deep_point_count * 2 * extension_degree
                + phase_pair_query_coordinate_count)
                * 2
        );
    }

    #[test]
    fn more_than_two_rotations_expand_the_complete_query_preimage() {
        let phase_pair_query_coordinate_count = 200;
        let required = required_trace_mask_coefficient_count(
            4,
            1,
            phase_pair_query_coordinate_count,
            &rotation_set(&[(false, 0), (false, 1), (true, 1), (false, 2)]),
        )
        .expect("mask-image count must fit");

        assert_eq!(required, 4 + 4 * phase_pair_query_coordinate_count);
        assert!(required > (4 + phase_pair_query_coordinate_count) * 2);
    }

    #[test]
    fn mask_image_count_refuses_arithmetic_overflow() {
        assert_eq!(
            required_trace_mask_coefficient_count(
                u64::MAX,
                2,
                2,
                &rotation_set(&[(false, 0)]),
            ),
            Err(RelationPlanError::CountOverflow)
        );
        assert_eq!(
            required_trace_mask_coefficient_count(
                1,
                1,
                u64::MAX,
                &rotation_set(&[(false, 0), (false, 1)]),
            ),
            Err(RelationPlanError::CountOverflow)
        );
    }
}
