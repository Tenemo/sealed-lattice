use std::collections::{BTreeMap, BTreeSet};

use super::super::{
    expressions::required_column_rotations,
    layout::{
        RelationMaskKind, RelationMaskTargetClass, RelationOpeningPointDescriptor,
        RelationOpeningSourceClass, RelationPlanVariant,
    },
    model::{ProofPrivacyMode, RelationColumnOrigin, RelationPlanError},
};
use super::RelationPlanChecker;

impl RelationPlanChecker<'_> {
    pub(super) fn check_openings(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        if variant.ordered_opening_points.is_empty() || variant.ordered_opening_claims.is_empty() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let required_rotations_by_column = required_column_rotations(
            &variant.ordered_constraints,
            &variant.ordered_radix_convolutions,
        )?;
        if required_rotations_by_column.len() != variant.ordered_columns.len() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let required_rotations = required_rotations_by_column
            .values()
            .flat_map(|rotations| rotations.iter().copied())
            .collect::<BTreeSet<_>>();
        let expected_points = (0..self.context.out_of_domain_point_count)
            .flat_map(|out_of_domain_point_ordinal| {
                required_rotations
                    .iter()
                    .map(move |rotation| RelationOpeningPointDescriptor {
                        out_of_domain_point_ordinal,
                        trace_rotation_is_negative: rotation.0,
                        trace_rotation_magnitude: rotation.1,
                        conjugate_index: 0,
                    })
            })
            .collect::<BTreeSet<_>>();
        let mut points = BTreeSet::new();
        for point in &variant.ordered_opening_points {
            if point.out_of_domain_point_ordinal >= self.context.out_of_domain_point_count
                || point.conjugate_index >= self.context.challenge_extension_degree
                || !points.insert(*point)
            {
                return Err(RelationPlanError::InvalidOpening);
            }
        }
        if points != expected_points {
            return Err(RelationPlanError::InvalidOpening);
        }
        let mut tree_ordinal_by_column = vec![None; variant.ordered_columns.len()];
        for (tree_ordinal, tree) in variant.ordered_trees.iter().enumerate() {
            let tree_ordinal =
                u32::try_from(tree_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            for column_ordinal in tree.ordered_column_ordinals() {
                let owner = tree_ordinal_by_column
                    .get_mut(*column_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidOpening)?;
                if owner.replace(tree_ordinal).is_some() {
                    return Err(RelationPlanError::InvalidOpening);
                }
            }
        }
        let mut claims = BTreeSet::new();
        for claim in &variant.ordered_opening_claims {
            if claim.opening_point_ordinal as usize >= variant.ordered_opening_points.len()
                || claim.source_degree_bound_exclusive == 0
                || claim.source_degree_bound_exclusive > variant.opening_degree_bound_exclusive
                || !claims.insert((
                    claim.source_class as u16,
                    claim.source_ordinal,
                    claim.column_ordinal,
                    claim.opening_point_ordinal,
                ))
            {
                return Err(RelationPlanError::InvalidOpening);
            }
            match claim.source_class {
                RelationOpeningSourceClass::TreeColumn => {
                    let column_ordinal = claim
                        .column_ordinal
                        .ok_or(RelationPlanError::InvalidOpening)?;
                    let column = variant
                        .ordered_columns
                        .get(column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidOpening)?;
                    if matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
                        || tree_ordinal_by_column
                            .get(column_ordinal as usize)
                            .copied()
                            .flatten()
                            != Some(claim.source_ordinal)
                        || column.source_degree_bound_exclusive
                            != claim.source_degree_bound_exclusive
                    {
                        return Err(RelationPlanError::InvalidOpening);
                    }
                }
                RelationOpeningSourceClass::Quotient => {
                    if claim.column_ordinal.is_some()
                        || claim.source_ordinal >= self.context.quotient_component_count
                        || claim.source_degree_bound_exclusive
                            != self.context.quotient_component_degree_bound_exclusive
                    {
                        return Err(RelationPlanError::InvalidOpening);
                    }
                }
                RelationOpeningSourceClass::BatchMask => {
                    if variant.proof_privacy_mode != ProofPrivacyMode::SecretBearing
                        || claim.source_ordinal != 0
                        || claim.column_ordinal.is_some()
                        || claim.source_degree_bound_exclusive
                            != variant.opening_degree_bound_exclusive - 1
                    {
                        return Err(RelationPlanError::InvalidOpening);
                    }
                }
            }
        }
        let mut expected_claims = BTreeSet::new();
        let point_ordinals = variant
            .ordered_opening_points
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, point)| {
                Ok((
                    point,
                    u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, RelationPlanError>>()?;
        for (tree_ordinal, tree) in variant.ordered_trees.iter().enumerate() {
            let tree_ordinal =
                u32::try_from(tree_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            for column_ordinal in tree.ordered_column_ordinals() {
                let rotations = required_rotations_by_column
                    .get(column_ordinal)
                    .ok_or(RelationPlanError::InvalidOpening)?;
                for out_of_domain_point_ordinal in 0..self.context.out_of_domain_point_count {
                    for rotation in rotations {
                        let opening_point_ordinal = point_ordinals
                            .get(&RelationOpeningPointDescriptor {
                                out_of_domain_point_ordinal,
                                trace_rotation_is_negative: rotation.0,
                                trace_rotation_magnitude: rotation.1,
                                conjugate_index: 0,
                            })
                            .copied()
                            .ok_or(RelationPlanError::InvalidOpening)?;
                        expected_claims.insert((
                            RelationOpeningSourceClass::TreeColumn as u16,
                            tree_ordinal,
                            Some(*column_ordinal),
                            opening_point_ordinal,
                        ));
                    }
                }
            }
        }
        for quotient_ordinal in 0..self.context.quotient_component_count {
            for out_of_domain_point_ordinal in 0..self.context.out_of_domain_point_count {
                let opening_point_ordinal = point_ordinals
                    .get(&RelationOpeningPointDescriptor {
                        out_of_domain_point_ordinal,
                        trace_rotation_is_negative: false,
                        trace_rotation_magnitude: 0,
                        conjugate_index: 0,
                    })
                    .copied()
                    .ok_or(RelationPlanError::InvalidOpening)?;
                expected_claims.insert((
                    RelationOpeningSourceClass::Quotient as u16,
                    quotient_ordinal,
                    None,
                    opening_point_ordinal,
                ));
            }
        }
        if variant.proof_privacy_mode == ProofPrivacyMode::SecretBearing {
            expected_claims.insert((RelationOpeningSourceClass::BatchMask as u16, 0, None, 0));
        }
        if claims != expected_claims {
            return Err(RelationPlanError::InvalidOpening);
        }
        Ok(())
    }

    pub(super) fn check_masks(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        let prover_columns = variant
            .ordered_columns
            .iter()
            .enumerate()
            .filter_map(|(ordinal, column)| {
                matches!(column.origin, RelationColumnOrigin::Prover)
                    .then_some(u32::try_from(ordinal).ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        if variant.proof_privacy_mode == ProofPrivacyMode::PublicOnly {
            if !prover_columns.is_empty() || !variant.ordered_masks.is_empty() {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            return Ok(());
        }
        if prover_columns.is_empty() || variant.ordered_masks.is_empty() {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let mut previous_mask_coordinate = None;
        let mut next_mask_ordinal_by_class = [0_u32; 3];
        let mut trace_targets = BTreeSet::new();
        let mut telescoping_targets = BTreeSet::new();
        let mut batch_count = 0_usize;
        let mut trace_degree = None;
        let mut telescoping_degree = None;
        for mask in &variant.ordered_masks {
            let mask_coordinate = mask.mask_coordinate();
            let purpose_class_index = usize::from(mask_coordinate.purpose_class() - 1);
            if purpose_class_index >= next_mask_ordinal_by_class.len()
                || mask_coordinate.mask_ordinal() != next_mask_ordinal_by_class[purpose_class_index]
                || previous_mask_coordinate.is_some_and(|previous| previous >= mask_coordinate)
                || mask.mask_degree_bound_exclusive == 0
            {
                return Err(RelationPlanError::InvalidMaskGrammar);
            }
            next_mask_ordinal_by_class[purpose_class_index] = next_mask_ordinal_by_class
                [purpose_class_index]
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
            previous_mask_coordinate = Some(mask_coordinate);
            match (mask.mask_kind, mask.target_class) {
                (RelationMaskKind::Trace, RelationMaskTargetClass::Column) => {
                    if !prover_columns.contains(&mask.target_ordinal)
                        || mask.mask_degree_bound_exclusive > variant.trace_domain_size
                        || trace_degree
                            .is_some_and(|degree| degree != mask.mask_degree_bound_exclusive)
                        || !trace_targets.insert(mask.target_ordinal)
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                    trace_degree = Some(mask.mask_degree_bound_exclusive);
                }
                (RelationMaskKind::Telescoping, RelationMaskTargetClass::QuotientComponent) => {
                    if mask.target_ordinal + 1 >= self.context.quotient_component_count
                        || telescoping_degree
                            .is_some_and(|degree| degree != mask.mask_degree_bound_exclusive)
                        || !telescoping_targets.insert(mask.target_ordinal)
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                    telescoping_degree = Some(mask.mask_degree_bound_exclusive);
                }
                (RelationMaskKind::OpeningBatch, RelationMaskTargetClass::Batch) => {
                    if mask.target_ordinal != 0
                        || mask.mask_degree_bound_exclusive
                            != variant.opening_degree_bound_exclusive - 1
                    {
                        return Err(RelationPlanError::InvalidMaskGrammar);
                    }
                    batch_count += 1;
                }
                _ => return Err(RelationPlanError::InvalidMaskGrammar),
            }
        }
        if trace_targets != prover_columns
            || telescoping_targets.len() != (self.context.quotient_component_count - 1) as usize
            || batch_count != 1
        {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let decomposition_stride = variant.quotient_decomposition_stride(self.context)?;
        let expected_telescoping_degree = self
            .context
            .quotient_component_degree_bound_exclusive
            .checked_sub(decomposition_stride)
            .filter(|degree| *degree != 0)
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        if telescoping_degree != Some(expected_telescoping_degree) {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        Ok(())
    }
}
