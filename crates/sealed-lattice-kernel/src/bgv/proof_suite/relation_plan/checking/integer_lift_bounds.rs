use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use super::super::{
    bounds::{
        RelationBoundCertificate, RelationConstraintDescriptor, SemanticCellDescriptor,
        SignedIntegerInterval,
    },
    compiled_plan::RelationPlanCheckContext,
    expressions::{
        binary_constraint_expression, finite_integer_set_factor_expression,
        ordered_injective_integer_factor_product_expression, radix_recomposition_expression,
        resolved_modulus_multiple, strictly_sorted_unique, trinary_constraint_expression,
    },
    integer_lift::{RelationIntegerLiftCoefficient, resolved_modulus_radix_digit},
    layout::RelationPlanVariant,
    model::{
        BoundTreeConstructionKind, RelationColumnOrigin, RelationElementKind,
        RelationEmbeddingKind, RelationPlanError, RelationTreeDescriptor, RelationVerifierSource,
    },
};
use super::{
    constraints::full_trace_zeroifier_expression,
    model::{validate_canonical_modulus_recomposition_bound, validate_radix_digit_bounds},
};

pub(super) fn integer_lift_tree_roles_by_column(
    variant: &RelationPlanVariant,
) -> Result<BTreeMap<u32, Option<u16>>, RelationPlanError> {
    let mut roles = BTreeMap::new();
    for tree in &variant.ordered_trees {
        let role = match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role, ..
            } => Some(*proof_tree_role),
            RelationTreeDescriptor::BoundPublic { .. } => None,
        };
        for column_ordinal in tree.ordered_column_ordinals() {
            if roles.insert(*column_ordinal, role).is_some() {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
    }
    Ok(roles)
}

pub(super) fn integer_lift_require_pre_challenge_column(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    tree_roles_by_column: &BTreeMap<u32, Option<u16>>,
) -> Result<(), RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    let role = tree_roles_by_column.get(&column_ordinal).copied();
    match column.origin {
        RelationColumnOrigin::Prover if role == Some(Some(1)) => Ok(()),
        RelationColumnOrigin::VerifierSequence { .. } if role.is_none() => Ok(()),
        RelationColumnOrigin::BoundTree { .. } if role == Some(None) => Ok(()),
        _ => Err(RelationPlanError::InvalidConstraint),
    }
}

pub(super) fn integer_lift_require_auxiliary_column(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    tree_roles_by_column: &BTreeMap<u32, Option<u16>>,
    explicitly_certified_columns: &BTreeSet<u32>,
) -> Result<(), RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    if !matches!(column.origin, RelationColumnOrigin::Prover)
        || tree_roles_by_column.get(&column_ordinal) != Some(&Some(2))
        || explicitly_certified_columns.contains(&column_ordinal)
        || column.canonical_residue_modulus.is_some()
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(())
}

pub(super) fn integer_lift_require_unbounded_reversed_base_column(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    tree_roles_by_column: &BTreeMap<u32, Option<u16>>,
    explicitly_certified_columns: &BTreeSet<u32>,
) -> Result<(), RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    if !matches!(column.origin, RelationColumnOrigin::Prover)
        || tree_roles_by_column.get(&column_ordinal) != Some(&Some(1))
        || explicitly_certified_columns.contains(&column_ordinal)
        || column.canonical_residue_modulus.is_some()
    {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(())
}

pub(in crate::bgv::proof_suite::relation_plan) fn integer_lift_maximum_absolute_product(
    left: &SignedIntegerInterval,
    right: &SignedIntegerInterval,
) -> Result<BigUint, RelationPlanError> {
    let product = left.clone().multiply(right.clone())?;
    Ok(product
        .minimum
        .magnitude()
        .max(product.maximum.magnitude())
        .clone())
}

pub(super) fn integer_lift_column_interval(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
    semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    explicitly_certified_columns: &BTreeSet<u32>,
    context: &RelationPlanCheckContext,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let column = variant
        .ordered_columns
        .get(column_ordinal as usize)
        .ok_or(RelationPlanError::InvalidColumn)?;
    match column.origin {
        RelationColumnOrigin::VerifierSequence {
            verifier_source_ordinal,
            ..
        } => {
            let source = variant
                .ordered_verifier_sources
                .get(verifier_source_ordinal as usize)
                .ok_or(RelationPlanError::InvalidSource)?;
            if let RelationVerifierSource::RadixDecomposition { radix, .. } = source {
                if column.canonical_residue_modulus.is_some() {
                    return Err(RelationPlanError::InvalidSemanticCell);
                }
                return SignedIntegerInterval::from_bigints(
                    BigInt::zero(),
                    BigInt::from(radix - 1),
                );
            }
            let modulus_reference = column
                .canonical_residue_modulus
                .ok_or(RelationPlanError::InvalidSemanticCell)?;
            let layout = source.value_layout()?;
            if layout.element_kind != RelationElementKind::Residue
                || layout.residue_modulus != Some(modulus_reference)
            {
                return Err(RelationPlanError::InvalidSemanticCell);
            }
            let modulus = context.resolved_modulus(modulus_reference)?;
            match layout.embedding_kind {
                RelationEmbeddingKind::LeastNonnegative => {
                    SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(modulus - 1))
                }
                RelationEmbeddingKind::Centered => {
                    let absolute_bound = (modulus - 1) / 2;
                    SignedIntegerInterval::from_bigints(
                        -BigInt::from(absolute_bound),
                        BigInt::from(absolute_bound),
                    )
                }
                _ => Err(RelationPlanError::InvalidSemanticCell),
            }
        }
        RelationColumnOrigin::BoundTree { .. } => {
            if explicitly_certified_columns.contains(&column_ordinal) {
                return semantic_bounds
                    .get(&column_ordinal)
                    .cloned()
                    .ok_or(RelationPlanError::InvalidSemanticCell);
            }
            let modulus_reference = column
                .canonical_residue_modulus
                .filter(|_| {
                    integer_lift_bound_tree_has_canonical_residue_capability(
                        column_ordinal,
                        variant,
                    )
                })
                .ok_or(RelationPlanError::InvalidBoundCertificate)?;
            let modulus = context.resolved_modulus(modulus_reference)?;
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(modulus - 1))
        }
        RelationColumnOrigin::Prover => semantic_bounds
            .get(&column_ordinal)
            .cloned()
            .ok_or(RelationPlanError::InvalidSemanticCell),
    }
}

pub(super) fn integer_lift_bound_tree_has_canonical_residue_capability(
    column_ordinal: u32,
    variant: &RelationPlanVariant,
) -> bool {
    variant.ordered_trees.iter().any(|tree| {
        matches!(
            tree,
            RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } if ordered_column_ordinals.binary_search(&column_ordinal).is_ok()
        )
    })
}

pub(super) fn integer_lift_coefficient_value(
    coefficient: RelationIntegerLiftCoefficient,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    match coefficient {
        RelationIntegerLiftCoefficient::Constant(value) => {
            if !(1..context.base_field_modulus).contains(&value) {
                return Err(RelationPlanError::NoWrapBoundViolated);
            }
            Ok(value)
        }
        RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier,
        } => resolved_modulus_multiple(modulus_reference, multiplier, context),
        RelationIntegerLiftCoefficient::ModulusRadixDigit {
            modulus_reference,
            multiplier,
            radix,
            digit_ordinal,
        } => {
            let value = resolved_modulus_radix_digit(
                modulus_reference,
                multiplier,
                radix,
                digit_ordinal,
                context,
            )?;
            if value == 0 {
                return Err(RelationPlanError::NoWrapBoundViolated);
            }
            Ok(value)
        }
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn derive_semantic_cell_interval(
    column_ordinal: u32,
    semantic_cells_by_column: &BTreeMap<u32, &SemanticCellDescriptor>,
    constraints: &[RelationConstraintDescriptor],
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
    derived_intervals: &mut BTreeMap<u32, SignedIntegerInterval>,
    active_columns: &mut BTreeSet<u32>,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let proof_base_field_modulus = context.base_field_modulus;
    if let Some(interval) = derived_intervals.get(&column_ordinal) {
        return Ok(interval.clone());
    }
    if !active_columns.insert(column_ordinal) {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let semantic_cell = semantic_cells_by_column
        .get(&column_ordinal)
        .copied()
        .ok_or(RelationPlanError::InvalidSemanticCell)?;
    let constraint = constraints
        .get(semantic_cell.bound_certificate.constraint_ordinal() as usize)
        .ok_or(RelationPlanError::InvalidBoundCertificate)?;
    if constraint.enforce_proof_base_field_no_wrap
        || constraint.zeroifier_postfix_expression
            != full_trace_zeroifier_expression(trace_domain_size)
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let derived_interval = match &semantic_cell.bound_certificate {
        RelationBoundCertificate::Trinary { .. } => {
            if constraint.numerator_postfix_expression
                != trinary_constraint_expression(column_ordinal)
            {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::new(0, 2)
        }
        RelationBoundCertificate::Binary { .. } => {
            if constraint.numerator_postfix_expression
                != binary_constraint_expression(column_ordinal)
            {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::new(0, 1)
        }
        RelationBoundCertificate::UnsignedRadixRecomposition {
            radix,
            ordered_digit_column_ordinals,
            ..
        } => {
            let maximum = validate_radix_digit_bounds(
                column_ordinal,
                *radix,
                ordered_digit_column_ordinals,
                semantic_cells_by_column,
                constraints,
                trace_domain_size,
                context,
                derived_intervals,
                active_columns,
            )?;
            let expected_expression = radix_recomposition_expression(
                column_ordinal,
                *radix,
                None,
                ordered_digit_column_ordinals,
                proof_base_field_modulus,
            )?;
            if constraint.numerator_postfix_expression != expected_expression {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?
        }
        RelationBoundCertificate::ShiftedRadixRecomposition {
            radix,
            offset,
            ordered_digit_column_ordinals,
            ..
        } => {
            if offset.is_zero() || offset >= &BigUint::from(proof_base_field_modulus) {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            let maximum = validate_radix_digit_bounds(
                column_ordinal,
                *radix,
                ordered_digit_column_ordinals,
                semantic_cells_by_column,
                constraints,
                trace_domain_size,
                context,
                derived_intervals,
                active_columns,
            )?;
            let expected_expression = radix_recomposition_expression(
                column_ordinal,
                *radix,
                Some(offset),
                ordered_digit_column_ordinals,
                proof_base_field_modulus,
            )?;
            if constraint.numerator_postfix_expression != expected_expression {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            let offset = BigInt::from(offset.clone());
            SignedIntegerInterval::from_bigints(-offset.clone(), BigInt::from(maximum) - offset)?
        }
        RelationBoundCertificate::CanonicalModulusRecomposition {
            modulus_reference,
            radix,
            ordered_digit_column_ordinals,
            ordered_comparator_constraint_ordinals,
            ordered_difference_digit_column_ordinals,
            ordered_borrow_column_ordinals,
            ..
        } => validate_canonical_modulus_recomposition_bound(
            column_ordinal,
            *modulus_reference,
            *radix,
            ordered_digit_column_ordinals,
            ordered_comparator_constraint_ordinals,
            ordered_difference_digit_column_ordinals,
            ordered_borrow_column_ordinals,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )?,
        RelationBoundCertificate::FiniteIntegerSet { ordered_values, .. } => {
            if ordered_values.len() < 2 || !strictly_sorted_unique(ordered_values) {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            let ordered_factor_expressions = ordered_values
                .iter()
                .map(|value| {
                    finite_integer_set_factor_expression(
                        column_ordinal,
                        value,
                        proof_base_field_modulus,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            if constraint.ordered_injective_integer_factor_expressions != ordered_factor_expressions
                || constraint.numerator_postfix_expression
                    != ordered_injective_integer_factor_product_expression(
                        &ordered_factor_expressions,
                    )?
            {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            SignedIntegerInterval::from_bigints(
                ordered_values
                    .first()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
                ordered_values
                    .last()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
            )?
        }
    };

    if semantic_cell.claimed_interval != derived_interval {
        return Err(RelationPlanError::InvalidSemanticCell);
    }
    active_columns.remove(&column_ordinal);
    derived_intervals.insert(column_ordinal, derived_interval.clone());
    Ok(derived_interval)
}
