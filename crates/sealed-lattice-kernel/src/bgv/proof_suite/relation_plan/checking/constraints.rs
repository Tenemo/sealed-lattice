use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;

use crate::foundation::ProofApplicationSlotCeilings;

use super::super::{
    bounds::SignedIntegerInterval,
    committed_material::COMMITTED_MATERIAL_TRACE_PACKING_FACTOR,
    expressions::{
        RelationExpressionInstruction, canonical_nested_list, check_expression,
        compile_base_field_polynomial, evaluate_integer_interval, evaluate_polynomial,
        expression_column_ordinals, modular_power, modular_product,
        ordered_injective_integer_factor_product_expression, strictly_sorted_unique,
    },
    integer_lift::RelationCoefficientLocalIdentityBatchDescriptor,
    layout::RelationPlanVariant,
    model::{
        RelationChallengeRole, RelationColumnOrigin, RelationPlanError, RelationTreeDescriptor,
        SuiteModulusReference,
    },
    schema::MAXIMUM_EXHAUSTIVE_ZEROIFIER_COSET_CHECK_DOMAIN_SIZE,
};
use super::{
    RelationPlanChecker,
    integer_lift_bounds::{
        integer_lift_require_pre_challenge_column, integer_lift_tree_roles_by_column,
    },
};

impl RelationPlanChecker<'_> {
    pub(super) fn check_trees(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        if variant.ordered_trees.is_empty() {
            return Err(RelationPlanError::InvalidRoot);
        }
        let mut owned_columns = BTreeSet::new();
        for tree in &variant.ordered_trees {
            if tree.ordered_column_ordinals().is_empty()
                || !strictly_sorted_unique(tree.ordered_column_ordinals())
            {
                return Err(RelationPlanError::InvalidRoot);
            }
            match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role, ..
                } if !matches!(proof_tree_role, 1 | 2) => {
                    return Err(RelationPlanError::InvalidRoot);
                }
                RelationTreeDescriptor::BoundPublic {
                    expected_root_source_ordinal,
                    ordered_column_ordinals,
                    ..
                } => {
                    for ordinal in ordered_column_ordinals {
                        let column = variant
                            .ordered_columns
                            .get(*ordinal as usize)
                            .ok_or(RelationPlanError::InvalidRoot)?;
                        if !matches!(
                            column.origin,
                            RelationColumnOrigin::BoundTree {
                                expected_root_source_ordinal: source
                            } if source == *expected_root_source_ordinal
                        ) {
                            return Err(RelationPlanError::InvalidRoot);
                        }
                    }
                }
                _ => {}
            }
            for ordinal in tree.ordered_column_ordinals() {
                let column = variant
                    .ordered_columns
                    .get(*ordinal as usize)
                    .ok_or(RelationPlanError::InvalidRoot)?;
                if matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
                    || !owned_columns.insert(*ordinal)
                {
                    return Err(RelationPlanError::InvalidRoot);
                }
            }
        }
        let tree_owned_column_count = variant
            .ordered_columns
            .iter()
            .filter(|column| {
                !matches!(column.origin, RelationColumnOrigin::VerifierSequence { .. })
            })
            .count();
        if owned_columns.len() != tree_owned_column_count {
            return Err(RelationPlanError::MissingRoot);
        }
        Ok(())
    }

    pub(super) fn check_constraints(
        &self,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        if variant.ordered_constraints.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut roles = BTreeSet::new();
        let mut checked_zeroifiers = Vec::<Vec<RelationExpressionInstruction>>::new();
        let quotient_decomposition_stride = variant.quotient_decomposition_stride(self.context)?;
        if quotient_decomposition_stride > self.context.quotient_component_degree_bound_exclusive {
            return Err(RelationPlanError::DegreeBoundExceeded);
        }
        let quotient_coefficient_capacity = quotient_decomposition_stride
            .checked_mul(u64::from(self.context.quotient_component_count))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        for constraint in &variant.ordered_constraints {
            if !roles.insert((
                constraint.constraint_role,
                constraint.role_coordinates.clone(),
            )) {
                return Err(RelationPlanError::DuplicateItem);
            }
            let numerator = check_expression(
                &constraint.numerator_postfix_expression,
                variant,
                self.context,
                false,
            )?;
            if numerator.degree >= variant.evaluation_domain_size {
                return Err(RelationPlanError::DegreeBoundExceeded);
            }
            let zeroifier = check_expression(
                &constraint.zeroifier_postfix_expression,
                variant,
                self.context,
                true,
            )?;
            if zeroifier.degree == 0 && zeroifier.constant_value == Some(0) {
                return Err(RelationPlanError::InvalidZeroifier);
            }
            let quotient_coefficient_count = numerator
                .degree
                .checked_sub(zeroifier.degree)
                .map_or(1, |quotient_degree| quotient_degree + 1);
            if quotient_coefficient_count > quotient_coefficient_capacity {
                return Err(RelationPlanError::DegreeBoundExceeded);
            }
            if !checked_zeroifiers
                .iter()
                .any(|checked| checked == &constraint.zeroifier_postfix_expression)
            {
                self.check_zeroifier_on_coset(
                    &constraint.zeroifier_postfix_expression,
                    variant.trace_domain_size,
                    variant.evaluation_domain_size,
                )?;
                checked_zeroifiers.push(constraint.zeroifier_postfix_expression.clone());
            }

            if constraint.enforce_proof_base_field_no_wrap {
                let referenced_columns =
                    expression_column_ordinals(&constraint.numerator_postfix_expression, variant)?;
                let declared_bounds = referenced_columns
                    .iter()
                    .map(|column_ordinal| {
                        semantic_bounds
                            .get(column_ordinal)
                            .cloned()
                            .map(|interval| (*column_ordinal, interval))
                            .ok_or(RelationPlanError::InvalidSemanticCell)
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let interval = evaluate_integer_interval(
                    &constraint.numerator_postfix_expression,
                    &declared_bounds,
                    variant,
                    self.context,
                )?;
                if !interval.is_injective_modulo(&BigInt::from(self.context.base_field_modulus)) {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
            }
            if !constraint
                .ordered_injective_integer_factor_expressions
                .is_empty()
            {
                if constraint.enforce_proof_base_field_no_wrap
                    || constraint
                        .ordered_injective_integer_factor_expressions
                        .len()
                        < 2
                    || constraint.numerator_postfix_expression
                        != ordered_injective_integer_factor_product_expression(
                            &constraint.ordered_injective_integer_factor_expressions,
                        )?
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                for factor_expression in &constraint.ordered_injective_integer_factor_expressions {
                    check_expression(factor_expression, variant, self.context, false)?;
                    let referenced_columns =
                        expression_column_ordinals(factor_expression, variant)?;
                    let declared_bounds = referenced_columns
                        .iter()
                        .map(|column_ordinal| {
                            semantic_bounds
                                .get(column_ordinal)
                                .cloned()
                                .map(|interval| (*column_ordinal, interval))
                                .ok_or(RelationPlanError::InvalidSemanticCell)
                        })
                        .collect::<Result<BTreeMap<_, _>, _>>()?;
                    let interval = evaluate_integer_interval(
                        factor_expression,
                        &declared_bounds,
                        variant,
                        self.context,
                    )?;
                    if !interval.is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
                    {
                        return Err(RelationPlanError::NoWrapBoundViolated);
                    }
                }
            }
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn check_zeroifier_on_coset(
        &self,
        expression: &[RelationExpressionInstruction],
        trace_domain_size: u64,
        evaluation_domain_size: u64,
    ) -> Result<(), RelationPlanError> {
        // Every evaluation-coset point x = offset * generator^i has
        // x^evaluation_domain_size = offset^evaluation_domain_size. Every
        // trace root has evaluation_domain_size-th power one because the
        // trace size divides the evaluation size. The domain checks establish
        // that the offset power is not one, so an exact zeroifier whose roots
        // are confined to the trace subgroup cannot vanish on the coset.
        if zeroifier_roots_are_confined_to_trace_domain(
            expression,
            trace_domain_size,
            self.context.base_field_modulus,
        ) && evaluation_domain_size.is_multiple_of(trace_domain_size)
            && modular_power(
                self.context.evaluation_domain_generator,
                evaluation_domain_size,
                self.context.base_field_modulus,
            ) == 1
            && modular_power(
                self.context.evaluation_coset_offset,
                evaluation_domain_size,
                self.context.base_field_modulus,
            ) != 1
        {
            return Ok(());
        }
        if evaluation_domain_size > MAXIMUM_EXHAUSTIVE_ZEROIFIER_COSET_CHECK_DOMAIN_SIZE {
            return Err(RelationPlanError::InvalidZeroifier);
        }
        let polynomial = compile_base_field_polynomial(
            expression,
            self.context.base_field_modulus,
            usize::try_from(evaluation_domain_size)
                .map_err(|_| RelationPlanError::CountOverflow)?,
        )?;
        if polynomial.iter().all(|coefficient| *coefficient == 0) {
            return Err(RelationPlanError::InvalidZeroifier);
        }
        let mut point = self.context.evaluation_coset_offset;
        for _ in 0..evaluation_domain_size {
            if evaluate_polynomial(&polynomial, point, self.context.base_field_modulus) == 0 {
                return Err(RelationPlanError::ZeroifierVanishesOnEvaluationCoset);
            }
            point = modular_product(
                point,
                self.context.evaluation_domain_generator,
                self.context.base_field_modulus,
            );
        }
        Ok(())
    }

    pub(super) fn check_coefficient_local_identity_batches(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        if application_statement_schema_identifier
            == ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        {
            return self.check_deterministic_coefficient_local_identities(variant, semantic_bounds);
        }
        let is_coefficient_local_family = application_statement_schema_identifier
            == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        if !is_coefficient_local_family {
            return if variant
                .ordered_coefficient_local_identity_batches
                .is_empty()
            {
                Ok(())
            } else {
                Err(RelationPlanError::InvalidConstraint)
            };
        }
        if variant
            .ordered_coefficient_local_identity_batches
            .is_empty()
            || !variant.ordered_integer_lift_batches.is_empty()
            || !variant.ordered_radix_convolutions.is_empty()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let canonical_batch_bytes = variant
            .ordered_coefficient_local_identity_batches
            .iter()
            .map(RelationCoefficientLocalIdentityBatchDescriptor::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_sorted_unique(&canonical_batch_bytes) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let expected_batch_coordinates = variant
            .ordered_non_native_moduli
            .iter()
            .copied()
            .flat_map(|modulus_reference| {
                (0..self.context.non_native_modular_identity_challenge_count).flat_map(
                    move |challenge_ordinal| {
                        (0_u16..2).map(move |batch_ordinal| {
                            (modulus_reference, challenge_ordinal, batch_ordinal)
                        })
                    },
                )
            })
            .collect::<BTreeSet<_>>();
        let mut seen_batch_coordinates = BTreeSet::new();
        let mut matched_constraint_ordinals = BTreeSet::new();
        let expected_identity_zeroifier =
            packed_coefficient_local_identity_zeroifier(variant.trace_domain_size)?;

        for batch in &variant.ordered_coefficient_local_identity_batches {
            let modulus_ordinal = u16::try_from(
                variant
                    .ordered_non_native_moduli
                    .binary_search(&batch.modulus_reference)
                    .map_err(|_| RelationPlanError::MissingModulus)?,
            )
            .map_err(|_| RelationPlanError::CountOverflow)?;
            if batch.challenge_ordinal >= self.context.non_native_modular_identity_challenge_count
                || batch.batch_ordinal >= 2
                || batch.ordered_residuals.is_empty()
                || !seen_batch_coordinates.insert((
                    batch.modulus_reference,
                    batch.challenge_ordinal,
                    batch.batch_ordinal,
                ))
            {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }

            let mut residual_bytes = BTreeSet::new();
            for (residual_index, residual) in batch.ordered_residuals.iter().enumerate() {
                if residual.unit_ordinal
                    != u32::try_from(residual_index)
                        .map_err(|_| RelationPlanError::CountOverflow)?
                    || residual.residual_postfix_expression.is_empty()
                    || residual
                        .residual_postfix_expression
                        .iter()
                        .any(|instruction| {
                            !matches!(
                                instruction,
                                RelationExpressionInstruction::BaseFieldConstant(_)
                                    | RelationExpressionInstruction::NonNativeModulusConstant { .. }
                                    | RelationExpressionInstruction::ColumnValue { .. }
                                    | RelationExpressionInstruction::Addition
                                    | RelationExpressionInstruction::Multiplication
                                    | RelationExpressionInstruction::Negation
                            )
                        })
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let residual_canonical_bytes = canonical_nested_list(
                    residual
                        .residual_postfix_expression
                        .iter()
                        .map(RelationExpressionInstruction::canonical_tuple)
                        .collect::<Result<Vec<_>, _>>()?,
                )?
                .canonical_bytes()
                .to_vec();
                if !residual_bytes.insert(residual_canonical_bytes) {
                    return Err(RelationPlanError::DuplicateItem);
                }

                let referenced_moduli = residual
                    .residual_postfix_expression
                    .iter()
                    .filter_map(|instruction| match instruction {
                        RelationExpressionInstruction::NonNativeModulusConstant {
                            modulus_reference,
                            ..
                        } => Some(*modulus_reference),
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>();
                if referenced_moduli != BTreeSet::from([batch.modulus_reference]) {
                    return Err(RelationPlanError::InvalidModulus);
                }
                check_expression(
                    &residual.residual_postfix_expression,
                    variant,
                    self.context,
                    false,
                )?;
                let referenced_columns =
                    expression_column_ordinals(&residual.residual_postfix_expression, variant)?;
                if referenced_columns.is_empty() {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let declared_bounds = referenced_columns
                    .iter()
                    .map(|column_ordinal| {
                        integer_lift_require_pre_challenge_column(
                            *column_ordinal,
                            variant,
                            &tree_roles_by_column,
                        )?;
                        semantic_bounds
                            .get(column_ordinal)
                            .cloned()
                            .map(|interval| (*column_ordinal, interval))
                            .ok_or(RelationPlanError::InvalidSemanticCell)
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let residual_interval = evaluate_integer_interval(
                    &residual.residual_postfix_expression,
                    &declared_bounds,
                    variant,
                    self.context,
                )?;
                if !residual_interval
                    .is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
                {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
            }

            let constraint = variant
                .ordered_constraints
                .get(batch.constraint_ordinal as usize)
                .ok_or(RelationPlanError::InvalidConstraint)?;
            if !matched_constraint_ordinals.insert(batch.constraint_ordinal)
                || constraint.enforce_proof_base_field_no_wrap
                || !constraint
                    .ordered_injective_integer_factor_expressions
                    .is_empty()
                || constraint.zeroifier_postfix_expression != expected_identity_zeroifier
                || constraint.numerator_postfix_expression
                    != batch.numerator_postfix_expression(modulus_ordinal)?
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }

        let alpha_constraint_ordinals = variant
            .ordered_constraints
            .iter()
            .enumerate()
            .filter_map(|(constraint_ordinal, constraint)| {
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        matches!(
                            instruction,
                            RelationExpressionInstruction::TranscriptChallenge {
                                challenge_role: RelationChallengeRole::NonNativeAlpha,
                                ..
                            }
                        )
                    })
                    .then(|| u32::try_from(constraint_ordinal).ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        if variant.ordered_constraints.iter().any(|constraint| {
            constraint
                .numerator_postfix_expression
                .iter()
                .any(|instruction| {
                    matches!(
                        instruction,
                        RelationExpressionInstruction::TranscriptChallenge {
                            challenge_role: RelationChallengeRole::NonNativeTheta,
                            ..
                        }
                    )
                })
        }) || seen_batch_coordinates != expected_batch_coordinates
            || matched_constraint_ordinals != alpha_constraint_ordinals
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        Ok(())
    }

    pub(super) fn check_deterministic_coefficient_local_identities(
        &self,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        if !variant
            .ordered_coefficient_local_identity_batches
            .is_empty()
            || !variant.ordered_integer_lift_batches.is_empty()
            || !variant.ordered_radix_convolutions.is_empty()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let deterministic_constraints = variant
            .ordered_constraints
            .iter()
            .enumerate()
            .filter(|(_, constraint)| {
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        matches!(
                            instruction,
                            RelationExpressionInstruction::NonNativeModulusConstant { .. }
                        )
                    })
            })
            .collect::<Vec<_>>();
        let expected_constraint_count = variant
            .ordered_non_native_moduli
            .len()
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?;
        if deterministic_constraints.len() != expected_constraint_count {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let mut residuals_by_modulus = BTreeMap::<SuiteModulusReference, BTreeSet<Vec<u8>>>::new();
        let expected_identity_zeroifier =
            packed_coefficient_local_identity_zeroifier(variant.trace_domain_size)?;
        for (deterministic_ordinal, (_, constraint)) in
            deterministic_constraints.into_iter().enumerate()
        {
            let expected_modulus = variant.ordered_non_native_moduli[deterministic_ordinal / 2];
            if constraint.enforce_proof_base_field_no_wrap
                || !constraint
                    .ordered_injective_integer_factor_expressions
                    .is_empty()
                || constraint.zeroifier_postfix_expression != expected_identity_zeroifier
                || constraint.numerator_postfix_expression.is_empty()
                || constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        !matches!(
                            instruction,
                            RelationExpressionInstruction::BaseFieldConstant(_)
                                | RelationExpressionInstruction::NonNativeModulusConstant { .. }
                                | RelationExpressionInstruction::ColumnValue { .. }
                                | RelationExpressionInstruction::Addition
                                | RelationExpressionInstruction::Multiplication
                                | RelationExpressionInstruction::Negation
                        )
                    })
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let referenced_moduli = constraint
                .numerator_postfix_expression
                .iter()
                .filter_map(|instruction| match instruction {
                    RelationExpressionInstruction::NonNativeModulusConstant {
                        modulus_reference,
                        ..
                    } => Some(*modulus_reference),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if referenced_moduli != BTreeSet::from([expected_modulus]) {
                return Err(RelationPlanError::InvalidModulus);
            }
            check_expression(
                &constraint.numerator_postfix_expression,
                variant,
                self.context,
                false,
            )?;
            let referenced_columns =
                expression_column_ordinals(&constraint.numerator_postfix_expression, variant)?;
            if referenced_columns.is_empty() {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let declared_bounds = referenced_columns
                .iter()
                .map(|column_ordinal| {
                    integer_lift_require_pre_challenge_column(
                        *column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    semantic_bounds
                        .get(column_ordinal)
                        .cloned()
                        .map(|interval| (*column_ordinal, interval))
                        .ok_or(RelationPlanError::InvalidSemanticCell)
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            let residual_interval = evaluate_integer_interval(
                &constraint.numerator_postfix_expression,
                &declared_bounds,
                variant,
                self.context,
            )?;
            if !residual_interval
                .is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
            {
                return Err(RelationPlanError::NoWrapBoundViolated);
            }
            let residual_bytes = canonical_nested_list(
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .map(RelationExpressionInstruction::canonical_tuple)
                    .collect::<Result<Vec<_>, _>>()?,
            )?
            .canonical_bytes()
            .to_vec();
            if !residuals_by_modulus
                .entry(expected_modulus)
                .or_default()
                .insert(residual_bytes)
            {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
        if residuals_by_modulus
            .values()
            .any(|residuals| residuals.len() != 2)
            || variant.ordered_constraints.iter().any(|constraint| {
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .any(|instruction| {
                        matches!(
                            instruction,
                            RelationExpressionInstruction::TranscriptChallenge {
                                challenge_role: RelationChallengeRole::NonNativeAlpha
                                    | RelationChallengeRole::NonNativeTheta,
                                ..
                            }
                        )
                    })
            })
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        Ok(())
    }
}

fn packed_coefficient_local_identity_zeroifier(
    trace_domain_size: u64,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    // Coefficient-local identities hold on the logical-row subgroup, not on
    // every coset of the packed trace. The relation owner is the sole packing
    // authority, so the compiler and checker cannot silently drift apart.
    if !trace_domain_size.is_multiple_of(COMMITTED_MATERIAL_TRACE_PACKING_FACTOR) {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let identity_domain_size = trace_domain_size / COMMITTED_MATERIAL_TRACE_PACKING_FACTOR;
    if identity_domain_size == 0 || !identity_domain_size.is_power_of_two() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(full_trace_zeroifier_expression(identity_domain_size))
}

pub(in crate::bgv::proof_suite::relation_plan) fn zeroifier_roots_are_confined_to_trace_domain(
    expression: &[RelationExpressionInstruction],
    trace_domain_size: u64,
    base_field_modulus: u64,
) -> bool {
    if trace_domain_size == 0 || base_field_modulus < 3 {
        return false;
    }
    match expression {
        [
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::NonnegativePower(exponent),
            RelationExpressionInstruction::BaseFieldConstant(1),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
            // When the exponent divides the trace-domain order, every root of
            // X^exponent - 1 belongs to the unique trace subgroup. This covers
            // exact constraints on a plan-fixed subgroup without broadening the
            // accepted root set beyond the trace domain.
        ] => *exponent != 0 && trace_domain_size.is_multiple_of(*exponent),
        [
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size: encoded_trace_domain_size,
                ordered_excluded_roots,
            },
        ] => {
            *encoded_trace_domain_size == trace_domain_size
                && !ordered_excluded_roots.is_empty()
                && (ordered_excluded_roots.len() as u64) < trace_domain_size
                && strictly_sorted_unique(ordered_excluded_roots)
                && ordered_excluded_roots.iter().all(|root| {
                    *root > 0
                        && *root < base_field_modulus
                        && modular_power(*root, trace_domain_size, base_field_modulus) == 1
                })
        }
        [
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::BaseFieldConstant(root),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ] => {
            *root > 0
                && *root < base_field_modulus
                && modular_power(*root, trace_domain_size, base_field_modulus) == 1
        }
        _ => false,
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn full_trace_zeroifier_expression(
    trace_domain_size: u64,
) -> Vec<RelationExpressionInstruction> {
    vec![
        RelationExpressionInstruction::EvaluationVariable,
        RelationExpressionInstruction::NonnegativePower(trace_domain_size),
        RelationExpressionInstruction::BaseFieldConstant(1),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        COMMITTED_MATERIAL_TRACE_PACKING_FACTOR, full_trace_zeroifier_expression,
        packed_coefficient_local_identity_zeroifier,
    };
    use crate::bgv::proof_suite::relation_plan::committed_material::CommittedMaterialRelationPlanInput;

    #[test]
    fn coefficient_local_zeroifier_uses_the_relation_owned_packing_factor() {
        let input = CommittedMaterialRelationPlanInput {
            ring_degree: 32,
            evaluation_domain_size: 1_024,
            opening_degree_bound_exclusive: 512,
            material_column_degree_bound_exclusive: 10,
            participant_count: 3,
            threshold: 2,
            sharing_data_modulus_indices: vec![0],
            trace_mask_degree_bound_exclusive: 14,
        };
        let message_trace_domain_size = input
            .message_trace_domain_size()
            .expect("test message trace domain derives");
        let relation_trace_domain_size = input
            .relation_trace_domain_size()
            .expect("test relation trace domain derives");
        assert_eq!(
            relation_trace_domain_size,
            message_trace_domain_size * COMMITTED_MATERIAL_TRACE_PACKING_FACTOR
        );
        assert_eq!(
            packed_coefficient_local_identity_zeroifier(relation_trace_domain_size)
                .expect("packed coefficient-local zeroifier derives"),
            full_trace_zeroifier_expression(message_trace_domain_size)
        );
    }
}
