use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;

use crate::foundation::ProofApplicationSlotCeilings;

use super::super::trustee_evaluation_key::selected_galois_key_share_relation_schedule;
use super::super::{
    bounds::SignedIntegerInterval,
    expressions::strictly_sorted_unique,
    integer_lift::{
        RelationIntegerLiftBatchDescriptor, RelationIntegerLiftComponentDescriptor,
        RelationIntegerLiftConvolutionProductDescriptor,
        RelationIntegerLiftFullRingNegacyclicProductDescriptor,
        RelationIntegerLiftLinearTermDescriptor,
        RelationIntegerLiftReversedColumnBindingDescriptor,
        theta_sampling_field_exceeds_bad_polynomial_degree,
    },
    layout::RelationPlanVariant,
    model::{
        RelationColumnOrigin, RelationColumnValueType, RelationPlanError, RelationVerifierSource,
        SuiteModulusReference, validate_negacyclic_automorphism,
    },
};
use super::{
    ApplicationChallengePhaseColumns, RelationPlanChecker,
    integer_lift_bounds::{
        integer_lift_coefficient_value, integer_lift_column_interval,
        integer_lift_maximum_absolute_product, integer_lift_require_auxiliary_column,
        integer_lift_require_pre_challenge_column,
        integer_lift_require_unbounded_reversed_base_column, integer_lift_tree_roles_by_column,
    },
};

impl RelationPlanChecker<'_> {
    pub(super) fn check_integer_lift_batches(
        &self,
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<ApplicationChallengePhaseColumns, RelationPlanError> {
        if variant.ordered_integer_lift_batches.is_empty() {
            return Ok(ApplicationChallengePhaseColumns::default());
        }
        let canonical_batch_bytes = variant
            .ordered_integer_lift_batches
            .iter()
            .map(RelationIntegerLiftBatchDescriptor::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_sorted_unique(&canonical_batch_bytes) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }

        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let explicitly_certified_columns = variant
            .ordered_semantic_cells
            .iter()
            .map(|cell| cell.column_ordinal)
            .collect::<BTreeSet<_>>();
        let expected_challenge_ordinals =
            (0..self.context.non_native_theta_repetition_count).collect::<BTreeSet<_>>();
        let mut challenge_ordinals_by_modulus =
            BTreeMap::<SuiteModulusReference, BTreeSet<u16>>::new();
        let mut descriptor_auxiliary_columns = BTreeSet::new();
        let mut derived_base_columns = BTreeSet::new();
        let mut matched_constraint_ordinals = BTreeSet::new();
        let mut constraint_ordinals_by_program = BTreeMap::new();
        for (constraint_ordinal, constraint) in variant.ordered_constraints.iter().enumerate() {
            if constraint.enforce_proof_base_field_no_wrap
                || !constraint
                    .ordered_injective_integer_factor_expressions
                    .is_empty()
            {
                continue;
            }
            constraint_ordinals_by_program
                .entry((
                    constraint.numerator_postfix_expression.clone(),
                    constraint.zeroifier_postfix_expression.clone(),
                ))
                .or_insert_with(Vec::new)
                .push(
                    u32::try_from(constraint_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                );
        }
        let mut automorphism_permutation_coordinates = BTreeSet::new();
        let mut automorphism_semantics_by_galois_element = BTreeMap::new();
        let galois_key_share_relation = application_statement_schema_identifier
            == ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let allowed_galois_elements = if galois_key_share_relation {
            selected_galois_key_share_relation_schedule()?
                .into_iter()
                .map(|(galois_element, _)| galois_element)
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        let mut observed_galois_elements = None::<Vec<u64>>;

        for batch in &variant.ordered_integer_lift_batches {
            let modulus_ordinal = u16::try_from(
                variant
                    .ordered_non_native_moduli
                    .binary_search(&batch.modulus_reference)
                    .map_err(|_| RelationPlanError::MissingModulus)?,
            )
            .map_err(|_| RelationPlanError::CountOverflow)?;
            let theta_bad_polynomial_degree =
                batch.theta_bad_polynomial_degree(variant.trace_domain_size)?;
            if !theta_sampling_field_exceeds_bad_polynomial_degree(
                self.context.base_field_modulus,
                theta_bad_polynomial_degree,
            ) || batch.challenge_ordinal >= self.context.non_native_theta_repetition_count
                || batch.ordered_components.is_empty()
                || !challenge_ordinals_by_modulus
                    .entry(batch.modulus_reference)
                    .or_default()
                    .insert(batch.challenge_ordinal)
            {
                return Err(RelationPlanError::InvalidChallengeCatalog);
            }

            let reversed_binding_bytes = batch
                .ordered_reversed_column_bindings
                .iter()
                .map(RelationIntegerLiftReversedColumnBindingDescriptor::canonical_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            if !reversed_binding_bytes.is_empty()
                && !strictly_sorted_unique(&reversed_binding_bytes)
            {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
            let mut reversed_bindings_by_columns = BTreeMap::new();
            let mut reversed_bindings_by_reversed_column = BTreeMap::new();
            for binding in &batch.ordered_reversed_column_bindings {
                if binding.source_column_ordinal == binding.reversed_column_ordinal {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                integer_lift_require_pre_challenge_column(
                    binding.source_column_ordinal,
                    variant,
                    &tree_roles_by_column,
                )?;
                integer_lift_require_unbounded_reversed_base_column(
                    binding.reversed_column_ordinal,
                    variant,
                    &tree_roles_by_column,
                    &explicitly_certified_columns,
                )?;
                derived_base_columns.insert(binding.reversed_column_ordinal);
                integer_lift_column_interval(
                    binding.source_column_ordinal,
                    variant,
                    semantic_bounds,
                    &explicitly_certified_columns,
                    self.context,
                )?;
                if reversed_bindings_by_columns
                    .insert(
                        (
                            binding.source_column_ordinal,
                            binding.reversed_column_ordinal,
                        ),
                        binding,
                    )
                    .is_some()
                    || reversed_bindings_by_reversed_column
                        .insert(binding.reversed_column_ordinal, binding)
                        .is_some()
                {
                    return Err(RelationPlanError::DuplicateItem);
                }
                for auxiliary_column in [
                    binding.source_prefix_evaluation_column_ordinal,
                    binding.reversed_suffix_evaluation_column_ordinal,
                ] {
                    integer_lift_require_auxiliary_column(
                        auxiliary_column,
                        variant,
                        &tree_roles_by_column,
                        &explicitly_certified_columns,
                    )?;
                    if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                        return Err(RelationPlanError::DuplicateItem);
                    }
                }
            }

            let batch_galois_elements = batch
                .ordered_negacyclic_automorphism_permutations
                .iter()
                .map(|permutation| permutation.galois_element)
                .collect::<Vec<_>>();
            if galois_key_share_relation
                && variant.ordered_non_native_moduli.first().copied()
                    == Some(batch.modulus_reference)
            {
                if batch_galois_elements.is_empty()
                    || batch_galois_elements
                        .iter()
                        .any(|galois_element| !allowed_galois_elements.contains(galois_element))
                    || batch_galois_elements
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    || observed_galois_elements
                        .as_ref()
                        .is_some_and(|observed| observed != &batch_galois_elements)
                {
                    return Err(RelationPlanError::NonCanonicalOrder);
                }
                observed_galois_elements.get_or_insert(batch_galois_elements);
            } else if !batch_galois_elements.is_empty() {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
            for permutation in &batch.ordered_negacyclic_automorphism_permutations {
                if !automorphism_permutation_coordinates.insert((
                    batch.modulus_reference,
                    batch.challenge_ordinal,
                    permutation.galois_element,
                )) {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let ring_degree = variant
                    .trace_domain_size
                    .checked_mul(2)
                    .ok_or(RelationPlanError::CountOverflow)?;
                validate_negacyclic_automorphism(ring_degree, permutation.galois_element)?;
                match variant
                    .ordered_verifier_sources
                    .get(permutation.mapping_verifier_source_ordinal as usize)
                {
                    Some(RelationVerifierSource::NegacyclicAutomorphismMapping {
                        ring_degree: source_ring_degree,
                        galois_element,
                    }) if *source_ring_degree == ring_degree
                        && *galois_element == permutation.galois_element => {}
                    _ => return Err(RelationPlanError::InvalidSource),
                }

                let semantic_columns = [
                    permutation.source_low_column_ordinal,
                    permutation.source_high_column_ordinal,
                    permutation.target_low_column_ordinal,
                    permutation.target_high_column_ordinal,
                ];
                for column_ordinal in semantic_columns {
                    integer_lift_require_pre_challenge_column(
                        column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    let column = variant
                        .ordered_columns
                        .get(column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidColumn)?;
                    if !matches!(column.origin, RelationColumnOrigin::Prover)
                        || integer_lift_column_interval(
                            column_ordinal,
                            variant,
                            semantic_bounds,
                            &explicitly_certified_columns,
                            self.context,
                        )? != SignedIntegerInterval::new(-1, 1)
                    {
                        return Err(RelationPlanError::InvalidSemanticCell);
                    }
                }

                let mapping_columns = [
                    permutation.mapped_low_position_column_ordinal,
                    permutation.low_negation_bit_column_ordinal,
                    permutation.mapped_high_position_column_ordinal,
                    permutation.high_negation_bit_column_ordinal,
                    permutation.target_low_position_column_ordinal,
                    permutation.target_high_position_column_ordinal,
                ];
                for (sequence_ordinal, column_ordinal) in
                    mapping_columns.iter().copied().enumerate()
                {
                    integer_lift_require_pre_challenge_column(
                        column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    let expected_first_element_index = u64::try_from(sequence_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?
                        .checked_mul(variant.trace_domain_size)
                        .ok_or(RelationPlanError::CountOverflow)?;
                    let column = variant
                        .ordered_columns
                        .get(column_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidColumn)?;
                    if !matches!(
                        column.origin,
                        RelationColumnOrigin::VerifierSequence {
                            verifier_source_ordinal,
                            first_logical_element_index,
                            logical_element_stride: 1,
                        } if verifier_source_ordinal
                            == permutation.mapping_verifier_source_ordinal
                            && first_logical_element_index == expected_first_element_index
                    ) || column.value_type != RelationColumnValueType::BaseField
                        || column.source_degree_bound_exclusive != variant.trace_domain_size
                        || column.canonical_residue_modulus.is_some()
                    {
                        return Err(RelationPlanError::InvalidColumn);
                    }
                }

                let accumulator_columns = [
                    permutation.source_product_before_column_ordinal,
                    permutation.source_low_product_column_ordinal,
                    permutation.target_product_before_column_ordinal,
                    permutation.target_low_product_column_ordinal,
                ];
                for column_ordinal in accumulator_columns {
                    integer_lift_require_auxiliary_column(
                        column_ordinal,
                        variant,
                        &tree_roles_by_column,
                        &explicitly_certified_columns,
                    )?;
                    if !descriptor_auxiliary_columns.insert(column_ordinal) {
                        return Err(RelationPlanError::DuplicateItem);
                    }
                }
                let all_columns = semantic_columns
                    .into_iter()
                    .chain(mapping_columns)
                    .chain(accumulator_columns)
                    .collect::<BTreeSet<_>>();
                if all_columns.len() != 14 {
                    return Err(RelationPlanError::DuplicateItem);
                }
                let current_semantics = (
                    permutation.mapping_verifier_source_ordinal,
                    [
                        permutation.source_low_column_ordinal,
                        permutation.source_high_column_ordinal,
                    ],
                    [
                        permutation.target_low_column_ordinal,
                        permutation.target_high_column_ordinal,
                    ],
                    mapping_columns,
                );
                if automorphism_semantics_by_galois_element
                    .insert(permutation.galois_element, current_semantics)
                    .is_some_and(|existing| existing != current_semantics)
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
            }
            let mut used_reversed_bindings = BTreeSet::new();

            let component_bytes = batch
                .ordered_components
                .iter()
                .map(RelationIntegerLiftComponentDescriptor::canonical_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            if !strictly_sorted_unique(&component_bytes) {
                return Err(RelationPlanError::NonCanonicalOrder);
            }

            for component in &batch.ordered_components {
                let linear_term_bytes = component
                    .ordered_linear_terms
                    .iter()
                    .map(RelationIntegerLiftLinearTermDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                let product_bytes = component
                    .ordered_convolution_products
                    .iter()
                    .map(RelationIntegerLiftConvolutionProductDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                let full_ring_product_bytes = component
                    .ordered_full_ring_negacyclic_products
                    .iter()
                    .map(RelationIntegerLiftFullRingNegacyclicProductDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                if linear_term_bytes.is_empty()
                    || !strictly_sorted_unique(&linear_term_bytes)
                    || (!product_bytes.is_empty() && !strictly_sorted_unique(&product_bytes))
                    || (!full_ring_product_bytes.is_empty()
                        && !strictly_sorted_unique(&full_ring_product_bytes))
                {
                    return Err(RelationPlanError::NonCanonicalOrder);
                }

                let mut residual_interval = SignedIntegerInterval::new(0, 0);

                for term in &component.ordered_linear_terms {
                    integer_lift_require_pre_challenge_column(
                        term.column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    if term.column_offset >= self.context.base_field_modulus {
                        return Err(RelationPlanError::NoWrapBoundViolated);
                    }
                    let interval = integer_lift_column_interval(
                        term.column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let shifted = SignedIntegerInterval::from_bigints(
                        interval.minimum - BigInt::from(term.column_offset),
                        interval.maximum - BigInt::from(term.column_offset),
                    )?;
                    let coefficient =
                        integer_lift_coefficient_value(term.coefficient, self.context)?;
                    let mut term_interval =
                        shifted.multiply(SignedIntegerInterval::from_bigints(
                            BigInt::from(coefficient),
                            BigInt::from(coefficient),
                        )?)?;
                    if term.negative {
                        term_interval = term_interval.negate()?;
                    }
                    residual_interval = residual_interval.add(term_interval)?;
                }

                for product in &component.ordered_convolution_products {
                    integer_lift_require_pre_challenge_column(
                        product.multiplicand_column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    integer_lift_require_pre_challenge_column(
                        product.reversed_multiplier_column_ordinal,
                        variant,
                        &tree_roles_by_column,
                    )?;
                    if product.multiplier_offset >= self.context.base_field_modulus {
                        return Err(RelationPlanError::NoWrapBoundViolated);
                    }
                    let multiplicand_interval = integer_lift_column_interval(
                        product.multiplicand_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplier_interval = if let Some(reversed_binding) =
                        reversed_bindings_by_reversed_column
                            .get(&product.reversed_multiplier_column_ordinal)
                            .copied()
                    {
                        // The derived reversal target is intentionally unbounded. When the
                        // reversal identity holds it permutes the source coefficients and
                        // therefore inherits this interval; a false identity is already
                        // covered by the batch's theta polynomial check.
                        used_reversed_bindings.insert((
                            reversed_binding.source_column_ordinal,
                            reversed_binding.reversed_column_ordinal,
                        ));
                        integer_lift_column_interval(
                            reversed_binding.source_column_ordinal,
                            variant,
                            semantic_bounds,
                            &explicitly_certified_columns,
                            self.context,
                        )?
                    } else {
                        integer_lift_column_interval(
                            product.reversed_multiplier_column_ordinal,
                            variant,
                            semantic_bounds,
                            &explicitly_certified_columns,
                            self.context,
                        )?
                    };
                    let shifted_multiplier = SignedIntegerInterval::from_bigints(
                        multiplier_interval.minimum - BigInt::from(product.multiplier_offset),
                        multiplier_interval.maximum - BigInt::from(product.multiplier_offset),
                    )?;
                    let coefficient_product = multiplicand_interval.multiply(shifted_multiplier)?;
                    let maximum_absolute_product = coefficient_product
                        .minimum
                        .magnitude()
                        .max(coefficient_product.maximum.magnitude())
                        .clone();
                    let convolution_bound = BigInt::from(maximum_absolute_product)
                        * BigInt::from(variant.trace_domain_size);
                    let mut product_interval = SignedIntegerInterval::from_bigints(
                        -convolution_bound.clone(),
                        convolution_bound,
                    )?;
                    if product.negative {
                        product_interval = product_interval.negate()?;
                    }
                    residual_interval = residual_interval.add(product_interval)?;

                    for auxiliary_column in [
                        product.suffix_evaluation_column_ordinal,
                        product.reversed_transpose_column_ordinal,
                    ] {
                        integer_lift_require_auxiliary_column(
                            auxiliary_column,
                            variant,
                            &tree_roles_by_column,
                            &explicitly_certified_columns,
                        )?;
                        if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                            return Err(RelationPlanError::DuplicateItem);
                        }
                    }
                }

                for product in &component.ordered_full_ring_negacyclic_products {
                    if product.multiplicand_low_column_ordinal
                        == product.multiplicand_high_column_ordinal
                        || product.multiplier_low_column_ordinal
                            == product.multiplier_high_column_ordinal
                        || product.reversed_multiplier_low_column_ordinal
                            == product.reversed_multiplier_high_column_ordinal
                        || product.multiplier_low_offset >= self.context.base_field_modulus
                        || product.multiplier_high_offset >= self.context.base_field_modulus
                    {
                        return Err(RelationPlanError::InvalidConstraint);
                    }
                    for column_ordinal in [
                        product.multiplicand_low_column_ordinal,
                        product.multiplicand_high_column_ordinal,
                        product.multiplier_low_column_ordinal,
                        product.multiplier_high_column_ordinal,
                        product.reversed_multiplier_low_column_ordinal,
                        product.reversed_multiplier_high_column_ordinal,
                    ] {
                        integer_lift_require_pre_challenge_column(
                            column_ordinal,
                            variant,
                            &tree_roles_by_column,
                        )?;
                    }
                    for binding_key in [
                        (
                            product.multiplier_low_column_ordinal,
                            product.reversed_multiplier_low_column_ordinal,
                        ),
                        (
                            product.multiplier_high_column_ordinal,
                            product.reversed_multiplier_high_column_ordinal,
                        ),
                    ] {
                        if !reversed_bindings_by_columns.contains_key(&binding_key) {
                            return Err(RelationPlanError::InvalidConstraint);
                        }
                        used_reversed_bindings.insert(binding_key);
                    }
                    let multiplicand_low_interval = integer_lift_column_interval(
                        product.multiplicand_low_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplicand_high_interval = integer_lift_column_interval(
                        product.multiplicand_high_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplier_low_interval = integer_lift_column_interval(
                        product.multiplier_low_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let multiplier_high_interval = integer_lift_column_interval(
                        product.multiplier_high_column_ordinal,
                        variant,
                        semantic_bounds,
                        &explicitly_certified_columns,
                        self.context,
                    )?;
                    let shifted_multiplier_low = SignedIntegerInterval::from_bigints(
                        multiplier_low_interval.minimum
                            - BigInt::from(product.multiplier_low_offset),
                        multiplier_low_interval.maximum
                            - BigInt::from(product.multiplier_low_offset),
                    )?;
                    let shifted_multiplier_high = SignedIntegerInterval::from_bigints(
                        multiplier_high_interval.minimum
                            - BigInt::from(product.multiplier_high_offset),
                        multiplier_high_interval.maximum
                            - BigInt::from(product.multiplier_high_offset),
                    )?;
                    let low_low = integer_lift_maximum_absolute_product(
                        &multiplicand_low_interval,
                        &shifted_multiplier_low,
                    )?;
                    let high_low = integer_lift_maximum_absolute_product(
                        &multiplicand_high_interval,
                        &shifted_multiplier_low,
                    )?;
                    let low_high = integer_lift_maximum_absolute_product(
                        &multiplicand_low_interval,
                        &shifted_multiplier_high,
                    )?;
                    let high_high = integer_lift_maximum_absolute_product(
                        &multiplicand_high_interval,
                        &shifted_multiplier_high,
                    )?;
                    let diagonal_bound = low_low + high_high;
                    let cross_bound = high_low + low_high;
                    let convolution_bound = BigInt::from(diagonal_bound.max(cross_bound))
                        * BigInt::from(variant.trace_domain_size);
                    let mut product_interval = SignedIntegerInterval::from_bigints(
                        -convolution_bound.clone(),
                        convolution_bound,
                    )?;
                    if product.negative {
                        product_interval = product_interval.negate()?;
                    }
                    residual_interval = residual_interval.add(product_interval)?;

                    for auxiliary_column in [
                        product.multiplicand_low_suffix_evaluation_column_ordinal,
                        product.multiplicand_high_suffix_evaluation_column_ordinal,
                        product.reversed_multiplier_low_transpose_column_ordinal,
                        product.reversed_multiplier_high_transpose_column_ordinal,
                    ] {
                        integer_lift_require_auxiliary_column(
                            auxiliary_column,
                            variant,
                            &tree_roles_by_column,
                            &explicitly_certified_columns,
                        )?;
                        if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                            return Err(RelationPlanError::DuplicateItem);
                        }
                    }
                }

                for auxiliary_column in [
                    component.linear_evaluation_column_ordinal,
                    component.product_accumulator_column_ordinal,
                ] {
                    integer_lift_require_auxiliary_column(
                        auxiliary_column,
                        variant,
                        &tree_roles_by_column,
                        &explicitly_certified_columns,
                    )?;
                    if !descriptor_auxiliary_columns.insert(auxiliary_column) {
                        return Err(RelationPlanError::DuplicateItem);
                    }
                }

                if !residual_interval
                    .is_injective_modulo(&BigInt::from(self.context.base_field_modulus))
                {
                    return Err(RelationPlanError::NoWrapBoundViolated);
                }
            }

            if used_reversed_bindings != reversed_bindings_by_columns.keys().copied().collect() {
                return Err(RelationPlanError::InvalidConstraint);
            }

            for program in batch.constraint_programs(
                modulus_ordinal,
                variant.trace_domain_size,
                variant.evaluation_domain_size,
                self.context,
            )? {
                let matching_ordinals = constraint_ordinals_by_program
                    .remove(&(
                        program.numerator_postfix_expression,
                        program.zeroifier_postfix_expression,
                    ))
                    .ok_or(RelationPlanError::InvalidConstraint)?;
                if matching_ordinals.len() != 1
                    || !matched_constraint_ordinals.insert(matching_ordinals[0])
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
            }
        }

        if challenge_ordinals_by_modulus
            .values()
            .any(|ordinals| ordinals != &expected_challenge_ordinals)
        {
            return Err(RelationPlanError::InvalidChallengeCatalog);
        }
        let expected_automorphism_permutation_coordinates = if galois_key_share_relation {
            let modulus_reference = variant
                .ordered_non_native_moduli
                .first()
                .copied()
                .ok_or(RelationPlanError::MissingModulus)?;
            let observed_galois_elements = observed_galois_elements
                .as_ref()
                .ok_or(RelationPlanError::InvalidConstraint)?;
            expected_challenge_ordinals
                .iter()
                .copied()
                .flat_map(|challenge_ordinal| {
                    observed_galois_elements
                        .iter()
                        .copied()
                        .map(move |galois_element| {
                            (modulus_reference, challenge_ordinal, galois_element)
                        })
                })
                .collect()
        } else {
            BTreeSet::new()
        };
        let has_automorphism_semantics = !automorphism_semantics_by_galois_element.is_empty();
        if automorphism_permutation_coordinates != expected_automorphism_permutation_coordinates
            || galois_key_share_relation != has_automorphism_semantics
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        if galois_key_share_relation {
            let observed_galois_elements = observed_galois_elements
                .as_ref()
                .ok_or(RelationPlanError::InvalidConstraint)?;
            let ordered_galois_elements = automorphism_semantics_by_galois_element
                .keys()
                .copied()
                .collect::<Vec<_>>();
            let source_column_pairs = automorphism_semantics_by_galois_element
                .values()
                .map(|semantics| semantics.1)
                .collect::<BTreeSet<_>>();
            let target_column_pairs = automorphism_semantics_by_galois_element
                .values()
                .map(|semantics| semantics.2)
                .collect::<BTreeSet<_>>();
            let mapping_source_ordinals = automorphism_semantics_by_galois_element
                .values()
                .map(|semantics| semantics.0)
                .collect::<BTreeSet<_>>();
            let mapping_column_sets = automorphism_semantics_by_galois_element
                .values()
                .map(|semantics| semantics.3)
                .collect::<BTreeSet<_>>();
            if &ordered_galois_elements != observed_galois_elements
                || source_column_pairs.len() != 1
                || target_column_pairs.len() != observed_galois_elements.len()
                || mapping_source_ordinals.len() != observed_galois_elements.len()
                || mapping_column_sets.len() != observed_galois_elements.len()
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }
        Ok(ApplicationChallengePhaseColumns {
            derived_base_columns,
            derived_auxiliary_columns: descriptor_auxiliary_columns,
        })
    }

    /// Ensures the first application oracle contains every essential witness
    /// value. Later application oracles may contain only columns whose values
    /// are determined by the checked integer-lift grammar and the preceding
    /// public challenge. This prevents a prover from first supplying a
    /// semantic witness after observing that challenge.
    pub(super) fn check_application_challenge_phase_ownership(
        &self,
        variant: &RelationPlanVariant,
        phase_columns: &ApplicationChallengePhaseColumns,
    ) -> Result<(), RelationPlanError> {
        let tree_roles_by_column = integer_lift_tree_roles_by_column(variant)?;
        let semantic_prover_columns = variant
            .ordered_semantic_cells
            .iter()
            .filter_map(|cell| {
                variant
                    .ordered_columns
                    .get(cell.column_ordinal as usize)
                    .is_some_and(|column| matches!(column.origin, RelationColumnOrigin::Prover))
                    .then_some(cell.column_ordinal)
            })
            .collect::<BTreeSet<_>>();

        for semantic_column in &semantic_prover_columns {
            if tree_roles_by_column.get(semantic_column) != Some(&Some(1)) {
                return Err(RelationPlanError::InvalidConstraint);
            }
        }

        let mut observed_auxiliary_columns = BTreeSet::new();
        for (column_index, column) in variant.ordered_columns.iter().enumerate() {
            let column_ordinal =
                u32::try_from(column_index).map_err(|_| RelationPlanError::CountOverflow)?;
            let tree_role = tree_roles_by_column.get(&column_ordinal).copied();
            match (tree_role, &column.origin) {
                (None, RelationColumnOrigin::VerifierSequence { .. }) => {}
                (None, _) => return Err(RelationPlanError::MissingRoot),
                (Some(_), RelationColumnOrigin::VerifierSequence { .. }) => {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                (Some(Some(1)), RelationColumnOrigin::Prover)
                    if !semantic_prover_columns.contains(&column_ordinal)
                        && !phase_columns.derived_base_columns.contains(&column_ordinal) =>
                {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                (Some(Some(2)), RelationColumnOrigin::Prover) => {
                    observed_auxiliary_columns.insert(column_ordinal);
                }
                (Some(Some(2)), _) => return Err(RelationPlanError::InvalidConstraint),
                _ => {}
            }
        }
        if observed_auxiliary_columns != phase_columns.derived_auxiliary_columns {
            return Err(RelationPlanError::InvalidConstraint);
        }
        Ok(())
    }
}
