use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

#[cfg(test)]
use super::super::model::{
    RelationRadixFactorDescriptor, RelationRadixProductTermDescriptor, canonical_encoding_error,
};
use super::super::{
    bounds::{
        RelationBoundCertificate, RelationConstraintDescriptor, SemanticCellDescriptor,
        SignedIntegerInterval,
    },
    compiled_plan::RelationPlanCheckContext,
    expressions::{
        RelationExpressionInstruction, fixed_radix_u64_digits, minimum_radix_digit_count,
        modular_power, radix_recomposition_expression, strictly_sorted_unique,
        unsigned_radix_comparator_digit_expression,
    },
    layout::RelationPlanVariant,
    model::{
        ModulusCatalog, RelationChallengeRole, RelationColumnOrigin, RelationColumnValueType,
        RelationElementKind, RelationEmbeddingKind, RelationPlanError, RelationValueLayout,
        RelationVerifierSource, SuiteModulusReference,
    },
};
use super::{
    RelationPlanChecker,
    constraints::full_trace_zeroifier_expression,
    integer_lift_bounds::{
        derive_semantic_cell_interval, integer_lift_bound_tree_has_canonical_residue_capability,
    },
};

impl RelationPlanChecker<'_> {
    pub(super) fn check_domains(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        if variant.trace_domain_size == 0
            || !variant.trace_domain_size.is_power_of_two()
            || variant.evaluation_domain_size == 0
            || !variant.evaluation_domain_size.is_power_of_two()
            || !variant
                .evaluation_domain_size
                .is_multiple_of(variant.trace_domain_size)
            || variant.opening_degree_bound_exclusive <= 1
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let next_degree_domain = variant
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(RelationPlanError::CountOverflow)?;
        let expected_evaluation_domain = next_degree_domain
            .checked_mul(u64::from(self.context.evaluation_blowup_factor))
            .ok_or(RelationPlanError::CountOverflow)?;
        if expected_evaluation_domain != variant.evaluation_domain_size
            || !(self.context.base_field_modulus - 1).is_multiple_of(variant.evaluation_domain_size)
            || modular_power(
                self.context.evaluation_domain_generator,
                variant.evaluation_domain_size,
                self.context.base_field_modulus,
            ) != 1
            || modular_power(
                self.context.evaluation_domain_generator,
                variant.evaluation_domain_size / 2,
                self.context.base_field_modulus,
            ) == 1
            || modular_power(
                self.context.evaluation_coset_offset,
                variant.trace_domain_size,
                self.context.base_field_modulus,
            ) == 1
            || modular_power(
                self.context.evaluation_coset_offset,
                variant.evaluation_domain_size,
                self.context.base_field_modulus,
            ) == 1
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let initial_fri_degree_bound_exclusive = variant
            .opening_degree_bound_exclusive
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidDomain)?;
        let final_degree_bound = u64::from(self.context.final_polynomial_degree_bound_exclusive);
        if final_degree_bound >= initial_fri_degree_bound_exclusive {
            return Err(RelationPlanError::InvalidDomain);
        }
        let mut folded_degree_bound = initial_fri_degree_bound_exclusive;
        let mut expected_fold_count = 0_u16;
        while folded_degree_bound > final_degree_bound {
            folded_degree_bound = folded_degree_bound
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?
                / 2;
            expected_fold_count = expected_fold_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        if expected_fold_count != self.context.fri_fold_count {
            return Err(RelationPlanError::InvalidDomain);
        }
        Ok(())
    }

    pub(super) fn check_moduli(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        if !strictly_sorted_unique(&variant.ordered_non_native_moduli)
            || variant
                .ordered_non_native_moduli
                .iter()
                .any(|reference| reference.catalog == ModulusCatalog::ProofField)
        {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for reference in &variant.ordered_non_native_moduli {
            let modulus = self.context.resolved_modulus(*reference)?;
            if modulus >= self.context.base_field_modulus {
                return Err(RelationPlanError::InvalidModulus);
            }
        }
        let used = self.used_moduli(variant)?;
        let declared = variant
            .ordered_non_native_moduli
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if used != declared {
            return Err(if used.is_subset(&declared) {
                RelationPlanError::UnusedModulus
            } else {
                RelationPlanError::MissingModulus
            });
        }
        Ok(())
    }

    pub(super) fn used_moduli(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<BTreeSet<SuiteModulusReference>, RelationPlanError> {
        let mut used = BTreeSet::new();
        for source in &variant.ordered_verifier_sources {
            if let RelationVerifierSource::ApplicationStatement { value_layout, .. }
            | RelationVerifierSource::Protocol { value_layout, .. } = source
                && let Some(modulus) = value_layout.residue_modulus
            {
                used.insert(modulus);
            }
            if let RelationVerifierSource::RadixDecomposition {
                modulus_reference, ..
            } = source
            {
                used.insert(*modulus_reference);
            }
        }
        for sampler in &variant.ordered_public_samplers {
            used.insert(sampler.output_modulus);
        }
        for column in &variant.ordered_columns {
            if let Some(modulus_reference) = column.canonical_residue_modulus {
                used.insert(modulus_reference);
            }
        }
        for semantic_cell in &variant.ordered_semantic_cells {
            if let RelationBoundCertificate::CanonicalModulusRecomposition {
                modulus_reference,
                ..
            } = &semantic_cell.bound_certificate
            {
                used.insert(*modulus_reference);
            }
        }
        for batch in &variant.ordered_integer_lift_batches {
            used.insert(batch.modulus_reference);
            for component in &batch.ordered_components {
                for term in &component.ordered_linear_terms {
                    match term.coefficient {
                        super::super::integer_lift::RelationIntegerLiftCoefficient::Modulus {
                            modulus_reference,
                            ..
                        }
                        | super::super::integer_lift::RelationIntegerLiftCoefficient::ModulusRadixDigit {
                            modulus_reference,
                            ..
                        } => {
                            used.insert(modulus_reference);
                        }
                        super::super::integer_lift::RelationIntegerLiftCoefficient::Constant(_) => {}
                    }
                }
            }
        }
        for constraint in &variant.ordered_constraints {
            for instruction in &constraint.numerator_postfix_expression {
                match instruction {
                    RelationExpressionInstruction::TranscriptChallenge {
                        challenge_role:
                            RelationChallengeRole::NonNativeTheta
                            | RelationChallengeRole::NonNativeAlpha,
                        role_coordinates,
                    } => {
                        let modulus_ordinal = role_coordinates
                            .first()
                            .copied()
                            .and_then(|ordinal| usize::try_from(ordinal).ok())
                            .ok_or(RelationPlanError::InvalidChallengeCatalog)?;
                        used.insert(
                            variant
                                .ordered_non_native_moduli
                                .get(modulus_ordinal)
                                .copied()
                                .ok_or(RelationPlanError::InvalidChallengeCatalog)?,
                        );
                    }
                    RelationExpressionInstruction::NonNativeModulusConstant {
                        modulus_reference,
                        ..
                    } => {
                        used.insert(*modulus_reference);
                    }
                    _ => {}
                }
            }
        }
        Ok(used)
    }

    pub(super) fn check_sources_and_samplers(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<(), RelationPlanError> {
        let source_bytes = variant
            .ordered_verifier_sources
            .iter()
            .map(RelationVerifierSource::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        if !strictly_sorted_unique(&source_bytes) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for source in &variant.ordered_verifier_sources {
            source.validate_shape()?;
            if let RelationVerifierSource::RadixDecomposition {
                modulus_reference,
                scale,
                radix,
                digit_count,
                ..
            } = source
            {
                let modulus = self.context.resolved_modulus(*modulus_reference)?;
                let maximum_scaled = u128::from(modulus - 1)
                    .checked_mul(u128::from(*scale))
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?;
                let capacity = (0..*digit_count).try_fold(1_u128, |capacity, _| {
                    capacity
                        .checked_mul(u128::from(*radix))
                        .ok_or(RelationPlanError::IntegerBoundOverflow)
                })?;
                if maximum_scaled >= capacity
                    || (*digit_count > 1
                        && maximum_scaled
                            < (0..(*digit_count - 1)).try_fold(1_u128, |capacity, _| {
                                capacity
                                    .checked_mul(u128::from(*radix))
                                    .ok_or(RelationPlanError::IntegerBoundOverflow)
                            })?)
                {
                    return Err(RelationPlanError::InvalidSource);
                }
            }
        }
        if !variant.ordered_public_samplers.is_empty() {
            return Err(RelationPlanError::InvalidSampler);
        }
        let mut consumed_sources = BTreeSet::new();
        for column in &variant.ordered_columns {
            match column.origin {
                RelationColumnOrigin::VerifierSequence {
                    verifier_source_ordinal,
                    ..
                } => {
                    consumed_sources.insert(verifier_source_ordinal);
                }
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                } => {
                    consumed_sources.insert(expected_root_source_ordinal);
                }
                RelationColumnOrigin::Prover => {}
            }
        }
        if consumed_sources.len() != variant.ordered_verifier_sources.len() {
            return Err(RelationPlanError::UnusedSource);
        }
        Ok(())
    }

    pub(super) fn check_columns_and_semantic_cells(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<BTreeMap<u32, SignedIntegerInterval>, RelationPlanError> {
        if variant.ordered_columns.is_empty() {
            return Err(RelationPlanError::InvalidColumn);
        }
        let mut verifier_columns_by_source = BTreeMap::<u32, Vec<(u64, u64)>>::new();
        let mut expected_semantic_ordinal = 0_u32;
        let mut semantic_columns = BTreeSet::new();
        for cell in &variant.ordered_semantic_cells {
            if cell.semantic_cell_ordinal != expected_semantic_ordinal
                || cell.claimed_interval.minimum > cell.claimed_interval.maximum
                || !semantic_columns.insert(cell.column_ordinal)
            {
                return Err(RelationPlanError::InvalidSemanticCell);
            }
            let column = variant
                .ordered_columns
                .get(cell.column_ordinal as usize)
                .ok_or(RelationPlanError::InvalidSemanticCell)?;
            if column.value_type != RelationColumnValueType::BaseField {
                return Err(RelationPlanError::InvalidSemanticCell);
            }
            expected_semantic_ordinal = expected_semantic_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        for column in &variant.ordered_columns {
            if column.source_degree_bound_exclusive == 0
                || column.source_degree_bound_exclusive > variant.opening_degree_bound_exclusive
                || (column.canonical_residue_modulus.is_some()
                    && (column.value_type != RelationColumnValueType::BaseField
                        || matches!(column.origin, RelationColumnOrigin::Prover)))
            {
                return Err(
                    if column.source_degree_bound_exclusive == 0
                        || column.source_degree_bound_exclusive
                            > variant.opening_degree_bound_exclusive
                    {
                        RelationPlanError::DegreeBoundExceeded
                    } else {
                        RelationPlanError::InvalidColumn
                    },
                );
            }
            match column.origin {
                RelationColumnOrigin::VerifierSequence {
                    verifier_source_ordinal,
                    first_logical_element_index,
                    logical_element_stride,
                } => {
                    let layout = variant
                        .ordered_verifier_sources
                        .get(verifier_source_ordinal as usize)
                        .ok_or(RelationPlanError::InvalidColumn)?
                        .value_layout()?;
                    let last_trace_row = variant.trace_domain_size - 1;
                    let last_index = first_logical_element_index
                        .checked_add(
                            last_trace_row
                                .checked_mul(logical_element_stride)
                                .ok_or(RelationPlanError::CountOverflow)?,
                        )
                        .ok_or(RelationPlanError::CountOverflow)?;
                    if last_index >= layout.logical_element_count()?
                        || matches!(layout.element_kind, RelationElementKind::Hash512)
                    {
                        return Err(RelationPlanError::InvalidColumn);
                    }
                    verifier_columns_by_source
                        .entry(verifier_source_ordinal)
                        .or_default()
                        .push((first_logical_element_index, logical_element_stride));
                }
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                } => {
                    let layout = variant
                        .ordered_verifier_sources
                        .get(expected_root_source_ordinal as usize)
                        .ok_or(RelationPlanError::MissingRoot)?
                        .value_layout()?;
                    if layout != RelationValueLayout::scalar_hash() {
                        return Err(RelationPlanError::InvalidRoot);
                    }
                }
                RelationColumnOrigin::Prover => {}
            }
        }
        for (source_ordinal, source) in variant.ordered_verifier_sources.iter().enumerate() {
            let source_ordinal =
                u32::try_from(source_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
            let layout = source.value_layout()?;
            if matches!(layout.element_kind, RelationElementKind::Hash512) {
                if verifier_columns_by_source.contains_key(&source_ordinal) {
                    return Err(RelationPlanError::InvalidColumn);
                }
                continue;
            }
            let logical_element_count = layout.logical_element_count()?;
            let mappings = verifier_columns_by_source
                .get_mut(&source_ordinal)
                .ok_or(RelationPlanError::InvalidColumn)?;
            mappings.sort_unstable();
            if logical_element_count == 1 {
                if mappings.as_slice() != [(0, 0)] {
                    return Err(RelationPlanError::InvalidColumn);
                }
                continue;
            }
            if !logical_element_count.is_multiple_of(variant.trace_domain_size) {
                return Err(RelationPlanError::InvalidColumn);
            }
            let expected_mapping_count = logical_element_count / variant.trace_domain_size;
            if u64::try_from(mappings.len()).map_err(|_| RelationPlanError::CountOverflow)?
                != expected_mapping_count
            {
                return Err(RelationPlanError::InvalidColumn);
            }
            for (mapping_ordinal, (first_logical_element_index, logical_element_stride)) in
                mappings.iter().copied().enumerate()
            {
                let expected_first = u64::try_from(mapping_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?
                    .checked_mul(variant.trace_domain_size)
                    .ok_or(RelationPlanError::CountOverflow)?;
                if first_logical_element_index != expected_first || logical_element_stride != 1 {
                    return Err(RelationPlanError::InvalidColumn);
                }
            }
        }
        self.derive_semantic_bounds(variant)
    }

    pub(super) fn derive_semantic_bounds(
        &self,
        variant: &RelationPlanVariant,
    ) -> Result<BTreeMap<u32, SignedIntegerInterval>, RelationPlanError> {
        let semantic_cells_by_column = variant
            .ordered_semantic_cells
            .iter()
            .map(|cell| (cell.column_ordinal, cell))
            .collect::<BTreeMap<_, _>>();
        if semantic_cells_by_column.len() != variant.ordered_semantic_cells.len() {
            return Err(RelationPlanError::InvalidSemanticCell);
        }

        let mut derived_intervals = BTreeMap::new();
        let mut active_columns = BTreeSet::new();
        for column_ordinal in semantic_cells_by_column.keys().copied() {
            derive_semantic_cell_interval(
                column_ordinal,
                &semantic_cells_by_column,
                &variant.ordered_constraints,
                variant.trace_domain_size,
                self.context,
                &mut derived_intervals,
                &mut active_columns,
            )?;
        }
        for (column_ordinal, column) in variant.ordered_columns.iter().enumerate() {
            if let Some(modulus_reference) = column.canonical_residue_modulus {
                let column_ordinal =
                    u32::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
                let modulus = self.context.resolved_modulus(modulus_reference)?;
                let canonical_interval = match column.origin {
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal,
                        ..
                    } => {
                        let layout = variant
                            .ordered_verifier_sources
                            .get(verifier_source_ordinal as usize)
                            .ok_or(RelationPlanError::InvalidSource)?
                            .value_layout()?;
                        if layout.element_kind != RelationElementKind::Residue
                            || layout.residue_modulus != Some(modulus_reference)
                        {
                            return Err(RelationPlanError::InvalidColumn);
                        }
                        match layout.embedding_kind {
                            RelationEmbeddingKind::LeastNonnegative => {
                                SignedIntegerInterval::from_bigints(
                                    BigInt::zero(),
                                    BigInt::from(modulus - 1),
                                )?
                            }
                            RelationEmbeddingKind::Centered => {
                                let absolute_bound = (modulus - 1) / 2;
                                SignedIntegerInterval::from_bigints(
                                    -BigInt::from(absolute_bound),
                                    BigInt::from(absolute_bound),
                                )?
                            }
                            _ => return Err(RelationPlanError::InvalidColumn),
                        }
                    }
                    RelationColumnOrigin::BoundTree { .. }
                        if integer_lift_bound_tree_has_canonical_residue_capability(
                            column_ordinal,
                            variant,
                        ) =>
                    {
                        SignedIntegerInterval::from_bigints(
                            BigInt::zero(),
                            BigInt::from(modulus - 1),
                        )?
                    }
                    RelationColumnOrigin::BoundTree { .. } => continue,
                    RelationColumnOrigin::Prover => {
                        return Err(RelationPlanError::InvalidColumn);
                    }
                };
                if let Some(derived_interval) = derived_intervals.get(&column_ordinal) {
                    if derived_interval != &canonical_interval {
                        return Err(RelationPlanError::InvalidSemanticCell);
                    }
                } else {
                    derived_intervals.insert(column_ordinal, canonical_interval);
                }
            }
        }
        Ok(derived_intervals)
    }

    #[cfg(not(test))]
    pub(super) fn check_radix_convolutions(
        &self,
        variant: &RelationPlanVariant,
        _semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        if variant.ordered_radix_convolutions.is_empty() {
            Ok(())
        } else {
            Err(RelationPlanError::InvalidConstraint)
        }
    }

    #[cfg(test)]
    pub(super) fn check_radix_convolutions(
        &self,
        variant: &RelationPlanVariant,
        semantic_bounds: &BTreeMap<u32, SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        let mut referenced_convolutions = BTreeSet::new();
        for constraint in &variant.ordered_constraints {
            for instruction in &constraint.numerator_postfix_expression {
                if let RelationExpressionInstruction::RadixConvolutionCoefficient {
                    convolution_ordinal,
                    ..
                } = instruction
                {
                    referenced_convolutions.insert(*convolution_ordinal);
                }
            }
        }
        if referenced_convolutions
            != (0..variant.ordered_radix_convolutions.len())
                .map(|ordinal| u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow))
                .collect::<Result<BTreeSet<_>, _>>()?
        {
            return Err(RelationPlanError::InvalidConstraint);
        }

        let mut convolution_bytes = BTreeSet::new();
        for convolution in &variant.ordered_radix_convolutions {
            if !(2..self.context.base_field_modulus).contains(&convolution.radix)
                || convolution.ordered_terms.is_empty()
                || !convolution_bytes.insert(
                    convolution
                        .canonical_tuple()?
                        .encode()
                        .map_err(canonical_encoding_error)?,
                )
            {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let binary_interval = SignedIntegerInterval::new(0, 1);
            let term_bytes = convolution
                .ordered_terms
                .iter()
                .map(RelationRadixProductTermDescriptor::canonical_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            if !strictly_sorted_unique(&term_bytes) {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
            for term in &convolution.ordered_terms {
                if term.ordered_factors.is_empty() {
                    return Err(RelationPlanError::InvalidConstraint);
                }
                let factor_bytes = term
                    .ordered_factors
                    .iter()
                    .map(RelationRadixFactorDescriptor::canonical_bytes)
                    .collect::<Result<Vec<_>, _>>()?;
                if !strictly_sorted_unique(&factor_bytes) {
                    return Err(RelationPlanError::NonCanonicalOrder);
                }
                for factor in &term.ordered_factors {
                    match factor {
                        RelationRadixFactorDescriptor::ColumnDigits {
                            ordered_column_ordinals,
                            rotation_is_negative,
                            rotation_magnitude,
                        } => {
                            if ordered_column_ordinals.is_empty()
                                || !strictly_sorted_unique(ordered_column_ordinals)
                                || (*rotation_is_negative && *rotation_magnitude == 0)
                                || *rotation_magnitude >= variant.trace_domain_size
                                || ordered_column_ordinals.iter().any(|column_ordinal| {
                                    semantic_bounds.get(column_ordinal).is_none_or(|interval| {
                                        interval.minimum < BigInt::zero()
                                            || interval.maximum
                                                > BigInt::from(convolution.radix - 1)
                                    })
                                })
                            {
                                return Err(RelationPlanError::InvalidBoundCertificate);
                            }
                        }
                        RelationRadixFactorDescriptor::ConstantDigits { ordered_digits } => {
                            if ordered_digits.is_empty()
                                || ordered_digits.last() == Some(&0)
                                || ordered_digits
                                    .iter()
                                    .any(|digit| *digit >= convolution.radix)
                            {
                                return Err(RelationPlanError::InvalidConstraint);
                            }
                        }
                        RelationRadixFactorDescriptor::ScalarColumn { column_ordinal, .. } => {
                            if semantic_bounds.get(column_ordinal) != Some(&binary_interval) {
                                return Err(RelationPlanError::InvalidBoundCertificate);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_radix_digit_bounds(
    target_column_ordinal: u32,
    radix: u64,
    ordered_digit_column_ordinals: &[u32],
    semantic_cells_by_column: &BTreeMap<u32, &SemanticCellDescriptor>,
    constraints: &[RelationConstraintDescriptor],
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
    derived_intervals: &mut BTreeMap<u32, SignedIntegerInterval>,
    active_columns: &mut BTreeSet<u32>,
) -> Result<BigUint, RelationPlanError> {
    let proof_base_field_modulus = context.base_field_modulus;
    if !(2..proof_base_field_modulus).contains(&radix)
        || ordered_digit_column_ordinals.is_empty()
        || !strictly_sorted_unique(ordered_digit_column_ordinals)
        || ordered_digit_column_ordinals.contains(&target_column_ordinal)
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let maximum_per_digit = BigInt::from(radix - 1);
    let mut radix_power = BigUint::one();
    let radix = BigUint::from(radix);
    let mut maximum = BigUint::zero();
    for digit_column_ordinal in ordered_digit_column_ordinals {
        let interval = derive_semantic_cell_interval(
            *digit_column_ordinal,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )?;
        if interval.minimum != BigInt::zero()
            || interval.maximum < BigInt::zero()
            || interval.maximum > maximum_per_digit
        {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
        maximum += interval
            .maximum
            .to_biguint()
            .ok_or(RelationPlanError::InvalidBoundCertificate)?
            * &radix_power;
        radix_power *= &radix;
    }
    if maximum >= BigUint::from(proof_base_field_modulus) {
        return Err(RelationPlanError::NoWrapBoundViolated);
    }
    Ok(maximum)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_canonical_modulus_recomposition_bound(
    target_column_ordinal: u32,
    modulus_reference: SuiteModulusReference,
    radix: u64,
    ordered_digit_column_ordinals: &[u32],
    ordered_comparator_constraint_ordinals: &[u32],
    ordered_difference_digit_column_ordinals: &[u32],
    ordered_borrow_column_ordinals: &[u32],
    semantic_cells_by_column: &BTreeMap<u32, &SemanticCellDescriptor>,
    constraints: &[RelationConstraintDescriptor],
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
    derived_intervals: &mut BTreeMap<u32, SignedIntegerInterval>,
    active_columns: &mut BTreeSet<u32>,
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let digit_count = ordered_digit_column_ordinals.len();
    if digit_count == 0
        || ordered_comparator_constraint_ordinals.len() != digit_count
        || ordered_difference_digit_column_ordinals.len() != digit_count
        || ordered_borrow_column_ordinals.len() != digit_count.saturating_sub(1)
        || !strictly_sorted_unique(ordered_comparator_constraint_ordinals)
        || !strictly_sorted_unique(ordered_difference_digit_column_ordinals)
        || (!ordered_borrow_column_ordinals.is_empty()
            && !strictly_sorted_unique(ordered_borrow_column_ordinals))
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let auxiliary_columns = ordered_digit_column_ordinals
        .iter()
        .chain(ordered_difference_digit_column_ordinals)
        .chain(ordered_borrow_column_ordinals)
        .copied()
        .collect::<BTreeSet<_>>();
    if auxiliary_columns.len()
        != ordered_digit_column_ordinals.len()
            + ordered_difference_digit_column_ordinals.len()
            + ordered_borrow_column_ordinals.len()
        || auxiliary_columns.contains(&target_column_ordinal)
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let broad_maximum = validate_radix_digit_bounds(
        target_column_ordinal,
        radix,
        ordered_digit_column_ordinals,
        semantic_cells_by_column,
        constraints,
        trace_domain_size,
        context,
        derived_intervals,
        active_columns,
    )?;
    let recomposition_constraint = constraints
        .get(
            semantic_cells_by_column
                .get(&target_column_ordinal)
                .ok_or(RelationPlanError::InvalidSemanticCell)?
                .bound_certificate
                .constraint_ordinal() as usize,
        )
        .ok_or(RelationPlanError::InvalidBoundCertificate)?;
    if recomposition_constraint.numerator_postfix_expression
        != radix_recomposition_expression(
            target_column_ordinal,
            radix,
            None,
            ordered_digit_column_ordinals,
            context.base_field_modulus,
        )?
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }

    let maximum = context
        .resolved_modulus(modulus_reference)?
        .checked_sub(1)
        .ok_or(RelationPlanError::InvalidModulus)?;
    if usize::from(minimum_radix_digit_count(maximum, radix)?) != digit_count
        || BigUint::from(maximum) > broad_maximum
    {
        return Err(RelationPlanError::InvalidBoundCertificate);
    }
    let maximum_digits = fixed_radix_u64_digits(maximum, digit_count, radix)?;
    let expected_digit_interval =
        SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(radix - 1))?;
    for difference_column_ordinal in ordered_difference_digit_column_ordinals {
        if derive_semantic_cell_interval(
            *difference_column_ordinal,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )? != expected_digit_interval
        {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
    }
    for borrow_column_ordinal in ordered_borrow_column_ordinals {
        if derive_semantic_cell_interval(
            *borrow_column_ordinal,
            semantic_cells_by_column,
            constraints,
            trace_domain_size,
            context,
            derived_intervals,
            active_columns,
        )? != SignedIntegerInterval::new(0, 1)
        {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
    }
    for digit_ordinal in 0..digit_count {
        let comparator_constraint = constraints
            .get(ordered_comparator_constraint_ordinals[digit_ordinal] as usize)
            .ok_or(RelationPlanError::InvalidBoundCertificate)?;
        let incoming_borrow = digit_ordinal
            .checked_sub(1)
            .map(|ordinal| ordered_borrow_column_ordinals[ordinal]);
        let outgoing_borrow = (digit_ordinal + 1 < digit_count)
            .then(|| ordered_borrow_column_ordinals[digit_ordinal]);
        if !comparator_constraint.enforce_proof_base_field_no_wrap
            || comparator_constraint.zeroifier_postfix_expression
                != full_trace_zeroifier_expression(trace_domain_size)
            || comparator_constraint.numerator_postfix_expression
                != unsigned_radix_comparator_digit_expression(
                    maximum_digits[digit_ordinal],
                    ordered_digit_column_ordinals[digit_ordinal],
                    ordered_difference_digit_column_ordinals[digit_ordinal],
                    incoming_borrow,
                    outgoing_borrow,
                    radix,
                )
        {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
    }
    SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))
}
