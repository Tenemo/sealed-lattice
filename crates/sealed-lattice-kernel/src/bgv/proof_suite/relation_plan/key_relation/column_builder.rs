use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use super::super::{
    bounds::{
        RelationBoundCertificate, RelationConstraintDescriptor, SemanticCellDescriptor,
        SignedIntegerInterval,
    },
    checking::full_trace_zeroifier_expression,
    compiled_plan::{CompiledRelationPlan, RelationPlan, RelationPlanCheckContext},
    expressions::{
        RelationExpressionInstruction, binary_constraint_expression,
        finite_integer_set_constraint_expressions, radix_recomposition_expression,
        required_column_rotations, trinary_constraint_expression, unrotated_column_expression,
        unsigned_radix_comparator_digit_expression,
    },
    integer_lift::{
        RelationIntegerLiftCoefficient, RelationIntegerLiftFullRingHalf,
        RelationIntegerLiftLinearTermDescriptor,
    },
    layout::{
        RelationMaskDescriptor, RelationMaskKind, RelationMaskTargetClass,
        RelationOpeningClaimDescriptor, RelationOpeningPointDescriptor, RelationOpeningSourceClass,
        RelationPlanVariant,
    },
    model::{
        ProofPrivacyMode, RelationColumnDescriptor, RelationColumnOrigin, RelationColumnValueType,
        RelationElementKind, RelationEmbeddingKind, RelationPlanError, RelationSelectorPathStep,
        RelationTreeDescriptor, RelationValueLayout, RelationVerifierSource, SelectorPathStepKind,
        SuiteModulusReference,
    },
};
use super::{
    BoundedMaterialDigitWitnessLayout, BoundedUnsignedColumn, EXACT_INTEGER_LIFT_RADIX,
    EXACT_INTEGER_LIFT_RADIX_TRIT_COUNT, KeyRelationGeometry, KeyRelationPlanBuilder,
    KeyVerifierSourceKey, MATERIAL_DIGIT_RADIX, ProofTreePhase, TRIT_RADIX,
    TRUSTEE_QUOTIENT_HIGH_RADIX, UpperBoundComparatorWitnessLayout,
};

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(in crate::bgv::proof_suite::relation_plan) fn new(
        application_statement_schema_identifier: u16,
        geometry: &'context KeyRelationGeometry,
        context: &'context RelationPlanCheckContext,
        sources: Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
    ) -> Result<Self, RelationPlanError> {
        let resolved = geometry.validate(context)?;
        let (ordered_verifier_sources, source_ordinals) = canonical_sources(sources)?;
        Ok(Self {
            application_statement_schema_identifier,
            geometry,
            context,
            ordered_non_native_moduli: resolved.iter().map(|(reference, _)| *reference).collect(),
            resolved_moduli: resolved.into_iter().collect(),
            ordered_verifier_sources,
            source_ordinals,
            ordered_columns: Vec::new(),
            semantic_cells_by_column: BTreeMap::new(),
            exact_radix_digits_by_column: BTreeMap::new(),
            exact_carry_columns_by_component: BTreeMap::new(),
            reversed_columns_by_source_halves: BTreeMap::new(),
            bound_trees: Vec::new(),
            base_tree_columns: Vec::new(),
            auxiliary_tree_columns: Vec::new(),
            pending_integer_lift_batches: BTreeMap::new(),
            ordered_integer_lift_batches: Vec::new(),
            ordered_constraints: Vec::new(),
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn modulus(
        &self,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u64, RelationPlanError> {
        self.resolved_moduli
            .get(&modulus_reference)
            .copied()
            .ok_or(RelationPlanError::MissingModulus)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn modulus_ordinal(
        &self,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u16, RelationPlanError> {
        u16::try_from(
            self.ordered_non_native_moduli
                .binary_search(&modulus_reference)
                .map_err(|_| RelationPlanError::MissingModulus)?,
        )
        .map_err(|_| RelationPlanError::CountOverflow)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn source_ordinal(
        &self,
        key: &KeyVerifierSourceKey,
    ) -> Result<u32, RelationPlanError> {
        self.source_ordinals
            .get(key)
            .copied()
            .ok_or(RelationPlanError::InvalidSource)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn push_column(
        &mut self,
        origin: RelationColumnOrigin,
        source_degree_bound_exclusive: u64,
        canonical_residue_modulus: Option<SuiteModulusReference>,
        phase: Option<ProofTreePhase>,
    ) -> Result<u32, RelationPlanError> {
        let ordinal = u32::try_from(self.ordered_columns.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_columns.push(RelationColumnDescriptor {
            origin,
            value_type: RelationColumnValueType::BaseField,
            source_degree_bound_exclusive,
            canonical_residue_modulus,
        });
        match phase {
            Some(ProofTreePhase::Base) => self.base_tree_columns.push(ordinal),
            Some(ProofTreePhase::Auxiliary) => self.auxiliary_tree_columns.push(ordinal),
            None => {}
        }
        Ok(ordinal)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn push_prover_column(
        &mut self,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        self.push_column(
            RelationColumnOrigin::Prover,
            self.geometry.trace_domain_size()?,
            None,
            Some(phase),
        )
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_constraint(
        &mut self,
        numerator_postfix_expression: Vec<RelationExpressionInstruction>,
        zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
        enforce_proof_base_field_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        self.add_constraint_with_integer_factors(
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
            Vec::new(),
        )
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_constraint_with_integer_factors(
        &mut self,
        numerator_postfix_expression: Vec<RelationExpressionInstruction>,
        zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
        enforce_proof_base_field_no_wrap: bool,
        ordered_injective_integer_factor_expressions: Vec<Vec<RelationExpressionInstruction>>,
    ) -> Result<u32, RelationPlanError> {
        let ordinal = u32::try_from(self.ordered_constraints.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_constraints.push(RelationConstraintDescriptor {
            constraint_role: 1,
            role_coordinates: vec![u64::from(ordinal)],
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
            ordered_injective_integer_factor_expressions,
        });
        Ok(ordinal)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_full_trace_constraint(
        &mut self,
        expression: Vec<RelationExpressionInstruction>,
        enforce_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        self.add_constraint(
            expression,
            full_trace_zeroifier_expression(self.geometry.trace_domain_size()?),
            enforce_no_wrap,
        )
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn insert_semantic_cell(
        &mut self,
        column_ordinal: u32,
        interval: SignedIntegerInterval,
        bound_certificate: RelationBoundCertificate,
    ) -> Result<(), RelationPlanError> {
        if self
            .semantic_cells_by_column
            .insert(column_ordinal, (interval, bound_certificate))
            .is_some()
        {
            return Err(RelationPlanError::InvalidSemanticCell);
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_trit_column(
        &mut self,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let column = self.push_prover_column(phase)?;
        let constraint_ordinal =
            self.add_full_trace_constraint(trinary_constraint_expression(column), false)?;
        self.insert_semantic_cell(
            column,
            SignedIntegerInterval::new(0, 2),
            RelationBoundCertificate::Trinary { constraint_ordinal },
        )?;
        Ok(column)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_binary_column(
        &mut self,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let column = self.push_prover_column(phase)?;
        let constraint_ordinal =
            self.add_full_trace_constraint(binary_constraint_expression(column), false)?;
        self.insert_semantic_cell(
            column,
            SignedIntegerInterval::new(0, 1),
            RelationBoundCertificate::Binary { constraint_ordinal },
        )?;
        Ok(column)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_finite_integer_set_column(
        &mut self,
        ordered_values: Vec<BigInt>,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let column = self.push_prover_column(phase)?;
        let (expression, ordered_factor_expressions) = finite_integer_set_constraint_expressions(
            column,
            &ordered_values,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_constraint_with_integer_factors(
            expression,
            full_trace_zeroifier_expression(self.geometry.trace_domain_size()?),
            false,
            ordered_factor_expressions,
        )?;
        self.insert_semantic_cell(
            column,
            SignedIntegerInterval::from_bigints(
                ordered_values
                    .first()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
                ordered_values
                    .last()
                    .cloned()
                    .ok_or(RelationPlanError::InvalidBoundCertificate)?,
            )?,
            RelationBoundCertificate::FiniteIntegerSet {
                constraint_ordinal,
                ordered_values,
            },
        )?;
        Ok(column)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_trit_columns(
        &mut self,
        count: usize,
        phase: ProofTreePhase,
    ) -> Result<Vec<u32>, RelationPlanError> {
        (0..count).map(|_| self.add_trit_column(phase)).collect()
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn certify_unsigned_recomposition(
        &mut self,
        target_column_ordinal: u32,
        radix: u64,
        ordered_digit_column_ordinals: &[u32],
    ) -> Result<(), RelationPlanError> {
        let expression = radix_recomposition_expression(
            target_column_ordinal,
            radix,
            None,
            ordered_digit_column_ordinals,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = BigUint::from(radix).pow(
            u32::try_from(ordered_digit_column_ordinals.len())
                .map_err(|_| RelationPlanError::CountOverflow)?,
        ) - BigUint::one();
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?,
            RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal,
                radix,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.to_vec(),
            },
        )
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_bounded_material_digit(
        &mut self,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<BoundedMaterialDigitWitnessLayout, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let target = self.push_prover_column(phase)?;
        let trit_count = minimum_unsigned_radix_digit_count(maximum, TRIT_RADIX)?;
        let trits = self.add_trit_columns(trit_count, phase)?;
        self.certify_unsigned_recomposition(target, TRIT_RADIX, &trits)?;
        Ok(BoundedMaterialDigitWitnessLayout {
            target_column_ordinal: target,
            trit_column_ordinals: trits,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_bounded_unsigned_column(
        &mut self,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<BoundedUnsignedColumn, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::IntegerBoundOverflow);
        }
        let bounded_digit = self.add_bounded_material_digit(maximum, phase)?;
        let target_column_ordinal = bounded_digit.target_column_ordinal;
        let maximum_digits = vec![maximum];
        let _ =
            self.add_upper_bound_comparator(&[target_column_ordinal], &maximum_digits, phase)?;
        Ok(BoundedUnsignedColumn {
            target_column_ordinal,
            ordered_digit_column_ordinals: vec![target_column_ordinal],
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_canonical_modulus_column(
        &mut self,
        modulus_reference: SuiteModulusReference,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        let maximum = self
            .context
            .resolved_modulus(modulus_reference)?
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidModulus)?;
        let digit_count = minimum_unsigned_radix_digit_count(maximum, TRIT_RADIX)?;
        let target_column_ordinal = self.push_prover_column(phase)?;
        let ordered_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        let recomposition_constraint_ordinal = self.add_full_trace_constraint(
            radix_recomposition_expression(
                target_column_ordinal,
                TRIT_RADIX,
                None,
                &ordered_digit_column_ordinals,
                self.context.base_field_modulus,
            )?,
            false,
        )?;
        let maximum_digits = fixed_radix_digits(maximum, digit_count, TRIT_RADIX)?;
        let ordered_difference_digit_column_ordinals = self.add_trit_columns(digit_count, phase)?;
        let ordered_borrow_column_ordinals = (0..digit_count.saturating_sub(1))
            .map(|_| self.add_binary_column(phase))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ordered_comparator_constraint_ordinals = Vec::with_capacity(digit_count);
        for digit_ordinal in 0..digit_count {
            ordered_comparator_constraint_ordinals.push(
                self.add_full_trace_constraint(
                    unsigned_radix_comparator_digit_expression(
                        maximum_digits[digit_ordinal],
                        ordered_digit_column_ordinals[digit_ordinal],
                        ordered_difference_digit_column_ordinals[digit_ordinal],
                        digit_ordinal
                            .checked_sub(1)
                            .map(|ordinal| ordered_borrow_column_ordinals[ordinal]),
                        (digit_ordinal + 1 < digit_count)
                            .then(|| ordered_borrow_column_ordinals[digit_ordinal]),
                        TRIT_RADIX,
                    ),
                    true,
                )?,
            );
        }
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(maximum))?,
            RelationBoundCertificate::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                modulus_reference,
                radix: TRIT_RADIX,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.clone(),
                ordered_comparator_constraint_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
            },
        )?;
        self.register_exact_radix_decomposition(
            target_column_ordinal,
            modulus_reference,
            Some(&ordered_digit_column_ordinals),
        )?;
        Ok(target_column_ordinal)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn register_exact_radix_decomposition(
        &mut self,
        target_column_ordinal: u32,
        modulus_reference: SuiteModulusReference,
        existing_trit_column_ordinals: Option<&[u32]>,
    ) -> Result<Vec<u32>, RelationPlanError> {
        if let Some(digits) = self
            .exact_radix_digits_by_column
            .get(&target_column_ordinal)
        {
            return Ok(digits.clone());
        }
        let modulus = self.modulus(modulus_reference)?;
        let trit_count = minimum_unsigned_radix_digit_count(modulus - 1, TRIT_RADIX)?;
        if existing_trit_column_ordinals.is_some_and(|trits| trits.len() != trit_count) {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let exact_digit_count = trit_count.div_ceil(EXACT_INTEGER_LIFT_RADIX_TRIT_COUNT);
        let mut exact_digit_columns = Vec::with_capacity(exact_digit_count);
        for exact_digit_ordinal in 0..exact_digit_count {
            let first_trit = exact_digit_ordinal
                .checked_mul(EXACT_INTEGER_LIFT_RADIX_TRIT_COUNT)
                .ok_or(RelationPlanError::CountOverflow)?;
            let end_trit = (first_trit + EXACT_INTEGER_LIFT_RADIX_TRIT_COUNT).min(trit_count);
            let exact_digit_column = self.push_prover_column(ProofTreePhase::Base)?;
            let owned_trits;
            let exact_digit_trits = if let Some(existing_trits) = existing_trit_column_ordinals {
                &existing_trits[first_trit..end_trit]
            } else {
                owned_trits = self.add_trit_columns(end_trit - first_trit, ProofTreePhase::Base)?;
                &owned_trits
            };
            self.certify_unsigned_recomposition(exact_digit_column, TRIT_RADIX, exact_digit_trits)?;
            exact_digit_columns.push(exact_digit_column);
        }
        self.add_full_trace_constraint(
            radix_recomposition_expression(
                target_column_ordinal,
                EXACT_INTEGER_LIFT_RADIX,
                None,
                &exact_digit_columns,
                self.context.base_field_modulus,
            )?,
            true,
        )?;
        if self
            .exact_radix_digits_by_column
            .insert(target_column_ordinal, exact_digit_columns.clone())
            .is_some()
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        Ok(exact_digit_columns)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_centered_integer_column(
        &mut self,
        maximum_absolute_value: &BigUint,
    ) -> Result<u32, RelationPlanError> {
        let mut trit_count = 1_usize;
        loop {
            let capacity = BigUint::from(TRIT_RADIX)
                .pow(u32::try_from(trit_count).map_err(|_| RelationPlanError::CountOverflow)?);
            let offset = (&capacity - BigUint::one()) / BigUint::from(2_u8);
            if &offset >= maximum_absolute_value {
                let offset_u64 =
                    u64::try_from(&offset).map_err(|_| RelationPlanError::IntegerBoundOverflow)?;
                let target = self.push_prover_column(ProofTreePhase::Base)?;
                let trits = self.add_trit_columns(trit_count, ProofTreePhase::Base)?;
                let expression = radix_recomposition_expression(
                    target,
                    TRIT_RADIX,
                    Some(&offset),
                    &trits,
                    self.context.base_field_modulus,
                )?;
                let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
                self.insert_semantic_cell(
                    target,
                    SignedIntegerInterval::new(-i128::from(offset_u64), i128::from(offset_u64)),
                    RelationBoundCertificate::ShiftedRadixRecomposition {
                        constraint_ordinal,
                        radix: TRIT_RADIX,
                        offset,
                        ordered_digit_column_ordinals: trits,
                    },
                )?;
                return Ok(target);
            }
            trit_count = trit_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_upper_bound_comparator(
        &mut self,
        value_digits: &[u32],
        maximum_digits: &[u64],
        phase: ProofTreePhase,
    ) -> Result<UpperBoundComparatorWitnessLayout, RelationPlanError> {
        if value_digits.is_empty() || value_digits.len() != maximum_digits.len() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut difference_digits = Vec::with_capacity(maximum_digits.len());
        for (digit_ordinal, maximum_digit) in maximum_digits.iter().copied().enumerate() {
            let difference_maximum = if digit_ordinal + 1 == maximum_digits.len() {
                maximum_digit
            } else {
                MATERIAL_DIGIT_RADIX - 1
            };
            difference_digits.push(self.add_bounded_material_digit(difference_maximum, phase)?);
        }
        let borrows = (0..value_digits.len().saturating_sub(1))
            .map(|_| self.add_binary_column(phase))
            .collect::<Result<Vec<_>, _>>()?;
        for digit_ordinal in 0..value_digits.len() {
            let mut terms = vec![integer_constant_term(maximum_digits[digit_ordinal], false)];
            terms.push(integer_column_term(value_digits[digit_ordinal], true));
            if digit_ordinal > 0 {
                terms.push(integer_column_term(borrows[digit_ordinal - 1], true));
            }
            if digit_ordinal + 1 < value_digits.len() {
                terms.push(integer_scaled_column_term(
                    borrows[digit_ordinal],
                    MATERIAL_DIGIT_RADIX,
                    false,
                ));
            }
            terms.push(integer_column_term(
                difference_digits[digit_ordinal].target_column_ordinal,
                true,
            ));
            self.add_full_trace_constraint(sum_integer_terms(terms)?, true)?;
        }
        Ok(UpperBoundComparatorWitnessLayout {
            difference_digits,
            borrow_column_ordinals: borrows,
        })
    }
}

impl KeyRelationPlanBuilder<'_> {
    pub(in crate::bgv::proof_suite::relation_plan) fn finish(
        mut self,
    ) -> Result<CompiledRelationPlan, RelationPlanError> {
        #[cfg(test)]
        let phase_started = std::time::Instant::now();
        self.finalize_integer_lift_batches()?;
        #[cfg(test)]
        eprintln!(
            "key relation finalize integer lifts: {:?}; columns={} constraints={} batches={}",
            phase_started.elapsed(),
            self.ordered_columns.len(),
            self.ordered_constraints.len(),
            self.ordered_integer_lift_batches.len()
        );
        if self.base_tree_columns.is_empty()
            || self.auxiliary_tree_columns.is_empty()
            || self.ordered_integer_lift_batches.is_empty()
        {
            return Err(RelationPlanError::InvalidRoot);
        }
        #[cfg(test)]
        let phase_started = std::time::Instant::now();
        let required_rotations_by_column =
            required_column_rotations(&self.ordered_constraints, &[])?;
        #[cfg(test)]
        eprintln!(
            "key relation required rotations: {:?}",
            phase_started.elapsed()
        );
        if required_rotations_by_column.len() != self.ordered_columns.len() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let trace_mask_degree_bound_exclusive = derived_trace_mask_degree_bound(
            &self.ordered_columns,
            &required_rotations_by_column,
            self.geometry.trace_domain_size()?,
            self.context,
        )?;
        let prover_column_degree_bound_exclusive = self
            .geometry
            .trace_domain_size()?
            .checked_add(trace_mask_degree_bound_exclusive)
            .filter(|degree| *degree <= self.geometry.opening_degree_bound_exclusive)
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        for column in &mut self.ordered_columns {
            if matches!(column.origin, RelationColumnOrigin::Prover) {
                column.source_degree_bound_exclusive = prover_column_degree_bound_exclusive;
            }
        }

        let used_rotations = required_rotations_by_column
            .values()
            .flat_map(|rotations| rotations.iter().copied())
            .collect::<BTreeSet<_>>();
        if !used_rotations.contains(&(false, 0)) {
            return Err(RelationPlanError::InvalidOpening);
        }
        let mut ordered_trees = self.bound_trees;
        ordered_trees.push(RelationTreeDescriptor::ProofCreated {
            proof_tree_role: 1,
            ordered_column_ordinals: self.base_tree_columns,
        });
        ordered_trees.push(RelationTreeDescriptor::ProofCreated {
            proof_tree_role: 2,
            ordered_column_ordinals: self.auxiliary_tree_columns,
        });
        let ordered_semantic_cells = self
            .semantic_cells_by_column
            .into_iter()
            .enumerate()
            .map(
                |(
                    semantic_cell_ordinal,
                    (column_ordinal, (claimed_interval, bound_certificate)),
                )| {
                    Ok(SemanticCellDescriptor {
                        semantic_cell_ordinal: u32::try_from(semantic_cell_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                        column_ordinal,
                        claimed_interval,
                        bound_certificate,
                    })
                },
            )
            .collect::<Result<Vec<_>, RelationPlanError>>()?;

        let ordered_opening_points = (0..self.context.out_of_domain_point_count)
            .flat_map(|out_of_domain_point_ordinal| {
                used_rotations
                    .iter()
                    .map(move |rotation| RelationOpeningPointDescriptor {
                        out_of_domain_point_ordinal,
                        trace_rotation_is_negative: rotation.0,
                        trace_rotation_magnitude: rotation.1,
                        conjugate_index: 0,
                    })
            })
            .collect::<Vec<_>>();
        let opening_point_ordinals = ordered_opening_points
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
        #[cfg(test)]
        let phase_started = std::time::Instant::now();
        let mut ordered_opening_claims = Vec::new();
        for (tree_ordinal, tree) in ordered_trees.iter().enumerate() {
            for column_ordinal in tree.ordered_column_ordinals() {
                let source_degree_bound_exclusive = self
                    .ordered_columns
                    .get(*column_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidOpening)?
                    .source_degree_bound_exclusive;
                for out_of_domain_point_ordinal in 0..self.context.out_of_domain_point_count {
                    for rotation in required_rotations_by_column
                        .get(column_ordinal)
                        .ok_or(RelationPlanError::InvalidOpening)?
                    {
                        let opening_point_ordinal = opening_point_ordinals
                            .get(&RelationOpeningPointDescriptor {
                                out_of_domain_point_ordinal,
                                trace_rotation_is_negative: rotation.0,
                                trace_rotation_magnitude: rotation.1,
                                conjugate_index: 0,
                            })
                            .copied()
                            .ok_or(RelationPlanError::InvalidOpening)?;
                        ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                            source_class: RelationOpeningSourceClass::TreeColumn,
                            source_ordinal: u32::try_from(tree_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                            column_ordinal: Some(*column_ordinal),
                            opening_point_ordinal,
                            source_degree_bound_exclusive,
                        });
                    }
                }
            }
        }
        for quotient_ordinal in 0..self.context.quotient_component_count {
            for out_of_domain_point_ordinal in 0..self.context.out_of_domain_point_count {
                let opening_point_ordinal = opening_point_ordinals
                    .get(&RelationOpeningPointDescriptor {
                        out_of_domain_point_ordinal,
                        trace_rotation_is_negative: false,
                        trace_rotation_magnitude: 0,
                        conjugate_index: 0,
                    })
                    .copied()
                    .ok_or(RelationPlanError::InvalidOpening)?;
                ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                    source_class: RelationOpeningSourceClass::Quotient,
                    source_ordinal: quotient_ordinal,
                    column_ordinal: None,
                    opening_point_ordinal,
                    source_degree_bound_exclusive: self
                        .context
                        .quotient_component_degree_bound_exclusive,
                });
            }
        }
        ordered_opening_claims.push(RelationOpeningClaimDescriptor {
            source_class: RelationOpeningSourceClass::BatchMask,
            source_ordinal: 0,
            column_ordinal: None,
            opening_point_ordinal: 0,
            source_degree_bound_exclusive: self
                .geometry
                .opening_degree_bound_exclusive
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        });
        #[cfg(test)]
        eprintln!(
            "key relation opening claims: {:?}; claims={}",
            phase_started.elapsed(),
            ordered_opening_claims.len()
        );

        let mut next_trace_mask_ordinal = 0_u32;
        let mut ordered_masks = Vec::new();
        for (column_ordinal, column) in self.ordered_columns.iter().enumerate() {
            if matches!(column.origin, RelationColumnOrigin::Prover) {
                ordered_masks.push(RelationMaskDescriptor {
                    mask_ordinal: next_trace_mask_ordinal,
                    mask_kind: RelationMaskKind::Trace,
                    target_class: RelationMaskTargetClass::Column,
                    target_ordinal: u32::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    mask_degree_bound_exclusive: trace_mask_degree_bound_exclusive,
                });
                next_trace_mask_ordinal = next_trace_mask_ordinal
                    .checked_add(1)
                    .ok_or(RelationPlanError::CountOverflow)?;
            }
        }
        let quotient_component_count = self.context.quotient_component_count;
        if quotient_component_count < 2 {
            return Err(RelationPlanError::InvalidMaskGrammar);
        }
        let component_count = u128::from(quotient_component_count);
        let rounded_mask_degree = component_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(u128::from(trace_mask_degree_bound_exclusive)))
            .and_then(|degree| degree.checked_add(component_count - 1))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?
            / component_count;
        let decomposition_stride = self
            .geometry
            .trace_domain_size()?
            .checked_add(
                u64::try_from(rounded_mask_degree)
                    .map_err(|_| RelationPlanError::DegreeBoundExceeded)?,
            )
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        let telescoping_degree = self
            .context
            .quotient_component_degree_bound_exclusive
            .checked_sub(decomposition_stride)
            .filter(|degree| *degree != 0)
            .ok_or(RelationPlanError::InvalidMaskGrammar)?;
        for quotient_ordinal in 0..quotient_component_count - 1 {
            ordered_masks.push(RelationMaskDescriptor {
                mask_ordinal: quotient_ordinal,
                mask_kind: RelationMaskKind::Telescoping,
                target_class: RelationMaskTargetClass::QuotientComponent,
                target_ordinal: quotient_ordinal,
                mask_degree_bound_exclusive: telescoping_degree,
            });
        }
        ordered_masks.push(RelationMaskDescriptor {
            mask_ordinal: 0,
            mask_kind: RelationMaskKind::OpeningBatch,
            target_class: RelationMaskTargetClass::Batch,
            target_ordinal: 0,
            mask_degree_bound_exclusive: self
                .geometry
                .opening_degree_bound_exclusive
                .checked_sub(1)
                .ok_or(RelationPlanError::DegreeBoundExceeded)?,
        });

        let compiled = CompiledRelationPlan {
            plan: RelationPlan {
                application_statement_schema_identifier: self
                    .application_statement_schema_identifier,
                variants: vec![RelationPlanVariant {
                    schedule_position: self.geometry.schedule_position,
                    top_count: None,
                    proof_privacy_mode: ProofPrivacyMode::SecretBearing,
                    trace_domain_size: self.geometry.trace_domain_size()?,
                    evaluation_domain_size: self.geometry.evaluation_domain_size,
                    opening_degree_bound_exclusive: self.geometry.opening_degree_bound_exclusive,
                    ordered_non_native_moduli: self.ordered_non_native_moduli,
                    ordered_verifier_sources: self.ordered_verifier_sources,
                    ordered_public_samplers: Vec::new(),
                    ordered_columns: self.ordered_columns,
                    ordered_semantic_cells,
                    ordered_radix_convolutions: Vec::new(),
                    ordered_integer_lift_batches: self.ordered_integer_lift_batches,
                    ordered_coefficient_local_identity_batches: Vec::new(),
                    ordered_trees,
                    ordered_constraints: self.ordered_constraints,
                    ordered_opening_points,
                    ordered_opening_claims,
                    ordered_masks,
                }],
            },
        };
        #[cfg(test)]
        let phase_started = std::time::Instant::now();
        compiled.check(self.context)?;
        #[cfg(test)]
        eprintln!("key relation compiled check: {:?}", phase_started.elapsed());
        Ok(compiled)
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn derived_trace_mask_degree_bound(
    ordered_columns: &[RelationColumnDescriptor],
    required_rotations_by_column: &BTreeMap<u32, BTreeSet<(bool, u64)>>,
    trace_domain_size: u64,
    context: &RelationPlanCheckContext,
) -> Result<u64, RelationPlanError> {
    let mut maximum_view_count = 0_u64;
    for (column_ordinal, column) in ordered_columns.iter().enumerate() {
        if !matches!(column.origin, RelationColumnOrigin::Prover) {
            continue;
        }
        let rotation_count = u64::try_from(
            required_rotations_by_column
                .get(&u32::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?)
                .ok_or(RelationPlanError::InvalidOpening)?
                .len(),
        )
        .map_err(|_| RelationPlanError::CountOverflow)?;
        let out_of_domain_opening_view_count = u64::from(context.challenge_extension_degree)
            .checked_mul(u64::from(context.out_of_domain_point_count))
            .and_then(|count| count.checked_mul(rotation_count))
            .ok_or(RelationPlanError::CountOverflow)?;
        let query_view_count = u64::from(context.phase_column_query_coordinate_count)
            .checked_mul(rotation_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        maximum_view_count = maximum_view_count.max(
            out_of_domain_opening_view_count
                .checked_add(query_view_count)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    }
    if maximum_view_count == 0 || maximum_view_count > trace_domain_size {
        Err(RelationPlanError::InvalidMaskGrammar)
    } else {
        Ok(maximum_view_count)
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn statement_root_source(
    field_ordinal: u64,
    list_ordinal: Option<u64>,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let mut value_path = vec![RelationSelectorPathStep::tuple_field(field_ordinal)];
    if let Some(list_ordinal) = list_ordinal {
        value_path.push(RelationSelectorPathStep {
            step_kind: SelectorPathStepKind::LiteralListIndex,
            argument: list_ordinal,
        });
    }
    (
        KeyVerifierSourceKey::StatementRoot {
            field_ordinal,
            list_ordinal,
        },
        RelationVerifierSource::ApplicationStatement {
            value_path,
            value_layout: RelationValueLayout::scalar_hash(),
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn nested_statement_root_source(
    field_ordinal: u64,
    list_ordinal: u64,
    nested_field_ordinal: u64,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    (
        KeyVerifierSourceKey::NestedStatementRoot {
            field_ordinal,
            list_ordinal,
            nested_field_ordinal,
        },
        RelationVerifierSource::ApplicationStatement {
            value_path: vec![
                RelationSelectorPathStep::tuple_field(field_ordinal),
                RelationSelectorPathStep {
                    step_kind: SelectorPathStepKind::LiteralListIndex,
                    argument: list_ordinal,
                },
                RelationSelectorPathStep::tuple_field(nested_field_ordinal),
            ],
            value_layout: RelationValueLayout::scalar_hash(),
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn bdlop_matrix_source(
    ring_degree: u64,
    data_modulus_index: u16,
    matrix_part: u16,
    row: u16,
    column: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::data(data_modulus_index);
    (
        KeyVerifierSourceKey::BdlopMatrix {
            data_modulus_index,
            matrix_part,
            row,
            column,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 5,
            source_coordinates: vec![
                u64::from(data_modulus_index),
                u64::from(matrix_part),
                u64::from(row),
                u64::from(column),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: centered_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn trustee_bdlop_matrix_source(
    ring_degree: u64,
    data_modulus_index: u16,
    matrix_part: u16,
    row: u16,
    column: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::data(data_modulus_index);
    (
        KeyVerifierSourceKey::TrusteeBdlopMatrix {
            data_modulus_index,
            matrix_part,
            row,
            column,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 5,
            source_coordinates: vec![
                u64::from(data_modulus_index),
                u64::from(matrix_part),
                u64::from(row),
                u64::from(column),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn relinearization_common_reference_source(
    ring_degree: u64,
    schedule_position: u32,
    decomposition_block_index: u16,
    modulus_reference: SuiteModulusReference,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    (
        KeyVerifierSourceKey::RelinearizationCommonReference {
            schedule_position,
            decomposition_block_index,
            modulus_reference,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 7,
            source_coordinates: vec![
                u64::from(schedule_position),
                u64::from(decomposition_block_index),
                modulus_reference.catalog as u64,
                u64::from(modulus_reference.modulus_index),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn galois_common_reference_source(
    ring_degree: u64,
    schedule_position: u32,
    decomposition_block_index: u16,
    modulus_reference: SuiteModulusReference,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    (
        KeyVerifierSourceKey::GaloisCommonReference {
            schedule_position,
            decomposition_block_index,
            modulus_reference,
        },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 8,
            source_coordinates: vec![
                u64::from(schedule_position),
                u64::from(decomposition_block_index),
                modulus_reference.catalog as u64,
                u64::from(modulus_reference.modulus_index),
            ],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn negacyclic_automorphism_mapping_source(
    ring_degree: u64,
    galois_element: u64,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    (
        KeyVerifierSourceKey::NegacyclicAutomorphismMapping {
            ring_degree,
            galois_element,
        },
        RelationVerifierSource::NegacyclicAutomorphismMapping {
            ring_degree,
            galois_element,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::bgv::proof_suite::relation_plan) fn target_converted_radix_digit_source(
    ring_degree: u64,
    target_role: u16,
    component_ordinal: u16,
    target_modulus_index: u16,
    scale: u64,
    radix: u64,
    digit_ordinal: u16,
    digit_count: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::target(target_modulus_index);
    let key = KeyVerifierSourceKey::TargetConvertedRadixDigit {
        target_role,
        component_ordinal,
        target_modulus_index,
        scale,
        radix,
        digit_ordinal,
        digit_count,
    };
    let source = RelationVerifierSource::Protocol {
        protocol_source_kind: 3,
        source_coordinates: vec![
            u64::from(target_role),
            u64::from(component_ordinal),
            u64::from(target_modulus_index),
        ],
        statement_binding_path: vec![RelationSelectorPathStep::tuple_field(6)],
        value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
    };
    (
        key,
        RelationVerifierSource::RadixDecomposition {
            source: Box::new(source),
            modulus_reference,
            scale,
            radix,
            digit_ordinal,
            digit_count,
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn target_partial_decryption_radix_digit_source(
    ring_degree: u64,
    target_role: u16,
    target_modulus_index: u16,
    radix: u64,
    digit_ordinal: u16,
    digit_count: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::target(target_modulus_index);
    let key = KeyVerifierSourceKey::TargetPartialDecryptionRadixDigit {
        target_role,
        target_modulus_index,
        radix,
        digit_ordinal,
        digit_count,
    };
    let source = RelationVerifierSource::Protocol {
        protocol_source_kind: 4,
        source_coordinates: vec![u64::from(target_role), u64::from(target_modulus_index)],
        statement_binding_path: vec![RelationSelectorPathStep::tuple_field(
            11_u64 + u64::from(target_role),
        )],
        value_layout: least_nonnegative_residue_vector(modulus_reference, ring_degree),
    };
    (
        key,
        RelationVerifierSource::RadixDecomposition {
            source: Box::new(source),
            modulus_reference,
            scale: 1,
            radix,
            digit_ordinal,
            digit_count,
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn public_key_common_reference_source(
    ring_degree: u64,
    data_modulus_index: u16,
) -> (KeyVerifierSourceKey, RelationVerifierSource) {
    let modulus_reference = SuiteModulusReference::data(data_modulus_index);
    (
        KeyVerifierSourceKey::PublicKeyCommonReference { data_modulus_index },
        RelationVerifierSource::Protocol {
            protocol_source_kind: 6,
            source_coordinates: vec![u64::from(data_modulus_index)],
            statement_binding_path: vec![RelationSelectorPathStep::tuple_field(0)],
            value_layout: centered_residue_vector(modulus_reference, ring_degree),
        },
    )
}

pub(in crate::bgv::proof_suite::relation_plan) fn centered_residue_vector(
    modulus_reference: SuiteModulusReference,
    element_count: u64,
) -> RelationValueLayout {
    RelationValueLayout {
        element_kind: RelationElementKind::Residue,
        residue_modulus: Some(modulus_reference),
        shape: vec![element_count],
        embedding_kind: RelationEmbeddingKind::Centered,
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn least_nonnegative_residue_vector(
    modulus_reference: SuiteModulusReference,
    element_count: u64,
) -> RelationValueLayout {
    RelationValueLayout::residue_vector(modulus_reference, element_count)
}

pub(in crate::bgv::proof_suite::relation_plan) fn canonical_sources(
    sources: Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
) -> Result<
    (
        Vec<RelationVerifierSource>,
        BTreeMap<KeyVerifierSourceKey, u32>,
    ),
    RelationPlanError,
> {
    if sources.is_empty() {
        return Err(RelationPlanError::InvalidSource);
    }
    let mut keyed = sources
        .into_iter()
        .map(|(key, source)| Ok((source.canonical_bytes()?, key, source)))
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if !keyed.windows(2).all(|window| window[0].0 < window[1].0) {
        return Err(RelationPlanError::DuplicateItem);
    }
    let mut ordered_sources = Vec::with_capacity(keyed.len());
    let mut source_ordinals = BTreeMap::new();
    for (ordinal, (_, key, source)) in keyed.into_iter().enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        if source_ordinals.insert(key, ordinal).is_some() {
            return Err(RelationPlanError::DuplicateItem);
        }
        ordered_sources.push(source);
    }
    Ok((ordered_sources, source_ordinals))
}

pub(in crate::bgv::proof_suite::relation_plan) fn fixed_radix_digits(
    mut value: u64,
    count: usize,
    radix: u64,
) -> Result<Vec<u64>, RelationPlanError> {
    if count == 0 || radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut digits = Vec::with_capacity(count);
    for _ in 0..count {
        digits.push(value % radix);
        value /= radix;
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

pub(in crate::bgv::proof_suite::relation_plan) fn minimum_unsigned_radix_digit_count(
    maximum: u64,
    radix: u64,
) -> Result<usize, RelationPlanError> {
    if radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut value = maximum;
    let mut count = 1_usize;
    while value >= radix {
        value /= radix;
        count = count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(count)
}

pub(in crate::bgv::proof_suite::relation_plan) fn constant_linear_term(
    column_ordinal: u32,
    column_offset: u64,
    negative: bool,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal,
        column_offset,
        coefficient: RelationIntegerLiftCoefficient::Constant(1),
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn scaled_constant_linear_term(
    column_ordinal: u32,
    negative: bool,
    coefficient: u64,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal,
        column_offset: 0,
        coefficient: RelationIntegerLiftCoefficient::Constant(coefficient),
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn plaintext_scaled_linear_term(
    column_ordinal: u32,
    negative: bool,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative,
        column_ordinal,
        column_offset: 0,
        coefficient: RelationIntegerLiftCoefficient::Modulus {
            modulus_reference: SuiteModulusReference::plaintext(),
            multiplier: 1,
        },
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn trustee_quotient_carry_linear_term(
    carry_column_ordinal: u32,
    modulus_reference: SuiteModulusReference,
) -> RelationIntegerLiftLinearTermDescriptor {
    RelationIntegerLiftLinearTermDescriptor {
        negative: true,
        column_ordinal: carry_column_ordinal,
        column_offset: 0,
        coefficient: RelationIntegerLiftCoefficient::Modulus {
            modulus_reference,
            multiplier: TRUSTEE_QUOTIENT_HIGH_RADIX,
        },
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn integer_lift_half(
    half_ordinal: usize,
) -> Result<RelationIntegerLiftFullRingHalf, RelationPlanError> {
    match half_ordinal {
        0 => Ok(RelationIntegerLiftFullRingHalf::Low),
        1 => Ok(RelationIntegerLiftFullRingHalf::High),
        _ => Err(RelationPlanError::InvalidConstraint),
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn sort_canonical_items<T>(
    items: &mut Vec<T>,
    mut canonical_bytes: impl FnMut(&T) -> Result<Vec<u8>, RelationPlanError>,
) -> Result<(), RelationPlanError> {
    let mut keyed = items
        .drain(..)
        .map(|item| Ok((canonical_bytes(&item)?, item)))
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if keyed.windows(2).any(|window| window[0].0 >= window[1].0) {
        return Err(RelationPlanError::DuplicateItem);
    }
    items.extend(keyed.into_iter().map(|(_, item)| item));
    Ok(())
}

pub(in crate::bgv::proof_suite::relation_plan) struct IntegerExpressionTerm {
    expression: Vec<RelationExpressionInstruction>,
    negative: bool,
}

pub(in crate::bgv::proof_suite::relation_plan) fn integer_constant_term(
    value: u64,
    negative: bool,
) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![RelationExpressionInstruction::BaseFieldConstant(value)],
        negative,
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn integer_column_term(
    column_ordinal: u32,
    negative: bool,
) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![unrotated_column_expression(column_ordinal)],
        negative,
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn integer_scaled_column_term(
    column_ordinal: u32,
    multiplier: u64,
    negative: bool,
) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![
            unrotated_column_expression(column_ordinal),
            RelationExpressionInstruction::BaseFieldConstant(multiplier),
            RelationExpressionInstruction::Multiplication,
        ],
        negative,
    }
}

pub(in crate::bgv::proof_suite::relation_plan) fn sum_integer_terms(
    terms: Vec<IntegerExpressionTerm>,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut terms = terms.into_iter();
    let first = terms.next().ok_or(RelationPlanError::InvalidConstraint)?;
    let mut expression = first.expression;
    if first.negative {
        expression.push(RelationExpressionInstruction::Negation);
    }
    for term in terms {
        expression.extend(term.expression);
        if term.negative {
            expression.push(RelationExpressionInstruction::Negation);
        }
        expression.push(RelationExpressionInstruction::Addition);
    }
    Ok(expression)
}
