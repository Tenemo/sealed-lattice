use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

use super::super::{
    bounds::SignedIntegerInterval,
    integer_lift::{
        RelationIntegerLiftBatchDescriptor, RelationIntegerLiftCoefficient,
        RelationIntegerLiftComponentDescriptor, RelationIntegerLiftFullRingHalf,
        RelationIntegerLiftFullRingNegacyclicProductDescriptor,
        RelationIntegerLiftLinearTermDescriptor,
        RelationIntegerLiftReversedColumnBindingDescriptor,
    },
    model::{
        RelationColumnOrigin, RelationPlanError, RelationVerifierSource, SuiteModulusReference,
    },
};
use super::{
    AnchorEquationInputs, EXACT_INTEGER_LIFT_RADIX, KeyRelationPlanBuilder,
    PendingFullRingNegacyclicProduct, ProofTreePhase, PublicKeyEquationInputs,
    ReversibleShiftedSmallVector, ShiftedSmallVector, SplitIntegerVector,
    TrusteeAnchorOpeningWitness, TrusteeRadixThreeQuotientWitness,
    column_builder::{
        constant_linear_term, integer_lift_half, plaintext_scaled_linear_term,
        scaled_constant_linear_term, sort_canonical_items, trustee_quotient_carry_linear_term,
    },
};

fn exact_radix_digits(mut value: u128) -> Result<Vec<u64>, RelationPlanError> {
    let radix = u128::from(EXACT_INTEGER_LIFT_RADIX);
    let mut digits = Vec::new();
    while value != 0 {
        digits.push(
            u64::try_from(value % radix).map_err(|_| RelationPlanError::IntegerBoundOverflow)?,
        );
        value /= radix;
    }
    if digits.is_empty() {
        digits.push(0);
    }
    Ok(digits)
}

fn fixed_exact_radix_digits(
    mut value: u128,
    digit_count: usize,
) -> Result<Vec<u64>, RelationPlanError> {
    if digit_count == 0 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let radix = u128::from(EXACT_INTEGER_LIFT_RADIX);
    let mut digits = Vec::with_capacity(digit_count);
    for _ in 0..digit_count {
        digits.push(
            u64::try_from(value % radix).map_err(|_| RelationPlanError::IntegerBoundOverflow)?,
        );
        value /= radix;
    }
    if value != 0 {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok(digits)
}

fn split_exact_radix_digits(
    digits_by_column: &std::collections::BTreeMap<u32, Vec<u32>>,
    vector: SplitIntegerVector,
) -> Result<Option<Vec<SplitIntegerVector>>, RelationPlanError> {
    let low = digits_by_column.get(&vector.halves[0]);
    let high = digits_by_column.get(&vector.halves[1]);
    match (low, high) {
        (None, None) => Ok(None),
        (Some(low), Some(high)) if low.len() == high.len() && !low.is_empty() => Ok(Some(
            low.iter()
                .copied()
                .zip(high.iter().copied())
                .map(|(low, high)| SplitIntegerVector {
                    halves: [low, high],
                })
                .collect(),
        )),
        _ => Err(RelationPlanError::InvalidConstraint),
    }
}

fn ensure_exact_limb(
    terms: &mut Vec<Vec<RelationIntegerLiftLinearTermDescriptor>>,
    intervals: &mut Vec<SignedIntegerInterval>,
    limb: usize,
) -> Result<(), RelationPlanError> {
    while terms.len() <= limb {
        terms.push(Vec::new());
    }
    while intervals.len() <= limb {
        intervals.push(SignedIntegerInterval::new(0, 0));
    }
    Ok(())
}

fn ensure_exact_product_limb(
    products: &mut Vec<Vec<RelationIntegerLiftFullRingNegacyclicProductDescriptor>>,
    intervals: &mut Vec<SignedIntegerInterval>,
    limb: usize,
) -> Result<(), RelationPlanError> {
    while products.len() <= limb {
        products.push(Vec::new());
    }
    while intervals.len() <= limb {
        intervals.push(SignedIntegerInterval::new(0, 0));
    }
    Ok(())
}

fn maximum_absolute_product(
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

fn interval_maximum_absolute(interval: &SignedIntegerInterval) -> BigUint {
    interval
        .minimum
        .magnitude()
        .max(interval.maximum.magnitude())
        .clone()
}

fn divide_ceil(value: &BigUint, divisor: u64) -> BigUint {
    if value.is_zero() {
        return BigUint::zero();
    }
    (value + BigUint::from(divisor - 1)) / BigUint::from(divisor)
}

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(in crate::bgv::proof_suite::relation_plan) fn ensure_reversed_vector_bindings(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        source: SplitIntegerVector,
        reversed: SplitIntegerVector,
    ) -> Result<(), RelationPlanError> {
        for half_ordinal in 0..2 {
            let source_column_ordinal = source.halves[half_ordinal];
            let reversed_column_ordinal = reversed.halves[half_ordinal];
            let binding_key = (source_column_ordinal, reversed_column_ordinal);
            let already_present = self
                .pending_integer_lift_batches
                .get(&batch_key)
                .is_some_and(|batch| batch.reversed_bindings.contains_key(&binding_key));
            if already_present {
                continue;
            }
            let binding = RelationIntegerLiftReversedColumnBindingDescriptor {
                source_column_ordinal,
                reversed_column_ordinal,
                source_prefix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                reversed_suffix_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            };
            if self
                .pending_integer_lift_batches
                .entry(batch_key)
                .or_default()
                .reversed_bindings
                .insert(binding_key, binding)
                .is_some()
            {
                return Err(RelationPlanError::DuplicateItem);
            }
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn full_ring_product(
        &mut self,
        _batch_key: (SuiteModulusReference, u16),
        selected_half: RelationIntegerLiftFullRingHalf,
        negative: bool,
        multiplicand: SplitIntegerVector,
        multiplier: &ReversibleShiftedSmallVector,
    ) -> Result<PendingFullRingNegacyclicProduct, RelationPlanError> {
        Ok(PendingFullRingNegacyclicProduct {
            negative,
            selected_half,
            multiplicand,
            multiplier: multiplier.clone(),
        })
    }

    fn materialize_full_ring_product(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        pending: &PendingFullRingNegacyclicProduct,
        multiplicand: SplitIntegerVector,
        multiplier: &ReversibleShiftedSmallVector,
    ) -> Result<RelationIntegerLiftFullRingNegacyclicProductDescriptor, RelationPlanError> {
        let reversed = self.reversed_vector(multiplier.source.coefficients)?;
        self.ensure_reversed_vector_bindings(batch_key, multiplier.source.coefficients, reversed)?;
        Ok(RelationIntegerLiftFullRingNegacyclicProductDescriptor {
            negative: pending.negative,
            selected_half: pending.selected_half,
            multiplicand_low_column_ordinal: multiplicand.halves[0],
            multiplicand_high_column_ordinal: multiplicand.halves[1],
            multiplier_low_column_ordinal: multiplier.source.coefficients.halves[0],
            multiplier_high_column_ordinal: multiplier.source.coefficients.halves[1],
            reversed_multiplier_low_column_ordinal: reversed.halves[0],
            reversed_multiplier_high_column_ordinal: reversed.halves[1],
            multiplier_low_offset: multiplier.source.offset,
            multiplier_high_offset: multiplier.source.offset,
            multiplicand_low_suffix_evaluation_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            multiplicand_high_suffix_evaluation_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            reversed_multiplier_low_transpose_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            reversed_multiplier_high_transpose_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
        })
    }

    fn reversed_vector(
        &mut self,
        source: SplitIntegerVector,
    ) -> Result<SplitIntegerVector, RelationPlanError> {
        if let Some(reversed) = self.reversed_columns_by_source_halves.get(&source.halves) {
            return Ok(*reversed);
        }
        let reversed = SplitIntegerVector {
            halves: [
                self.push_prover_column(ProofTreePhase::Base)?,
                self.push_prover_column(ProofTreePhase::Base)?,
            ],
        };
        self.reversed_columns_by_source_halves
            .insert(source.halves, reversed);
        Ok(reversed)
    }

    fn exact_column_interval(
        &self,
        column_ordinal: u32,
    ) -> Result<SignedIntegerInterval, RelationPlanError> {
        if let Some((interval, _)) = self.semantic_cells_by_column.get(&column_ordinal) {
            return Ok(interval.clone());
        }
        let column = self
            .ordered_columns
            .get(column_ordinal as usize)
            .ok_or(RelationPlanError::InvalidColumn)?;
        if let RelationColumnOrigin::VerifierSequence {
            verifier_source_ordinal,
            ..
        } = &column.origin
        {
            let verifier_source = self
                .ordered_verifier_sources
                .get(
                    usize::try_from(*verifier_source_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::InvalidSource)?;
            if let RelationVerifierSource::RadixDecomposition { radix, .. } = verifier_source {
                if column.canonical_residue_modulus.is_some() || *radix < 2 {
                    return Err(RelationPlanError::InvalidSemanticCell);
                }
                return SignedIntegerInterval::from_bigints(
                    BigInt::zero(),
                    BigInt::from(*radix - 1),
                );
            }
        }
        let modulus_reference = column
            .canonical_residue_modulus
            .ok_or(RelationPlanError::InvalidSemanticCell)?;
        let modulus = self.modulus(modulus_reference)?;
        SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(modulus - 1))
    }

    fn exact_coefficient_digits(
        &self,
        coefficient: RelationIntegerLiftCoefficient,
    ) -> Result<Vec<u64>, RelationPlanError> {
        let value = match coefficient {
            RelationIntegerLiftCoefficient::Constant(value) => u128::from(value),
            RelationIntegerLiftCoefficient::Modulus {
                modulus_reference,
                multiplier,
            } => u128::from(self.modulus(modulus_reference)?)
                .checked_mul(u128::from(multiplier))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?,
            RelationIntegerLiftCoefficient::ModulusRadixDigit { .. } => {
                return Err(RelationPlanError::InvalidConstraint);
            }
        };
        exact_radix_digits(value)
    }

    fn expand_exact_linear_term(
        &self,
        term: &RelationIntegerLiftLinearTermDescriptor,
        ordered_terms_by_limb: &mut Vec<Vec<RelationIntegerLiftLinearTermDescriptor>>,
        intervals_by_limb: &mut Vec<SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        let coefficient_digits = self.exact_coefficient_digits(term.coefficient)?;
        let value_digits = self
            .exact_radix_digits_by_column
            .get(&term.column_ordinal)
            .cloned();
        let value_is_digitized = value_digits.is_some();
        if value_digits.is_some() && term.column_offset != 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let source_columns = value_digits.unwrap_or_else(|| vec![term.column_ordinal]);
        for (value_limb, source_column) in source_columns.into_iter().enumerate() {
            let source_interval = self.exact_column_interval(source_column)?;
            for (coefficient_limb, coefficient_digit) in
                coefficient_digits.iter().copied().enumerate()
            {
                if coefficient_digit == 0 {
                    continue;
                }
                let limb = value_limb
                    .checked_add(coefficient_limb)
                    .ok_or(RelationPlanError::CountOverflow)?;
                ensure_exact_limb(ordered_terms_by_limb, intervals_by_limb, limb)?;
                let expanded_coefficient = match term.coefficient {
                    RelationIntegerLiftCoefficient::Constant(_) => {
                        RelationIntegerLiftCoefficient::Constant(coefficient_digit)
                    }
                    RelationIntegerLiftCoefficient::Modulus {
                        modulus_reference,
                        multiplier,
                    } => RelationIntegerLiftCoefficient::ModulusRadixDigit {
                        modulus_reference,
                        multiplier,
                        radix: EXACT_INTEGER_LIFT_RADIX,
                        digit_ordinal: u16::try_from(coefficient_limb)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                    RelationIntegerLiftCoefficient::ModulusRadixDigit { .. } => {
                        return Err(RelationPlanError::InvalidConstraint);
                    }
                };
                let expanded = RelationIntegerLiftLinearTermDescriptor {
                    negative: term.negative,
                    column_ordinal: source_column,
                    column_offset: if value_limb == 0 && !value_is_digitized {
                        term.column_offset
                    } else {
                        0
                    },
                    coefficient: expanded_coefficient,
                };
                let shifted_interval = SignedIntegerInterval::from_bigints(
                    source_interval.minimum.clone() - BigInt::from(expanded.column_offset),
                    source_interval.maximum.clone() - BigInt::from(expanded.column_offset),
                )?;
                let coefficient_interval = SignedIntegerInterval::from_bigints(
                    BigInt::from(coefficient_digit),
                    BigInt::from(coefficient_digit),
                )?;
                let mut contribution = shifted_interval.multiply(coefficient_interval)?;
                if expanded.negative {
                    contribution = contribution.negate()?;
                }
                intervals_by_limb[limb] = intervals_by_limb[limb].clone().add(contribution)?;
                ordered_terms_by_limb[limb].push(expanded);
            }
        }
        Ok(())
    }

    fn expand_exact_full_ring_product(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        pending: &PendingFullRingNegacyclicProduct,
        ordered_products_by_limb: &mut Vec<
            Vec<RelationIntegerLiftFullRingNegacyclicProductDescriptor>,
        >,
        intervals_by_limb: &mut Vec<SignedIntegerInterval>,
    ) -> Result<(), RelationPlanError> {
        let multiplicand_digits =
            split_exact_radix_digits(&self.exact_radix_digits_by_column, pending.multiplicand)?;
        let multiplier_digits = split_exact_radix_digits(
            &self.exact_radix_digits_by_column,
            pending.multiplier.source.coefficients,
        )?;
        match (multiplicand_digits, multiplier_digits) {
            (Some(_), Some(_)) => Err(RelationPlanError::NoWrapBoundViolated),
            (Some(digits), None) => {
                for (limb, digit) in digits.into_iter().enumerate() {
                    ensure_exact_product_limb(ordered_products_by_limb, intervals_by_limb, limb)?;
                    let descriptor = self.materialize_full_ring_product(
                        batch_key,
                        pending,
                        digit,
                        &pending.multiplier,
                    )?;
                    let interval = self.full_ring_product_interval(&descriptor)?;
                    intervals_by_limb[limb] = intervals_by_limb[limb].clone().add(interval)?;
                    ordered_products_by_limb[limb].push(descriptor);
                }
                Ok(())
            }
            (None, Some(digits)) => {
                let offset_digits = fixed_exact_radix_digits(
                    u128::from(pending.multiplier.source.offset),
                    digits.len(),
                )?;
                for (limb, digit) in digits.into_iter().enumerate() {
                    ensure_exact_product_limb(ordered_products_by_limb, intervals_by_limb, limb)?;
                    let digit_multiplier = ReversibleShiftedSmallVector {
                        source: ShiftedSmallVector {
                            coefficients: digit,
                            offset: offset_digits[limb],
                        },
                    };
                    let descriptor = self.materialize_full_ring_product(
                        batch_key,
                        pending,
                        pending.multiplicand,
                        &digit_multiplier,
                    )?;
                    let interval = self.full_ring_product_interval(&descriptor)?;
                    intervals_by_limb[limb] = intervals_by_limb[limb].clone().add(interval)?;
                    ordered_products_by_limb[limb].push(descriptor);
                }
                Ok(())
            }
            (None, None) => {
                ensure_exact_product_limb(ordered_products_by_limb, intervals_by_limb, 0)?;
                let descriptor = self.materialize_full_ring_product(
                    batch_key,
                    pending,
                    pending.multiplicand,
                    &pending.multiplier,
                )?;
                let interval = self.full_ring_product_interval(&descriptor)?;
                intervals_by_limb[0] = intervals_by_limb[0].clone().add(interval)?;
                ordered_products_by_limb[0].push(descriptor);
                Ok(())
            }
        }
    }

    fn full_ring_product_interval(
        &self,
        product: &RelationIntegerLiftFullRingNegacyclicProductDescriptor,
    ) -> Result<SignedIntegerInterval, RelationPlanError> {
        let multiplicand_low =
            self.exact_column_interval(product.multiplicand_low_column_ordinal)?;
        let multiplicand_high =
            self.exact_column_interval(product.multiplicand_high_column_ordinal)?;
        let multiplier_low = self.exact_column_interval(product.multiplier_low_column_ordinal)?;
        let multiplier_high = self.exact_column_interval(product.multiplier_high_column_ordinal)?;
        let shifted_low = SignedIntegerInterval::from_bigints(
            multiplier_low.minimum - BigInt::from(product.multiplier_low_offset),
            multiplier_low.maximum - BigInt::from(product.multiplier_low_offset),
        )?;
        let shifted_high = SignedIntegerInterval::from_bigints(
            multiplier_high.minimum - BigInt::from(product.multiplier_high_offset),
            multiplier_high.maximum - BigInt::from(product.multiplier_high_offset),
        )?;
        let low_low = maximum_absolute_product(&multiplicand_low, &shifted_low)?;
        let high_low = maximum_absolute_product(&multiplicand_high, &shifted_low)?;
        let low_high = maximum_absolute_product(&multiplicand_low, &shifted_high)?;
        let high_high = maximum_absolute_product(&multiplicand_high, &shifted_high)?;
        let bound = BigInt::from((low_low + high_high).max(high_low + low_high))
            * BigInt::from(self.geometry.trace_domain_size()?);
        SignedIntegerInterval::from_bigints(-bound.clone(), bound)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_integer_lift_component(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        quotient_column_ordinal: u32,
        mut ordered_linear_terms: Vec<RelationIntegerLiftLinearTermDescriptor>,
        ordered_full_ring_negacyclic_products: Vec<PendingFullRingNegacyclicProduct>,
    ) -> Result<Vec<u32>, RelationPlanError> {
        ordered_linear_terms.push(RelationIntegerLiftLinearTermDescriptor {
            negative: true,
            column_ordinal: quotient_column_ordinal,
            column_offset: 0,
            coefficient: RelationIntegerLiftCoefficient::Modulus {
                modulus_reference: batch_key.0,
                multiplier: 1,
            },
        });
        let exact_carry_component_key = (
            batch_key.0,
            ordered_linear_terms.clone(),
            ordered_full_ring_negacyclic_products.clone(),
        );
        let existing_carry_columns = self
            .exact_carry_columns_by_component
            .get(&exact_carry_component_key)
            .cloned();
        let mut expanded_linear_terms = Vec::new();
        let mut expanded_products = Vec::new();
        let mut intervals = Vec::new();
        for term in &ordered_linear_terms {
            self.expand_exact_linear_term(term, &mut expanded_linear_terms, &mut intervals)?;
        }
        for product in &ordered_full_ring_negacyclic_products {
            self.expand_exact_full_ring_product(
                batch_key,
                product,
                &mut expanded_products,
                &mut intervals,
            )?;
        }
        while expanded_linear_terms.len() < intervals.len() {
            expanded_linear_terms.push(Vec::new());
        }
        while expanded_products.len() < intervals.len() {
            expanded_products.push(Vec::new());
        }
        if intervals.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let required_carry_count = intervals.len().saturating_sub(1);
        if existing_carry_columns
            .as_ref()
            .is_some_and(|columns| columns.len() != required_carry_count)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut newly_allocated_carry_columns = Vec::with_capacity(required_carry_count);
        for limb in 0..intervals.len().saturating_sub(1) {
            let maximum_absolute = interval_maximum_absolute(&intervals[limb]);
            let carry_bound = divide_ceil(&maximum_absolute, EXACT_INTEGER_LIFT_RADIX);
            let carry_column = if let Some(existing_columns) = &existing_carry_columns {
                existing_columns[limb]
            } else {
                let column = self.add_centered_integer_column(&carry_bound)?;
                newly_allocated_carry_columns.push(column);
                column
            };
            let carry_interval = self.exact_column_interval(carry_column)?;
            let outgoing = RelationIntegerLiftLinearTermDescriptor {
                negative: true,
                column_ordinal: carry_column,
                column_offset: 0,
                coefficient: RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX),
            };
            let incoming = RelationIntegerLiftLinearTermDescriptor {
                negative: false,
                column_ordinal: carry_column,
                column_offset: 0,
                coefficient: RelationIntegerLiftCoefficient::Constant(1),
            };
            expanded_linear_terms[limb].push(outgoing);
            expanded_linear_terms[limb + 1].push(incoming);
            let scaled_carry =
                carry_interval
                    .clone()
                    .multiply(SignedIntegerInterval::from_bigints(
                        BigInt::from(EXACT_INTEGER_LIFT_RADIX),
                        BigInt::from(EXACT_INTEGER_LIFT_RADIX),
                    )?)?;
            intervals[limb] = intervals[limb].clone().add(scaled_carry.negate()?)?;
            intervals[limb + 1] = intervals[limb + 1].clone().add(carry_interval)?;
        }
        if existing_carry_columns.is_none()
            && self
                .exact_carry_columns_by_component
                .insert(
                    exact_carry_component_key,
                    newly_allocated_carry_columns.clone(),
                )
                .is_some()
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        let exact_carry_columns = existing_carry_columns.unwrap_or(newly_allocated_carry_columns);
        let mut components = Vec::with_capacity(intervals.len());
        for limb in 0..intervals.len() {
            sort_canonical_items(&mut expanded_linear_terms[limb], |term| {
                term.canonical_bytes()
            })?;
            sort_canonical_items(&mut expanded_products[limb], |product| {
                product.canonical_bytes()
            })?;
            components.push(RelationIntegerLiftComponentDescriptor {
                ordered_linear_terms: std::mem::take(&mut expanded_linear_terms[limb]),
                ordered_convolution_products: Vec::new(),
                ordered_full_ring_negacyclic_products: std::mem::take(&mut expanded_products[limb]),
                linear_evaluation_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                product_accumulator_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            });
        }
        self.pending_integer_lift_batches
            .entry(batch_key)
            .or_default()
            .components
            .extend(components);
        Ok(exact_carry_columns)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_relinearization_round_one_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        round_one_left: &SplitIntegerVector,
        round_one_right: &SplitIntegerVector,
        common_reference: SplitIntegerVector,
        secret: &ReversibleShiftedSmallVector,
        ephemeral_secret: &ReversibleShiftedSmallVector,
        round_one_left_error: &ShiftedSmallVector,
        round_one_right_error: &ShiftedSmallVector,
        gadget_coefficient: u64,
        left_quotient: TrusteeRadixThreeQuotientWitness,
        right_quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        if secret.source.offset != 0
            || ephemeral_secret.source.offset != 0
            || round_one_left_error.offset != 0
            || round_one_right_error.offset != 0
            || gadget_coefficient >= modulus
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut left_linear_terms = vec![
                constant_linear_term(round_one_left.halves[half_ordinal], 0, false),
                plaintext_scaled_linear_term(
                    round_one_left_error.coefficients.halves[half_ordinal],
                    true,
                ),
                trustee_quotient_carry_linear_term(
                    left_quotient.high_carries[half_ordinal],
                    modulus_reference,
                ),
            ];
            if gadget_coefficient != 0 {
                left_linear_terms.push(scaled_constant_linear_term(
                    secret.source.coefficients.halves[half_ordinal],
                    true,
                    gadget_coefficient,
                ));
            }
            let common_reference_times_ephemeral = self.full_ring_product(
                batch_key,
                selected_half,
                false,
                common_reference,
                ephemeral_secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                left_quotient.low_quotients[half_ordinal],
                left_linear_terms,
                vec![common_reference_times_ephemeral],
            )?;

            let common_reference_times_secret =
                self.full_ring_product(batch_key, selected_half, true, common_reference, secret)?;
            self.add_integer_lift_component(
                batch_key,
                right_quotient.low_quotients[half_ordinal],
                vec![
                    constant_linear_term(round_one_right.halves[half_ordinal], 0, false),
                    plaintext_scaled_linear_term(
                        round_one_right_error.coefficients.halves[half_ordinal],
                        true,
                    ),
                    trustee_quotient_carry_linear_term(
                        right_quotient.high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                vec![common_reference_times_secret],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_relinearization_round_two_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        round_two: &SplitIntegerVector,
        aggregate_round_one_left: &ReversibleShiftedSmallVector,
        aggregate_round_one_right: &ReversibleShiftedSmallVector,
        secret: &ReversibleShiftedSmallVector,
        ephemeral_secret: &ReversibleShiftedSmallVector,
        round_two_error: &ShiftedSmallVector,
        quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        let centered_offset = (modulus - 1) / 2;
        if secret.source.offset != 0
            || ephemeral_secret.source.offset != 0
            || round_two_error.offset != 0
            || aggregate_round_one_left.source.offset != centered_offset
            || aggregate_round_one_right.source.offset != centered_offset
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let secret_times_aggregate_left = self.full_ring_product(
                batch_key,
                selected_half,
                true,
                secret.source.coefficients,
                aggregate_round_one_left,
            )?;
            let ephemeral_times_aggregate_right = self.full_ring_product(
                batch_key,
                selected_half,
                true,
                ephemeral_secret.source.coefficients,
                aggregate_round_one_right,
            )?;
            let secret_times_aggregate_right = self.full_ring_product(
                batch_key,
                selected_half,
                false,
                secret.source.coefficients,
                aggregate_round_one_right,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient.low_quotients[half_ordinal],
                vec![
                    constant_linear_term(round_two.halves[half_ordinal], 0, false),
                    plaintext_scaled_linear_term(
                        round_two_error.coefficients.halves[half_ordinal],
                        true,
                    ),
                    trustee_quotient_carry_linear_term(
                        quotient.high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                vec![
                    secret_times_aggregate_left,
                    ephemeral_times_aggregate_right,
                    secret_times_aggregate_right,
                ],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_trustee_anchor_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        commitments: &[SplitIntegerVector],
        first_matrix: &[Vec<ReversibleShiftedSmallVector>],
        second_matrix: &[ReversibleShiftedSmallVector],
        opening: &TrusteeAnchorOpeningWitness,
        secret: &ShiftedSmallVector,
        quotients: &[TrusteeRadixThreeQuotientWitness],
    ) -> Result<(), RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let centered_offset = (self.modulus(modulus_reference)? - 1) / 2;
        if commitments.len() != rank + 1
            || first_matrix.len() != rank
            || first_matrix.iter().any(|row| row.len() != rank + 1)
            || second_matrix.len() != rank
            || opening.hiding_secrets.len() != rank + 1
            || opening.hiding_errors.len() != rank
            || quotients.len() != rank + 1
            || secret.offset != 0
            || first_matrix
                .iter()
                .flatten()
                .chain(second_matrix)
                .any(|matrix| matrix.source.offset != centered_offset)
            || opening.hiding_errors.iter().any(|value| value.offset != 0)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for row_ordinal in 0..rank {
            for half_ordinal in 0..2 {
                let selected_half = integer_lift_half(half_ordinal)?;
                let mut products = Vec::with_capacity(rank + 1);
                for column_ordinal in 0..=rank {
                    products.push(self.full_ring_product(
                        batch_key,
                        selected_half,
                        true,
                        opening.hiding_secrets[column_ordinal],
                        &first_matrix[row_ordinal][column_ordinal],
                    )?);
                }
                self.add_integer_lift_component(
                    batch_key,
                    quotients[row_ordinal].low_quotients[half_ordinal],
                    vec![
                        constant_linear_term(
                            commitments[row_ordinal].halves[half_ordinal],
                            0,
                            false,
                        ),
                        constant_linear_term(
                            opening.hiding_errors[row_ordinal].coefficients.halves[half_ordinal],
                            0,
                            true,
                        ),
                        trustee_quotient_carry_linear_term(
                            quotients[row_ordinal].high_carries[half_ordinal],
                            modulus_reference,
                        ),
                    ],
                    products,
                )?;
            }
        }

        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut products = Vec::with_capacity(rank);
            for (hiding_secret, second_matrix_column) in
                opening.hiding_secrets.iter().copied().zip(second_matrix)
            {
                products.push(self.full_ring_product(
                    batch_key,
                    selected_half,
                    true,
                    hiding_secret,
                    second_matrix_column,
                )?);
            }
            self.add_integer_lift_component(
                batch_key,
                quotients[rank].low_quotients[half_ordinal],
                vec![
                    constant_linear_term(commitments[rank].halves[half_ordinal], 0, false),
                    constant_linear_term(
                        opening.hiding_secrets[rank].halves[half_ordinal],
                        0,
                        true,
                    ),
                    constant_linear_term(secret.coefficients.halves[half_ordinal], 0, true),
                    trustee_quotient_carry_linear_term(
                        quotients[rank].high_carries[half_ordinal],
                        modulus_reference,
                    ),
                ],
                products,
            )?;
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_anchor_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        inputs: AnchorEquationInputs<'_>,
    ) -> Result<(), RelationPlanError> {
        let AnchorEquationInputs {
            commitments,
            first_matrix,
            second_matrix,
            opening,
            secret,
            quotients,
        } = inputs;
        let rank = usize::from(self.geometry.commitment_module_rank);
        if commitments.len() != rank + 1
            || first_matrix.len() != rank
            || first_matrix.iter().any(|row| row.len() != rank + 1)
            || second_matrix.len() != rank
            || opening.hiding_secrets.len() != rank + 1
            || opening.hiding_errors.len() != rank
            || quotients.rows.len() != rank + 1
            || secret.offset != 1
            || opening
                .hiding_secrets
                .iter()
                .any(|value| value.source.offset != 1)
            || opening.hiding_errors.iter().any(|value| value.offset != 1)
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for row_ordinal in 0..rank {
            for half_ordinal in 0..2 {
                let selected_half = integer_lift_half(half_ordinal)?;
                let mut products = Vec::with_capacity(rank + 1);
                for column_ordinal in 0..=rank {
                    products.push(self.full_ring_product(
                        batch_key,
                        selected_half,
                        true,
                        first_matrix[row_ordinal][column_ordinal],
                        &opening.hiding_secrets[column_ordinal],
                    )?);
                }
                self.add_integer_lift_component(
                    batch_key,
                    quotients.rows[row_ordinal][half_ordinal],
                    vec![
                        constant_linear_term(
                            commitments[row_ordinal].halves[half_ordinal],
                            0,
                            false,
                        ),
                        constant_linear_term(
                            opening.hiding_errors[row_ordinal].coefficients.halves[half_ordinal],
                            opening.hiding_errors[row_ordinal].offset,
                            true,
                        ),
                    ],
                    products,
                )?;
            }
        }

        for half_ordinal in 0..2 {
            let selected_half = integer_lift_half(half_ordinal)?;
            let mut products = Vec::with_capacity(rank);
            for (second_matrix_column, hiding_secret) in
                second_matrix.iter().copied().zip(&opening.hiding_secrets)
            {
                products.push(self.full_ring_product(
                    batch_key,
                    selected_half,
                    true,
                    second_matrix_column,
                    hiding_secret,
                )?);
            }
            self.add_integer_lift_component(
                batch_key,
                quotients.rows[rank][half_ordinal],
                vec![
                    constant_linear_term(commitments[rank].halves[half_ordinal], 0, false),
                    constant_linear_term(
                        opening.hiding_secrets[rank].source.coefficients.halves[half_ordinal],
                        opening.hiding_secrets[rank].source.offset,
                        true,
                    ),
                    constant_linear_term(
                        secret.coefficients.halves[half_ordinal],
                        secret.offset,
                        true,
                    ),
                ],
                products,
            )?;
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_public_key_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        inputs: PublicKeyEquationInputs<'_>,
    ) -> Result<(), RelationPlanError> {
        let PublicKeyEquationInputs {
            public_key_share,
            common_reference,
            secret,
            error,
            quotient_columns,
        } = inputs;
        if secret.source.offset != 1 || error.offset != 2 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for (half_ordinal, quotient_column) in quotient_columns.into_iter().enumerate() {
            let product = self.full_ring_product(
                batch_key,
                integer_lift_half(half_ordinal)?,
                false,
                *common_reference,
                secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient_column,
                vec![
                    constant_linear_term(public_key_share.halves[half_ordinal], 0, false),
                    RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: error.coefficients.halves[half_ordinal],
                        column_offset: error.offset,
                        coefficient: RelationIntegerLiftCoefficient::Modulus {
                            modulus_reference: SuiteModulusReference::plaintext(),
                            multiplier: 1,
                        },
                    },
                ],
                vec![product],
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::bgv::proof_suite::relation_plan) fn add_galois_key_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        galois_key_share: &SplitIntegerVector,
        common_reference: SplitIntegerVector,
        secret: &ReversibleShiftedSmallVector,
        automorphed_secret: &ShiftedSmallVector,
        error: &ShiftedSmallVector,
        gadget_coefficient: u64,
        quotient: TrusteeRadixThreeQuotientWitness,
    ) -> Result<(), RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        if secret.source.offset != 0
            || automorphed_secret.offset != 0
            || error.offset != 0
            || gadget_coefficient >= modulus
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let mut linear_terms = vec![
                constant_linear_term(galois_key_share.halves[half_ordinal], 0, false),
                plaintext_scaled_linear_term(error.coefficients.halves[half_ordinal], true),
                trustee_quotient_carry_linear_term(
                    quotient.high_carries[half_ordinal],
                    modulus_reference,
                ),
            ];
            if gadget_coefficient != 0 {
                linear_terms.push(scaled_constant_linear_term(
                    automorphed_secret.coefficients.halves[half_ordinal],
                    true,
                    gadget_coefficient,
                ));
            }
            let common_reference_times_secret = self.full_ring_product(
                batch_key,
                integer_lift_half(half_ordinal)?,
                false,
                common_reference,
                secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient.low_quotients[half_ordinal],
                linear_terms,
                vec![common_reference_times_secret],
            )?;
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn finalize_integer_lift_batches(
        &mut self,
    ) -> Result<(), RelationPlanError> {
        let pending = std::mem::take(&mut self.pending_integer_lift_batches);
        let mut batches = Vec::with_capacity(pending.len());
        for ((modulus_reference, challenge_ordinal), pending_batch) in pending {
            let mut ordered_reversed_column_bindings = pending_batch
                .reversed_bindings
                .into_values()
                .collect::<Vec<_>>();
            sort_canonical_items(&mut ordered_reversed_column_bindings, |binding| {
                binding.canonical_bytes()
            })?;
            let mut ordered_negacyclic_automorphism_permutations =
                pending_batch.negacyclic_automorphism_permutations;
            ordered_negacyclic_automorphism_permutations
                .sort_unstable_by_key(|permutation| permutation.galois_element);
            if ordered_negacyclic_automorphism_permutations
                .windows(2)
                .any(|pair| pair[0].galois_element == pair[1].galois_element)
            {
                return Err(RelationPlanError::DuplicateItem);
            }
            let mut ordered_components = pending_batch.components;
            sort_canonical_items(&mut ordered_components, |component| {
                component.canonical_bytes()
            })?;
            let batch = RelationIntegerLiftBatchDescriptor {
                modulus_reference,
                challenge_ordinal,
                ordered_reversed_column_bindings,
                ordered_negacyclic_automorphism_permutations,
                ordered_components,
            };
            let modulus_ordinal = self.modulus_ordinal(modulus_reference)?;
            for program in batch.constraint_programs(
                modulus_ordinal,
                self.geometry.trace_domain_size()?,
                self.geometry.evaluation_domain_size,
                self.context,
            )? {
                self.add_constraint(
                    program.numerator_postfix_expression,
                    program.zeroifier_postfix_expression,
                    false,
                )?;
            }
            batches.push(batch);
        }
        sort_canonical_items(&mut batches, |batch| batch.canonical_bytes())?;
        self.ordered_integer_lift_batches = batches;
        Ok(())
    }
}
