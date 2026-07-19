use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use super::super::{
    bounds::{RelationBoundCertificate, SignedIntegerInterval},
    expressions::{
        RelationExpressionInstruction, radix_recomposition_expression, strictly_sorted_unique,
        unrotated_column_expression,
    },
    integer_lift::RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor,
    model::{
        BoundTreeConstructionKind, BoundTreeRootUse, RelationColumnOrigin, RelationPlanError,
        RelationTreeDescriptor, SuiteModulusReference,
    },
};
use super::{
    AnchorOpeningWitness, AnchorQuotientWitness, BoundPolynomialRootUse, BoundedUnsignedColumn,
    KeyRelationPlanBuilder, KeyVerifierSourceKey, MATERIAL_DIGIT_RADIX, MATERIAL_DIGIT_TRIT_COUNT,
    MODULAR_QUOTIENT_BIT_COUNT, ProofTreePhase, RecenteredVerifierVectorWitness,
    ReversibleShiftedSmallVector, ShiftedSmallVector, SplitIntegerVector, TRIT_RADIX,
    TRUSTEE_QUOTIENT_LOW_TRIT_COUNT, TargetBoundedUnsignedVector, TargetCenteredVector,
    TargetCommittedMaterialVector, TrusteeAnchorOpeningWitness, TrusteeRadixThreeQuotientWitness,
    column_builder::{fixed_radix_digits, minimum_unsigned_radix_digit_count},
};

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(in crate::bgv::proof_suite::relation_plan) fn add_split_verifier_vector(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<SplitIntegerVector, RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let trace_domain_size = self.geometry.trace_domain_size()?;
        let mut halves = Vec::with_capacity(2);
        for half_ordinal in 0..2_u64 {
            halves.push(
                self.push_column(
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal: source_ordinal,
                        first_logical_element_index: half_ordinal
                            .checked_mul(trace_domain_size)
                            .ok_or(RelationPlanError::CountOverflow)?,
                        logical_element_stride: 1,
                    },
                    self.geometry
                        .public_polynomial_column_degree_bound_exclusive,
                    Some(modulus_reference),
                    Some(ProofTreePhase::Base),
                )?,
            );
        }
        let vector = SplitIntegerVector {
            halves: halves
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        };
        for half in vector.halves {
            self.register_exact_radix_decomposition(half, modulus_reference, None)?;
        }
        Ok(vector)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_split_verifier_base_vector(
        &mut self,
        source_key: &KeyVerifierSourceKey,
    ) -> Result<SplitIntegerVector, RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let trace_domain_size = self.geometry.trace_domain_size()?;
        let mut halves = Vec::with_capacity(2);
        for half_ordinal in 0..2_u64 {
            halves.push(
                self.push_column(
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal: source_ordinal,
                        first_logical_element_index: half_ordinal
                            .checked_mul(trace_domain_size)
                            .ok_or(RelationPlanError::CountOverflow)?,
                        logical_element_stride: 1,
                    },
                    self.geometry
                        .public_polynomial_column_degree_bound_exclusive,
                    None,
                    Some(ProofTreePhase::Base),
                )?,
            );
        }
        Ok(SplitIntegerVector {
            halves: halves
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_negacyclic_automorphism_permutation(
        &mut self,
        mapping_source_key: &KeyVerifierSourceKey,
        galois_element: u64,
        source: &ReversibleShiftedSmallVector,
        target: &ShiftedSmallVector,
    ) -> Result<(), RelationPlanError> {
        if source.source.offset != 0
            || target.offset != 0
            || source.source.coefficients.halves[0] == source.source.coefficients.halves[1]
            || target.coefficients.halves[0] == target.coefficients.halves[1]
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mapping_source_ordinal = self.source_ordinal(mapping_source_key)?;
        let trace_domain_size = self.geometry.trace_domain_size()?;
        let mut mapping_columns = Vec::with_capacity(6);
        for sequence_ordinal in 0..6_u64 {
            mapping_columns.push(
                self.push_column(
                    RelationColumnOrigin::VerifierSequence {
                        verifier_source_ordinal: mapping_source_ordinal,
                        first_logical_element_index: sequence_ordinal
                            .checked_mul(trace_domain_size)
                            .ok_or(RelationPlanError::CountOverflow)?,
                        logical_element_stride: 1,
                    },
                    trace_domain_size,
                    None,
                    Some(ProofTreePhase::Base),
                )?,
            );
        }
        let mapping_columns: [u32; 6] = mapping_columns
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let challenge_modulus_reference = self
            .ordered_non_native_moduli
            .first()
            .copied()
            .ok_or(RelationPlanError::MissingModulus)?;
        if challenge_modulus_reference != SuiteModulusReference::data(0) {
            return Err(RelationPlanError::NonCanonicalOrder);
        }
        for challenge_ordinal in 0..self.context.non_native_modular_identity_challenge_count {
            let descriptor = RelationIntegerLiftNegacyclicAutomorphismPermutationDescriptor {
                galois_element,
                mapping_verifier_source_ordinal: mapping_source_ordinal,
                source_low_column_ordinal: source.source.coefficients.halves[0],
                source_high_column_ordinal: source.source.coefficients.halves[1],
                target_low_column_ordinal: target.coefficients.halves[0],
                target_high_column_ordinal: target.coefficients.halves[1],
                mapped_low_position_column_ordinal: mapping_columns[0],
                low_negation_bit_column_ordinal: mapping_columns[1],
                mapped_high_position_column_ordinal: mapping_columns[2],
                high_negation_bit_column_ordinal: mapping_columns[3],
                target_low_position_column_ordinal: mapping_columns[4],
                target_high_position_column_ordinal: mapping_columns[5],
                source_product_before_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                source_low_product_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                target_product_before_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
                target_low_product_column_ordinal: self
                    .push_prover_column(ProofTreePhase::Auxiliary)?,
            };
            self.pending_integer_lift_batches
                .entry((challenge_modulus_reference, challenge_ordinal))
                .or_default()
                .negacyclic_automorphism_permutations
                .push(descriptor);
        }
        Ok(())
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_setup_polynomial_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
        logical_row_count: usize,
        root_use: BoundPolynomialRootUse,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if logical_row_count == 0 {
            return Err(RelationPlanError::InvalidRoot);
        }
        let source_ordinal = self.source_ordinal(source_key)?;
        let mut tree_columns = Vec::with_capacity(
            logical_row_count
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        let mut rows = Vec::with_capacity(logical_row_count);
        for _ in 0..logical_row_count {
            let low = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                None,
            )?;
            let high = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                None,
            )?;
            let halves = [low, high];
            for half in halves {
                self.register_exact_radix_decomposition(half, modulus_reference, None)?;
            }
            tree_columns.extend(halves);
            rows.push(SplitIntegerVector { halves });
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal: source_ordinal,
            root_use: match root_use {
                BoundPolynomialRootUse::Input => BoundTreeRootUse::Input,
                BoundPolynomialRootUse::Output => BoundTreeRootUse::Output,
            },
            ordered_column_ordinals: tree_columns,
        });
        Ok(rows)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_setup_polynomial_limb_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        ordered_modulus_references: &[SuiteModulusReference],
        root_use: BoundPolynomialRootUse,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if ordered_modulus_references.is_empty()
            || !strictly_sorted_unique(ordered_modulus_references)
        {
            return Err(RelationPlanError::InvalidRoot);
        }
        let source_ordinal = self.source_ordinal(source_key)?;
        let mut tree_columns = Vec::with_capacity(
            ordered_modulus_references
                .len()
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        let mut limbs = Vec::with_capacity(ordered_modulus_references.len());
        for modulus_reference in ordered_modulus_references {
            let vector = self.add_bound_setup_polynomial_vector(
                source_ordinal,
                *modulus_reference,
                &mut tree_columns,
            )?;
            limbs.push(vector);
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal: source_ordinal,
            root_use: match root_use {
                BoundPolynomialRootUse::Input => BoundTreeRootUse::Input,
                BoundPolynomialRootUse::Output => BoundTreeRootUse::Output,
            },
            ordered_column_ordinals: tree_columns,
        });
        Ok(limbs)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_setup_polynomial_rows_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        ordered_row_modulus_references: &[SuiteModulusReference],
        root_use: BoundPolynomialRootUse,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if ordered_row_modulus_references.is_empty() {
            return Err(RelationPlanError::InvalidRoot);
        }
        let source_ordinal = self.source_ordinal(source_key)?;
        let mut tree_columns = Vec::with_capacity(
            ordered_row_modulus_references
                .len()
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
        let mut rows = Vec::with_capacity(ordered_row_modulus_references.len());
        for modulus_reference in ordered_row_modulus_references {
            self.modulus(*modulus_reference)?;
            let vector = self.add_bound_setup_polynomial_vector(
                source_ordinal,
                *modulus_reference,
                &mut tree_columns,
            )?;
            rows.push(vector);
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal: source_ordinal,
            root_use: match root_use {
                BoundPolynomialRootUse::Input => BoundTreeRootUse::Input,
                BoundPolynomialRootUse::Output => BoundTreeRootUse::Output,
            },
            ordered_column_ordinals: tree_columns,
        });
        Ok(rows)
    }

    fn add_bound_setup_polynomial_vector(
        &mut self,
        source_ordinal: u32,
        modulus_reference: SuiteModulusReference,
        tree_columns: &mut Vec<u32>,
    ) -> Result<SplitIntegerVector, RelationPlanError> {
        let mut halves = [0_u32; 2];
        for half in &mut halves {
            *half = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry
                    .public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                None,
            )?;
            self.register_exact_radix_decomposition(*half, modulus_reference, None)?;
        }
        tree_columns.extend(halves);
        Ok(SplitIntegerVector { halves })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_committed_material_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<[BoundedUnsignedColumn; 2], RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let modulus = self.modulus(modulus_reference)?;
        let source_degree_bound_exclusive = self
            .geometry
            .material_column_degree_bound_exclusive
            .ok_or(RelationPlanError::InvalidDomain)?;
        let mut bound_columns = Vec::with_capacity(4);
        for _ in 0..4 {
            bound_columns.push(self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                source_degree_bound_exclusive,
                None,
                None,
            )?);
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::CommittedMaterial,
            expected_root_source_ordinal: source_ordinal,
            root_use: BoundTreeRootUse::Input,
            ordered_column_ordinals: bound_columns.clone(),
        });

        let maximum_digits = fixed_radix_digits(modulus - 1, 2, MATERIAL_DIGIT_RADIX)?;
        let mut halves = Vec::with_capacity(2);
        for half_ordinal in 0..2 {
            let low_column = bound_columns[half_ordinal];
            let high_column = bound_columns[2 + half_ordinal];
            let low_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            let high_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            self.certify_unsigned_recomposition(low_column, TRIT_RADIX, &low_trits)?;
            self.certify_unsigned_recomposition(high_column, TRIT_RADIX, &high_trits)?;
            self.add_upper_bound_comparator(
                &[low_column, high_column],
                &maximum_digits,
                ProofTreePhase::Base,
            )?;
            halves.push(BoundedUnsignedColumn {
                target_column_ordinal: low_column,
                ordered_digit_column_ordinals: vec![low_column, high_column],
            });
        }
        halves
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_target_committed_material_root(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<TargetCommittedMaterialVector, RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let modulus = self.modulus(modulus_reference)?;
        let source_degree_bound_exclusive = self
            .geometry
            .material_column_degree_bound_exclusive
            .ok_or(RelationPlanError::InvalidDomain)?;
        let mut bound_columns = Vec::with_capacity(4);
        for _ in 0..4 {
            bound_columns.push(self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                source_degree_bound_exclusive,
                None,
                None,
            )?);
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::CommittedMaterial,
            expected_root_source_ordinal: source_ordinal,
            root_use: BoundTreeRootUse::Input,
            ordered_column_ordinals: bound_columns.clone(),
        });

        let maximum_digits = fixed_radix_digits(modulus - 1, 2, MATERIAL_DIGIT_RADIX)?;
        let mut trits_by_half = Vec::with_capacity(2);
        let mut upper_bound_comparators = Vec::with_capacity(2);
        for half_ordinal in 0..2 {
            let low_column = bound_columns[half_ordinal];
            let high_column = bound_columns[2 + half_ordinal];
            let low_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            let high_trits =
                self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT, ProofTreePhase::Base)?;
            self.certify_unsigned_recomposition(low_column, TRIT_RADIX, &low_trits)?;
            self.certify_unsigned_recomposition(high_column, TRIT_RADIX, &high_trits)?;
            upper_bound_comparators.push(self.add_upper_bound_comparator(
                &[low_column, high_column],
                &maximum_digits,
                ProofTreePhase::Base,
            )?);
            trits_by_half.push(low_trits.into_iter().chain(high_trits).collect::<Vec<_>>());
        }
        Ok(TargetCommittedMaterialVector {
            bound_columns: bound_columns
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            trits_by_half: trits_by_half
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            upper_bound_comparators,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_grouped_trit_limbs(
        &mut self,
        trits_by_half: &[Vec<u32>; 2],
        trits_per_limb: usize,
    ) -> Result<Vec<ReversibleShiftedSmallVector>, RelationPlanError> {
        let split_limbs = self.add_grouped_trit_split_limbs(trits_by_half, trits_per_limb)?;
        split_limbs
            .into_iter()
            .map(|coefficients| {
                Ok(ReversibleShiftedSmallVector {
                    source: ShiftedSmallVector {
                        coefficients,
                        offset: 0,
                    },
                })
            })
            .collect()
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_grouped_trit_split_limbs(
        &mut self,
        trits_by_half: &[Vec<u32>; 2],
        trits_per_limb: usize,
    ) -> Result<Vec<SplitIntegerVector>, RelationPlanError> {
        if trits_per_limb == 0
            || trits_by_half[0].is_empty()
            || trits_by_half[0].len() != trits_by_half[1].len()
        {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let limb_count = trits_by_half[0].len().div_ceil(trits_per_limb);
        let mut limbs = Vec::with_capacity(limb_count);
        for limb_ordinal in 0..limb_count {
            let start = limb_ordinal
                .checked_mul(trits_per_limb)
                .ok_or(RelationPlanError::CountOverflow)?;
            let end = (start + trits_per_limb).min(trits_by_half[0].len());
            let mut halves = [0_u32; 2];
            for half_ordinal in 0..2 {
                halves[half_ordinal] = self.push_prover_column(ProofTreePhase::Base)?;
                self.certify_unsigned_recomposition(
                    halves[half_ordinal],
                    TRIT_RADIX,
                    &trits_by_half[half_ordinal][start..end],
                )?;
            }
            limbs.push(SplitIntegerVector { halves });
        }
        Ok(limbs)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_unsigned_vector_trits(
        &mut self,
        trit_count: usize,
    ) -> Result<[Vec<u32>; 2], RelationPlanError> {
        if trit_count == 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut halves = Vec::with_capacity(2);
        for _ in 0..2 {
            let target = self.push_prover_column(ProofTreePhase::Base)?;
            let trits = self.add_trit_columns(trit_count, ProofTreePhase::Base)?;
            self.certify_unsigned_recomposition(target, TRIT_RADIX, &trits)?;
            halves.push(trits);
        }
        halves
            .try_into()
            .map_err(|_| RelationPlanError::CountOverflow)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_bounded_unsigned_vector_trits(
        &mut self,
        maximum: &BigUint,
    ) -> Result<TargetBoundedUnsignedVector, RelationPlanError> {
        if maximum.is_zero() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let material_digit_radix = BigUint::from(MATERIAL_DIGIT_RADIX);
        let mut remaining = maximum.clone();
        let mut maximum_digits = Vec::new();
        while !remaining.is_zero() {
            maximum_digits.push(
                u64::try_from(&remaining % &material_digit_radix)
                    .map_err(|_| RelationPlanError::IntegerBoundOverflow)?,
            );
            remaining /= &material_digit_radix;
        }
        let mut halves = Vec::with_capacity(2);
        let mut digit_columns_by_half = Vec::with_capacity(2);
        let mut upper_bound_comparators = Vec::with_capacity(2);
        for _ in 0..2 {
            let mut digit_columns = Vec::with_capacity(maximum_digits.len());
            let mut all_trits = Vec::new();
            for (digit_ordinal, maximum_digit) in maximum_digits.iter().copied().enumerate() {
                let digit_column = self.push_prover_column(ProofTreePhase::Base)?;
                let trit_count = if digit_ordinal + 1 == maximum_digits.len() {
                    minimum_unsigned_radix_digit_count(maximum_digit, TRIT_RADIX)?
                } else {
                    MATERIAL_DIGIT_TRIT_COUNT
                };
                let trits = self.add_trit_columns(trit_count, ProofTreePhase::Base)?;
                self.certify_unsigned_recomposition(digit_column, TRIT_RADIX, &trits)?;
                digit_columns.push(digit_column);
                all_trits.extend(trits);
            }
            upper_bound_comparators.push(self.add_upper_bound_comparator(
                &digit_columns,
                &maximum_digits,
                ProofTreePhase::Base,
            )?);
            digit_columns_by_half.push(digit_columns);
            halves.push(all_trits);
        }
        Ok(TargetBoundedUnsignedVector {
            digit_columns_by_half: digit_columns_by_half
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            trits_by_half: halves
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
            upper_bound_comparators,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_centered_split_vector(
        &mut self,
        trit_count: usize,
    ) -> Result<TargetCenteredVector, RelationPlanError> {
        if trit_count == 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let capacity = BigUint::from(TRIT_RADIX)
            .pow(u32::try_from(trit_count).map_err(|_| RelationPlanError::CountOverflow)?);
        let offset = u64::try_from((capacity - BigUint::one()) / BigUint::from(2_u8))
            .map_err(|_| RelationPlanError::IntegerBoundOverflow)?;
        let mut halves = [0_u32; 2];
        let mut trits_by_half = Vec::with_capacity(2);
        for half in &mut halves {
            *half = self.push_prover_column(ProofTreePhase::Base)?;
            let trits = self.add_trit_columns(trit_count, ProofTreePhase::Base)?;
            let offset_magnitude = BigUint::from(offset);
            let expression = radix_recomposition_expression(
                *half,
                TRIT_RADIX,
                Some(&offset_magnitude),
                &trits,
                self.context.base_field_modulus,
            )?;
            let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
            trits_by_half.push(trits.clone());
            self.insert_semantic_cell(
                *half,
                SignedIntegerInterval::new(-i128::from(offset), i128::from(offset)),
                RelationBoundCertificate::ShiftedRadixRecomposition {
                    constraint_ordinal,
                    radix: TRIT_RADIX,
                    offset: offset_magnitude,
                    ordered_digit_column_ordinals: trits,
                },
            )?;
        }
        Ok(TargetCenteredVector {
            value: ShiftedSmallVector {
                coefficients: SplitIntegerVector { halves },
                offset,
            },
            trits_by_half: trits_by_half
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    fn add_fixed_binary_column(&mut self, value: bool) -> Result<u32, RelationPlanError> {
        let column = self.add_binary_column(ProofTreePhase::Base)?;
        let mut equality_expression = vec![unrotated_column_expression(column)];
        if value {
            equality_expression.extend([
                RelationExpressionInstruction::BaseFieldConstant(1),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
            ]);
        }
        self.add_full_trace_constraint(equality_expression, true)?;
        Ok(column)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_zero_column(
        &mut self,
    ) -> Result<u32, RelationPlanError> {
        self.add_fixed_binary_column(false)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_one_column(
        &mut self,
    ) -> Result<u32, RelationPlanError> {
        self.add_fixed_binary_column(true)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_shifted_ternary_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_trit_column(ProofTreePhase::Base)?,
                    self.add_trit_column(ProofTreePhase::Base)?,
                ],
            },
            offset: 1,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_reversible_shifted_ternary_vector(
        &mut self,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        let source = self.add_shifted_ternary_vector()?;
        Ok(ReversibleShiftedSmallVector { source })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_signed_ternary_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        let ordered_values = vec![BigInt::from(-1), BigInt::zero(), BigInt::one()];
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_finite_integer_set_column(
                        ordered_values.clone(),
                        ProofTreePhase::Base,
                    )?,
                    self.add_finite_integer_set_column(ordered_values, ProofTreePhase::Base)?,
                ],
            },
            offset: 0,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_reversible_signed_ternary_vector(
        &mut self,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        let source = self.add_signed_ternary_vector()?;
        Ok(ReversibleShiftedSmallVector { source })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_binary_vector(
        &mut self,
    ) -> Result<[u32; 2], RelationPlanError> {
        Ok([
            self.add_binary_column(ProofTreePhase::Base)?,
            self.add_binary_column(ProofTreePhase::Base)?,
        ])
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_shifted_eta_two_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?
                        .target_column_ordinal,
                    self.add_bounded_unsigned_column(4, ProofTreePhase::Base)?
                        .target_column_ordinal,
                ],
            },
            offset: 2,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_signed_eta_two_vector(
        &mut self,
    ) -> Result<ShiftedSmallVector, RelationPlanError> {
        let ordered_values = (-2..=2).map(BigInt::from).collect::<Vec<_>>();
        Ok(ShiftedSmallVector {
            coefficients: SplitIntegerVector {
                halves: [
                    self.add_finite_integer_set_column(
                        ordered_values.clone(),
                        ProofTreePhase::Base,
                    )?,
                    self.add_finite_integer_set_column(ordered_values, ProofTreePhase::Base)?,
                ],
            },
            offset: 0,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_recentered_vector(
        &mut self,
        canonical_vector: SplitIntegerVector,
        modulus_reference: SuiteModulusReference,
    ) -> Result<RecenteredVerifierVectorWitness, RelationPlanError> {
        let modulus = self.modulus(modulus_reference)?;
        let centered_offset = modulus
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidModulus)?
            / 2;
        let mut shifted_centered_halves = Vec::with_capacity(2);
        let mut carry_columns = Vec::with_capacity(2);
        for canonical_half in canonical_vector.halves {
            let shifted_centered =
                self.add_canonical_modulus_column(modulus_reference, ProofTreePhase::Base)?;
            let recentering_carry = self.add_binary_column(ProofTreePhase::Base)?;
            let expression = vec![
                unrotated_column_expression(shifted_centered),
                unrotated_column_expression(canonical_half),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                RelationExpressionInstruction::BaseFieldConstant(centered_offset),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                unrotated_column_expression(recentering_carry),
                RelationExpressionInstruction::NonNativeModulusConstant {
                    modulus_reference,
                    multiplier: 1,
                },
                RelationExpressionInstruction::Multiplication,
                RelationExpressionInstruction::Addition,
            ];
            self.add_full_trace_constraint(expression, true)?;
            shifted_centered_halves.push(shifted_centered);
            carry_columns.push(recentering_carry);
        }
        Ok(RecenteredVerifierVectorWitness {
            canonical: canonical_vector,
            centered: ReversibleShiftedSmallVector {
                source: ShiftedSmallVector {
                    coefficients: SplitIntegerVector {
                        halves: shifted_centered_halves
                            .try_into()
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                    offset: centered_offset,
                },
            },
            carry_columns: carry_columns
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_recentered_split_verifier_vector(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        self.add_recentered_split_verifier_vector_with_witness(source_key, modulus_reference)
            .map(|witness| witness.centered)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_recentered_split_verifier_vector_with_witness(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<RecenteredVerifierVectorWitness, RelationPlanError> {
        let canonical_vector = self.add_split_verifier_vector(source_key, modulus_reference)?;
        let modulus = self.modulus(modulus_reference)?;
        let centered_offset = modulus
            .checked_sub(1)
            .ok_or(RelationPlanError::InvalidModulus)?
            / 2;
        let mut shifted_centered_halves = Vec::with_capacity(2);
        let mut carry_columns = Vec::with_capacity(2);
        for canonical_half in canonical_vector.halves {
            let shifted_centered =
                self.add_canonical_modulus_column(modulus_reference, ProofTreePhase::Base)?;
            let recentering_carry = self.add_binary_column(ProofTreePhase::Base)?;
            let expression = vec![
                unrotated_column_expression(shifted_centered),
                unrotated_column_expression(canonical_half),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                RelationExpressionInstruction::BaseFieldConstant(centered_offset),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                unrotated_column_expression(recentering_carry),
                RelationExpressionInstruction::NonNativeModulusConstant {
                    modulus_reference,
                    multiplier: 1,
                },
                RelationExpressionInstruction::Multiplication,
                RelationExpressionInstruction::Addition,
            ];
            self.add_full_trace_constraint(expression, true)?;
            shifted_centered_halves.push(shifted_centered);
            carry_columns.push(recentering_carry);
        }
        Ok(RecenteredVerifierVectorWitness {
            canonical: canonical_vector,
            centered: ReversibleShiftedSmallVector {
                source: ShiftedSmallVector {
                    coefficients: SplitIntegerVector {
                        halves: shifted_centered_halves
                            .try_into()
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    },
                    offset: centered_offset,
                },
            },
            carry_columns: carry_columns
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_anchor_opening_witness(
        &mut self,
    ) -> Result<AnchorOpeningWitness, RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let hiding_secrets = (0..=rank)
            .map(|_| self.add_reversible_shifted_ternary_vector())
            .collect::<Result<Vec<_>, _>>()?;
        let hiding_errors = (0..rank)
            .map(|_| self.add_shifted_ternary_vector())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AnchorOpeningWitness {
            hiding_secrets,
            hiding_errors,
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_trustee_anchor_opening_witness(
        &mut self,
    ) -> Result<TrusteeAnchorOpeningWitness, RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let hiding_secrets = (0..=rank)
            .map(|_| {
                self.add_signed_ternary_vector()
                    .map(|vector| vector.coefficients)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let hiding_errors = (0..rank)
            .map(|_| self.add_signed_ternary_vector())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TrusteeAnchorOpeningWitness {
            hiding_secrets,
            hiding_errors,
        })
    }

    fn add_signed_modular_quotient_column(&mut self) -> Result<u32, RelationPlanError> {
        let target = self.push_prover_column(ProofTreePhase::Base)?;
        let bits = (0..MODULAR_QUOTIENT_BIT_COUNT)
            .map(|_| self.add_binary_column(ProofTreePhase::Base))
            .collect::<Result<Vec<_>, _>>()?;
        let offset = BigUint::one() << (MODULAR_QUOTIENT_BIT_COUNT - 1);
        let expression = radix_recomposition_expression(
            target,
            2,
            Some(&offset),
            &bits,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = BigInt::from(&offset - BigUint::one());
        self.insert_semantic_cell(
            target,
            SignedIntegerInterval::from_bigints(-BigInt::from(offset.clone()), maximum)?,
            RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix: 2,
                offset,
                ordered_digit_column_ordinals: bits,
            },
        )?;
        Ok(target)
    }

    fn add_trustee_quotient_low_column(&mut self) -> Result<u32, RelationPlanError> {
        let target = self.push_prover_column(ProofTreePhase::Base)?;
        let trits = self.add_trit_columns(TRUSTEE_QUOTIENT_LOW_TRIT_COUNT, ProofTreePhase::Base)?;
        let radix_power = BigUint::from(TRIT_RADIX).pow(
            u32::try_from(TRUSTEE_QUOTIENT_LOW_TRIT_COUNT)
                .map_err(|_| RelationPlanError::CountOverflow)?,
        );
        let offset = (&radix_power - BigUint::one()) / BigUint::from(2_u8);
        let expression = radix_recomposition_expression(
            target,
            TRIT_RADIX,
            Some(&offset),
            &trits,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let maximum = BigInt::from(&radix_power - BigUint::one()) - BigInt::from(offset.clone());
        self.insert_semantic_cell(
            target,
            SignedIntegerInterval::from_bigints(-BigInt::from(offset.clone()), maximum)?,
            RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix: TRIT_RADIX,
                offset,
                ordered_digit_column_ordinals: trits,
            },
        )?;
        Ok(target)
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_trustee_radix_three_quotient_witness(
        &mut self,
    ) -> Result<TrusteeRadixThreeQuotientWitness, RelationPlanError> {
        let carry_values = (-2..=2).map(BigInt::from).collect::<Vec<_>>();
        Ok(TrusteeRadixThreeQuotientWitness {
            low_quotients: [
                self.add_trustee_quotient_low_column()?,
                self.add_trustee_quotient_low_column()?,
            ],
            high_carries: [
                self.add_finite_integer_set_column(carry_values.clone(), ProofTreePhase::Base)?,
                self.add_finite_integer_set_column(carry_values, ProofTreePhase::Base)?,
            ],
        })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_anchor_quotient_witness(
        &mut self,
    ) -> Result<AnchorQuotientWitness, RelationPlanError> {
        let row_count = usize::from(self.geometry.commitment_module_rank)
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        let rows = (0..row_count)
            .map(|_| {
                Ok([
                    self.add_signed_modular_quotient_column()?,
                    self.add_signed_modular_quotient_column()?,
                ])
            })
            .collect::<Result<Vec<_>, RelationPlanError>>()?;
        Ok(AnchorQuotientWitness { rows })
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_public_key_quotient_witness(
        &mut self,
    ) -> Result<[u32; 2], RelationPlanError> {
        Ok([
            self.add_signed_modular_quotient_column()?,
            self.add_signed_modular_quotient_column()?,
        ])
    }

    pub(in crate::bgv::proof_suite::relation_plan) fn add_material_secret_equality(
        &mut self,
        material: &[BoundedUnsignedColumn; 2],
        secret: &ShiftedSmallVector,
        negative_indicator: &[u32; 2],
        modulus_reference: SuiteModulusReference,
    ) -> Result<(), RelationPlanError> {
        if secret.offset != 1 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        for half_ordinal in 0..2 {
            let material_digits = &material[half_ordinal].ordered_digit_column_ordinals;
            if material_digits.len() != 2 {
                return Err(RelationPlanError::InvalidConstraint);
            }
            let expression = vec![
                unrotated_column_expression(material_digits[0]),
                unrotated_column_expression(material_digits[1]),
                RelationExpressionInstruction::BaseFieldConstant(MATERIAL_DIGIT_RADIX),
                RelationExpressionInstruction::Multiplication,
                RelationExpressionInstruction::Addition,
                unrotated_column_expression(secret.coefficients.halves[half_ordinal]),
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
                RelationExpressionInstruction::BaseFieldConstant(1),
                RelationExpressionInstruction::Addition,
                unrotated_column_expression(negative_indicator[half_ordinal]),
                RelationExpressionInstruction::NonNativeModulusConstant {
                    modulus_reference,
                    multiplier: 1,
                },
                RelationExpressionInstruction::Multiplication,
                RelationExpressionInstruction::Negation,
                RelationExpressionInstruction::Addition,
            ];
            self.add_full_trace_constraint(expression, true)?;
        }
        Ok(())
    }
}
