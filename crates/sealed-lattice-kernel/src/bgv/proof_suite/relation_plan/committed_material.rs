use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use super::*;

pub(super) const MESSAGE_TRIT_COUNT: usize = 34;
const MATERIAL_DIGIT_TRIT_COUNT: usize = MESSAGE_TRIT_COUNT / 2;
const TRIT_RADIX: u64 = 3;
const MATERIAL_DIGIT_RADIX: u64 = 129_140_163;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) material_column_degree_bound_exclusive: u64,
    pub(crate) participant_count: u16,
    pub(crate) threshold: u16,
    pub(crate) sharing_data_modulus_indices: Vec<u16>,
    pub(crate) trace_mask_degree_bound_exclusive: u64,
    pub(crate) first_mask_purpose: u16,
}

impl CommittedMaterialRelationPlanInput {
    pub(super) fn trace_domain_size(&self) -> Result<u64, RelationPlanError> {
        self.ring_degree
            .checked_div(2)
            .filter(|trace_size| *trace_size > 1 && self.ring_degree == trace_size * 2)
            .ok_or(RelationPlanError::InvalidDomain)
    }

    pub(super) fn point_stride(&self) -> Result<u64, RelationPlanError> {
        let padded_participant_count = u64::from(self.participant_count).next_power_of_two();
        let twice_ring_degree = self
            .ring_degree
            .checked_mul(2)
            .ok_or(RelationPlanError::InvalidDomain)?;
        twice_ring_degree
            .checked_div(padded_participant_count)
            .filter(|stride| {
                *stride > 0
                    && stride
                        .checked_mul(padded_participant_count)
                        .is_some_and(|product| product == twice_ring_degree)
            })
            .ok_or(RelationPlanError::InvalidDomain)
    }

    fn prover_column_degree_bound_exclusive(&self) -> Result<u64, RelationPlanError> {
        self.trace_domain_size()?
            .checked_add(self.trace_mask_degree_bound_exclusive)
            .ok_or(RelationPlanError::DegreeBoundExceeded)
    }

    pub(super) fn validate(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<(SuiteModulusReference, u64)>, RelationPlanError> {
        let trace_domain_size = self.trace_domain_size()?;
        let roster_parameters =
            crate::foundation::derive_foundation_roster_parameters(self.participant_count)
                .ok_or(RelationPlanError::InvalidDomain)?;
        if !self.ring_degree.is_power_of_two()
            || self.threshold != roster_parameters.reconstruction_threshold
            || self.sharing_data_modulus_indices.is_empty()
            || !strictly_sorted_unique(&self.sharing_data_modulus_indices)
            || self.trace_mask_degree_bound_exclusive == 0
            || self.trace_mask_degree_bound_exclusive > trace_domain_size
            || self.material_column_degree_bound_exclusive == 0
            || self.material_column_degree_bound_exclusive > self.opening_degree_bound_exclusive
            || self.prover_column_degree_bound_exclusive()? > self.opening_degree_bound_exclusive
            || self.first_mask_purpose == 0
            || self.first_mask_purpose >= 0xff00
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let message_capacity = MATERIAL_DIGIT_RADIX
            .checked_mul(MATERIAL_DIGIT_RADIX)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        self.sharing_data_modulus_indices
            .iter()
            .copied()
            .map(|modulus_index| {
                let reference = SuiteModulusReference::data(modulus_index);
                let modulus = context.resolved_modulus(reference)?;
                if modulus < 3
                    || modulus.is_multiple_of(2)
                    || modulus >= message_capacity
                    || modulus >= context.base_field_modulus
                {
                    return Err(RelationPlanError::InvalidModulus);
                }
                Ok((reference, modulus))
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MaterialRootUse {
    Input,
    Output,
}

#[derive(Clone, Debug)]
pub(super) struct MaterialMessageColumns {
    pub(super) message_digits_by_half: [[u32; 2]; 2],
}

#[derive(Clone, Debug)]
pub(super) struct IntegerResidual {
    pub(super) expression: Vec<RelationExpressionInstruction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MonomialActionBranch {
    source_half_ordinal: usize,
    rotation_magnitude: u64,
    use_upper_row_selector: Option<bool>,
    negates_source: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofTreePhase {
    Base,
}

pub(super) struct CommittedMaterialPlanBuilder<'context> {
    application_statement_schema_identifier: u16,
    geometry: &'context CommittedMaterialRelationPlanInput,
    context: &'context RelationPlanCheckContext,
    ordered_non_native_moduli: Vec<SuiteModulusReference>,
    resolved_moduli: Vec<u64>,
    ordered_verifier_sources: Vec<RelationVerifierSource>,
    root_source_ordinals: Vec<u32>,
    ordered_columns: Vec<RelationColumnDescriptor>,
    semantic_cells_by_column: BTreeMap<u32, (SignedIntegerInterval, RelationBoundCertificate)>,
    bound_trees: Vec<RelationTreeDescriptor>,
    base_tree_columns: Vec<u32>,
    ordered_constraints: Vec<RelationConstraintDescriptor>,
    ordered_coefficient_local_identity_batches:
        Vec<RelationCoefficientLocalIdentityBatchDescriptor>,
    shift_selectors: BTreeMap<u64, u32>,
    used_rotations: BTreeSet<(bool, u64)>,
}

impl<'context> CommittedMaterialPlanBuilder<'context> {
    pub(super) fn new(
        application_statement_schema_identifier: u16,
        geometry: &'context CommittedMaterialRelationPlanInput,
        context: &'context RelationPlanCheckContext,
        root_paths: Vec<Vec<RelationSelectorPathStep>>,
    ) -> Result<Self, RelationPlanError> {
        let resolved = geometry.validate(context)?;
        let (ordered_verifier_sources, root_source_ordinals) = canonical_root_sources(root_paths)?;
        let mut used_rotations = BTreeSet::new();
        used_rotations.insert((false, 0));
        Ok(Self {
            application_statement_schema_identifier,
            geometry,
            context,
            ordered_non_native_moduli: resolved.iter().map(|(reference, _)| *reference).collect(),
            resolved_moduli: resolved.into_iter().map(|(_, modulus)| modulus).collect(),
            ordered_verifier_sources,
            root_source_ordinals,
            ordered_columns: Vec::new(),
            semantic_cells_by_column: BTreeMap::new(),
            bound_trees: Vec::new(),
            base_tree_columns: Vec::new(),
            ordered_constraints: Vec::new(),
            ordered_coefficient_local_identity_batches: Vec::new(),
            shift_selectors: BTreeMap::new(),
            used_rotations,
        })
    }

    pub(super) fn modulus(&self, modulus_ordinal: usize) -> Result<u64, RelationPlanError> {
        self.resolved_moduli
            .get(modulus_ordinal)
            .copied()
            .ok_or(RelationPlanError::MissingModulus)
    }

    pub(super) fn modulus_reference(
        &self,
        modulus_ordinal: usize,
    ) -> Result<SuiteModulusReference, RelationPlanError> {
        self.ordered_non_native_moduli
            .get(modulus_ordinal)
            .copied()
            .ok_or(RelationPlanError::MissingModulus)
    }

    fn push_column(
        &mut self,
        origin: RelationColumnOrigin,
        phase: Option<ProofTreePhase>,
    ) -> Result<u32, RelationPlanError> {
        let source_degree_bound_exclusive = if matches!(origin, RelationColumnOrigin::Prover) {
            self.geometry.prover_column_degree_bound_exclusive()?
        } else {
            self.geometry.material_column_degree_bound_exclusive
        };
        let ordinal = u32::try_from(self.ordered_columns.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_columns.push(RelationColumnDescriptor {
            origin,
            value_type: RelationColumnValueType::BaseField,
            source_degree_bound_exclusive,
            canonical_residue_modulus: None,
        });
        if matches!(phase, Some(ProofTreePhase::Base)) {
            self.base_tree_columns.push(ordinal);
        }
        Ok(ordinal)
    }

    fn push_prover_column(&mut self) -> Result<u32, RelationPlanError> {
        self.push_column(RelationColumnOrigin::Prover, Some(ProofTreePhase::Base))
    }

    fn add_constraint_with_integer_factors(
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

    fn add_constraint(
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

    fn add_full_trace_constraint(
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

    fn insert_semantic_cell(
        &mut self,
        column_ordinal: u32,
        interval: SignedIntegerInterval,
        certificate: RelationBoundCertificate,
    ) -> Result<(), RelationPlanError> {
        if self
            .semantic_cells_by_column
            .insert(column_ordinal, (interval, certificate))
            .is_some()
        {
            return Err(RelationPlanError::InvalidSemanticCell);
        }
        Ok(())
    }

    fn certify_trit_column(&mut self, column_ordinal: u32) -> Result<(), RelationPlanError> {
        let constraint_ordinal =
            self.add_full_trace_constraint(trinary_constraint_expression(column_ordinal), false)?;
        self.insert_semantic_cell(
            column_ordinal,
            SignedIntegerInterval::new(0, 2),
            RelationBoundCertificate::Trinary { constraint_ordinal },
        )
    }

    fn certify_binary_column(&mut self, column_ordinal: u32) -> Result<(), RelationPlanError> {
        let constraint_ordinal =
            self.add_full_trace_constraint(binary_constraint_expression(column_ordinal), false)?;
        self.insert_semantic_cell(
            column_ordinal,
            SignedIntegerInterval::new(0, 1),
            RelationBoundCertificate::Binary { constraint_ordinal },
        )
    }

    fn add_trit_columns(&mut self, count: usize) -> Result<Vec<u32>, RelationPlanError> {
        (0..count)
            .map(|_| {
                let column = self.push_prover_column()?;
                self.certify_trit_column(column)?;
                Ok(column)
            })
            .collect()
    }

    fn add_binary_column(&mut self) -> Result<u32, RelationPlanError> {
        let column = self.push_prover_column()?;
        self.certify_binary_column(column)?;
        Ok(column)
    }

    fn certify_unsigned_recomposition(
        &mut self,
        target_column_ordinal: u32,
        ordered_digit_column_ordinals: &[u32],
    ) -> Result<(), RelationPlanError> {
        let expression = radix_recomposition_expression(
            target_column_ordinal,
            TRIT_RADIX,
            None,
            ordered_digit_column_ordinals,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let mut radix_power = BigInt::one();
        for _ in ordered_digit_column_ordinals {
            radix_power *= TRIT_RADIX;
        }
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), radix_power - 1)?,
            RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal,
                radix: TRIT_RADIX,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.to_vec(),
            },
        )
    }

    fn add_bounded_digit(&mut self, maximum: u64) -> Result<u32, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let target = self.push_prover_column()?;
        let trits =
            self.add_trit_columns(minimum_unsigned_radix_digit_count(maximum, TRIT_RADIX)?)?;
        self.certify_unsigned_recomposition(target, &trits)?;
        Ok(target)
    }

    fn add_upper_bound_comparator(
        &mut self,
        value_digits: &[u32],
        maximum_digits: &[u64],
    ) -> Result<(), RelationPlanError> {
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
            difference_digits.push(self.add_bounded_digit(difference_maximum)?);
        }
        let internal_borrows = (0..value_digits.len().saturating_sub(1))
            .map(|_| self.add_binary_column())
            .collect::<Result<Vec<_>, _>>()?;
        for digit_ordinal in 0..value_digits.len() {
            let mut terms = vec![integer_term_constant(maximum_digits[digit_ordinal], false)];
            terms.push(integer_term_column(
                value_digits[digit_ordinal],
                false,
                0,
                true,
            ));
            if digit_ordinal > 0 {
                terms.push(integer_term_column(
                    internal_borrows[digit_ordinal - 1],
                    false,
                    0,
                    true,
                ));
            }
            if digit_ordinal + 1 < value_digits.len() {
                terms.push(integer_term_scaled_column(
                    internal_borrows[digit_ordinal],
                    MATERIAL_DIGIT_RADIX,
                    false,
                    0,
                    false,
                ));
            }
            terms.push(integer_term_column(
                difference_digits[digit_ordinal],
                false,
                0,
                true,
            ));
            self.add_full_trace_constraint(sum_integer_terms(terms)?, true)?;
        }
        Ok(())
    }

    pub(super) fn add_material_message(
        &mut self,
        logical_root_ordinal: usize,
        modulus_ordinal: usize,
        root_use: MaterialRootUse,
    ) -> Result<MaterialMessageColumns, RelationPlanError> {
        let source_ordinal = self
            .root_source_ordinals
            .get(logical_root_ordinal)
            .copied()
            .ok_or(RelationPlanError::InvalidSource)?;
        let mut bound_columns = Vec::with_capacity(4);
        for _ in 0..4 {
            bound_columns.push(self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                None,
            )?);
        }
        self.bound_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::CommittedMaterial,
            expected_root_source_ordinal: source_ordinal,
            root_use: match root_use {
                MaterialRootUse::Input => BoundTreeRootUse::Input,
                MaterialRootUse::Output => BoundTreeRootUse::Output,
            },
            ordered_column_ordinals: bound_columns.clone(),
        });

        let modulus = self.modulus(modulus_ordinal)?;
        let maximum_digits = fixed_radix_digits(modulus - 1, 2, MATERIAL_DIGIT_RADIX)?;
        let mut message_digits_by_half = [[0_u32; 2]; 2];
        for half_ordinal in 0..2 {
            let low_digit_trits = self.add_trit_columns(MATERIAL_DIGIT_TRIT_COUNT)?;
            let high_digit_trits = self.add_trit_columns(minimum_unsigned_radix_digit_count(
                maximum_digits[1],
                TRIT_RADIX,
            )?)?;
            let low_digit_column = bound_columns[half_ordinal];
            let high_digit_column = bound_columns[2 + half_ordinal];
            self.certify_unsigned_recomposition(low_digit_column, &low_digit_trits)?;
            self.certify_unsigned_recomposition(high_digit_column, &high_digit_trits)?;
            self.add_upper_bound_comparator(
                &[low_digit_column, high_digit_column],
                &maximum_digits,
            )?;
            message_digits_by_half[half_ordinal] = [low_digit_column, high_digit_column];
        }
        Ok(MaterialMessageColumns {
            message_digits_by_half,
        })
    }

    pub(super) fn add_unsigned_quotient_column(
        &mut self,
        required_maximum: u64,
    ) -> Result<u32, RelationPlanError> {
        let digit_count = minimum_unsigned_radix_digit_count(required_maximum, TRIT_RADIX)?;
        let quotient = self.push_prover_column()?;
        let digits = self.add_trit_columns(digit_count)?;
        self.certify_unsigned_recomposition(quotient, &digits)?;
        Ok(quotient)
    }

    pub(super) fn add_signed_quotient_column(
        &mut self,
        required_absolute_bound: u64,
    ) -> Result<u32, RelationPlanError> {
        if required_absolute_bound == 0 {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
        let mut digit_count = 1_usize;
        let mut radix_power = TRIT_RADIX;
        while (radix_power - 1) / 2 < required_absolute_bound {
            digit_count = digit_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
            radix_power = radix_power
                .checked_mul(TRIT_RADIX)
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        }
        let offset = (radix_power - 1) / 2;
        let quotient = self.push_prover_column()?;
        let digits = self.add_trit_columns(digit_count)?;
        let offset_magnitude = BigUint::from(offset);
        let expression = radix_recomposition_expression(
            quotient,
            TRIT_RADIX,
            Some(&offset_magnitude),
            &digits,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        self.insert_semantic_cell(
            quotient,
            SignedIntegerInterval::from_bigints(
                -BigInt::from(offset),
                BigInt::from(radix_power - 1 - offset),
            )?,
            RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix: TRIT_RADIX,
                offset: offset_magnitude,
                ordered_digit_column_ordinals: digits,
            },
        )?;
        Ok(quotient)
    }

    pub(super) fn append_unrotated_message_integer_term(
        &mut self,
        terms: &mut Vec<IntegerTerm>,
        message: &MaterialMessageColumns,
        physical_half_ordinal: usize,
        negative: bool,
    ) -> Result<(), RelationPlanError> {
        let message_digits = message
            .message_digits_by_half
            .get(physical_half_ordinal)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        terms.push(IntegerTerm {
            expression: self.message_integer_expression(message_digits, 0)?,
            negative,
        });
        Ok(())
    }

    pub(super) fn append_monomial_action_message_integer_terms(
        &mut self,
        terms: &mut Vec<IntegerTerm>,
        message: &MaterialMessageColumns,
        exponent: u64,
        target_half_ordinal: usize,
        relation_term_is_negative: bool,
    ) -> Result<(), RelationPlanError> {
        for branch in
            monomial_action_branches(self.geometry.ring_degree, exponent, target_half_ordinal)?
        {
            let mut expression = self.message_integer_expression(
                &message.message_digits_by_half[branch.source_half_ordinal],
                branch.rotation_magnitude,
            )?;
            if let Some(use_upper_row_selector) = branch.use_upper_row_selector {
                let selector_column_ordinal = self.shift_selector(branch.rotation_magnitude)?;
                expression.push(unrotated_column_expression(selector_column_ordinal));
                if !use_upper_row_selector {
                    expression.push(RelationExpressionInstruction::Negation);
                    expression.push(RelationExpressionInstruction::BaseFieldConstant(1));
                    expression.push(RelationExpressionInstruction::Addition);
                }
                expression.push(RelationExpressionInstruction::Multiplication);
            }
            terms.push(IntegerTerm {
                expression,
                negative: relation_term_is_negative ^ branch.negates_source,
            });
        }
        Ok(())
    }

    pub(super) fn append_modulus_quotient_integer_term(
        &self,
        terms: &mut Vec<IntegerTerm>,
        modulus_ordinal: usize,
        quotient_column_ordinal: u32,
    ) -> Result<(), RelationPlanError> {
        terms.push(IntegerTerm {
            expression: vec![
                unrotated_column_expression(quotient_column_ordinal),
                RelationExpressionInstruction::NonNativeModulusConstant {
                    modulus_reference: self.modulus_reference(modulus_ordinal)?,
                    multiplier: 1,
                },
                RelationExpressionInstruction::Multiplication,
            ],
            negative: true,
        });
        Ok(())
    }

    pub(super) fn integer_residual(
        &self,
        terms: Vec<IntegerTerm>,
    ) -> Result<IntegerResidual, RelationPlanError> {
        Ok(IntegerResidual {
            expression: sum_integer_terms(terms)?,
        })
    }

    pub(super) fn add_randomized_residual_batch(
        &mut self,
        modulus_ordinal: usize,
        challenge_ordinal: u16,
        batch_ordinal: u16,
        ordered_residuals: &[IntegerResidual],
    ) -> Result<(), RelationPlanError> {
        if ordered_residuals.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let modulus_coordinate =
            u64::try_from(modulus_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        let mut batch_expression = Vec::new();
        for (unit_ordinal, residual) in ordered_residuals.iter().enumerate() {
            batch_expression.push(RelationExpressionInstruction::TranscriptChallenge {
                challenge_role: RelationChallengeRole::NonNativeAlpha,
                role_coordinates: vec![
                    modulus_coordinate,
                    u64::from(challenge_ordinal),
                    u64::try_from(unit_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ],
            });
            batch_expression.extend_from_slice(&residual.expression);
            batch_expression.push(RelationExpressionInstruction::Multiplication);
            if unit_ordinal > 0 {
                batch_expression.push(RelationExpressionInstruction::Addition);
            }
        }
        let constraint_ordinal = self.add_full_trace_constraint(batch_expression, false)?;
        self.ordered_coefficient_local_identity_batches.push(
            RelationCoefficientLocalIdentityBatchDescriptor {
                modulus_reference: self.modulus_reference(modulus_ordinal)?,
                challenge_ordinal,
                batch_ordinal,
                constraint_ordinal,
                ordered_residuals: ordered_residuals
                    .iter()
                    .enumerate()
                    .map(|(unit_ordinal, residual)| {
                        Ok(RelationCoefficientLocalResidualDescriptor {
                            unit_ordinal: u32::try_from(unit_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                            residual_postfix_expression: residual.expression.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, RelationPlanError>>()?,
            },
        );
        Ok(())
    }

    pub(super) fn add_deterministic_residual(
        &mut self,
        residual: IntegerResidual,
    ) -> Result<(), RelationPlanError> {
        self.add_full_trace_constraint(residual.expression, false)?;
        Ok(())
    }

    fn message_integer_expression(
        &mut self,
        message_digits: &[u32; 2],
        rotation_magnitude: u64,
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        if rotation_magnitude >= self.geometry.trace_domain_size()? {
            return Err(RelationPlanError::InvalidConstraint);
        }
        self.used_rotations.insert((false, rotation_magnitude));
        Ok(vec![
            RelationExpressionInstruction::ColumnValue {
                column_ordinal: message_digits[0],
                rotation_is_negative: false,
                rotation_magnitude,
            },
            RelationExpressionInstruction::ColumnValue {
                column_ordinal: message_digits[1],
                rotation_is_negative: false,
                rotation_magnitude,
            },
            RelationExpressionInstruction::BaseFieldConstant(MATERIAL_DIGIT_RADIX),
            RelationExpressionInstruction::Multiplication,
            RelationExpressionInstruction::Addition,
        ])
    }

    fn shift_selector(&mut self, row_shift: u64) -> Result<u32, RelationPlanError> {
        let trace_domain_size = self.geometry.trace_domain_size()?;
        if row_shift == 0 || row_shift >= trace_domain_size {
            return Err(RelationPlanError::InvalidConstraint);
        }
        if let Some(selector) = self.shift_selectors.get(&row_shift) {
            return Ok(*selector);
        }
        let selector = self.add_binary_column()?;
        let transition_row = trace_domain_size - row_shift - 1;
        let last_row = trace_domain_size - 1;
        self.used_rotations.insert((false, 1));
        let difference = subtract_rotated_columns(selector, false, 1, selector, false, 0);
        self.add_constraint(
            difference.clone(),
            self.trace_except_rows_zeroifier(&[transition_row, last_row])?,
            true,
        )?;
        self.add_constraint(
            add_constant_to_expression(difference.clone(), 1, true),
            self.point_zeroifier(transition_row)?,
            true,
        )?;
        self.add_constraint(
            add_constant_to_expression(difference, 1, false),
            self.point_zeroifier(last_row)?,
            true,
        )?;
        self.add_constraint(
            vec![unrotated_column_expression(selector)],
            self.point_zeroifier(0)?,
            true,
        )?;
        self.shift_selectors.insert(row_shift, selector);
        Ok(selector)
    }

    fn trace_root(&self, row_ordinal: u64) -> Result<u64, RelationPlanError> {
        let trace_domain_size = self.geometry.trace_domain_size()?;
        if row_ordinal >= trace_domain_size
            || !self
                .geometry
                .evaluation_domain_size
                .is_multiple_of(trace_domain_size)
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let trace_generator = modular_power(
            self.context.evaluation_domain_generator,
            self.geometry.evaluation_domain_size / trace_domain_size,
            self.context.base_field_modulus,
        );
        Ok(modular_power(
            trace_generator,
            row_ordinal,
            self.context.base_field_modulus,
        ))
    }

    fn point_zeroifier(
        &self,
        row_ordinal: u64,
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        let root = self.trace_root(row_ordinal)?;
        Ok(vec![
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::BaseFieldConstant(root),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ])
    }

    fn trace_except_rows_zeroifier(
        &self,
        excluded_rows: &[u64],
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        if excluded_rows.is_empty() {
            return Err(RelationPlanError::InvalidZeroifier);
        }
        let mut roots = excluded_rows
            .iter()
            .copied()
            .map(|row| self.trace_root(row))
            .collect::<Result<Vec<_>, _>>()?;
        roots.sort_unstable();
        if !strictly_sorted_unique(&roots) {
            return Err(RelationPlanError::InvalidZeroifier);
        }
        Ok(vec![
            RelationExpressionInstruction::TraceDomainExceptRoots {
                trace_domain_size: self.geometry.trace_domain_size()?,
                ordered_excluded_roots: roots,
            },
        ])
    }

    pub(super) fn finish(self) -> Result<CompiledRelationPlan, RelationPlanError> {
        if self.base_tree_columns.is_empty() {
            return Err(RelationPlanError::InvalidRoot);
        }
        let required_rotations_by_column =
            required_column_rotations(&self.ordered_constraints, &[])?;
        if required_rotations_by_column.len() != self.ordered_columns.len() {
            return Err(RelationPlanError::InvalidOpening);
        }
        let used_rotations = required_rotations_by_column
            .values()
            .flat_map(|rotations| rotations.iter().copied())
            .collect::<BTreeSet<_>>();
        if used_rotations != self.used_rotations {
            return Err(RelationPlanError::InvalidOpening);
        }
        let mut ordered_trees = self.bound_trees;
        ordered_trees.push(RelationTreeDescriptor::ProofCreated {
            proof_tree_role: 1,
            ordered_column_ordinals: self.base_tree_columns,
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

        let ordered_opening_points = (0..self.context.deep_point_count)
            .flat_map(|deep_point_ordinal| {
                used_rotations
                    .iter()
                    .map(move |rotation| RelationOpeningPointDescriptor {
                        deep_point_ordinal,
                        trace_rotation_is_negative: rotation.0,
                        trace_rotation_magnitude: rotation.1,
                        conjugate_index: 0,
                    })
            })
            .collect::<Vec<_>>();
        if ordered_opening_points.is_empty() {
            return Err(RelationPlanError::InvalidOpening);
        }
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

        let mut ordered_opening_claims = Vec::new();
        for (tree_ordinal, tree) in ordered_trees.iter().enumerate() {
            for column_ordinal in tree.ordered_column_ordinals() {
                let source_degree_bound_exclusive = self
                    .ordered_columns
                    .get(*column_ordinal as usize)
                    .ok_or(RelationPlanError::InvalidOpening)?
                    .source_degree_bound_exclusive;
                for deep_point_ordinal in 0..self.context.deep_point_count {
                    for rotation in required_rotations_by_column
                        .get(column_ordinal)
                        .ok_or(RelationPlanError::InvalidOpening)?
                    {
                        let opening_point_ordinal = opening_point_ordinals
                            .get(&RelationOpeningPointDescriptor {
                                deep_point_ordinal,
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
            for deep_point_ordinal in 0..self.context.deep_point_count {
                let opening_point_ordinal = opening_point_ordinals
                    .get(&RelationOpeningPointDescriptor {
                        deep_point_ordinal,
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

        let mut next_mask_purpose = self.geometry.first_mask_purpose;
        let mut ordered_masks = Vec::new();
        for (column_ordinal, column) in self.ordered_columns.iter().enumerate() {
            if matches!(column.origin, RelationColumnOrigin::Prover) {
                ordered_masks.push(RelationMaskDescriptor {
                    mask_purpose: next_mask_purpose,
                    mask_kind: RelationMaskKind::Trace,
                    target_class: RelationMaskTargetClass::Column,
                    target_ordinal: u32::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    mask_degree_bound_exclusive: self.geometry.trace_mask_degree_bound_exclusive,
                });
                next_mask_purpose = next_mask_purpose
                    .checked_add(1)
                    .filter(|purpose| *purpose < 0xff00)
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
            .and_then(|count| {
                count.checked_mul(u128::from(self.geometry.trace_mask_degree_bound_exclusive))
            })
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
                mask_purpose: next_mask_purpose,
                mask_kind: RelationMaskKind::Telescoping,
                target_class: RelationMaskTargetClass::QuotientComponent,
                target_ordinal: quotient_ordinal,
                mask_degree_bound_exclusive: telescoping_degree,
            });
            next_mask_purpose = next_mask_purpose
                .checked_add(1)
                .filter(|purpose| *purpose < 0xff00)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        ordered_masks.push(RelationMaskDescriptor {
            mask_purpose: next_mask_purpose,
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
                    schedule_position: None,
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
                    ordered_integer_lift_batches: Vec::new(),
                    ordered_coefficient_local_identity_batches: self
                        .ordered_coefficient_local_identity_batches,
                    ordered_trees,
                    ordered_constraints: self.ordered_constraints,
                    ordered_opening_points,
                    ordered_opening_claims,
                    ordered_masks,
                }],
            },
        };
        compiled.check(self.context)?;
        Ok(compiled)
    }
}

fn monomial_action_branches(
    ring_degree: u64,
    exponent: u64,
    target_half_ordinal: usize,
) -> Result<Vec<MonomialActionBranch>, RelationPlanError> {
    if ring_degree < 2 || !ring_degree.is_multiple_of(2) || target_half_ordinal >= 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let trace_domain_size = ring_degree / 2;
    let twice_ring_degree = ring_degree
        .checked_mul(2)
        .ok_or(RelationPlanError::CountOverflow)?;
    let reduced_exponent = exponent % twice_ring_degree;
    let exponent_is_negative = reduced_exponent >= ring_degree;
    let rotation_exponent = reduced_exponent % ring_degree;
    let source_half_offset = rotation_exponent / trace_domain_size;
    let source_row_offset = rotation_exponent % trace_domain_size;
    let rotation_magnitude = if source_row_offset == 0 {
        0
    } else {
        trace_domain_size - source_row_offset
    };
    let branch_count = if rotation_magnitude == 0 { 1 } else { 2 };
    let mut branches = Vec::with_capacity(branch_count);
    for borrow_branch in 0..branch_count {
        let unwrapped_source_half = i64::try_from(target_half_ordinal)
            .map_err(|_| RelationPlanError::CountOverflow)?
            - i64::try_from(source_half_offset).map_err(|_| RelationPlanError::CountOverflow)?
            - i64::try_from(borrow_branch).map_err(|_| RelationPlanError::CountOverflow)?;
        let crosses_ring_boundary = unwrapped_source_half < 0;
        let source_half_ordinal = usize::try_from(if crosses_ring_boundary {
            unwrapped_source_half + 2
        } else {
            unwrapped_source_half
        })
        .map_err(|_| RelationPlanError::CountOverflow)?;
        if source_half_ordinal >= 2 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        branches.push(MonomialActionBranch {
            source_half_ordinal,
            rotation_magnitude,
            use_upper_row_selector: (rotation_magnitude != 0).then_some(borrow_branch == 0),
            negates_source: exponent_is_negative ^ crosses_ring_boundary,
        });
    }
    Ok(branches)
}

pub(super) fn canonical_root_sources(
    root_paths: Vec<Vec<RelationSelectorPathStep>>,
) -> Result<(Vec<RelationVerifierSource>, Vec<u32>), RelationPlanError> {
    if root_paths.is_empty() {
        return Err(RelationPlanError::InvalidSource);
    }
    let mut indexed_sources = root_paths
        .into_iter()
        .enumerate()
        .map(|(logical_ordinal, value_path)| {
            let source = RelationVerifierSource::ApplicationStatement {
                value_path,
                value_layout: RelationValueLayout::scalar_hash(),
            };
            Ok((source.canonical_bytes()?, logical_ordinal, source))
        })
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    indexed_sources.sort_by(|left, right| left.0.cmp(&right.0));
    if !indexed_sources
        .windows(2)
        .all(|window| window[0].0 < window[1].0)
    {
        return Err(RelationPlanError::NonCanonicalOrder);
    }
    let mut logical_to_source = vec![0_u32; indexed_sources.len()];
    let mut ordered_sources = Vec::with_capacity(indexed_sources.len());
    for (source_ordinal, (_, logical_ordinal, source)) in indexed_sources.into_iter().enumerate() {
        logical_to_source[logical_ordinal] =
            u32::try_from(source_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        ordered_sources.push(source);
    }
    Ok((ordered_sources, logical_to_source))
}

pub(super) fn root_path(field_ordinal: u64, list_ordinal: u64) -> Vec<RelationSelectorPathStep> {
    vec![
        RelationSelectorPathStep::tuple_field(field_ordinal),
        RelationSelectorPathStep {
            step_kind: SelectorPathStepKind::LiteralListIndex,
            argument: list_ordinal,
        },
    ]
}

fn fixed_radix_digits(
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

fn minimum_unsigned_radix_digit_count(
    maximum_value: u64,
    radix: u64,
) -> Result<usize, RelationPlanError> {
    if radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut digit_count = 1_usize;
    let mut remaining = maximum_value;
    while remaining >= radix {
        remaining /= radix;
        digit_count = digit_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    Ok(digit_count)
}

#[derive(Clone)]
pub(super) struct IntegerTerm {
    pub(super) expression: Vec<RelationExpressionInstruction>,
    pub(super) negative: bool,
}

fn integer_term_constant(value: u64, negative: bool) -> IntegerTerm {
    IntegerTerm {
        expression: vec![RelationExpressionInstruction::BaseFieldConstant(value)],
        negative,
    }
}

fn integer_term_column(
    column_ordinal: u32,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
    negative: bool,
) -> IntegerTerm {
    IntegerTerm {
        expression: vec![RelationExpressionInstruction::ColumnValue {
            column_ordinal,
            rotation_is_negative,
            rotation_magnitude,
        }],
        negative,
    }
}

fn integer_term_scaled_column(
    column_ordinal: u32,
    scale: u64,
    rotation_is_negative: bool,
    rotation_magnitude: u64,
    negative: bool,
) -> IntegerTerm {
    let mut term = integer_term_column(
        column_ordinal,
        rotation_is_negative,
        rotation_magnitude,
        negative,
    );
    term.expression
        .push(RelationExpressionInstruction::BaseFieldConstant(scale));
    term.expression
        .push(RelationExpressionInstruction::Multiplication);
    term
}

pub(super) fn sum_integer_terms(
    terms: Vec<IntegerTerm>,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let mut expression = Vec::new();
    for (ordinal, term) in terms.into_iter().enumerate() {
        if term.expression.is_empty() {
            return Err(RelationPlanError::InvalidConstraint);
        }
        expression.extend(term.expression);
        if term.negative {
            expression.push(RelationExpressionInstruction::Negation);
        }
        if ordinal > 0 {
            expression.push(RelationExpressionInstruction::Addition);
        }
    }
    if expression.is_empty() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    Ok(expression)
}

fn subtract_rotated_columns(
    left: u32,
    left_rotation_is_negative: bool,
    left_rotation_magnitude: u64,
    right: u32,
    right_rotation_is_negative: bool,
    right_rotation_magnitude: u64,
) -> Vec<RelationExpressionInstruction> {
    vec![
        RelationExpressionInstruction::ColumnValue {
            column_ordinal: left,
            rotation_is_negative: left_rotation_is_negative,
            rotation_magnitude: left_rotation_magnitude,
        },
        RelationExpressionInstruction::ColumnValue {
            column_ordinal: right,
            rotation_is_negative: right_rotation_is_negative,
            rotation_magnitude: right_rotation_magnitude,
        },
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ]
}

fn add_constant_to_expression(
    mut expression: Vec<RelationExpressionInstruction>,
    value: u64,
    negative: bool,
) -> Vec<RelationExpressionInstruction> {
    expression.push(RelationExpressionInstruction::BaseFieldConstant(value));
    if negative {
        expression.push(RelationExpressionInstruction::Negation);
    }
    expression.push(RelationExpressionInstruction::Addition);
    expression
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        CommittedMaterialRelationPlanInput, MonomialActionBranch, monomial_action_branches,
    };
    use crate::foundation::{
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        derive_foundation_roster_parameters,
    };

    fn branch_is_active(
        branch: MonomialActionBranch,
        row_ordinal: u64,
        trace_domain_size: u64,
    ) -> bool {
        match branch.use_upper_row_selector {
            None => true,
            Some(use_upper_rows) => {
                let upper_rows_begin = trace_domain_size - branch.rotation_magnitude;
                (row_ordinal >= upper_rows_begin) == use_upper_rows
            }
        }
    }

    #[test]
    fn committed_material_points_cover_every_configurable_roster_without_collisions() {
        const RING_DEGREE: u64 = 32_768;
        for participant_count in
            MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
        {
            let roster_parameters = derive_foundation_roster_parameters(participant_count)
                .expect("configurable roster parameters derive");
            let input = CommittedMaterialRelationPlanInput {
                ring_degree: RING_DEGREE,
                evaluation_domain_size: RING_DEGREE,
                opening_degree_bound_exclusive: RING_DEGREE,
                material_column_degree_bound_exclusive: RING_DEGREE / 2,
                participant_count,
                threshold: roster_parameters.reconstruction_threshold,
                sharing_data_modulus_indices: vec![0],
                trace_mask_degree_bound_exclusive: 1,
                first_mask_purpose: 1,
            };
            let point_stride = input.point_stride().expect("point stride derives");
            let padded_participant_count = u64::from(participant_count).next_power_of_two();
            assert_eq!(point_stride * padded_participant_count, 2 * RING_DEGREE);

            let exponents = (0..u64::from(participant_count))
                .map(|participant_ordinal| participant_ordinal * point_stride)
                .collect::<BTreeSet<_>>();
            assert_eq!(exponents.len(), usize::from(participant_count));
            assert!(
                exponents
                    .last()
                    .is_some_and(|last_exponent| *last_exponent < 2 * RING_DEGREE)
            );
        }
    }

    #[test]
    fn split_half_monomial_action_matches_dense_negacyclic_rotation() {
        for ring_degree in [8_u64, 16, 32] {
            let trace_domain_size = ring_degree / 2;
            let source = (0..ring_degree)
                .map(|coefficient_ordinal| {
                    i128::from(coefficient_ordinal)
                        .checked_mul(19)
                        .and_then(|value| value.checked_add(7))
                        .expect("small dense source coefficient")
                })
                .collect::<Vec<_>>();
            for exponent in 0..2 * ring_degree {
                for target_half_ordinal in 0..2 {
                    let branches =
                        monomial_action_branches(ring_degree, exponent, target_half_ordinal)
                            .expect("valid split-half monomial action");
                    for target_row_ordinal in 0..trace_domain_size {
                        let active_branches = branches
                            .iter()
                            .copied()
                            .filter(|branch| {
                                branch_is_active(*branch, target_row_ordinal, trace_domain_size)
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(active_branches.len(), 1);
                        let branch = active_branches[0];
                        let source_row_ordinal =
                            (target_row_ordinal + branch.rotation_magnitude) % trace_domain_size;
                        let source_coefficient_ordinal = u64::try_from(branch.source_half_ordinal)
                            .expect("half ordinal fits u64")
                            * trace_domain_size
                            + source_row_ordinal;
                        let observed = if branch.negates_source {
                            -source[source_coefficient_ordinal as usize]
                        } else {
                            source[source_coefficient_ordinal as usize]
                        };

                        let target_coefficient_ordinal = u64::try_from(target_half_ordinal)
                            .expect("half ordinal fits u64")
                            * trace_domain_size
                            + target_row_ordinal;
                        let reduced_exponent = exponent % (2 * ring_degree);
                        let unsigned_exponent = reduced_exponent % ring_degree;
                        let unwrapped_source =
                            i128::from(target_coefficient_ordinal) - i128::from(unsigned_exponent);
                        let wraps_below_zero = unwrapped_source < 0;
                        let canonical_source = if wraps_below_zero {
                            unwrapped_source + i128::from(ring_degree)
                        } else {
                            unwrapped_source
                        };
                        let expected_is_negative =
                            (reduced_exponent >= ring_degree) ^ wraps_below_zero;
                        let expected_source = source
                            [usize::try_from(canonical_source).expect("canonical source index")];
                        let expected = if expected_is_negative {
                            -expected_source
                        } else {
                            expected_source
                        };
                        assert_eq!(
                            observed, expected,
                            "ring degree {ring_degree}, exponent {exponent}, target coefficient {target_coefficient_ordinal}",
                        );
                    }
                }
            }
        }
    }
}
