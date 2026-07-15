use std::collections::{BTreeMap, BTreeSet};

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use super::*;

const TRIT_RADIX: u64 = 3;
const MATERIAL_DIGIT_RADIX: u64 = 129_140_163;
const MATERIAL_DIGIT_TRIT_COUNT: usize = 17;
const MODULAR_QUOTIENT_BIT_COUNT: usize = 17;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SameSecretRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) material_column_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) sharing_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_module_rank: u16,
    pub(crate) first_mask_purpose: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicKeyShareRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) data_modulus_indices: Vec<u16>,
    pub(crate) commitment_data_modulus_indices: Vec<u16>,
    pub(crate) commitment_module_rank: u16,
    pub(crate) plaintext_modulus: u64,
    pub(crate) first_mask_purpose: u16,
}

#[derive(Clone, Debug)]
pub(super) struct KeyRelationGeometry {
    ring_degree: u64,
    evaluation_domain_size: u64,
    opening_degree_bound_exclusive: u64,
    material_column_degree_bound_exclusive: Option<u64>,
    public_polynomial_column_degree_bound_exclusive: u64,
    relation_data_modulus_indices: Vec<u16>,
    commitment_data_modulus_indices: Vec<u16>,
    commitment_module_rank: u16,
    plaintext_modulus: Option<u64>,
    first_mask_purpose: u16,
}

impl KeyRelationGeometry {
    pub(super) fn for_same_secret(input: &SameSecretRelationPlanInput) -> Self {
        Self {
            ring_degree: input.ring_degree,
            evaluation_domain_size: input.evaluation_domain_size,
            opening_degree_bound_exclusive: input.opening_degree_bound_exclusive,
            material_column_degree_bound_exclusive: Some(
                input.material_column_degree_bound_exclusive,
            ),
            public_polynomial_column_degree_bound_exclusive: input
                .public_polynomial_column_degree_bound_exclusive,
            relation_data_modulus_indices: input.sharing_data_modulus_indices.clone(),
            commitment_data_modulus_indices: input.commitment_data_modulus_indices.clone(),
            commitment_module_rank: input.commitment_module_rank,
            plaintext_modulus: None,
            first_mask_purpose: input.first_mask_purpose,
        }
    }

    pub(super) fn for_public_key_share(input: &PublicKeyShareRelationPlanInput) -> Self {
        Self {
            ring_degree: input.ring_degree,
            evaluation_domain_size: input.evaluation_domain_size,
            opening_degree_bound_exclusive: input.opening_degree_bound_exclusive,
            material_column_degree_bound_exclusive: None,
            public_polynomial_column_degree_bound_exclusive: input
                .public_polynomial_column_degree_bound_exclusive,
            relation_data_modulus_indices: input.data_modulus_indices.clone(),
            commitment_data_modulus_indices: input.commitment_data_modulus_indices.clone(),
            commitment_module_rank: input.commitment_module_rank,
            plaintext_modulus: Some(input.plaintext_modulus),
            first_mask_purpose: input.first_mask_purpose,
        }
    }

    fn trace_domain_size(&self) -> Result<u64, RelationPlanError> {
        self.ring_degree
            .checked_div(2)
            .filter(|trace_size| *trace_size > 1 && *trace_size * 2 == self.ring_degree)
            .ok_or(RelationPlanError::InvalidDomain)
    }

    pub(super) fn validate(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<(SuiteModulusReference, u64)>, RelationPlanError> {
        RelationPlanChecker::new(context).check_context()?;
        self.trace_domain_size()?;
        if !self.ring_degree.is_power_of_two()
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.public_polynomial_column_degree_bound_exclusive == 0
            || self.public_polynomial_column_degree_bound_exclusive
                > self.opening_degree_bound_exclusive
            || self.material_column_degree_bound_exclusive.is_some_and(|degree| {
                degree == 0 || degree > self.opening_degree_bound_exclusive
            })
            || self.relation_data_modulus_indices.is_empty()
            || !strictly_sorted_unique(&self.relation_data_modulus_indices)
            || self.commitment_data_modulus_indices.is_empty()
            || !strictly_sorted_unique(&self.commitment_data_modulus_indices)
            || self.commitment_module_rank == 0
            || self.first_mask_purpose == 0
            || self.first_mask_purpose >= 0xff00
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let expected_evaluation_domain = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .and_then(|degree_domain| {
                degree_domain.checked_mul(u64::from(context.evaluation_blowup_factor))
            })
            .ok_or(RelationPlanError::CountOverflow)?;
        if expected_evaluation_domain != self.evaluation_domain_size {
            return Err(RelationPlanError::InvalidDomain);
        }
        if self.plaintext_modulus.is_some() {
            let expected_data_modulus_indices = (0..self.relation_data_modulus_indices.len())
                .map(|index| u16::try_from(index).map_err(|_| RelationPlanError::CountOverflow))
                .collect::<Result<Vec<_>, _>>()?;
            if self.relation_data_modulus_indices != expected_data_modulus_indices
                || self
                    .commitment_data_modulus_indices
                    .iter()
                    .any(|index| self.relation_data_modulus_indices.binary_search(index).is_err())
            {
                return Err(RelationPlanError::NonCanonicalOrder);
            }
        }

        let all_data_modulus_indices = self
            .relation_data_modulus_indices
            .iter()
            .chain(&self.commitment_data_modulus_indices)
            .copied()
            .collect::<BTreeSet<_>>();
        let mut resolved_moduli = all_data_modulus_indices
            .into_iter()
            .map(|index| {
                let reference = SuiteModulusReference::data(index);
                let modulus = context.resolved_modulus(reference)?;
                if modulus <= self.ring_degree
                    || modulus >= context.base_field_modulus
                    || modulus.is_multiple_of(2)
                {
                    return Err(RelationPlanError::InvalidModulus);
                }
                Ok((reference, modulus))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(plaintext_modulus) = self.plaintext_modulus {
            if context.resolved_modulus(SuiteModulusReference::plaintext())?
                != plaintext_modulus
                || plaintext_modulus < 3
                || resolved_moduli
                    .iter()
                    .any(|(_, modulus)| plaintext_modulus >= *modulus)
            {
                return Err(RelationPlanError::InvalidModulus);
            }
            resolved_moduli.push((SuiteModulusReference::plaintext(), plaintext_modulus));
        }
        resolved_moduli.sort_by_key(|(reference, _)| *reference);
        self.validate_anchor_lift_bound(context)?;
        Ok(resolved_moduli)
    }

    fn validate_anchor_lift_bound(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        let commitment_moduli = self
            .commitment_data_modulus_indices
            .iter()
            .copied()
            .map(|index| context.resolved_modulus(SuiteModulusReference::data(index)))
            .collect::<Result<Vec<_>, _>>()?;
        let modulus_product = commitment_moduli
            .iter()
            .copied()
            .map(BigUint::from)
            .product::<BigUint>();
        let maximum_modulus = commitment_moduli
            .iter()
            .copied()
            .max()
            .ok_or(RelationPlanError::MissingModulus)?;
        let maximum_centered_matrix_coefficient = (maximum_modulus - 1) / 2;
        let maximum_lift = u128::from(self.commitment_module_rank)
            .checked_add(1)
            .and_then(|term_count| term_count.checked_mul(u128::from(self.ring_degree)))
            .and_then(|coefficient_count| {
                coefficient_count.checked_mul(u128::from(
                    maximum_centered_matrix_coefficient,
                ))
            })
            .and_then(|bound| bound.checked_add(4))
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        if modulus_product <= BigUint::from(maximum_lift) * BigUint::from(2_u8) {
            return Err(RelationPlanError::NoWrapBoundViolated);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum KeyVerifierSourceKey {
    StatementRoot {
        field_ordinal: u64,
        list_ordinal: Option<u64>,
    },
    BdlopMatrix {
        data_modulus_index: u16,
        matrix_part: u16,
        row: u16,
        column: u16,
    },
    PublicKeyCommonReference {
        data_modulus_index: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BoundPolynomialRootUse {
    Input,
    Output,
}

#[derive(Clone, Copy)]
pub(super) enum ProofTreePhase {
    Base,
    Auxiliary,
}

#[derive(Clone, Debug)]
pub(super) struct BoundedUnsignedColumn {
    target_column_ordinal: u32,
    ordered_digit_column_ordinals: Vec<u32>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SplitIntegerVector {
    pub(super) halves: [u32; 2],
}

#[derive(Clone, Debug)]
pub(super) struct ShiftedSmallVector {
    pub(super) coefficients: SplitIntegerVector,
    pub(super) offset: u64,
}

#[derive(Clone, Debug)]
pub(super) struct ReversibleShiftedSmallVector {
    pub(super) source: ShiftedSmallVector,
    pub(super) reversed: SplitIntegerVector,
}

#[derive(Clone, Debug)]
pub(super) struct AnchorOpeningWitness {
    hiding_secrets: Vec<ReversibleShiftedSmallVector>,
    hiding_errors: Vec<ShiftedSmallVector>,
}

#[derive(Clone, Debug)]
pub(super) struct AnchorQuotientWitness {
    rows: Vec<[u32; 2]>,
}

#[derive(Default)]
struct PendingIntegerLiftBatch {
    reversed_bindings:
        BTreeMap<(u32, u32), RelationIntegerLiftReversedColumnBindingDescriptor>,
    components: Vec<RelationIntegerLiftComponentDescriptor>,
}

pub(super) struct KeyRelationPlanBuilder<'context> {
    application_statement_schema_identifier: u16,
    geometry: &'context KeyRelationGeometry,
    context: &'context RelationPlanCheckContext,
    ordered_non_native_moduli: Vec<SuiteModulusReference>,
    resolved_moduli: BTreeMap<SuiteModulusReference, u64>,
    ordered_verifier_sources: Vec<RelationVerifierSource>,
    source_ordinals: BTreeMap<KeyVerifierSourceKey, u32>,
    ordered_columns: Vec<RelationColumnDescriptor>,
    semantic_cells_by_column: BTreeMap<u32, (SignedIntegerInterval, RelationBoundCertificate)>,
    bound_trees: Vec<RelationTreeDescriptor>,
    base_tree_columns: Vec<u32>,
    auxiliary_tree_columns: Vec<u32>,
    pending_integer_lift_batches:
        BTreeMap<(SuiteModulusReference, u16), PendingIntegerLiftBatch>,
    ordered_integer_lift_batches: Vec<RelationIntegerLiftBatchDescriptor>,
    ordered_constraints: Vec<RelationConstraintDescriptor>,
}

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(super) fn new(
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
            bound_trees: Vec::new(),
            base_tree_columns: Vec::new(),
            auxiliary_tree_columns: Vec::new(),
            pending_integer_lift_batches: BTreeMap::new(),
            ordered_integer_lift_batches: Vec::new(),
            ordered_constraints: Vec::new(),
        })
    }

    fn modulus(
        &self,
        modulus_reference: SuiteModulusReference,
    ) -> Result<u64, RelationPlanError> {
        self.resolved_moduli
            .get(&modulus_reference)
            .copied()
            .ok_or(RelationPlanError::MissingModulus)
    }

    fn modulus_ordinal(
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

    fn source_ordinal(&self, key: &KeyVerifierSourceKey) -> Result<u32, RelationPlanError> {
        self.source_ordinals
            .get(key)
            .copied()
            .ok_or(RelationPlanError::InvalidSource)
    }

    fn push_column(
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

    fn push_prover_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
        self.push_column(
            RelationColumnOrigin::Prover,
            self.geometry.trace_domain_size()?,
            None,
            Some(phase),
        )
    }

    fn add_constraint(
        &mut self,
        numerator_postfix_expression: Vec<RelationExpressionInstruction>,
        zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
        enforce_proof_base_field_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        let ordinal = u32::try_from(self.ordered_constraints.len())
            .map_err(|_| RelationPlanError::CountOverflow)?;
        self.ordered_constraints.push(RelationConstraintDescriptor {
            constraint_role: 1,
            role_coordinates: vec![u64::from(ordinal)],
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
            ordered_injective_integer_factor_expressions: Vec::new(),
        });
        Ok(ordinal)
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

    fn add_trit_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
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

    fn add_binary_column(&mut self, phase: ProofTreePhase) -> Result<u32, RelationPlanError> {
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

    fn add_trit_columns(
        &mut self,
        count: usize,
        phase: ProofTreePhase,
    ) -> Result<Vec<u32>, RelationPlanError> {
        (0..count).map(|_| self.add_trit_column(phase)).collect()
    }

    fn certify_unsigned_recomposition(
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
        let maximum = BigUint::from(radix)
            .pow(
                u32::try_from(ordered_digit_column_ordinals.len())
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            - BigUint::one();
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

    fn add_bounded_material_digit(
        &mut self,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<u32, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let target = self.push_prover_column(phase)?;
        let trit_count = minimum_unsigned_radix_digit_count(maximum, TRIT_RADIX)?;
        let trits = self.add_trit_columns(trit_count, phase)?;
        self.certify_unsigned_recomposition(target, TRIT_RADIX, &trits)?;
        Ok(target)
    }

    fn add_bounded_unsigned_column(
        &mut self,
        maximum: u64,
        phase: ProofTreePhase,
    ) -> Result<BoundedUnsignedColumn, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::IntegerBoundOverflow);
        }
        let target_column_ordinal = self.add_bounded_material_digit(maximum, phase)?;
        let maximum_digits = vec![maximum];
        self.add_upper_bound_comparator(
            &[target_column_ordinal],
            &maximum_digits,
            phase,
        )?;
        Ok(BoundedUnsignedColumn {
            target_column_ordinal,
            ordered_digit_column_ordinals: vec![target_column_ordinal],
        })
    }

    fn add_upper_bound_comparator(
        &mut self,
        value_digits: &[u32],
        maximum_digits: &[u64],
        phase: ProofTreePhase,
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
            difference_digits.push(self.add_bounded_material_digit(
                difference_maximum,
                phase,
            )?);
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
            terms.push(integer_column_term(difference_digits[digit_ordinal], true));
            self.add_full_trace_constraint(sum_integer_terms(terms)?, true)?;
        }
        Ok(())
    }
}

impl KeyRelationPlanBuilder<'_> {
    pub(super) fn finish(mut self) -> Result<CompiledRelationPlan, RelationPlanError> {
        self.finalize_integer_lift_batches()?;
        if self.base_tree_columns.is_empty()
            || self.auxiliary_tree_columns.is_empty()
            || self.ordered_integer_lift_batches.is_empty()
        {
            return Err(RelationPlanError::InvalidRoot);
        }
        let required_rotations_by_column = required_column_rotations(
            &self.ordered_constraints,
            &[],
        )?;
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

        let ordered_opening_points = (0..self.context.deep_point_count)
            .flat_map(|deep_point_ordinal| {
                used_rotations.iter().map(move |rotation| {
                    RelationOpeningPointDescriptor {
                        deep_point_ordinal,
                        trace_rotation_is_negative: rotation.0,
                        trace_rotation_magnitude: rotation.1,
                        conjugate_index: 0,
                    }
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
                    mask_degree_bound_exclusive: trace_mask_degree_bound_exclusive,
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
                count.checked_mul(u128::from(trace_mask_degree_bound_exclusive))
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
                    opening_degree_bound_exclusive: self
                        .geometry
                        .opening_degree_bound_exclusive,
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
        compiled.check(self.context)?;
        Ok(compiled)
    }
}

fn derived_trace_mask_degree_bound(
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
                .get(
                    &u32::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                )
                .ok_or(RelationPlanError::InvalidOpening)?
                .len(),
        )
        .map_err(|_| RelationPlanError::CountOverflow)?;
        let deep_opening_view_count = u64::from(context.challenge_extension_degree)
            .checked_mul(u64::from(context.deep_point_count))
            .and_then(|count| count.checked_mul(rotation_count))
            .ok_or(RelationPlanError::CountOverflow)?;
        let query_view_count = u64::from(context.unique_query_count)
            .checked_mul(2)
            .ok_or(RelationPlanError::CountOverflow)?;
        maximum_view_count = maximum_view_count.max(
            deep_opening_view_count
                .checked_add(query_view_count)
                .ok_or(RelationPlanError::CountOverflow)?,
        );
    }
    maximum_view_count
        .checked_mul(2)
        .filter(|degree| *degree > 0 && *degree <= trace_domain_size)
        .ok_or(RelationPlanError::InvalidMaskGrammar)
}

pub(super) fn statement_root_source(
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

pub(super) fn bdlop_matrix_source(
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

pub(super) fn public_key_common_reference_source(
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

fn centered_residue_vector(
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

fn canonical_sources(
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

fn constant_linear_term(
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

fn integer_lift_half(
    half_ordinal: usize,
) -> Result<RelationIntegerLiftFullRingHalf, RelationPlanError> {
    match half_ordinal {
        0 => Ok(RelationIntegerLiftFullRingHalf::Low),
        1 => Ok(RelationIntegerLiftFullRingHalf::High),
        _ => Err(RelationPlanError::InvalidConstraint),
    }
}

fn sort_canonical_items<T>(
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

struct IntegerExpressionTerm {
    expression: Vec<RelationExpressionInstruction>,
    negative: bool,
}

fn integer_constant_term(value: u64, negative: bool) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![RelationExpressionInstruction::BaseFieldConstant(value)],
        negative,
    }
}

fn integer_column_term(column_ordinal: u32, negative: bool) -> IntegerExpressionTerm {
    IntegerExpressionTerm {
        expression: vec![unrotated_column_expression(column_ordinal)],
        negative,
    }
}

fn integer_scaled_column_term(
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

fn sum_integer_terms(
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

impl<'context> KeyRelationPlanBuilder<'context> {
    fn ensure_reversed_vector_bindings(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        vector: &ReversibleShiftedSmallVector,
    ) -> Result<(), RelationPlanError> {
        for half_ordinal in 0..2 {
            let source_column_ordinal = vector.source.coefficients.halves[half_ordinal];
            let reversed_column_ordinal = vector.reversed.halves[half_ordinal];
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

    fn full_ring_product(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        selected_half: RelationIntegerLiftFullRingHalf,
        negative: bool,
        multiplicand: SplitIntegerVector,
        multiplier: &ReversibleShiftedSmallVector,
    ) -> Result<RelationIntegerLiftFullRingNegacyclicProductDescriptor, RelationPlanError> {
        self.ensure_reversed_vector_bindings(batch_key, multiplier)?;
        Ok(RelationIntegerLiftFullRingNegacyclicProductDescriptor {
            negative,
            selected_half,
            multiplicand_low_column_ordinal: multiplicand.halves[0],
            multiplicand_high_column_ordinal: multiplicand.halves[1],
            multiplier_low_column_ordinal: multiplier.source.coefficients.halves[0],
            multiplier_high_column_ordinal: multiplier.source.coefficients.halves[1],
            reversed_multiplier_low_column_ordinal: multiplier.reversed.halves[0],
            reversed_multiplier_high_column_ordinal: multiplier.reversed.halves[1],
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

    fn add_integer_lift_component(
        &mut self,
        batch_key: (SuiteModulusReference, u16),
        quotient_column_ordinal: u32,
        mut ordered_linear_terms: Vec<RelationIntegerLiftLinearTermDescriptor>,
        mut ordered_full_ring_negacyclic_products:
            Vec<RelationIntegerLiftFullRingNegacyclicProductDescriptor>,
    ) -> Result<(), RelationPlanError> {
        sort_canonical_items(&mut ordered_linear_terms, |term| term.canonical_bytes())?;
        sort_canonical_items(
            &mut ordered_full_ring_negacyclic_products,
            |product| product.canonical_bytes(),
        )?;
        let component = RelationIntegerLiftComponentDescriptor {
            quotient_is_negative: true,
            quotient_column_ordinal,
            ordered_linear_terms,
            ordered_convolution_products: Vec::new(),
            ordered_full_ring_negacyclic_products,
            linear_evaluation_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
            product_accumulator_column_ordinal: self
                .push_prover_column(ProofTreePhase::Auxiliary)?,
        };
        self.pending_integer_lift_batches
            .entry(batch_key)
            .or_default()
            .components
            .push(component);
        Ok(())
    }

    pub(super) fn add_anchor_equations(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        commitments: &[SplitIntegerVector],
        first_matrix: &[Vec<SplitIntegerVector>],
        second_matrix: &[SplitIntegerVector],
        opening: &AnchorOpeningWitness,
        secret: &ShiftedSmallVector,
        quotients: &AnchorQuotientWitness,
    ) -> Result<(), RelationPlanError> {
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
            || opening.hiding_errors.iter().any(|value| value.offset != 2)
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
                            opening.hiding_errors[row_ordinal]
                                .coefficients
                                .halves[half_ordinal],
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
            for column_ordinal in 0..rank {
                products.push(self.full_ring_product(
                    batch_key,
                    selected_half,
                    true,
                    second_matrix[column_ordinal],
                    &opening.hiding_secrets[column_ordinal],
                )?);
            }
            self.add_integer_lift_component(
                batch_key,
                quotients.rows[rank][half_ordinal],
                vec![
                    constant_linear_term(commitments[rank].halves[half_ordinal], 0, false),
                    constant_linear_term(
                        opening.hiding_secrets[rank]
                            .source
                            .coefficients
                            .halves[half_ordinal],
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

    pub(super) fn add_public_key_equation(
        &mut self,
        modulus_reference: SuiteModulusReference,
        challenge_ordinal: u16,
        public_key_share: &SplitIntegerVector,
        common_reference: &SplitIntegerVector,
        secret: &ReversibleShiftedSmallVector,
        error: &ShiftedSmallVector,
        quotient_columns: [u32; 2],
    ) -> Result<(), RelationPlanError> {
        if secret.source.offset != 1 || error.offset != 2 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let batch_key = (modulus_reference, challenge_ordinal);
        for half_ordinal in 0..2 {
            let product = self.full_ring_product(
                batch_key,
                integer_lift_half(half_ordinal)?,
                false,
                *common_reference,
                secret,
            )?;
            self.add_integer_lift_component(
                batch_key,
                quotient_columns[half_ordinal],
                vec![
                    constant_linear_term(
                        public_key_share.halves[half_ordinal],
                        0,
                        false,
                    ),
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

    fn finalize_integer_lift_batches(&mut self) -> Result<(), RelationPlanError> {
        let pending = std::mem::take(&mut self.pending_integer_lift_batches);
        let mut batches = Vec::with_capacity(pending.len());
        for ((modulus_reference, challenge_ordinal), pending_batch) in pending {
            let mut ordered_reversed_column_bindings = pending_batch
                .reversed_bindings
                .into_values()
                .collect::<Vec<_>>();
            sort_canonical_items(
                &mut ordered_reversed_column_bindings,
                |binding| binding.canonical_bytes(),
            )?;
            let mut ordered_components = pending_batch.components;
            sort_canonical_items(&mut ordered_components, |component| {
                component.canonical_bytes()
            })?;
            let batch = RelationIntegerLiftBatchDescriptor {
                modulus_reference,
                challenge_ordinal,
                ordered_reversed_column_bindings,
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

impl<'context> KeyRelationPlanBuilder<'context> {
    pub(super) fn add_split_verifier_vector(
        &mut self,
        source_key: &KeyVerifierSourceKey,
        modulus_reference: SuiteModulusReference,
    ) -> Result<SplitIntegerVector, RelationPlanError> {
        let source_ordinal = self.source_ordinal(source_key)?;
        let trace_domain_size = self.geometry.trace_domain_size()?;
        let mut halves = Vec::with_capacity(2);
        for half_ordinal in 0..2_u64 {
            halves.push(self.push_column(
                RelationColumnOrigin::VerifierSequence {
                    verifier_source_ordinal: source_ordinal,
                    first_logical_element_index: half_ordinal
                        .checked_mul(trace_domain_size)
                        .ok_or(RelationPlanError::CountOverflow)?,
                    logical_element_stride: 1,
                },
                self.geometry.public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                Some(ProofTreePhase::Base),
            )?);
        }
        Ok(SplitIntegerVector {
            halves: halves
                .try_into()
                .map_err(|_| RelationPlanError::CountOverflow)?,
        })
    }

    pub(super) fn add_setup_polynomial_root(
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
                self.geometry.public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                None,
            )?;
            let high = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry.public_polynomial_column_degree_bound_exclusive,
                Some(modulus_reference),
                None,
            )?;
            let halves = [low, high];
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

    pub(super) fn add_setup_polynomial_limb_root(
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
            let low = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry.public_polynomial_column_degree_bound_exclusive,
                Some(*modulus_reference),
                None,
            )?;
            let high = self.push_column(
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal: source_ordinal,
                },
                self.geometry.public_polynomial_column_degree_bound_exclusive,
                Some(*modulus_reference),
                None,
            )?;
            tree_columns.extend([low, high]);
            limbs.push(SplitIntegerVector {
                halves: [low, high],
            });
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

    pub(super) fn add_committed_material_root(
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

    pub(super) fn add_shifted_ternary_vector(
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

    pub(super) fn add_reversible_shifted_ternary_vector(
        &mut self,
    ) -> Result<ReversibleShiftedSmallVector, RelationPlanError> {
        let source = self.add_shifted_ternary_vector()?;
        Ok(ReversibleShiftedSmallVector {
            source,
            reversed: SplitIntegerVector {
                halves: [
                    self.push_prover_column(ProofTreePhase::Base)?,
                    self.push_prover_column(ProofTreePhase::Base)?,
                ],
            },
        })
    }

    pub(super) fn add_binary_vector(&mut self) -> Result<[u32; 2], RelationPlanError> {
        Ok([
            self.add_binary_column(ProofTreePhase::Base)?,
            self.add_binary_column(ProofTreePhase::Base)?,
        ])
    }

    pub(super) fn add_shifted_eta_two_vector(
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

    pub(super) fn add_anchor_opening_witness(
        &mut self,
    ) -> Result<AnchorOpeningWitness, RelationPlanError> {
        let rank = usize::from(self.geometry.commitment_module_rank);
        let hiding_secrets = (0..=rank)
            .map(|_| self.add_reversible_shifted_ternary_vector())
            .collect::<Result<Vec<_>, _>>()?;
        let hiding_errors = (0..rank)
            .map(|_| self.add_shifted_eta_two_vector())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AnchorOpeningWitness {
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
            SignedIntegerInterval::from_bigints(
                -BigInt::from(offset.clone()),
                maximum,
            )?,
            RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal,
                radix: 2,
                offset,
                ordered_digit_column_ordinals: bits,
            },
        )?;
        Ok(target)
    }

    pub(super) fn add_anchor_quotient_witness(
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

    pub(super) fn add_public_key_quotient_witness(
        &mut self,
    ) -> Result<[u32; 2], RelationPlanError> {
        Ok([
            self.add_signed_modular_quotient_column()?,
            self.add_signed_modular_quotient_column()?,
        ])
    }

    pub(super) fn add_material_secret_equality(
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
