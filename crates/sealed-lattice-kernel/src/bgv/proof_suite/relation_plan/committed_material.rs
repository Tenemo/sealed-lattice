use std::collections::{BTreeMap, BTreeSet};

use super::*;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};
#[cfg(feature = "primitive-measurement-evidence")]
use zeroize::Zeroizing;

use crate::bgv::proof_suite::{AuthenticatedCompactCommittedMaterialSource, ProofBaseFieldElement};

const MATERIAL_DIGIT_TERNARY_DIGIT_COUNT: usize = 17;
const TERNARY_DIGIT_RADIX: u64 = 3;
const MATERIAL_DIGIT_RADIX: u64 = 129_140_163;
pub(super) const COMMITTED_MATERIAL_TRACE_PACKING_FACTOR: u64 = 4;
const COMMITTED_MATERIAL_RANGE_CONSTRAINT_ARITY: u64 = TERNARY_DIGIT_RADIX;

#[cfg(feature = "primitive-measurement-evidence")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VssRelationPackingCandidateGeometry {
    pub(crate) trace_packing_factor: u64,
    pub(crate) range_constraint_arity: u64,
    pub(crate) relation_trace_domain_size: u64,
    pub(crate) material_group_count: u64,
    pub(crate) material_range_digit_prover_column_count: u64,
    pub(crate) material_prover_column_count: u64,
    pub(crate) quotient_group_count: u64,
    pub(crate) quotient_range_digit_prover_column_count: u64,
    pub(crate) quotient_prover_column_count: u64,
    pub(crate) shift_selector_column_count: u64,
    pub(crate) prover_column_count: u64,
    pub(crate) prover_column_degree_bound_exclusive: u64,
    pub(crate) maximum_range_constraint_numerator_degree: u64,
    pub(crate) opening_point_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialRelationPlanInput {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) material_column_degree_bound_exclusive: u64,
    pub(crate) trace_packing_factor: u64,
    pub(crate) participant_count: u16,
    pub(crate) threshold: u16,
    pub(crate) sharing_data_modulus_indices: Vec<u16>,
    pub(crate) trace_mask_degree_bound_exclusive: u64,
}

impl CommittedMaterialRelationPlanInput {
    pub(crate) fn message_trace_domain_size(&self) -> Result<u64, RelationPlanError> {
        self.ring_degree
            .checked_div(2)
            .filter(|trace_size| *trace_size > 1 && self.ring_degree == trace_size * 2)
            .ok_or(RelationPlanError::InvalidDomain)
    }

    pub(crate) fn relation_trace_domain_size(&self) -> Result<u64, RelationPlanError> {
        self.message_trace_domain_size()?
            .checked_mul(self.trace_packing_factor)
            .ok_or(RelationPlanError::InvalidDomain)
    }

    pub(crate) fn point_stride(&self) -> Result<u64, RelationPlanError> {
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
        self.relation_trace_domain_size()?
            .checked_add(self.trace_mask_degree_bound_exclusive)
            .ok_or(RelationPlanError::DegreeBoundExceeded)
    }

    fn maximum_range_constraint_numerator_degree(&self) -> Result<u64, RelationPlanError> {
        self.prover_column_degree_bound_exclusive()?
            .checked_sub(1)
            .and_then(|maximum_source_degree| {
                maximum_source_degree.checked_mul(COMMITTED_MATERIAL_RANGE_CONSTRAINT_ARITY)
            })
            .ok_or(RelationPlanError::DegreeBoundExceeded)
    }

    pub(super) fn validate(
        &self,
        context: &RelationPlanCheckContext,
    ) -> Result<Vec<(SuiteModulusReference, u64)>, RelationPlanError> {
        let message_trace_domain_size = self.message_trace_domain_size()?;
        let relation_trace_domain_size = self.relation_trace_domain_size()?;
        let roster_parameters =
            crate::foundation::derive_foundation_roster_parameters(self.participant_count)
                .ok_or(RelationPlanError::InvalidDomain)?;
        if !self.ring_degree.is_power_of_two()
            || self.trace_packing_factor == 0
            || !self.trace_packing_factor.is_power_of_two()
            || self.threshold != roster_parameters.reconstruction_threshold
            || self.sharing_data_modulus_indices.is_empty()
            || !strictly_sorted_unique(&self.sharing_data_modulus_indices)
            || !self
                .evaluation_domain_size
                .is_multiple_of(relation_trace_domain_size)
            || self.trace_mask_degree_bound_exclusive == 0
            || self.trace_mask_degree_bound_exclusive > message_trace_domain_size
            || self.material_column_degree_bound_exclusive == 0
            || self.material_column_degree_bound_exclusive > self.opening_degree_bound_exclusive
            || self.prover_column_degree_bound_exclusive()? > self.opening_degree_bound_exclusive
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        if self.maximum_range_constraint_numerator_degree()? >= self.opening_degree_bound_exclusive
        {
            return Err(RelationPlanError::DegreeBoundExceeded);
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

#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) fn derive_vss_relation_packing_candidate_geometry(
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
    trace_packing_factor: u64,
) -> Result<VssRelationPackingCandidateGeometry, RelationPlanError> {
    derive_vss_relation_range_arity_candidate_geometry(
        input,
        context,
        trace_packing_factor,
        COMMITTED_MATERIAL_RANGE_CONSTRAINT_ARITY,
    )
}

#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) fn derive_vss_relation_range_arity_candidate_geometry(
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
    trace_packing_factor: u64,
    range_constraint_arity: u64,
) -> Result<VssRelationPackingCandidateGeometry, RelationPlanError> {
    if trace_packing_factor == 0 || !trace_packing_factor.is_power_of_two() {
        return Err(RelationPlanError::InvalidDomain);
    }
    if range_constraint_arity < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let resolved_moduli = input.validate(context)?;
    let relation_trace_domain_size = input
        .message_trace_domain_size()?
        .checked_mul(trace_packing_factor)
        .filter(|domain_size| input.evaluation_domain_size.is_multiple_of(*domain_size))
        .ok_or(RelationPlanError::InvalidDomain)?;
    let prover_column_degree_bound_exclusive = relation_trace_domain_size
        .checked_add(input.trace_mask_degree_bound_exclusive)
        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
    let maximum_range_constraint_numerator_degree = prover_column_degree_bound_exclusive
        .checked_sub(1)
        .and_then(|maximum_source_degree| maximum_source_degree.checked_mul(range_constraint_arity))
        .ok_or(RelationPlanError::DegreeBoundExceeded)?;
    let roots_per_limb = u64::from(input.threshold)
        .checked_add(u64::from(input.participant_count))
        .ok_or(RelationPlanError::CountOverflow)?;
    let groups_per_limb = roots_per_limb.div_ceil(trace_packing_factor);
    let material_digit_range_digit_count =
        minimum_unsigned_digit_count(MATERIAL_DIGIT_RADIX - 1, range_constraint_arity)?;
    let mut material_group_count = 0_u64;
    let mut material_range_digit_prover_column_count = 0_u64;
    let mut material_prover_column_count = 0_u64;
    for (_, modulus) in resolved_moduli.iter().copied() {
        let maximum_digits = fixed_material_digits(modulus - 1)?;
        let high_digit_range_digit_count =
            minimum_unsigned_digit_count(maximum_digits[1], range_constraint_arity)?;
        let range_digit_columns_per_physical_half = material_digit_range_digit_count
            .checked_add(high_digit_range_digit_count)
            .and_then(|count| count.checked_mul(2))
            .ok_or(RelationPlanError::CountOverflow)?;
        let columns_per_physical_half = material_digit_range_digit_count
            .checked_add(high_digit_range_digit_count)
            .and_then(|count| count.checked_add(1 + material_digit_range_digit_count))
            .and_then(|count| count.checked_add(1 + high_digit_range_digit_count))
            .and_then(|count| count.checked_add(1))
            .ok_or(RelationPlanError::CountOverflow)?;
        let columns_per_material_group = 4_u64
            .checked_add(
                columns_per_physical_half
                    .checked_mul(2)
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?;
        material_group_count = material_group_count
            .checked_add(groups_per_limb)
            .ok_or(RelationPlanError::CountOverflow)?;
        material_range_digit_prover_column_count = material_range_digit_prover_column_count
            .checked_add(
                groups_per_limb
                    .checked_mul(2)
                    .and_then(|count| count.checked_mul(range_digit_columns_per_physical_half))
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?;
        material_prover_column_count = material_prover_column_count
            .checked_add(
                groups_per_limb
                    .checked_mul(columns_per_material_group)
                    .ok_or(RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::CountOverflow)?;
    }

    let quotient_count = u64::try_from(resolved_moduli.len())
        .map_err(|_| RelationPlanError::CountOverflow)?
        .checked_mul(2)
        .and_then(|count| count.checked_mul(u64::from(input.participant_count)))
        .ok_or(RelationPlanError::CountOverflow)?;
    let mut quotient_range_digit_count = 1_u64;
    let mut quotient_range_capacity = range_constraint_arity;
    while (quotient_range_capacity - 1) / 2 < u64::from(input.threshold) {
        quotient_range_digit_count = quotient_range_digit_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        quotient_range_capacity = quotient_range_capacity
            .checked_mul(range_constraint_arity)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
    }
    let quotient_group_count = quotient_count.div_ceil(trace_packing_factor);
    let quotient_range_digit_prover_column_count = quotient_group_count
        .checked_mul(quotient_range_digit_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    let quotient_prover_column_count = quotient_group_count
        .checked_mul(
            quotient_range_digit_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
        )
        .ok_or(RelationPlanError::CountOverflow)?;

    let point_stride = input.point_stride()?;
    let mut shift_selector_rotations = BTreeSet::new();
    let mut used_packed_rotations = (0..trace_packing_factor).collect::<BTreeSet<_>>();
    for recipient_ordinal in 0..u64::from(input.participant_count) {
        for coefficient_ordinal in 0..u64::from(input.threshold) {
            let exponent = recipient_ordinal
                .checked_mul(coefficient_ordinal)
                .and_then(|product| product.checked_mul(point_stride))
                .ok_or(RelationPlanError::CountOverflow)?;
            for physical_half_ordinal in 0..2 {
                for branch in
                    monomial_action_branches(input.ring_degree, exponent, physical_half_ordinal)?
                {
                    let coefficient_packed_lane_ordinal =
                        coefficient_ordinal % trace_packing_factor;
                    let packed_rotation_magnitude = branch
                        .rotation_magnitude
                        .checked_mul(trace_packing_factor)
                        .and_then(|rotation| rotation.checked_add(coefficient_packed_lane_ordinal))
                        .filter(|rotation| *rotation < relation_trace_domain_size)
                        .ok_or(RelationPlanError::InvalidConstraint)?;
                    used_packed_rotations.insert(packed_rotation_magnitude);
                    if branch.use_upper_row_selector.is_some() {
                        shift_selector_rotations.insert(branch.rotation_magnitude);
                    }
                }
            }
        }
    }
    let shift_selector_column_count = u64::try_from(shift_selector_rotations.len())
        .map_err(|_| RelationPlanError::CountOverflow)?;
    if !shift_selector_rotations.is_empty() {
        used_packed_rotations.insert(trace_packing_factor);
    }
    let opening_point_count = u64::try_from(used_packed_rotations.len())
        .map_err(|_| RelationPlanError::CountOverflow)?
        .checked_mul(u64::from(context.out_of_domain_point_count))
        .ok_or(RelationPlanError::CountOverflow)?;
    let prover_column_count = material_prover_column_count
        .checked_add(quotient_prover_column_count)
        .and_then(|count| count.checked_add(shift_selector_column_count))
        .ok_or(RelationPlanError::CountOverflow)?;

    Ok(VssRelationPackingCandidateGeometry {
        trace_packing_factor,
        range_constraint_arity,
        relation_trace_domain_size,
        material_group_count,
        material_range_digit_prover_column_count,
        material_prover_column_count,
        quotient_group_count,
        quotient_range_digit_prover_column_count,
        quotient_prover_column_count,
        shift_selector_column_count,
        prover_column_count,
        prover_column_degree_bound_exclusive,
        maximum_range_constraint_numerator_degree,
        opening_point_count,
    })
}

#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) fn vss_relation_trinary_prover_column_ordinals(
    variant: &RelationPlanVariant,
) -> Result<BTreeSet<u32>, RelationPlanError> {
    let mut column_ordinals = BTreeSet::new();
    for cell in &variant.ordered_semantic_cells {
        if !matches!(
            cell.bound_certificate,
            RelationBoundCertificate::Trinary { .. }
        ) {
            continue;
        }
        let column = variant
            .ordered_columns
            .get(
                usize::try_from(cell.column_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .ok_or(RelationPlanError::InvalidColumn)?;
        if *column.origin() != RelationColumnOrigin::Prover
            || !column_ordinals.insert(cell.column_ordinal)
        {
            return Err(RelationPlanError::InvalidSemanticCell);
        }
    }
    if column_ordinals.is_empty() {
        return Err(RelationPlanError::InvalidSemanticCell);
    }
    Ok(column_ordinals)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MaterialRootUse {
    Input,
    Output,
}

#[derive(Clone, Debug)]
pub(super) struct MaterialMessageColumns {
    message_digits_by_half: [Vec<u32>; 2],
    packed_lane_ordinal: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PackedScalarColumn {
    column_ordinal: u32,
    packed_lane_ordinal: u64,
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
            full_trace_zeroifier_expression(self.geometry.relation_trace_domain_size()?),
            enforce_no_wrap,
        )
    }

    fn add_message_trace_constraint(
        &mut self,
        expression: Vec<RelationExpressionInstruction>,
        enforce_no_wrap: bool,
    ) -> Result<u32, RelationPlanError> {
        self.add_constraint(
            expression,
            full_trace_zeroifier_expression(self.geometry.message_trace_domain_size()?),
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

    fn add_ternary_digit_columns(
        &mut self,
        ternary_digit_count: usize,
    ) -> Result<Vec<u32>, RelationPlanError> {
        if ternary_digit_count == 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let mut columns = Vec::with_capacity(ternary_digit_count);
        for _ in 0..ternary_digit_count {
            let column = self.push_prover_column()?;
            self.certify_trit_column(column)?;
            columns.push(column);
        }
        Ok(columns)
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
            TERNARY_DIGIT_RADIX,
            None,
            ordered_digit_column_ordinals,
            self.context.base_field_modulus,
        )?;
        let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
        let mut radix_power = BigInt::one();
        let mut maximum = BigInt::zero();
        for digit_column_ordinal in ordered_digit_column_ordinals {
            let (digit_interval, _) = self
                .semantic_cells_by_column
                .get(digit_column_ordinal)
                .ok_or(RelationPlanError::InvalidSemanticCell)?;
            if digit_interval.minimum != BigInt::zero()
                || digit_interval.maximum >= BigInt::from(TERNARY_DIGIT_RADIX)
            {
                return Err(RelationPlanError::InvalidBoundCertificate);
            }
            maximum += &digit_interval.maximum * &radix_power;
            radix_power *= TERNARY_DIGIT_RADIX;
        }
        self.insert_semantic_cell(
            target_column_ordinal,
            SignedIntegerInterval::from_bigints(BigInt::zero(), maximum)?,
            RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal,
                radix: TERNARY_DIGIT_RADIX,
                ordered_digit_column_ordinals: ordered_digit_column_ordinals.to_vec(),
            },
        )
    }

    fn add_bounded_digit(&mut self, maximum: u64) -> Result<u32, RelationPlanError> {
        if maximum >= MATERIAL_DIGIT_RADIX {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let target = self.push_prover_column()?;
        let digit_count = minimum_unsigned_ternary_digit_count(maximum);
        let digits = self.add_ternary_digit_columns(digit_count)?;
        self.certify_unsigned_recomposition(target, &digits)?;
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
            // Comparator borrows use the material-digit radix; difference
            // digits are independently certified by the selected ternary
            // range relation.
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

    pub(super) fn add_material_messages(
        &mut self,
        ordered_roots: &[(usize, MaterialRootUse)],
        modulus_ordinal: usize,
    ) -> Result<Vec<MaterialMessageColumns>, RelationPlanError> {
        self.add_selected_material_messages(ordered_roots, modulus_ordinal)
    }

    fn add_selected_material_messages(
        &mut self,
        ordered_roots: &[(usize, MaterialRootUse)],
        modulus_ordinal: usize,
    ) -> Result<Vec<MaterialMessageColumns>, RelationPlanError> {
        if ordered_roots.is_empty() {
            return Err(RelationPlanError::InvalidRoot);
        }
        let modulus = self.modulus(modulus_ordinal)?;
        let maximum_digits = fixed_material_digits(modulus - 1)?;
        let high_digit_ternary_digit_count =
            minimum_unsigned_ternary_digit_count(maximum_digits[1]);
        let mut messages = Vec::with_capacity(ordered_roots.len());

        let trace_packing_factor = usize::try_from(self.geometry.trace_packing_factor)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for root_group in ordered_roots.chunks(trace_packing_factor) {
            let mut bound_columns_by_lane = Vec::<[u32; 4]>::with_capacity(root_group.len());
            for (logical_root_ordinal, root_use) in root_group.iter().copied() {
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
                bound_columns_by_lane.push(
                    bound_columns
                        .try_into()
                        .map_err(|_| RelationPlanError::InvalidColumn)?,
                );
            }

            let packed_message_columns = [
                self.push_prover_column()?,
                self.push_prover_column()?,
                self.push_prover_column()?,
                self.push_prover_column()?,
            ];
            let mut message_digits_by_half = [Vec::new(), Vec::new()];
            for physical_half_ordinal in 0..2 {
                let low_digit_column = packed_message_columns[physical_half_ordinal];
                let high_digit_column = packed_message_columns[2 + physical_half_ordinal];
                let low_digits =
                    self.add_ternary_digit_columns(MATERIAL_DIGIT_TERNARY_DIGIT_COUNT)?;
                let high_digits = self.add_ternary_digit_columns(high_digit_ternary_digit_count)?;
                self.certify_unsigned_recomposition(low_digit_column, &low_digits)?;
                self.certify_unsigned_recomposition(high_digit_column, &high_digits)?;
                self.add_upper_bound_comparator(
                    &[low_digit_column, high_digit_column],
                    &maximum_digits,
                )?;
                message_digits_by_half[physical_half_ordinal] =
                    vec![low_digit_column, high_digit_column];
            }

            for packed_lane_ordinal in 0..self.geometry.trace_packing_factor {
                self.used_rotations.insert((false, packed_lane_ordinal));
                if let Some(bound_columns) = bound_columns_by_lane.get(
                    usize::try_from(packed_lane_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                ) {
                    for physical_column_ordinal in 0..4 {
                        self.add_message_trace_constraint(
                            subtract_rotated_columns(
                                packed_message_columns[physical_column_ordinal],
                                false,
                                packed_lane_ordinal,
                                bound_columns[physical_column_ordinal],
                                false,
                                0,
                            ),
                            false,
                        )?;
                    }
                    messages.push(MaterialMessageColumns {
                        message_digits_by_half: message_digits_by_half.clone(),
                        packed_lane_ordinal,
                    });
                } else {
                    for packed_message_column in packed_message_columns {
                        self.add_message_trace_constraint(
                            vec![RelationExpressionInstruction::ColumnValue {
                                column_ordinal: packed_message_column,
                                rotation_is_negative: false,
                                rotation_magnitude: packed_lane_ordinal,
                            }],
                            false,
                        )?;
                    }
                }
            }
        }
        Ok(messages)
    }

    pub(super) fn add_packed_unsigned_quotient_columns(
        &mut self,
        quotient_count: usize,
        required_maximum: u64,
    ) -> Result<Vec<PackedScalarColumn>, RelationPlanError> {
        if quotient_count == 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let ternary_digit_count = minimum_unsigned_ternary_digit_count(required_maximum);
        let mut quotients = Vec::with_capacity(quotient_count);
        let trace_packing_factor = usize::try_from(self.geometry.trace_packing_factor)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for group_start in (0..quotient_count).step_by(trace_packing_factor) {
            let target = self.push_prover_column()?;
            let digits = self.add_ternary_digit_columns(ternary_digit_count)?;
            self.certify_unsigned_recomposition(target, &digits)?;
            self.append_packed_scalar_group(&mut quotients, target, group_start, quotient_count)?;
        }
        Ok(quotients)
    }

    pub(super) fn add_packed_signed_quotient_columns(
        &mut self,
        quotient_count: usize,
        required_absolute_bound: u64,
    ) -> Result<Vec<PackedScalarColumn>, RelationPlanError> {
        if quotient_count == 0 {
            return Err(RelationPlanError::InvalidConstraint);
        }
        if required_absolute_bound == 0 {
            return Err(RelationPlanError::InvalidBoundCertificate);
        }
        let mut ternary_digit_count = 1_usize;
        let mut ternary_capacity = TERNARY_DIGIT_RADIX;
        while (ternary_capacity - 1) / 2 < required_absolute_bound {
            ternary_digit_count = ternary_digit_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
            ternary_capacity = ternary_capacity
                .checked_mul(TERNARY_DIGIT_RADIX)
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        }
        let offset = (ternary_capacity - 1) / 2;
        let offset_magnitude = BigUint::from(offset);
        let mut quotients = Vec::with_capacity(quotient_count);
        let trace_packing_factor = usize::try_from(self.geometry.trace_packing_factor)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        for group_start in (0..quotient_count).step_by(trace_packing_factor) {
            let target = self.push_prover_column()?;
            let digits = self.add_ternary_digit_columns(ternary_digit_count)?;
            let expression = radix_recomposition_expression(
                target,
                TERNARY_DIGIT_RADIX,
                Some(&offset_magnitude),
                &digits,
                self.context.base_field_modulus,
            )?;
            let constraint_ordinal = self.add_full_trace_constraint(expression, false)?;
            self.insert_semantic_cell(
                target,
                SignedIntegerInterval::from_bigints(
                    -BigInt::from(offset),
                    BigInt::from(ternary_capacity - 1 - offset),
                )?,
                RelationBoundCertificate::ShiftedRadixRecomposition {
                    constraint_ordinal,
                    radix: TERNARY_DIGIT_RADIX,
                    offset: offset_magnitude.clone(),
                    ordered_digit_column_ordinals: digits,
                },
            )?;
            self.append_packed_scalar_group(&mut quotients, target, group_start, quotient_count)?;
        }
        Ok(quotients)
    }

    fn append_packed_scalar_group(
        &mut self,
        output: &mut Vec<PackedScalarColumn>,
        column_ordinal: u32,
        group_start: usize,
        total_count: usize,
    ) -> Result<(), RelationPlanError> {
        let remaining_count = total_count.saturating_sub(group_start);
        let trace_packing_factor = usize::try_from(self.geometry.trace_packing_factor)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let actual_lane_count = remaining_count.min(trace_packing_factor);
        for packed_lane_ordinal in 0..self.geometry.trace_packing_factor {
            self.used_rotations.insert((false, packed_lane_ordinal));
            if usize::try_from(packed_lane_ordinal).map_err(|_| RelationPlanError::CountOverflow)?
                < actual_lane_count
            {
                output.push(PackedScalarColumn {
                    column_ordinal,
                    packed_lane_ordinal,
                });
            } else {
                self.add_message_trace_constraint(
                    vec![RelationExpressionInstruction::ColumnValue {
                        column_ordinal,
                        rotation_is_negative: false,
                        rotation_magnitude: packed_lane_ordinal,
                    }],
                    false,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn append_unrotated_message_integer_term(
        &mut self,
        terms: &mut Vec<IntegerTerm>,
        message: &MaterialMessageColumns,
        physical_half_ordinal: usize,
        negative: bool,
    ) -> Result<(), RelationPlanError> {
        terms.push(IntegerTerm {
            expression: self.message_integer_expression(message, physical_half_ordinal, 0)?,
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
                message,
                branch.source_half_ordinal,
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
        &mut self,
        terms: &mut Vec<IntegerTerm>,
        modulus_ordinal: usize,
        quotient: PackedScalarColumn,
    ) -> Result<(), RelationPlanError> {
        self.used_rotations
            .insert((false, quotient.packed_lane_ordinal));
        terms.push(IntegerTerm {
            expression: vec![
                RelationExpressionInstruction::ColumnValue {
                    column_ordinal: quotient.column_ordinal,
                    rotation_is_negative: false,
                    rotation_magnitude: quotient.packed_lane_ordinal,
                },
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
        let constraint_ordinal = self.add_message_trace_constraint(batch_expression, false)?;
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
        self.add_message_trace_constraint(residual.expression, false)?;
        Ok(())
    }

    fn message_integer_expression(
        &mut self,
        message: &MaterialMessageColumns,
        physical_half_ordinal: usize,
        message_row_rotation_magnitude: u64,
    ) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
        if message_row_rotation_magnitude >= self.geometry.message_trace_domain_size()? {
            return Err(RelationPlanError::InvalidConstraint);
        }
        let message_digits = message
            .message_digits_by_half
            .get(physical_half_ordinal)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let relation_trace_domain_size = self.geometry.relation_trace_domain_size()?;
        let packed_rotation_magnitude = message_row_rotation_magnitude
            .checked_mul(self.geometry.trace_packing_factor)
            .and_then(|rotation| rotation.checked_add(message.packed_lane_ordinal))
            .filter(|rotation| *rotation < relation_trace_domain_size)
            .ok_or(RelationPlanError::InvalidConstraint)?;
        self.used_rotations
            .insert((false, packed_rotation_magnitude));
        let first_digit = message_digits
            .first()
            .copied()
            .ok_or(RelationPlanError::InvalidConstraint)?;
        let mut expression = vec![RelationExpressionInstruction::ColumnValue {
            column_ordinal: first_digit,
            rotation_is_negative: false,
            rotation_magnitude: packed_rotation_magnitude,
        }];
        let mut radix_power = MATERIAL_DIGIT_RADIX;
        for digit_column_ordinal in message_digits.iter().copied().skip(1) {
            expression.push(RelationExpressionInstruction::ColumnValue {
                column_ordinal: digit_column_ordinal,
                rotation_is_negative: false,
                rotation_magnitude: packed_rotation_magnitude,
            });
            expression.push(RelationExpressionInstruction::BaseFieldConstant(
                radix_power,
            ));
            expression.push(RelationExpressionInstruction::Multiplication);
            expression.push(RelationExpressionInstruction::Addition);
            radix_power = radix_power
                .checked_mul(MATERIAL_DIGIT_RADIX)
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        }
        Ok(expression)
    }

    fn shift_selector(&mut self, row_shift: u64) -> Result<u32, RelationPlanError> {
        let message_trace_domain_size = self.geometry.message_trace_domain_size()?;
        if row_shift == 0 || row_shift >= message_trace_domain_size {
            return Err(RelationPlanError::InvalidConstraint);
        }
        if let Some(selector) = self.shift_selectors.get(&row_shift) {
            return Ok(*selector);
        }
        let selector = self.add_binary_column()?;
        let transition_row = message_trace_domain_size - row_shift - 1;
        let last_row = message_trace_domain_size - 1;
        self.used_rotations
            .insert((false, self.geometry.trace_packing_factor));
        let difference = subtract_rotated_columns(
            selector,
            false,
            self.geometry.trace_packing_factor,
            selector,
            false,
            0,
        );
        let mut unchanged_rows_expression = difference.clone();
        for excluded_row in [transition_row, last_row] {
            unchanged_rows_expression.extend(self.point_zeroifier(excluded_row)?);
            unchanged_rows_expression.push(RelationExpressionInstruction::Multiplication);
        }
        self.add_message_trace_constraint(unchanged_rows_expression, false)?;
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
        let message_trace_domain_size = self.geometry.message_trace_domain_size()?;
        if row_ordinal >= message_trace_domain_size
            || !self
                .geometry
                .evaluation_domain_size
                .is_multiple_of(message_trace_domain_size)
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let trace_generator = modular_power(
            self.context.evaluation_domain_generator,
            self.geometry.evaluation_domain_size / message_trace_domain_size,
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
                    mask_degree_bound_exclusive: self.geometry.trace_mask_degree_bound_exclusive,
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
            .and_then(|count| {
                count.checked_mul(u128::from(self.geometry.trace_mask_degree_bound_exclusive))
            })
            .and_then(|degree| degree.checked_add(component_count - 1))
            .ok_or(RelationPlanError::DegreeBoundExceeded)?
            / component_count;
        let decomposition_stride = self
            .geometry
            .relation_trace_domain_size()?
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
                    schedule_position: None,
                    top_count: None,
                    proof_privacy_mode: ProofPrivacyMode::SecretBearing,
                    trace_domain_size: self.geometry.relation_trace_domain_size()?,
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum CommittedMaterialIntegerRecipe {
    Constant(i128),
    Packed {
        ordered_lane_sources: Box<[CommittedMaterialIntegerRecipe]>,
    },
    BoundDigit {
        logical_root_ordinal: usize,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
    },
    ComparatorDifference {
        logical_root_ordinal: usize,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
        modulus_ordinal: usize,
    },
    VssQuotient {
        sharing_limb_ordinal: usize,
        recipient_ordinal: usize,
        physical_half_ordinal: usize,
    },
    AggregateQuotient {
        sharing_limb_ordinal: usize,
        physical_half_ordinal: usize,
    },
    ComparatorBorrow {
        logical_root_ordinal: usize,
        physical_half_ordinal: usize,
        modulus_ordinal: usize,
    },
}

impl CommittedMaterialIntegerRecipe {
    fn nested_allocation_byte_length(&self) -> Result<usize, RelationPlanError> {
        let Self::Packed {
            ordered_lane_sources,
        } = self
        else {
            return Ok(0);
        };
        ordered_lane_sources.iter().try_fold(
            ordered_lane_sources
                .len()
                .checked_mul(size_of::<Self>())
                .ok_or(RelationPlanError::CountOverflow)?,
            |total, source| {
                total
                    .checked_add(source.nested_allocation_byte_length()?)
                    .ok_or(RelationPlanError::CountOverflow)
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CommittedMaterialColumnRecipe {
    Integer(CommittedMaterialIntegerRecipe),
    TernaryDigit {
        source: CommittedMaterialIntegerRecipe,
        digit_ordinal: usize,
        offset: u64,
    },
    ShiftSelector {
        row_shift: u64,
    },
}

impl CommittedMaterialColumnRecipe {
    fn nested_allocation_byte_length(&self) -> Result<usize, RelationPlanError> {
        match self {
            Self::Integer(source) | Self::TernaryDigit { source, .. } => {
                source.nested_allocation_byte_length()
            }
            Self::ShiftSelector { .. } => Ok(0),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CommittedMaterialTraceWitnessInput {
    ring_degree: u64,
    trace_packing_factor: u64,
    participant_count: u16,
    threshold: u16,
}

impl CommittedMaterialTraceWitnessInput {
    const fn from_relation_input(input: &CommittedMaterialRelationPlanInput) -> Self {
        Self {
            ring_degree: input.ring_degree,
            trace_packing_factor: input.trace_packing_factor,
            participant_count: input.participant_count,
            threshold: input.threshold,
        }
    }

    fn message_trace_domain_size(self) -> Result<u64, RelationPlanError> {
        self.ring_degree
            .checked_div(2)
            .filter(|trace_size| *trace_size > 1 && self.ring_degree == trace_size * 2)
            .ok_or(RelationPlanError::InvalidDomain)
    }

    fn relation_trace_domain_size(self) -> Result<u64, RelationPlanError> {
        self.message_trace_domain_size()?
            .checked_mul(self.trace_packing_factor)
            .ok_or(RelationPlanError::InvalidDomain)
    }

    fn point_stride(self) -> Result<u64, RelationPlanError> {
        let padded_participant_count = u64::from(self.participant_count).next_power_of_two();
        self.ring_degree
            .checked_mul(2)
            .and_then(|twice_ring_degree| {
                twice_ring_degree
                    .checked_div(padded_participant_count)
                    .filter(|stride| {
                        *stride > 0
                            && stride.checked_mul(padded_participant_count)
                                == Some(twice_ring_degree)
                    })
            })
            .ok_or(RelationPlanError::InvalidDomain)
    }
}

/// A restartable, relation-owned provider for unmasked proof-created trace
/// columns of the committed-material relations.
///
/// The provider stores only checked ordinal recipes and authenticated compact
/// sources. It therefore supports deterministic repeated passes without
/// retaining every witness column simultaneously. The common prover remains
/// responsible for interpolation and the plan-assigned trace mask.
pub(crate) trait CommittedMaterialTraceSource {
    fn material_digit(
        &self,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<u64, RelationPlanError>;
}

impl CommittedMaterialTraceSource for AuthenticatedCompactCommittedMaterialSource {
    fn material_digit(
        &self,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<u64, RelationPlanError> {
        AuthenticatedCompactCommittedMaterialSource::material_digit(
            self,
            physical_half_ordinal,
            material_digit_ordinal,
            row_ordinal,
        )
        .map_err(|_| RelationPlanError::InvalidColumn)
    }
}

/// Recipe-only input for the opt-in primitive measurement artifact.
///
/// It has no commitment root, seed, authenticated-source marker, or conversion
/// into a production source. Consequently it can exercise the same trace
/// recipes but cannot enter proving or verification.
#[cfg(feature = "primitive-measurement-evidence")]
struct PrimitiveMeasurementCommittedMaterialSource {
    canonical_message: Zeroizing<Box<[u64]>>,
    canonical_modulus: u64,
    trace_domain_size: usize,
}

#[cfg(feature = "primitive-measurement-evidence")]
impl PrimitiveMeasurementCommittedMaterialSource {
    fn new(
        canonical_message: Box<[u64]>,
        canonical_modulus: u64,
    ) -> Result<Self, RelationPlanError> {
        if canonical_modulus < 2
            || canonical_message.len() < 4
            || !canonical_message.len().is_power_of_two()
            || canonical_message
                .iter()
                .any(|coefficient| *coefficient >= canonical_modulus)
        {
            return Err(RelationPlanError::InvalidRoot);
        }
        Ok(Self {
            trace_domain_size: canonical_message.len() / 2,
            canonical_message: Zeroizing::new(canonical_message),
            canonical_modulus,
        })
    }
}

#[cfg(feature = "primitive-measurement-evidence")]
impl CommittedMaterialTraceSource for PrimitiveMeasurementCommittedMaterialSource {
    fn material_digit(
        &self,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<u64, RelationPlanError> {
        if physical_half_ordinal >= 2
            || material_digit_ordinal >= 2
            || row_ordinal >= self.trace_domain_size
        {
            return Err(RelationPlanError::InvalidColumn);
        }
        let coefficient_ordinal = physical_half_ordinal
            .checked_mul(self.trace_domain_size)
            .and_then(|offset| offset.checked_add(row_ordinal))
            .ok_or(RelationPlanError::CountOverflow)?;
        let coefficient = *self
            .canonical_message
            .get(coefficient_ordinal)
            .ok_or(RelationPlanError::InvalidColumn)?;
        if coefficient >= self.canonical_modulus {
            return Err(RelationPlanError::InvalidColumn);
        }
        Ok(if material_digit_ordinal == 0 {
            coefficient % MATERIAL_DIGIT_RADIX
        } else {
            coefficient / MATERIAL_DIGIT_RADIX
        })
    }
}

pub(crate) struct CommittedMaterialTraceWitnessProvider<
    Source = AuthenticatedCompactCommittedMaterialSource,
> {
    input: CommittedMaterialTraceWitnessInput,
    ordered_roots: Box<[Source]>,
    resolved_moduli: Box<[u64]>,
    ordered_recipes: Box<[(u32, CommittedMaterialColumnRecipe)]>,
    relation_plan_hash: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommittedMaterialTraceWitnessStructureMemoryAccounting {
    resolved_modulus_catalog_byte_length: u64,
    recipe_catalog_byte_length: u64,
    nested_recipe_catalog_byte_length: u64,
    total_byte_length: u64,
}

impl CommittedMaterialTraceWitnessStructureMemoryAccounting {
    fn from_catalog_dimensions(
        resolved_modulus_count: usize,
        ordered_recipes: &[(u32, CommittedMaterialColumnRecipe)],
    ) -> Result<Self, RelationPlanError> {
        let resolved_modulus_catalog_byte_length = resolved_modulus_count
            .checked_mul(size_of::<u64>())
            .and_then(|byte_length| u64::try_from(byte_length).ok())
            .ok_or(RelationPlanError::CountOverflow)?;
        let recipe_catalog_byte_length = ordered_recipes
            .len()
            .checked_mul(size_of::<(u32, CommittedMaterialColumnRecipe)>())
            .and_then(|byte_length| u64::try_from(byte_length).ok())
            .ok_or(RelationPlanError::CountOverflow)?;
        let nested_recipe_catalog_byte_length = ordered_recipes.iter().try_fold(
            0_u64,
            |total, (_, recipe)| -> Result<_, RelationPlanError> {
                let byte_length = u64::try_from(recipe.nested_allocation_byte_length()?)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                total
                    .checked_add(byte_length)
                    .ok_or(RelationPlanError::CountOverflow)
            },
        )?;
        let total_byte_length = resolved_modulus_catalog_byte_length
            .checked_add(recipe_catalog_byte_length)
            .and_then(|total| total.checked_add(nested_recipe_catalog_byte_length))
            .ok_or(RelationPlanError::CountOverflow)?;
        Ok(Self {
            resolved_modulus_catalog_byte_length,
            recipe_catalog_byte_length,
            nested_recipe_catalog_byte_length,
            total_byte_length,
        })
    }

    pub(crate) const fn resolved_modulus_catalog_byte_length(self) -> u64 {
        self.resolved_modulus_catalog_byte_length
    }

    pub(crate) const fn recipe_catalog_byte_length(self) -> u64 {
        self.recipe_catalog_byte_length
    }

    pub(crate) const fn nested_recipe_catalog_byte_length(self) -> u64 {
        self.nested_recipe_catalog_byte_length
    }

    pub(crate) const fn total_byte_length(self) -> u64 {
        self.total_byte_length
    }

    #[cfg(test)]
    pub(crate) fn from_exact_component_byte_lengths_for_test(
        resolved_modulus_catalog_byte_length: u64,
        recipe_catalog_byte_length: u64,
        nested_recipe_catalog_byte_length: u64,
    ) -> Result<Self, RelationPlanError> {
        let total_byte_length = resolved_modulus_catalog_byte_length
            .checked_add(recipe_catalog_byte_length)
            .and_then(|total| total.checked_add(nested_recipe_catalog_byte_length))
            .ok_or(RelationPlanError::CountOverflow)?;
        Ok(Self {
            resolved_modulus_catalog_byte_length,
            recipe_catalog_byte_length,
            nested_recipe_catalog_byte_length,
            total_byte_length,
        })
    }
}

impl<Source: CommittedMaterialTraceSource> CommittedMaterialTraceWitnessProvider<Source> {
    pub(crate) const fn relation_plan_hash(&self) -> [u8; 64] {
        self.relation_plan_hash
    }

    pub(crate) fn logical_root_count(&self) -> usize {
        self.ordered_roots.len()
    }

    pub(crate) fn structure_memory_accounting(
        &self,
    ) -> Result<CommittedMaterialTraceWitnessStructureMemoryAccounting, RelationPlanError> {
        CommittedMaterialTraceWitnessStructureMemoryAccounting::from_catalog_dimensions(
            self.resolved_moduli.len(),
            &self.ordered_recipes,
        )
    }

    #[cfg(test)]
    pub(crate) fn ordered_column_ordinals(&self) -> impl ExactSizeIterator<Item = u32> + '_ {
        self.ordered_recipes.iter().map(|(ordinal, _)| *ordinal)
    }

    #[cfg(test)]
    pub(crate) fn representative_aggregate_projection_digit_and_quotient_column_ordinals(
        &self,
    ) -> Result<[u32; 3], RelationPlanError> {
        fn contains_bound_material_digit(source: &CommittedMaterialIntegerRecipe) -> bool {
            match source {
                CommittedMaterialIntegerRecipe::Packed {
                    ordered_lane_sources,
                } => ordered_lane_sources
                    .iter()
                    .any(contains_bound_material_digit),
                CommittedMaterialIntegerRecipe::BoundDigit { .. } => true,
                _ => false,
            }
        }

        fn contains_aggregate_quotient(source: &CommittedMaterialIntegerRecipe) -> bool {
            match source {
                CommittedMaterialIntegerRecipe::Packed {
                    ordered_lane_sources,
                } => ordered_lane_sources.iter().any(contains_aggregate_quotient),
                CommittedMaterialIntegerRecipe::AggregateQuotient { .. } => true,
                _ => false,
            }
        }

        let projection_column_ordinal = self
            .ordered_recipes
            .iter()
            .find_map(|(column_ordinal, recipe)| match recipe {
                CommittedMaterialColumnRecipe::Integer(
                    source @ CommittedMaterialIntegerRecipe::Packed { .. },
                ) if contains_bound_material_digit(source) => Some(*column_ordinal),
                _ => None,
            })
            .ok_or(RelationPlanError::InvalidColumn)?;
        let digit_column_ordinal = self
            .ordered_recipes
            .iter()
            .find_map(|(column_ordinal, recipe)| match recipe {
                CommittedMaterialColumnRecipe::TernaryDigit { source, .. }
                    if contains_bound_material_digit(source) =>
                {
                    Some(*column_ordinal)
                }
                _ => None,
            })
            .ok_or(RelationPlanError::InvalidColumn)?;
        let quotient_column_ordinal = self
            .ordered_recipes
            .iter()
            .find_map(|(column_ordinal, recipe)| match recipe {
                CommittedMaterialColumnRecipe::Integer(source)
                    if contains_aggregate_quotient(source) =>
                {
                    Some(*column_ordinal)
                }
                _ => None,
            })
            .ok_or(RelationPlanError::InvalidColumn)?;
        let representative_ordinals = [
            projection_column_ordinal,
            digit_column_ordinal,
            quotient_column_ordinal,
        ];
        if representative_ordinals[0] == representative_ordinals[1]
            || representative_ordinals[0] == representative_ordinals[2]
            || representative_ordinals[1] == representative_ordinals[2]
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        Ok(representative_ordinals)
    }

    pub(crate) fn trace_value(
        &self,
        column_ordinal: u32,
        row_ordinal: usize,
    ) -> Result<u64, RelationPlanError> {
        if row_ordinal
            >= usize::try_from(self.input.relation_trace_domain_size()?)
                .map_err(|_| RelationPlanError::CountOverflow)?
        {
            return Err(RelationPlanError::InvalidColumn);
        }
        let recipe = self
            .ordered_recipes
            .binary_search_by_key(&column_ordinal, |(ordinal, _)| *ordinal)
            .ok()
            .and_then(|recipe_index| self.ordered_recipes.get(recipe_index))
            .map(|(_, recipe)| recipe)
            .ok_or(RelationPlanError::InvalidColumn)?;
        let integer_value = match recipe {
            CommittedMaterialColumnRecipe::Integer(source) => {
                self.integer_value(source, row_ordinal)?
            }
            CommittedMaterialColumnRecipe::TernaryDigit {
                source,
                digit_ordinal,
                offset,
            } => {
                let shifted = self
                    .integer_value(source, row_ordinal)?
                    .checked_add(i128::from(*offset))
                    .filter(|value| *value >= 0)
                    .ok_or(RelationPlanError::InvalidColumn)?;
                let divisor = i128::from(TERNARY_DIGIT_RADIX)
                    .checked_pow(
                        u32::try_from(*digit_ordinal)
                            .map_err(|_| RelationPlanError::CountOverflow)?,
                    )
                    .ok_or(RelationPlanError::IntegerBoundOverflow)?;
                shifted / divisor % i128::from(TERNARY_DIGIT_RADIX)
            }
            CommittedMaterialColumnRecipe::ShiftSelector { row_shift } => {
                let trace_domain_size = self.input.message_trace_domain_size()?;
                let message_row_ordinal = u64::try_from(row_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?
                    / self.input.trace_packing_factor;
                i128::from(message_row_ordinal >= trace_domain_size - row_shift)
            }
        };
        canonical_proof_base_field_integer(integer_value)
    }

    #[cfg(test)]
    fn column_trace_values(&self, column_ordinal: u32) -> Result<Vec<u64>, RelationPlanError> {
        let trace_domain_size = usize::try_from(self.input.relation_trace_domain_size()?)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        (0..trace_domain_size)
            .map(|row_ordinal| self.trace_value(column_ordinal, row_ordinal))
            .collect()
    }

    pub(crate) fn column_trace_field_values(
        &self,
        column_ordinal: u32,
    ) -> Result<Vec<ProofBaseFieldElement>, RelationPlanError> {
        let trace_domain_size = usize::try_from(self.input.relation_trace_domain_size()?)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        (0..trace_domain_size)
            .map(|row_ordinal| {
                self.trace_value(column_ordinal, row_ordinal)
                    .and_then(|value| {
                        ProofBaseFieldElement::from_canonical(value)
                            .map_err(|_| RelationPlanError::InvalidColumn)
                    })
            })
            .collect()
    }

    fn integer_value(
        &self,
        recipe: &CommittedMaterialIntegerRecipe,
        row_ordinal: usize,
    ) -> Result<i128, RelationPlanError> {
        match recipe {
            CommittedMaterialIntegerRecipe::Constant(value) => Ok(*value),
            CommittedMaterialIntegerRecipe::Packed {
                ordered_lane_sources,
            } => {
                let trace_packing_factor = usize::try_from(self.input.trace_packing_factor)
                    .map_err(|_| RelationPlanError::CountOverflow)?;
                if ordered_lane_sources.len() != trace_packing_factor {
                    return Err(RelationPlanError::InvalidColumn);
                }
                let packed_lane_ordinal = row_ordinal % trace_packing_factor;
                let message_row_ordinal = row_ordinal / trace_packing_factor;
                self.integer_value(
                    ordered_lane_sources
                        .get(packed_lane_ordinal)
                        .ok_or(RelationPlanError::InvalidColumn)?,
                    message_row_ordinal,
                )
            }
            CommittedMaterialIntegerRecipe::BoundDigit {
                logical_root_ordinal,
                physical_half_ordinal,
                material_digit_ordinal,
            } => self.material_digit(
                *logical_root_ordinal,
                *physical_half_ordinal,
                *material_digit_ordinal,
                row_ordinal,
            ),
            CommittedMaterialIntegerRecipe::ComparatorDifference {
                logical_root_ordinal,
                physical_half_ordinal,
                material_digit_ordinal,
                modulus_ordinal,
            } => self.comparator_difference(
                *logical_root_ordinal,
                *physical_half_ordinal,
                *material_digit_ordinal,
                *modulus_ordinal,
                row_ordinal,
            ),
            CommittedMaterialIntegerRecipe::VssQuotient {
                sharing_limb_ordinal,
                recipient_ordinal,
                physical_half_ordinal,
            } => self.vss_quotient(
                *sharing_limb_ordinal,
                *recipient_ordinal,
                *physical_half_ordinal,
                row_ordinal,
            ),
            CommittedMaterialIntegerRecipe::AggregateQuotient {
                sharing_limb_ordinal,
                physical_half_ordinal,
            } => {
                self.aggregate_quotient(*sharing_limb_ordinal, *physical_half_ordinal, row_ordinal)
            }
            CommittedMaterialIntegerRecipe::ComparatorBorrow {
                logical_root_ordinal,
                physical_half_ordinal,
                modulus_ordinal,
            } => Ok(i128::from(self.comparator_borrow(
                *logical_root_ordinal,
                *physical_half_ordinal,
                *modulus_ordinal,
                row_ordinal,
            )?)),
        }
    }

    fn material_digit(
        &self,
        logical_root_ordinal: usize,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<i128, RelationPlanError> {
        self.ordered_roots
            .get(logical_root_ordinal)
            .ok_or(RelationPlanError::InvalidRoot)?
            .material_digit(physical_half_ordinal, material_digit_ordinal, row_ordinal)
            .map(i128::from)
    }

    fn material_value(
        &self,
        logical_root_ordinal: usize,
        coefficient_ordinal: usize,
    ) -> Result<i128, RelationPlanError> {
        let trace_domain_size = usize::try_from(self.input.message_trace_domain_size()?)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let physical_half_ordinal = coefficient_ordinal / trace_domain_size;
        let row_ordinal = coefficient_ordinal % trace_domain_size;
        let low =
            self.material_digit(logical_root_ordinal, physical_half_ordinal, 0, row_ordinal)?;
        let high =
            self.material_digit(logical_root_ordinal, physical_half_ordinal, 1, row_ordinal)?;
        low.checked_add(
            high.checked_mul(i128::from(MATERIAL_DIGIT_RADIX))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?,
        )
        .ok_or(RelationPlanError::IntegerBoundOverflow)
    }

    fn comparator_borrow(
        &self,
        logical_root_ordinal: usize,
        physical_half_ordinal: usize,
        modulus_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<u64, RelationPlanError> {
        let modulus = *self
            .resolved_moduli
            .get(modulus_ordinal)
            .ok_or(RelationPlanError::MissingModulus)?;
        let maximum_digits = fixed_material_digits(modulus - 1)?;
        let low =
            self.material_digit(logical_root_ordinal, physical_half_ordinal, 0, row_ordinal)?;
        Ok(u64::from(low > i128::from(maximum_digits[0])))
    }

    fn comparator_difference(
        &self,
        logical_root_ordinal: usize,
        physical_half_ordinal: usize,
        material_digit_ordinal: usize,
        modulus_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<i128, RelationPlanError> {
        let modulus = *self
            .resolved_moduli
            .get(modulus_ordinal)
            .ok_or(RelationPlanError::MissingModulus)?;
        let maximum_digits = fixed_material_digits(modulus - 1)?;
        let value = self.material_digit(
            logical_root_ordinal,
            physical_half_ordinal,
            material_digit_ordinal,
            row_ordinal,
        )?;
        let borrow = i128::from(self.comparator_borrow(
            logical_root_ordinal,
            physical_half_ordinal,
            modulus_ordinal,
            row_ordinal,
        )?);
        let difference = match material_digit_ordinal {
            0 => i128::from(maximum_digits[0]) - value + i128::from(MATERIAL_DIGIT_RADIX) * borrow,
            1 => i128::from(maximum_digits[1]) - value - borrow,
            _ => return Err(RelationPlanError::InvalidColumn),
        };
        if difference < 0 {
            return Err(RelationPlanError::InvalidColumn);
        }
        Ok(difference)
    }

    fn vss_quotient(
        &self,
        sharing_limb_ordinal: usize,
        recipient_ordinal: usize,
        physical_half_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<i128, RelationPlanError> {
        let threshold = usize::from(self.input.threshold);
        let participant_count = usize::from(self.input.participant_count);
        let roots_per_limb = threshold
            .checked_add(participant_count)
            .ok_or(RelationPlanError::CountOverflow)?;
        let first_root = sharing_limb_ordinal
            .checked_mul(roots_per_limb)
            .ok_or(RelationPlanError::CountOverflow)?;
        let target_coefficient_ordinal = physical_half_ordinal
            .checked_mul(
                usize::try_from(self.input.message_trace_domain_size()?)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .and_then(|offset| offset.checked_add(row_ordinal))
            .ok_or(RelationPlanError::CountOverflow)?;
        let mut residual = 0_i128;
        for coefficient_ordinal in 0..threshold {
            let exponent = u64::try_from(recipient_ordinal)
                .ok()
                .and_then(|recipient| {
                    u64::try_from(coefficient_ordinal)
                        .ok()
                        .and_then(|coefficient| recipient.checked_mul(coefficient))
                })
                .and_then(|product| product.checked_mul(self.input.point_stride().ok()?))
                .ok_or(RelationPlanError::CountOverflow)?;
            residual = residual
                .checked_add(self.monomial_action_value(
                    first_root + coefficient_ordinal,
                    exponent,
                    target_coefficient_ordinal,
                )?)
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        }
        residual = residual
            .checked_sub(self.material_value(
                first_root + threshold + recipient_ordinal,
                target_coefficient_ordinal,
            )?)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        self.exact_modulus_quotient(sharing_limb_ordinal, residual)
    }

    fn aggregate_quotient(
        &self,
        sharing_limb_ordinal: usize,
        physical_half_ordinal: usize,
        row_ordinal: usize,
    ) -> Result<i128, RelationPlanError> {
        let participant_count = usize::from(self.input.participant_count);
        let roots_per_limb = participant_count
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        let first_root = sharing_limb_ordinal
            .checked_mul(roots_per_limb)
            .ok_or(RelationPlanError::CountOverflow)?;
        let coefficient_ordinal = physical_half_ordinal
            .checked_mul(
                usize::try_from(self.input.message_trace_domain_size()?)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
            )
            .and_then(|offset| offset.checked_add(row_ordinal))
            .ok_or(RelationPlanError::CountOverflow)?;
        let mut residual = 0_i128;
        for source_ordinal in 0..participant_count {
            residual = residual
                .checked_add(self.material_value(first_root + source_ordinal, coefficient_ordinal)?)
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        }
        residual = residual
            .checked_sub(self.material_value(first_root + participant_count, coefficient_ordinal)?)
            .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        let quotient = self.exact_modulus_quotient(sharing_limb_ordinal, residual)?;
        if quotient < 0 {
            return Err(RelationPlanError::InvalidColumn);
        }
        Ok(quotient)
    }

    fn monomial_action_value(
        &self,
        logical_root_ordinal: usize,
        exponent: u64,
        target_coefficient_ordinal: usize,
    ) -> Result<i128, RelationPlanError> {
        let ring_degree = self.input.ring_degree;
        let reduced_exponent = exponent
            % ring_degree
                .checked_mul(2)
                .ok_or(RelationPlanError::CountOverflow)?;
        let unsigned_exponent = reduced_exponent % ring_degree;
        let target = u64::try_from(target_coefficient_ordinal)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        let wraps_below_zero = target < unsigned_exponent;
        let source = if wraps_below_zero {
            target
                .checked_add(ring_degree)
                .and_then(|value| value.checked_sub(unsigned_exponent))
                .ok_or(RelationPlanError::CountOverflow)?
        } else {
            target - unsigned_exponent
        };
        let value = self.material_value(
            logical_root_ordinal,
            usize::try_from(source).map_err(|_| RelationPlanError::CountOverflow)?,
        )?;
        Ok(if (reduced_exponent >= ring_degree) ^ wraps_below_zero {
            -value
        } else {
            value
        })
    }

    fn exact_modulus_quotient(
        &self,
        modulus_ordinal: usize,
        residual: i128,
    ) -> Result<i128, RelationPlanError> {
        let modulus = i128::from(
            *self
                .resolved_moduli
                .get(modulus_ordinal)
                .ok_or(RelationPlanError::MissingModulus)?,
        );
        if residual % modulus != 0 {
            return Err(RelationPlanError::InvalidColumn);
        }
        Ok(residual / modulus)
    }
}

/// Prepared production-geometry source replay for the opt-in primitive
/// measurement artifact. Setup is kept outside the timed operation.
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) struct SelectedVssSourceReplayMeasurement {
    provider: CommittedMaterialTraceWitnessProvider<PrimitiveMeasurementCommittedMaterialSource>,
    trace_domain: crate::bgv::proof_suite::ProofEvaluationDomain,
    column_ordinal: u32,
    prover_column_degree_bound_exclusive: usize,
    trace_value_count: usize,
}

#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) struct VssRelationReplayRetainedRecipeGroup {
    pub(crate) coefficients: Vec<Zeroizing<Vec<ProofBaseFieldElement>>>,
    pub(crate) checksum: u64,
}

#[cfg(feature = "primitive-measurement-evidence")]
impl SelectedVssSourceReplayMeasurement {
    pub(crate) fn prepare() -> Result<Self, String> {
        let input = crate::bgv::proof_suite::selected_committed_material_relation_plan_input()
            .map_err(|_| "selected VSS source-replay input is invalid".to_owned())?;
        let context = crate::bgv::proof_suite::selected_relation_plan_check_context(
            crate::foundation::ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .ok_or_else(|| "selected VSS source-replay context is absent".to_owned())?;
        Self::prepare_for_relation(input, context)
    }

    pub(crate) fn prepare_relation_replay_candidate(
        trace_packing_factor: u64,
        opening_degree_bound_exclusive: u64,
    ) -> Result<Self, String> {
        let (input, context) = Self::relation_replay_candidate_definition(
            trace_packing_factor,
            opening_degree_bound_exclusive,
        )?;
        Self::prepare_for_relation(input, context)
    }

    pub(crate) fn validated_relation_replay_candidate(
        trace_packing_factor: u64,
        opening_degree_bound_exclusive: u64,
    ) -> Result<
        (
            crate::bgv::proof_suite::ValidatedRelationPlanArtifact,
            RelationPlanCheckContext,
        ),
        String,
    > {
        let (_, artifact, context) = Self::validated_relation_replay_candidate_with_input(
            trace_packing_factor,
            opening_degree_bound_exclusive,
        )?;
        Ok((artifact, context))
    }

    pub(crate) fn validated_relation_replay_candidate_with_input(
        trace_packing_factor: u64,
        opening_degree_bound_exclusive: u64,
    ) -> Result<
        (
            CommittedMaterialRelationPlanInput,
            crate::bgv::proof_suite::ValidatedRelationPlanArtifact,
            RelationPlanCheckContext,
        ),
        String,
    > {
        let (input, context) = Self::relation_replay_candidate_definition(
            trace_packing_factor,
            opening_degree_bound_exclusive,
        )?;
        let compiled =
            super::vss_share_linkage::compile_vss_share_linkage_relation_plan(&input, &context)
                .map_err(|error| {
                    format!("VSS relation-replay candidate relation is invalid: {error:?}")
                })?;
        let artifact = crate::bgv::proof_suite::ValidatedRelationPlanArtifact::from_primitive_measurement_compiled_plan(
            compiled,
            &context,
        )
        .map_err(|error| {
            format!("VSS relation-replay candidate artifact is invalid: {error:?}")
        })?;
        Ok((input, artifact, context))
    }

    fn relation_replay_candidate_definition(
        trace_packing_factor: u64,
        opening_degree_bound_exclusive: u64,
    ) -> Result<(CommittedMaterialRelationPlanInput, RelationPlanCheckContext), String> {
        let mut input = crate::bgv::proof_suite::selected_committed_material_relation_plan_input()
            .map_err(|_| "VSS relation-replay candidate input is invalid".to_owned())?;
        input.trace_packing_factor = trace_packing_factor;
        input.opening_degree_bound_exclusive = opening_degree_bound_exclusive;
        let mut context = crate::bgv::proof_suite::selected_relation_plan_check_context(
            crate::foundation::ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .ok_or_else(|| "VSS relation-replay candidate context is absent".to_owned())?;
        let quotient_component_count = u64::from(context.quotient_component_count);
        let rounded_mask_degree = quotient_component_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(input.trace_mask_degree_bound_exclusive))
            .and_then(|degree| degree.checked_add(quotient_component_count.checked_sub(1)?))
            .and_then(|degree| degree.checked_div(quotient_component_count))
            .ok_or_else(|| "VSS relation-replay quotient mask degree overflowed".to_owned())?;
        context.quotient_component_degree_bound_exclusive = input
            .relation_trace_domain_size()
            .map_err(|_| "VSS relation-replay candidate trace domain is invalid".to_owned())?
            .checked_add(rounded_mask_degree)
            .and_then(|stride| {
                stride.checked_add(
                    u64::from(context.phase_column_query_coordinate_count)
                        .checked_add(u64::from(context.out_of_domain_point_count))?,
                )
            })
            .ok_or_else(|| "VSS relation-replay quotient degree overflowed".to_owned())?;
        Ok((input, context))
    }

    fn prepare_for_relation(
        input: CommittedMaterialRelationPlanInput,
        context: RelationPlanCheckContext,
    ) -> Result<Self, String> {
        let resolved_moduli = input
            .validate(&context)
            .map_err(|error| format!("selected VSS source-replay moduli are invalid: {error:?}"))?;
        let roots_per_limb = usize::from(input.threshold)
            .checked_add(usize::from(input.participant_count))
            .ok_or_else(|| "selected VSS root count overflowed".to_owned())?;
        let canonical_coefficient_count = usize::try_from(input.ring_degree)
            .map_err(|_| "selected VSS ring degree exceeds usize".to_owned())?;
        let expected_root_count = resolved_moduli
            .len()
            .checked_mul(roots_per_limb)
            .ok_or_else(|| "selected VSS root count overflowed".to_owned())?;
        let mut ordered_sources = Vec::new();
        ordered_sources
            .try_reserve_exact(expected_root_count)
            .map_err(|_| "selected VSS source catalog allocation failed".to_owned())?;
        let point_stride = input
            .point_stride()
            .map_err(|_| "selected VSS point stride is invalid".to_owned())?;
        for (modulus_ordinal, (_, modulus)) in resolved_moduli.iter().copied().enumerate() {
            let mut coefficient_messages = Vec::new();
            coefficient_messages
                .try_reserve_exact(usize::from(input.threshold))
                .map_err(|_| "selected VSS coefficient catalog allocation failed".to_owned())?;
            for coefficient_ordinal in 0..usize::from(input.threshold) {
                let mut message = Vec::new();
                message
                    .try_reserve_exact(canonical_coefficient_count)
                    .map_err(|_| "selected VSS coefficient allocation failed".to_owned())?;
                for ring_coefficient_ordinal in 0..canonical_coefficient_count {
                    let seed = u128::try_from(modulus_ordinal + 1)
                        .ok()
                        .and_then(|value| value.checked_mul(1_000_003))
                        .and_then(|value| {
                            value
                                .checked_add(u128::try_from(coefficient_ordinal + 1).ok()? * 65_537)
                        })
                        .and_then(|value| {
                            value.checked_add(
                                u128::try_from(ring_coefficient_ordinal + 1).ok()? * 257,
                            )
                        })
                        .ok_or_else(|| "selected VSS coefficient seed overflowed".to_owned())?;
                    let canonical = u64::try_from(seed % u128::from(modulus - 1) + 1)
                        .map_err(|_| "selected VSS coefficient does not fit u64".to_owned())?;
                    message.push(canonical);
                }
                coefficient_messages.push(message.into_boxed_slice());
            }
            for message in &coefficient_messages {
                ordered_sources.push(
                    PrimitiveMeasurementCommittedMaterialSource::new(message.clone(), modulus)
                        .map_err(|_| {
                            "selected VSS measurement coefficient is invalid".to_owned()
                        })?,
                );
            }
            for recipient_ordinal in 0..usize::from(input.participant_count) {
                let mut share = vec![0_u64; canonical_coefficient_count];
                for (coefficient_ordinal, message) in coefficient_messages.iter().enumerate() {
                    let exponent = u64::try_from(recipient_ordinal)
                        .ok()
                        .and_then(|recipient| {
                            u64::try_from(coefficient_ordinal)
                                .ok()
                                .and_then(|coefficient| recipient.checked_mul(coefficient))
                        })
                        .and_then(|product| product.checked_mul(point_stride))
                        .ok_or_else(|| "selected VSS share exponent overflowed".to_owned())?;
                    let reduced_exponent = exponent
                        % input
                            .ring_degree
                            .checked_mul(2)
                            .ok_or_else(|| "selected VSS action domain overflowed".to_owned())?;
                    let unsigned_exponent = reduced_exponent % input.ring_degree;
                    for (target_ordinal, destination) in share.iter_mut().enumerate() {
                        let target = u64::try_from(target_ordinal)
                            .map_err(|_| "selected VSS target ordinal exceeds u64".to_owned())?;
                        let wraps_below_zero = target < unsigned_exponent;
                        let source_ordinal = if wraps_below_zero {
                            target
                                .checked_add(input.ring_degree)
                                .and_then(|value| value.checked_sub(unsigned_exponent))
                                .ok_or_else(|| {
                                    "selected VSS source ordinal overflowed".to_owned()
                                })?
                        } else {
                            target - unsigned_exponent
                        };
                        let value = *message
                            .get(usize::try_from(source_ordinal).map_err(|_| {
                                "selected VSS source ordinal exceeds usize".to_owned()
                            })?)
                            .ok_or_else(|| {
                                "selected VSS source coefficient is absent".to_owned()
                            })?;
                        let acted = if (reduced_exponent >= input.ring_degree) ^ wraps_below_zero {
                            if value == 0 { 0 } else { modulus - value }
                        } else {
                            value
                        };
                        *destination = u64::try_from(
                            (u128::from(*destination) + u128::from(acted)) % u128::from(modulus),
                        )
                        .map_err(|_| {
                            "selected VSS share coefficient does not fit u64".to_owned()
                        })?;
                    }
                }
                ordered_sources.push(
                    PrimitiveMeasurementCommittedMaterialSource::new(
                        share.into_boxed_slice(),
                        modulus,
                    )
                    .map_err(|_| "selected VSS measurement share is invalid".to_owned())?,
                );
            }
        }
        if ordered_sources.len() != expected_root_count {
            return Err("selected VSS source catalog is incomplete".to_owned());
        }
        super::vss_share_linkage::compile_vss_share_linkage_relation_plan(&input, &context)
            .map_err(|error| {
                format!("selected VSS source-replay relation is invalid: {error:?}")
            })?;
        let layout = derive_vss_share_linkage_trace_witness_layout(&input, &context)
            .map_err(|error| format!("selected VSS trace-witness layout is invalid: {error:?}"))?;
        let provider = CommittedMaterialTraceWitnessProvider {
            input: CommittedMaterialTraceWitnessInput::from_relation_input(&input),
            ordered_roots: ordered_sources.into_boxed_slice(),
            resolved_moduli: layout
                .resolved_moduli
                .into_iter()
                .map(|(_, modulus)| modulus)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            ordered_recipes: layout.ordered_recipes,
            relation_plan_hash: layout.relation_plan_hash,
        };

        fn contains_vss_quotient(source: &CommittedMaterialIntegerRecipe) -> bool {
            match source {
                CommittedMaterialIntegerRecipe::Packed {
                    ordered_lane_sources,
                } => ordered_lane_sources.iter().any(contains_vss_quotient),
                CommittedMaterialIntegerRecipe::VssQuotient { .. } => true,
                _ => false,
            }
        }

        let column_ordinal = provider
            .ordered_recipes
            .iter()
            .find_map(|(column_ordinal, recipe)| match recipe {
                CommittedMaterialColumnRecipe::Integer(source)
                | CommittedMaterialColumnRecipe::TernaryDigit { source, .. }
                    if contains_vss_quotient(source) =>
                {
                    Some(*column_ordinal)
                }
                _ => None,
            })
            .ok_or_else(|| "selected VSS quotient replay recipe is absent".to_owned())?;
        let trace_value_count = usize::try_from(
            input
                .relation_trace_domain_size()
                .map_err(|_| "selected VSS source-replay trace domain is invalid".to_owned())?,
        )
        .map_err(|_| "selected VSS source-replay trace domain exceeds usize".to_owned())?;
        let trace_domain =
            crate::bgv::proof_suite::ProofEvaluationDomain::new_subgroup(trace_value_count)
                .map_err(|_| "selected VSS source-replay trace domain is invalid".to_owned())?;
        let prover_column_degree_bound_exclusive = usize::try_from(
            input
                .prover_column_degree_bound_exclusive()
                .map_err(|_| "selected VSS source-replay degree bound is invalid".to_owned())?,
        )
        .map_err(|_| "selected VSS source-replay degree bound exceeds usize".to_owned())?;
        Ok(Self {
            provider,
            trace_domain,
            column_ordinal,
            prover_column_degree_bound_exclusive,
            trace_value_count,
        })
    }

    pub(crate) fn logical_root_count(&self) -> usize {
        self.provider.logical_root_count()
    }

    pub(crate) const fn trace_value_count(&self) -> usize {
        self.trace_value_count
    }

    pub(crate) const fn trace_packing_factor(&self) -> u64 {
        self.provider.input.trace_packing_factor
    }

    pub(crate) const fn column_ordinal(&self) -> u32 {
        self.column_ordinal
    }

    pub(crate) fn production_recipe_count(&self) -> usize {
        self.provider.ordered_recipes.len()
    }

    pub(crate) const fn relation_plan_hash(&self) -> [u8; 64] {
        self.provider.relation_plan_hash
    }

    pub(crate) const fn prover_column_degree_bound_exclusive(&self) -> usize {
        self.prover_column_degree_bound_exclusive
    }

    pub(crate) fn nonzero_source_coefficient_count(&self) -> Result<u64, String> {
        self.provider
            .ordered_roots
            .iter()
            .try_fold(0_u64, |total, source| {
                let source_count = u64::try_from(
                    source
                        .canonical_message
                        .iter()
                        .filter(|coefficient| **coefficient != 0)
                        .count(),
                )
                .map_err(|_| "selected VSS nonzero coefficient count exceeds u64".to_owned())?;
                total
                    .checked_add(source_count)
                    .ok_or_else(|| "selected VSS nonzero coefficient count overflowed".to_owned())
            })
    }

    pub(crate) fn retained_input_byte_length(&self) -> Result<u64, String> {
        let source_allocation_byte_length =
            self.provider
                .ordered_roots
                .iter()
                .try_fold(0_u64, |total, source| {
                    let coefficient_byte_length = u64::try_from(source.canonical_message.len())
                        .ok()
                        .and_then(|count| count.checked_mul(size_of::<u64>() as u64))
                        .ok_or_else(|| {
                            "selected VSS measurement source size overflowed".to_owned()
                        })?;
                    let source_byte_length = u64::try_from(size_of::<
                        PrimitiveMeasurementCommittedMaterialSource,
                    >())
                    .ok()
                    .and_then(|fixed| fixed.checked_add(coefficient_byte_length))
                    .ok_or_else(|| "selected VSS measurement source size overflowed".to_owned())?;
                    total.checked_add(source_byte_length).ok_or_else(|| {
                        "selected VSS measurement source catalog overflowed".to_owned()
                    })
                })?;
        let structure_byte_length = self
            .provider
            .structure_memory_accounting()
            .map_err(|_| "selected VSS measurement recipe accounting failed".to_owned())?
            .total_byte_length();
        u64::try_from(size_of::<Self>())
            .ok()
            .and_then(|fixed| fixed.checked_add(source_allocation_byte_length))
            .and_then(|total| total.checked_add(structure_byte_length))
            .ok_or_else(|| "selected VSS measurement retained input size overflowed".to_owned())
    }

    pub(crate) fn replay_once(&self) -> Result<Vec<ProofBaseFieldElement>, String> {
        let mut rows = self
            .provider
            .column_trace_field_values(self.column_ordinal)
            .map_err(|_| "selected VSS source-replay rows are invalid".to_owned())?;
        if rows.len() != self.trace_value_count {
            return Err("selected VSS source-replay row count is inconsistent".to_owned());
        }
        self.trace_domain
            .interpolate_base_polynomial_in_place(&mut rows)
            .map_err(|_| "selected VSS source-replay interpolation failed".to_owned())?;
        Ok(rows)
    }

    pub(crate) fn replay_production_recipe_catalog_once(&self) -> Result<u64, String> {
        let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
        for (recipe_ordinal, (column_ordinal, _)) in
            self.provider.ordered_recipes.iter().enumerate()
        {
            let mut coefficients = self
                .provider
                .column_trace_field_values(*column_ordinal)
                .map_err(|_| "selected VSS production replay rows are invalid".to_owned())?;
            if coefficients.len() != self.trace_value_count {
                return Err("selected VSS production replay row count is inconsistent".to_owned());
            }
            self.trace_domain
                .interpolate_base_polynomial_in_place(&mut coefficients)
                .map_err(|_| "selected VSS production replay interpolation failed".to_owned())?;
            let middle_ordinal = coefficients.len() / 2;
            let sampled_value = coefficients
                .first()
                .ok_or_else(|| "selected VSS production replay is empty".to_owned())?
                .canonical()
                ^ coefficients[middle_ordinal].canonical().rotate_left(21)
                ^ coefficients
                    .last()
                    .ok_or_else(|| "selected VSS production replay is empty".to_owned())?
                    .canonical()
                    .rotate_left(42)
                ^ u64::from(*column_ordinal).rotate_left(7)
                ^ u64::try_from(coefficients.len())
                    .map_err(|_| "production replay value count exceeds u64".to_owned())?;
            let ordinal = u64::try_from(recipe_ordinal)
                .map_err(|_| "production replay recipe ordinal exceeds u64".to_owned())?;
            checksum = checksum
                .rotate_left(17)
                .wrapping_add(sampled_value)
                .wrapping_add(ordinal.wrapping_mul(0x9e37_79b1_85eb_ca87))
                .wrapping_mul(0x1000_0000_01b3);
        }
        Ok(checksum)
    }

    pub(crate) fn materialize_retained_recipe_group(
        &self,
        retained_recipe_count: usize,
    ) -> Result<VssRelationReplayRetainedRecipeGroup, String> {
        if retained_recipe_count == 0 || retained_recipe_count > self.provider.ordered_recipes.len()
        {
            return Err("VSS retained replay group width is invalid".to_owned());
        }
        let mut retained_coefficients = Vec::new();
        retained_coefficients
            .try_reserve_exact(retained_recipe_count)
            .map_err(|_| "VSS retained replay group allocation failed".to_owned())?;
        for (column_ordinal, _) in self
            .provider
            .ordered_recipes
            .iter()
            .take(retained_recipe_count)
        {
            let mut coefficients = self
                .provider
                .column_trace_field_values(*column_ordinal)
                .map_err(|_| "VSS retained replay rows are invalid".to_owned())?;
            if coefficients.len() != self.trace_value_count {
                return Err("VSS retained replay row count is inconsistent".to_owned());
            }
            self.trace_domain
                .interpolate_base_polynomial_in_place(&mut coefficients)
                .map_err(|_| "VSS retained replay interpolation failed".to_owned())?;
            coefficients.resize(
                self.prover_column_degree_bound_exclusive,
                ProofBaseFieldElement::ZERO,
            );
            retained_coefficients.push(Zeroizing::new(coefficients));
        }
        let checksum = self.retained_recipe_group_checksum(&retained_coefficients)?;
        Ok(VssRelationReplayRetainedRecipeGroup {
            coefficients: retained_coefficients,
            checksum,
        })
    }

    fn retained_recipe_group_checksum(
        &self,
        retained_coefficients: &[Zeroizing<Vec<ProofBaseFieldElement>>],
    ) -> Result<u64, String> {
        if retained_coefficients.is_empty()
            || retained_coefficients.len() > self.provider.ordered_recipes.len()
        {
            return Err("VSS retained replay group width is invalid".to_owned());
        }
        let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
        for (recipe_ordinal, (coefficients, (column_ordinal, _))) in retained_coefficients
            .iter()
            .zip(self.provider.ordered_recipes.iter())
            .enumerate()
        {
            if coefficients.len() != self.prover_column_degree_bound_exclusive {
                return Err("VSS retained replay coefficient count is inconsistent".to_owned());
            }
            let middle_ordinal = coefficients.len() / 2;
            let sampled_value = coefficients
                .first()
                .ok_or_else(|| "VSS retained replay coefficients are empty".to_owned())?
                .canonical()
                ^ coefficients[middle_ordinal].canonical().rotate_left(21)
                ^ coefficients
                    .last()
                    .ok_or_else(|| "VSS retained replay coefficients are empty".to_owned())?
                    .canonical()
                    .rotate_left(42)
                ^ u64::from(*column_ordinal).rotate_left(7)
                ^ u64::try_from(coefficients.len())
                    .map_err(|_| "VSS retained replay value count exceeds u64".to_owned())?;
            let ordinal = u64::try_from(recipe_ordinal)
                .map_err(|_| "VSS retained replay recipe ordinal exceeds u64".to_owned())?;
            checksum = checksum
                .rotate_left(17)
                .wrapping_add(sampled_value)
                .wrapping_add(ordinal.wrapping_mul(0x9e37_79b1_85eb_ca87))
                .wrapping_mul(0x1000_0000_01b3);
        }
        for hash_word in self.relation_plan_hash().chunks_exact(size_of::<u64>()) {
            let hash_word = u64::from_le_bytes(
                hash_word
                    .try_into()
                    .map_err(|_| "VSS retained replay plan hash is malformed".to_owned())?,
            );
            checksum = checksum
                .rotate_left(17)
                .wrapping_add(hash_word)
                .wrapping_mul(0x1000_0000_01b3);
        }
        Ok(checksum)
    }

    pub(crate) fn materialize_retained_recipe_group_once(
        &self,
        retained_recipe_count: usize,
    ) -> Result<u64, String> {
        let retained_group = self.materialize_retained_recipe_group(retained_recipe_count)?;
        core::hint::black_box(&retained_group.coefficients);
        Ok(retained_group.checksum)
    }
}

struct CommittedMaterialTraceWitnessLayoutBuilder<'plan> {
    variant: &'plan RelationPlanVariant,
    trace_packing_factor: usize,
    next_column_ordinal: usize,
    ordered_recipes: Vec<(u32, CommittedMaterialColumnRecipe)>,
}

impl<'plan> CommittedMaterialTraceWitnessLayoutBuilder<'plan> {
    fn new(
        variant: &'plan RelationPlanVariant,
        trace_packing_factor: u64,
    ) -> Result<Self, RelationPlanError> {
        let trace_packing_factor = usize::try_from(trace_packing_factor)
            .ok()
            .filter(|factor| *factor > 0 && factor.is_power_of_two())
            .ok_or(RelationPlanError::InvalidDomain)?;
        let recipe_count = variant
            .ordered_columns
            .iter()
            .filter(|column| matches!(column.origin, RelationColumnOrigin::Prover))
            .count();
        let mut ordered_recipes = Vec::new();
        ordered_recipes
            .try_reserve_exact(recipe_count)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        Ok(Self {
            variant,
            trace_packing_factor,
            next_column_ordinal: 0,
            ordered_recipes,
        })
    }

    fn consume_bound_root(&mut self, column_count: usize) -> Result<(), RelationPlanError> {
        if column_count == 0 {
            return Err(RelationPlanError::InvalidColumn);
        }
        for _ in 0..column_count {
            let column = self
                .variant
                .ordered_columns
                .get(self.next_column_ordinal)
                .ok_or(RelationPlanError::InvalidColumn)?;
            if !matches!(column.origin, RelationColumnOrigin::BoundTree { .. }) {
                return Err(RelationPlanError::InvalidColumn);
            }
            self.next_column_ordinal = self
                .next_column_ordinal
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
        }
        Ok(())
    }

    fn push_recipe(
        &mut self,
        recipe: CommittedMaterialColumnRecipe,
    ) -> Result<(), RelationPlanError> {
        let column = self
            .variant
            .ordered_columns
            .get(self.next_column_ordinal)
            .ok_or(RelationPlanError::InvalidColumn)?;
        if !matches!(column.origin, RelationColumnOrigin::Prover) {
            return Err(RelationPlanError::InvalidColumn);
        }
        let ordinal = u32::try_from(self.next_column_ordinal)
            .map_err(|_| RelationPlanError::CountOverflow)?;
        if self
            .ordered_recipes
            .last()
            .is_some_and(|(previous_ordinal, _)| *previous_ordinal >= ordinal)
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        self.ordered_recipes.push((ordinal, recipe));
        self.next_column_ordinal = self
            .next_column_ordinal
            .checked_add(1)
            .ok_or(RelationPlanError::CountOverflow)?;
        Ok(())
    }

    fn add_ternary_digits(
        &mut self,
        source: CommittedMaterialIntegerRecipe,
        ternary_digit_count: usize,
        offset: u64,
    ) -> Result<(), RelationPlanError> {
        if ternary_digit_count == 0 {
            return Err(RelationPlanError::InvalidColumn);
        }
        let mut source = Some(source);
        for digit_ordinal in 0..ternary_digit_count {
            let digit_source = if digit_ordinal + 1 == ternary_digit_count {
                source.take().ok_or(RelationPlanError::InvalidColumn)?
            } else {
                source
                    .as_ref()
                    .ok_or(RelationPlanError::InvalidColumn)?
                    .clone()
            };
            self.push_recipe(CommittedMaterialColumnRecipe::TernaryDigit {
                source: digit_source,
                digit_ordinal,
                offset,
            })?;
        }
        Ok(())
    }

    fn packed_source(
        &self,
        actual_sources: impl IntoIterator<Item = CommittedMaterialIntegerRecipe>,
        padding_source: CommittedMaterialIntegerRecipe,
    ) -> Result<CommittedMaterialIntegerRecipe, RelationPlanError> {
        let mut ordered_lane_sources = Vec::with_capacity(self.trace_packing_factor);
        ordered_lane_sources.extend(actual_sources);
        if ordered_lane_sources.is_empty() || ordered_lane_sources.len() > self.trace_packing_factor
        {
            return Err(RelationPlanError::InvalidColumn);
        }
        ordered_lane_sources.resize(self.trace_packing_factor, padding_source);
        Ok(CommittedMaterialIntegerRecipe::Packed {
            ordered_lane_sources: ordered_lane_sources.into_boxed_slice(),
        })
    }

    fn packed_material_source(
        &self,
        first_logical_root_ordinal: usize,
        root_count: usize,
        physical_column_ordinal: usize,
    ) -> Result<CommittedMaterialIntegerRecipe, RelationPlanError> {
        let physical_half_ordinal = physical_column_ordinal % 2;
        let material_digit_ordinal = physical_column_ordinal / 2;
        self.packed_source(
            (0..root_count).map(|lane_ordinal| CommittedMaterialIntegerRecipe::BoundDigit {
                logical_root_ordinal: first_logical_root_ordinal + lane_ordinal,
                physical_half_ordinal,
                material_digit_ordinal,
            }),
            CommittedMaterialIntegerRecipe::Constant(0),
        )
    }

    fn add_material_group(
        &mut self,
        first_logical_root_ordinal: usize,
        root_count: usize,
        modulus_ordinal: usize,
        modulus: u64,
    ) -> Result<(), RelationPlanError> {
        if root_count == 0 || root_count > self.trace_packing_factor {
            return Err(RelationPlanError::InvalidRoot);
        }
        for _ in 0..root_count {
            self.consume_bound_root(4)?;
        }
        let maximum_digits = fixed_material_digits(modulus - 1)?;
        let high_digit_ternary_digit_count =
            minimum_unsigned_ternary_digit_count(maximum_digits[1]);
        for physical_column_ordinal in 0..4 {
            self.push_recipe(CommittedMaterialColumnRecipe::Integer(
                self.packed_material_source(
                    first_logical_root_ordinal,
                    root_count,
                    physical_column_ordinal,
                )?,
            ))?;
        }
        for physical_half_ordinal in 0..2 {
            self.add_ternary_digits(
                self.packed_material_source(
                    first_logical_root_ordinal,
                    root_count,
                    physical_half_ordinal,
                )?,
                MATERIAL_DIGIT_TERNARY_DIGIT_COUNT,
                0,
            )?;
            self.add_ternary_digits(
                self.packed_material_source(
                    first_logical_root_ordinal,
                    root_count,
                    2 + physical_half_ordinal,
                )?,
                high_digit_ternary_digit_count,
                0,
            )?;
            for (material_digit_ordinal, ternary_digit_count) in [
                (0, MATERIAL_DIGIT_TERNARY_DIGIT_COUNT),
                (1, high_digit_ternary_digit_count),
            ] {
                let difference = self.packed_source(
                    (0..root_count).map(|lane_ordinal| {
                        CommittedMaterialIntegerRecipe::ComparatorDifference {
                            logical_root_ordinal: first_logical_root_ordinal + lane_ordinal,
                            physical_half_ordinal,
                            material_digit_ordinal,
                            modulus_ordinal,
                        }
                    }),
                    CommittedMaterialIntegerRecipe::Constant(i128::from(
                        maximum_digits[material_digit_ordinal],
                    )),
                )?;
                self.push_recipe(CommittedMaterialColumnRecipe::Integer(difference.clone()))?;
                self.add_ternary_digits(difference, ternary_digit_count, 0)?;
            }
            let borrow = self.packed_source(
                (0..root_count).map(|lane_ordinal| {
                    CommittedMaterialIntegerRecipe::ComparatorBorrow {
                        logical_root_ordinal: first_logical_root_ordinal + lane_ordinal,
                        physical_half_ordinal,
                        modulus_ordinal,
                    }
                }),
                CommittedMaterialIntegerRecipe::Constant(0),
            )?;
            self.push_recipe(CommittedMaterialColumnRecipe::Integer(borrow))?;
        }
        Ok(())
    }

    fn ensure_shift_selector(&mut self, row_shift: u64) -> Result<(), RelationPlanError> {
        if row_shift != 0
            && !self.ordered_recipes.iter().any(|(_, recipe)| {
                matches!(recipe, CommittedMaterialColumnRecipe::ShiftSelector {
                    row_shift: existing_row_shift,
                } if *existing_row_shift == row_shift)
            })
        {
            self.push_recipe(CommittedMaterialColumnRecipe::ShiftSelector { row_shift })?;
        }
        Ok(())
    }

    fn add_packed_signed_quotients(
        &mut self,
        ordered_sources: impl IntoIterator<Item = CommittedMaterialIntegerRecipe>,
        required_absolute_bound: u64,
    ) -> Result<(), RelationPlanError> {
        let mut ternary_digit_count = 1_usize;
        let mut ternary_capacity = TERNARY_DIGIT_RADIX;
        while (ternary_capacity - 1) / 2 < required_absolute_bound {
            ternary_digit_count = ternary_digit_count
                .checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?;
            ternary_capacity = ternary_capacity
                .checked_mul(TERNARY_DIGIT_RADIX)
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
        }
        let offset = (ternary_capacity - 1) / 2;
        let mut ordered_sources = ordered_sources.into_iter().peekable();
        while ordered_sources.peek().is_some() {
            let source = self.packed_source(
                ordered_sources.by_ref().take(self.trace_packing_factor),
                CommittedMaterialIntegerRecipe::Constant(0),
            )?;
            self.push_recipe(CommittedMaterialColumnRecipe::Integer(source.clone()))?;
            self.add_ternary_digits(source, ternary_digit_count, offset)?;
        }
        Ok(())
    }

    fn add_packed_unsigned_quotients(
        &mut self,
        ordered_sources: impl IntoIterator<Item = CommittedMaterialIntegerRecipe>,
        required_maximum: u64,
    ) -> Result<(), RelationPlanError> {
        let ternary_digit_count = minimum_unsigned_ternary_digit_count(required_maximum);
        let mut ordered_sources = ordered_sources.into_iter().peekable();
        while ordered_sources.peek().is_some() {
            let source = self.packed_source(
                ordered_sources.by_ref().take(self.trace_packing_factor),
                CommittedMaterialIntegerRecipe::Constant(0),
            )?;
            self.push_recipe(CommittedMaterialColumnRecipe::Integer(source.clone()))?;
            self.add_ternary_digits(source, ternary_digit_count, 0)?;
        }
        Ok(())
    }

    fn finish(self) -> Result<Box<[(u32, CommittedMaterialColumnRecipe)]>, RelationPlanError> {
        if self.next_column_ordinal != self.variant.ordered_columns.len()
            || self.ordered_recipes.len()
                != self
                    .variant
                    .ordered_columns
                    .iter()
                    .filter(|column| matches!(column.origin, RelationColumnOrigin::Prover))
                    .count()
        {
            return Err(RelationPlanError::InvalidColumn);
        }
        Ok(self.ordered_recipes.into_boxed_slice())
    }
}

struct VssShareLinkageTraceWitnessLayout {
    resolved_moduli: Vec<(SuiteModulusReference, u64)>,
    roots_per_limb: usize,
    ordered_recipes: Box<[(u32, CommittedMaterialColumnRecipe)]>,
    relation_plan_hash: [u8; 64],
}

fn derive_vss_share_linkage_trace_witness_layout(
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<VssShareLinkageTraceWitnessLayout, RelationPlanError> {
    let resolved = input.validate(context)?;
    let compiled =
        super::vss_share_linkage::compile_vss_share_linkage_relation_plan(input, context)?;
    let variant = compiled
        .variants()
        .first()
        .ok_or(RelationPlanError::InvalidVariantSelector)?;
    let sharing_limb_count = resolved.len();
    let threshold = usize::from(input.threshold);
    let participant_count = usize::from(input.participant_count);
    let roots_per_limb = threshold
        .checked_add(participant_count)
        .ok_or(RelationPlanError::CountOverflow)?;
    let trace_packing_factor = usize::try_from(input.trace_packing_factor)
        .map_err(|_| RelationPlanError::CountOverflow)?;
    let mut layout =
        CommittedMaterialTraceWitnessLayoutBuilder::new(variant, input.trace_packing_factor)?;
    let mut logical_root_ordinal = 0_usize;
    for (modulus_ordinal, (_, modulus)) in resolved.iter().copied().enumerate() {
        for group_start in (0..roots_per_limb).step_by(trace_packing_factor) {
            layout.add_material_group(
                logical_root_ordinal + group_start,
                (roots_per_limb - group_start).min(trace_packing_factor),
                modulus_ordinal,
                modulus,
            )?;
        }
        logical_root_ordinal = logical_root_ordinal
            .checked_add(roots_per_limb)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    let quotient_sources = (0..sharing_limb_count).flat_map(|sharing_limb_ordinal| {
        (0..2).flat_map(move |physical_half_ordinal| {
            (0..participant_count).map(move |recipient_ordinal| {
                CommittedMaterialIntegerRecipe::VssQuotient {
                    sharing_limb_ordinal,
                    recipient_ordinal,
                    physical_half_ordinal,
                }
            })
        })
    });
    layout.add_packed_signed_quotients(quotient_sources, u64::from(input.threshold))?;
    let point_stride = input.point_stride()?;
    for _sharing_limb_ordinal in 0..sharing_limb_count {
        for physical_half_ordinal in 0..2 {
            for recipient_ordinal in 0..participant_count {
                for coefficient_ordinal in 0..threshold {
                    let exponent = u64::try_from(recipient_ordinal)
                        .ok()
                        .and_then(|recipient| {
                            u64::try_from(coefficient_ordinal)
                                .ok()
                                .and_then(|coefficient| recipient.checked_mul(coefficient))
                        })
                        .and_then(|product| product.checked_mul(point_stride))
                        .ok_or(RelationPlanError::CountOverflow)?;
                    for branch in monomial_action_branches(
                        input.ring_degree,
                        exponent,
                        physical_half_ordinal,
                    )? {
                        if branch.use_upper_row_selector.is_some() {
                            layout.ensure_shift_selector(branch.rotation_magnitude)?;
                        }
                    }
                }
            }
        }
    }
    Ok(VssShareLinkageTraceWitnessLayout {
        resolved_moduli: resolved,
        roots_per_limb,
        ordered_recipes: layout.finish()?,
        relation_plan_hash: compiled.canonical_hash()?,
    })
}

#[cfg(test)]
pub(crate) fn vss_share_linkage_trace_witness_structure_memory_accounting(
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CommittedMaterialTraceWitnessStructureMemoryAccounting, RelationPlanError> {
    let layout = derive_vss_share_linkage_trace_witness_layout(input, context)?;
    CommittedMaterialTraceWitnessStructureMemoryAccounting::from_catalog_dimensions(
        layout.resolved_moduli.len(),
        &layout.ordered_recipes,
    )
}

pub(crate) fn derive_vss_share_linkage_trace_witness_provider(
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
    ordered_sources: Vec<AuthenticatedCompactCommittedMaterialSource>,
) -> Result<CommittedMaterialTraceWitnessProvider, RelationPlanError> {
    let layout = derive_vss_share_linkage_trace_witness_layout(input, context)?;
    validate_authenticated_committed_material_sources(
        input,
        &ordered_sources,
        &layout.resolved_moduli,
        layout.roots_per_limb,
    )?;
    Ok(CommittedMaterialTraceWitnessProvider {
        input: CommittedMaterialTraceWitnessInput::from_relation_input(input),
        ordered_roots: ordered_sources.into_boxed_slice(),
        resolved_moduli: layout
            .resolved_moduli
            .into_iter()
            .map(|(_, modulus)| modulus)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        ordered_recipes: layout.ordered_recipes,
        relation_plan_hash: layout.relation_plan_hash,
    })
}

struct AggregateThresholdShareTraceWitnessLayout {
    resolved_moduli: Vec<(SuiteModulusReference, u64)>,
    roots_per_limb: usize,
    ordered_recipes: Box<[(u32, CommittedMaterialColumnRecipe)]>,
    relation_plan_hash: [u8; 64],
}

fn derive_aggregate_threshold_share_trace_witness_layout(
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
) -> Result<AggregateThresholdShareTraceWitnessLayout, RelationPlanError> {
    let resolved = input.validate(context)?;
    let compiled =
        super::aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan(
            input, context,
        )?;
    let variant = compiled
        .variants()
        .first()
        .ok_or(RelationPlanError::InvalidVariantSelector)?;
    let sharing_limb_count = resolved.len();
    let participant_count = usize::from(input.participant_count);
    let roots_per_limb = participant_count
        .checked_add(1)
        .ok_or(RelationPlanError::CountOverflow)?;
    let trace_packing_factor = usize::try_from(input.trace_packing_factor)
        .map_err(|_| RelationPlanError::CountOverflow)?;
    let mut layout =
        CommittedMaterialTraceWitnessLayoutBuilder::new(variant, input.trace_packing_factor)?;
    let mut logical_root_ordinal = 0_usize;
    for (modulus_ordinal, (_, modulus)) in resolved.iter().copied().enumerate() {
        for group_start in (0..roots_per_limb).step_by(trace_packing_factor) {
            layout.add_material_group(
                logical_root_ordinal + group_start,
                (roots_per_limb - group_start).min(trace_packing_factor),
                modulus_ordinal,
                modulus,
            )?;
        }
        logical_root_ordinal = logical_root_ordinal
            .checked_add(roots_per_limb)
            .ok_or(RelationPlanError::CountOverflow)?;
    }
    let quotient_sources = (0..sharing_limb_count).flat_map(|sharing_limb_ordinal| {
        (0..2).map(
            move |physical_half_ordinal| CommittedMaterialIntegerRecipe::AggregateQuotient {
                sharing_limb_ordinal,
                physical_half_ordinal,
            },
        )
    });
    layout.add_packed_unsigned_quotients(
        quotient_sources,
        u64::from(input.participant_count.saturating_sub(1)),
    )?;
    Ok(AggregateThresholdShareTraceWitnessLayout {
        resolved_moduli: resolved,
        roots_per_limb,
        ordered_recipes: layout.finish()?,
        relation_plan_hash: compiled.canonical_hash()?,
    })
}

pub(crate) fn derive_aggregate_threshold_share_trace_witness_provider(
    input: &CommittedMaterialRelationPlanInput,
    context: &RelationPlanCheckContext,
    ordered_sources: Vec<AuthenticatedCompactCommittedMaterialSource>,
) -> Result<CommittedMaterialTraceWitnessProvider, RelationPlanError> {
    let layout = derive_aggregate_threshold_share_trace_witness_layout(input, context)?;
    validate_authenticated_committed_material_sources(
        input,
        &ordered_sources,
        &layout.resolved_moduli,
        layout.roots_per_limb,
    )?;
    Ok(CommittedMaterialTraceWitnessProvider {
        input: CommittedMaterialTraceWitnessInput::from_relation_input(input),
        ordered_roots: ordered_sources.into_boxed_slice(),
        resolved_moduli: layout
            .resolved_moduli
            .into_iter()
            .map(|(_, modulus)| modulus)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        ordered_recipes: layout.ordered_recipes,
        relation_plan_hash: layout.relation_plan_hash,
    })
}

fn validate_authenticated_committed_material_sources(
    input: &CommittedMaterialRelationPlanInput,
    ordered_sources: &[AuthenticatedCompactCommittedMaterialSource],
    resolved_moduli: &[(SuiteModulusReference, u64)],
    roots_per_limb: usize,
) -> Result<(), RelationPlanError> {
    let expected_root_count = resolved_moduli
        .len()
        .checked_mul(roots_per_limb)
        .ok_or(RelationPlanError::CountOverflow)?;
    let trace_domain_size = usize::try_from(input.message_trace_domain_size()?)
        .map_err(|_| RelationPlanError::CountOverflow)?;
    let evaluation_domain_size = usize::try_from(input.evaluation_domain_size)
        .map_err(|_| RelationPlanError::CountOverflow)?;
    let material_column_degree_bound_exclusive =
        usize::try_from(input.material_column_degree_bound_exclusive)
            .map_err(|_| RelationPlanError::CountOverflow)?;
    if ordered_sources.len() != expected_root_count {
        return Err(RelationPlanError::InvalidRoot);
    }
    for (logical_root_ordinal, source) in ordered_sources.iter().enumerate() {
        let modulus = resolved_moduli
            .get(logical_root_ordinal / roots_per_limb)
            .map(|(_, modulus)| *modulus)
            .ok_or(RelationPlanError::MissingModulus)?;
        let profile = source.compact_source().profile();
        if source.canonical_modulus() != modulus
            || source.canonical_message().len() != usize::try_from(input.ring_degree).unwrap_or(0)
            || profile.trace_domain_size() != trace_domain_size
            || profile.evaluation_domain_size() != evaluation_domain_size
            || profile.material_column_degree_bound_exclusive()
                != material_column_degree_bound_exclusive
            || source.compact_source().root() == [0_u8; 64]
            || source.compact_source().material_context_hash() == [0_u8; 64]
            || source
                .canonical_message()
                .iter()
                .any(|coefficient| *coefficient >= modulus)
        {
            return Err(RelationPlanError::InvalidRoot);
        }
    }
    Ok(())
}

fn canonical_proof_base_field_integer(value: i128) -> Result<u64, RelationPlanError> {
    let modulus = i128::from(crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS);
    let canonical = value.rem_euclid(modulus);
    u64::try_from(canonical).map_err(|_| RelationPlanError::IntegerBoundOverflow)
}

fn fixed_material_digits(value: u64) -> Result<[u64; 2], RelationPlanError> {
    let low_digit = value % MATERIAL_DIGIT_RADIX;
    let high_digit = value / MATERIAL_DIGIT_RADIX;
    if high_digit >= MATERIAL_DIGIT_RADIX {
        return Err(RelationPlanError::IntegerBoundOverflow);
    }
    Ok([low_digit, high_digit])
}

fn minimum_unsigned_ternary_digit_count(maximum_value: u64) -> usize {
    let mut digit_count = 1_usize;
    let mut remaining = maximum_value;
    while remaining >= TERNARY_DIGIT_RADIX {
        remaining /= TERNARY_DIGIT_RADIX;
        digit_count += 1;
    }
    digit_count
}

#[cfg(feature = "primitive-measurement-evidence")]
fn minimum_unsigned_digit_count(maximum_value: u64, radix: u64) -> Result<u64, RelationPlanError> {
    if radix < 2 {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut digit_count = 1_u64;
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
        COMMITTED_MATERIAL_TRACE_PACKING_FACTOR, CommittedMaterialColumnRecipe,
        CommittedMaterialIntegerRecipe, CommittedMaterialRelationPlanInput,
        MATERIAL_DIGIT_TERNARY_DIGIT_COUNT, MonomialActionBranch, RelationBoundCertificate,
        RelationColumnOrigin, RelationPlanCheckContext, RelationPlanError, RelationTreeDescriptor,
        ResolvedSuiteModulus, SuiteModulusReference, TERNARY_DIGIT_RADIX,
        derive_aggregate_threshold_share_trace_witness_provider,
        derive_vss_share_linkage_trace_witness_provider, modular_power, monomial_action_branches,
        vss_share_linkage_trace_witness_structure_memory_accounting,
    };
    use crate::bgv::proof_suite::{
        AuthenticatedCompactCommittedMaterialSource, CommittedMaterialProfile,
        CommittedMaterialTree, ProofTreeRole,
    };
    use crate::foundation::{
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        derive_foundation_roster_parameters,
    };
    use zeroize::Zeroizing;

    fn trace_witness_context() -> RelationPlanCheckContext {
        let evaluation_domain_size = 4_096_u64;
        let relation_input = trace_witness_input();
        let quotient_component_count = 3_u64;
        let out_of_domain_point_count = 1_u64;
        let phase_column_query_coordinate_count = 1_u64;
        let rounded_mask_degree = quotient_component_count
            .checked_add(1)
            .and_then(|count| count.checked_mul(relation_input.trace_mask_degree_bound_exclusive))
            .and_then(|degree| degree.checked_add(quotient_component_count - 1))
            .and_then(|degree| degree.checked_div(quotient_component_count))
            .expect("test quotient mask degree derives");
        let quotient_decomposition_stride = relation_input
            .relation_trace_domain_size()
            .expect("test relation trace domain derives")
            .checked_add(rounded_mask_degree)
            .expect("test quotient decomposition stride derives");
        let minimum_telescoping_mask_degree_bound_exclusive = phase_column_query_coordinate_count
            .checked_add(out_of_domain_point_count)
            .expect("test telescoping mask degree derives");
        RelationPlanCheckContext {
            base_field_modulus: crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_domain_generator: modular_power(
                crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            out_of_domain_point_count: u16::try_from(out_of_domain_point_count)
                .expect("test out-of-domain-point count fits"),
            quotient_component_count: u32::try_from(quotient_component_count)
                .expect("test quotient component count fits"),
            quotient_component_degree_bound_exclusive: quotient_decomposition_stride
                .checked_add(minimum_telescoping_mask_degree_bound_exclusive)
                .expect("test quotient component degree bound derives"),
            phase_column_query_coordinate_count: u32::try_from(phase_column_query_coordinate_count)
                .expect("test phase-column query-coordinate count fits"),
            non_native_theta_repetition_count: 1,
            non_native_alpha_repetition_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![ResolvedSuiteModulus::new(
                SuiteModulusReference::data(0),
                97,
            )],
        }
    }

    fn trace_witness_input() -> CommittedMaterialRelationPlanInput {
        let trace_mask_degree_bound_exclusive = COMMITTED_MATERIAL_TRACE_PACKING_FACTOR
            .checked_mul(
                u64::try_from(crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE)
                    .expect("test challenge extension degree fits"),
            )
            .and_then(|out_of_domain_coordinate_count| {
                out_of_domain_coordinate_count.checked_add(1)
            })
            .expect("test trace mask degree derives");
        CommittedMaterialRelationPlanInput {
            ring_degree: 64,
            evaluation_domain_size: 4_096,
            opening_degree_bound_exclusive: 512,
            material_column_degree_bound_exclusive: 64,
            trace_packing_factor: COMMITTED_MATERIAL_TRACE_PACKING_FACTOR,
            participant_count: 3,
            threshold: 2,
            sharing_data_modulus_indices: vec![0],
            trace_mask_degree_bound_exclusive,
        }
    }

    fn authenticated_compact_source(
        input: &CommittedMaterialRelationPlanInput,
        canonical_message: &[u64],
        canonical_modulus: u64,
        logical_root_ordinal: usize,
    ) -> AuthenticatedCompactCommittedMaterialSource {
        let ring_degree = usize::try_from(input.ring_degree).expect("test ring degree fits usize");
        assert_eq!(canonical_message.len(), ring_degree);
        let profile = CommittedMaterialProfile::for_common_proof_evaluation_domain(
            ring_degree,
            usize::try_from(input.evaluation_domain_size)
                .expect("test evaluation domain size fits usize"),
            usize::try_from(input.opening_degree_bound_exclusive)
                .expect("test opening degree bound fits usize"),
        )
        .expect("test committed-material profile derives");
        assert_eq!(
            profile.material_column_degree_bound_exclusive(),
            usize::try_from(input.material_column_degree_bound_exclusive)
                .expect("test material-column bound fits usize")
        );
        let root_fill =
            u8::try_from(logical_root_ordinal + 1).expect("test logical root ordinal fits u8");
        let tree = CommittedMaterialTree::from_canonical_message(
            profile,
            [root_fill; 64],
            [root_fill.wrapping_add(0x40); 64],
            canonical_message,
            canonical_modulus,
        )
        .expect("test committed-material tree derives");
        AuthenticatedCompactCommittedMaterialSource::from_recomputed_tree_and_canonical_message(
            tree,
            Zeroizing::new(canonical_message.to_vec().into_boxed_slice()),
            canonical_modulus,
        )
        .expect("test committed-material source authenticates")
    }

    #[test]
    fn committed_material_compilers_reject_invalid_range_degree_before_building_columns() {
        let context = trace_witness_context();
        let mut input = trace_witness_input();
        input.opening_degree_bound_exclusive = input
            .maximum_range_constraint_numerator_degree()
            .expect("test range numerator degree derives");
        assert!(
            input.prover_column_degree_bound_exclusive().unwrap()
                < input.opening_degree_bound_exclusive
        );

        assert_eq!(
            super::super::vss_share_linkage::compile_vss_share_linkage_relation_plan(
                &input, &context,
            )
            .unwrap_err(),
            RelationPlanError::DegreeBoundExceeded
        );
        assert_eq!(
            super::super::aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan(
                &input, &context,
            )
            .unwrap_err(),
            RelationPlanError::DegreeBoundExceeded
        );
    }

    fn dense_negacyclic_monomial_action(source: &[u64], exponent: u64, modulus: u64) -> Vec<u64> {
        let ring_degree = u64::try_from(source.len()).expect("test ring degree fits u64");
        let reduced_exponent = exponent % (2 * ring_degree);
        let unsigned_exponent = reduced_exponent % ring_degree;
        (0..ring_degree)
            .map(|target| {
                let wraps_below_zero = target < unsigned_exponent;
                let source_ordinal = if wraps_below_zero {
                    target + ring_degree - unsigned_exponent
                } else {
                    target - unsigned_exponent
                };
                let value = i128::from(source[source_ordinal as usize]);
                let signed = if (reduced_exponent >= ring_degree) ^ wraps_below_zero {
                    -value
                } else {
                    value
                };
                u64::try_from(signed.rem_euclid(i128::from(modulus)))
                    .expect("canonical test residue fits u64")
            })
            .collect()
    }

    fn add_dense_messages(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
        left.iter()
            .copied()
            .zip(right.iter().copied())
            .map(|(left, right)| (left + right) % modulus)
            .collect()
    }

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
    fn vss_trace_witness_provider_is_restartable_and_rejects_a_broken_share() {
        const MODULUS: u64 = 97;
        let context = trace_witness_context();
        let input = trace_witness_input();
        let relation_trace_domain_size = usize::try_from(
            input
                .relation_trace_domain_size()
                .expect("test relation trace domain size derives"),
        )
        .expect("test relation trace domain size fits usize");
        let first_coefficient = (0..input.ring_degree)
            .map(|coefficient_ordinal| (37 * coefficient_ordinal + 96) % MODULUS)
            .collect::<Vec<_>>();
        let second_coefficient = (0..input.ring_degree)
            .map(|coefficient_ordinal| (53 * coefficient_ordinal + 71) % MODULUS)
            .collect::<Vec<_>>();
        let point_stride = input.point_stride().expect("test point stride");
        let mut ordered_messages = vec![first_coefficient.clone(), second_coefficient.clone()];
        for recipient_ordinal in 0..usize::from(input.participant_count) {
            let acted_second = dense_negacyclic_monomial_action(
                &second_coefficient,
                u64::try_from(recipient_ordinal).expect("recipient ordinal fits") * point_stride,
                MODULUS,
            );
            let share = add_dense_messages(&first_coefficient, &acted_second, MODULUS);
            ordered_messages.push(share);
        }
        let ordered_sources = ordered_messages
            .iter()
            .enumerate()
            .map(|(logical_root_ordinal, message)| {
                authenticated_compact_source(&input, message, MODULUS, logical_root_ordinal)
            })
            .collect::<Vec<_>>();
        let ordered_source_count = ordered_sources.len();
        let provider =
            derive_vss_share_linkage_trace_witness_provider(&input, &context, ordered_sources)
                .expect("honest VSS trace witness provider");
        let plan = super::super::vss_share_linkage::compile_vss_share_linkage_relation_plan(
            &input, &context,
        )
        .expect("test VSS relation plan");
        let expected_prover_column_count = plan.variants()[0]
            .ordered_columns
            .iter()
            .filter(|column| matches!(column.origin, RelationColumnOrigin::Prover))
            .count();
        let ordered_column_ordinals = provider.ordered_column_ordinals().collect::<Vec<_>>();
        assert_eq!(ordered_column_ordinals.len(), expected_prover_column_count);
        assert_eq!(provider.logical_root_count(), ordered_source_count);
        assert_eq!(
            provider.relation_plan_hash(),
            plan.canonical_hash().expect("test VSS plan hash")
        );
        let structure_memory_accounting = provider
            .structure_memory_accounting()
            .expect("VSS trace-witness structure accounting");
        assert_eq!(
            structure_memory_accounting,
            vss_share_linkage_trace_witness_structure_memory_accounting(&input, &context)
                .expect("production VSS trace-witness layout accounting")
        );
        assert_eq!(
            structure_memory_accounting.total_byte_length(),
            structure_memory_accounting.resolved_modulus_catalog_byte_length()
                + structure_memory_accounting.recipe_catalog_byte_length()
                + structure_memory_accounting.nested_recipe_catalog_byte_length()
        );
        assert!(
            provider
                .ordered_recipes
                .windows(2)
                .all(|recipes| recipes[0].0 < recipes[1].0)
        );

        let packed_low_material_source = provider
            .ordered_recipes
            .iter()
            .find_map(|(_, recipe)| match recipe {
                CommittedMaterialColumnRecipe::Integer(
                    source @ CommittedMaterialIntegerRecipe::Packed {
                        ordered_lane_sources,
                    },
                ) if matches!(
                    ordered_lane_sources.first(),
                    Some(CommittedMaterialIntegerRecipe::BoundDigit {
                        logical_root_ordinal: 0,
                        physical_half_ordinal: 0,
                        material_digit_ordinal: 0,
                    })
                ) =>
                {
                    Some(source.clone())
                }
                _ => None,
            })
            .expect("first packed low material source");
        let packed_low_material_column_ordinal = provider
            .ordered_recipes
            .iter()
            .find_map(|(column_ordinal, recipe)| {
                matches!(
                    recipe,
                    CommittedMaterialColumnRecipe::Integer(source)
                        if source == &packed_low_material_source
                )
                .then_some(*column_ordinal)
            })
            .expect("first packed low material column");
        let source_value = provider
            .trace_value(packed_low_material_column_ordinal, 0)
            .expect("first packed low material value");
        let ordered_ternary_digit_columns = provider
            .ordered_recipes
            .iter()
            .filter_map(|(column_ordinal, recipe)| match recipe {
                CommittedMaterialColumnRecipe::TernaryDigit {
                    source,
                    digit_ordinal,
                    offset,
                } if source == &packed_low_material_source && *offset == 0 => {
                    Some((*column_ordinal, *digit_ordinal))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ordered_ternary_digit_columns.len(),
            MATERIAL_DIGIT_TERNARY_DIGIT_COUNT
        );
        for (expected_digit_ordinal, (column_ordinal, digit_ordinal)) in
            ordered_ternary_digit_columns.iter().copied().enumerate()
        {
            assert_eq!(digit_ordinal, expected_digit_ordinal);
            let trit = source_value
                / TERNARY_DIGIT_RADIX.pow(
                    u32::try_from(expected_digit_ordinal).expect("test trit ordinal fits u32"),
                )
                % TERNARY_DIGIT_RADIX;
            assert_eq!(
                provider
                    .trace_value(column_ordinal, 0)
                    .expect("ternary material digit"),
                trit
            );

            let semantic_cell = plan.variants()[0]
                .ordered_semantic_cells
                .iter()
                .find(|semantic_cell| semantic_cell.column_ordinal == column_ordinal)
                .expect("ternary material digit semantic cell");
            assert!(matches!(
                semantic_cell.bound_certificate,
                RelationBoundCertificate::Trinary { .. }
            ));
        }

        for column_ordinal in &ordered_column_ordinals {
            for row_ordinal in 0..relation_trace_domain_size {
                assert!(
                    provider
                        .trace_value(*column_ordinal, row_ordinal)
                        .expect("honest VSS witness value")
                        < crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS
                );
            }
        }
        let first_column_ordinal = ordered_column_ordinals[0];
        assert_eq!(
            provider
                .column_trace_values(first_column_ordinal)
                .expect("first pass"),
            provider
                .column_trace_values(first_column_ordinal)
                .expect("restart pass")
        );

        let mut broken_messages = ordered_messages.clone();
        let recipient_root_ordinal = usize::from(input.threshold);
        broken_messages[recipient_root_ordinal][0] =
            (broken_messages[recipient_root_ordinal][0] + 1) % MODULUS;
        let broken_sources = broken_messages
            .iter()
            .enumerate()
            .map(|(logical_root_ordinal, message)| {
                authenticated_compact_source(&input, message, MODULUS, logical_root_ordinal)
            })
            .collect::<Vec<_>>();
        let broken_provider =
            derive_vss_share_linkage_trace_witness_provider(&input, &context, broken_sources)
                .expect("a canonical but inconsistent share reaches relation evaluation");
        assert!(
            broken_provider
                .ordered_column_ordinals()
                .any(|column_ordinal| {
                    (0..relation_trace_domain_size).any(|row_ordinal| {
                        broken_provider
                            .trace_value(column_ordinal, row_ordinal)
                            .is_err()
                    })
                })
        );
    }

    #[test]
    fn aggregate_trace_witness_provider_covers_carries_and_rejects_wrong_modulus_sources() {
        const MODULUS: u64 = 97;
        let context = trace_witness_context();
        let input = trace_witness_input();
        let source_messages = (0..usize::from(input.participant_count))
            .map(|source_ordinal| {
                (0..input.ring_degree)
                    .map(|coefficient_ordinal| {
                        (u64::try_from(source_ordinal + 1).unwrap() * 41 * coefficient_ordinal
                            + u64::try_from(source_ordinal).unwrap() * 29
                            + 83)
                            % MODULUS
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let aggregate = source_messages.iter().fold(
            vec![0; usize::try_from(input.ring_degree).unwrap()],
            |accumulated, source| add_dense_messages(&accumulated, source, MODULUS),
        );
        let mut ordered_messages = source_messages;
        ordered_messages.push(aggregate);
        let ordered_sources = ordered_messages
            .iter()
            .enumerate()
            .map(|(logical_root_ordinal, message)| {
                authenticated_compact_source(&input, message, MODULUS, logical_root_ordinal)
            })
            .collect::<Vec<_>>();
        let provider = derive_aggregate_threshold_share_trace_witness_provider(
            &input,
            &context,
            ordered_sources,
        )
        .expect("honest aggregate trace witness provider");
        let plan = super::super::aggregate_threshold_share::compile_aggregate_threshold_share_relation_plan(
            &input, &context,
        )
        .expect("test aggregate relation plan");
        let [projection_column_ordinal, _, _] = provider
            .representative_aggregate_projection_digit_and_quotient_column_ordinals()
            .expect("the aggregate witness exposes representative semantic columns");
        assert_eq!(projection_column_ordinal, 16);
        let variant = &plan.variants()[0];
        assert_eq!(
            variant.ordered_columns
                [usize::try_from(projection_column_ordinal).expect("column ordinal fits usize")]
            .origin,
            RelationColumnOrigin::Prover,
        );
        assert!(variant.ordered_trees.iter().any(|tree| {
            matches!(
                tree,
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } if *proof_tree_role == ProofTreeRole::BaseOracle as u16
                    && ordered_column_ordinals.contains(&projection_column_ordinal)
            )
        }));
        assert_eq!(
            provider.ordered_column_ordinals().len(),
            variant
                .ordered_columns
                .iter()
                .filter(|column| matches!(column.origin, RelationColumnOrigin::Prover))
                .count()
        );
        for column_ordinal in provider.ordered_column_ordinals() {
            provider
                .column_trace_values(column_ordinal)
                .expect("honest aggregate witness column");
        }

        let mut wrong_modulus_sources = ordered_messages
            .iter()
            .enumerate()
            .map(|(logical_root_ordinal, message)| {
                authenticated_compact_source(&input, message, MODULUS, logical_root_ordinal)
            })
            .collect::<Vec<_>>();
        wrong_modulus_sources[0] =
            authenticated_compact_source(&input, &ordered_messages[0], 101, 0);
        assert!(
            derive_aggregate_threshold_share_trace_witness_provider(
                &input,
                &context,
                wrong_modulus_sources,
            )
            .is_err()
        );
    }

    #[test]
    fn committed_material_points_cover_every_configurable_roster_without_collisions() {
        const RING_DEGREE: u64 = crate::bgv::parameters::POLYNOMIAL_DEGREE as u64;
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
                trace_packing_factor: COMMITTED_MATERIAL_TRACE_PACKING_FACTOR,
                participant_count,
                threshold: roster_parameters.reconstruction_threshold,
                sharing_data_modulus_indices: vec![0],
                trace_mask_degree_bound_exclusive: 1,
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
