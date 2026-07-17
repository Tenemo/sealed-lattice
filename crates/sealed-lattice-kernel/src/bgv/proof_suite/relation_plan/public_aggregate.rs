use std::collections::{BTreeMap, BTreeSet};

use super::*;

const COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = crate::foundation::ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
const RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = crate::foundation::ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
const EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER: u16 = crate::foundation::ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER;
const AGGREGATE_CONSTRAINT_ROLE: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicAggregateRelationGeometry {
    pub(crate) ring_degree: u64,
    pub(crate) evaluation_domain_size: u64,
    pub(crate) opening_degree_bound_exclusive: u64,
    pub(crate) public_polynomial_column_degree_bound_exclusive: u64,
    pub(crate) participant_count: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CollectivePublicKeyAggregatePlanInput {
    pub(crate) geometry: PublicAggregateRelationGeometry,
    pub(crate) ordered_component_moduli: Vec<SuiteModulusReference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RkgRoundOneAggregateVariantInput {
    pub(crate) schedule_position: u32,
    pub(crate) ordered_left_component_moduli: Vec<SuiteModulusReference>,
    pub(crate) ordered_right_component_moduli: Vec<SuiteModulusReference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RkgRoundOneAggregatePlanInput {
    pub(crate) geometry: PublicAggregateRelationGeometry,
    pub(crate) ordered_variants: Vec<RkgRoundOneAggregateVariantInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorKeyAggregateEntryPlanInput {
    pub(crate) schedule_position: u32,
    pub(crate) ordered_runtime_component_moduli: Vec<SuiteModulusReference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorKeyAggregateVariantInput {
    pub(crate) top_count: u16,
    pub(crate) entry_ordinal: u32,
    pub(crate) entry: EvaluatorKeyAggregateEntryPlanInput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorKeyAggregatePlanInput {
    pub(crate) geometry: PublicAggregateRelationGeometry,
    pub(crate) ordered_variants: Vec<EvaluatorKeyAggregateVariantInput>,
}

#[derive(Clone, Debug)]
struct AggregateComponent {
    source_root_paths: Vec<Vec<RelationSelectorPathStep>>,
    aggregate_root_path: Vec<RelationSelectorPathStep>,
    ordered_moduli: Vec<SuiteModulusReference>,
    constraint_role_coordinates: Vec<u64>,
}

#[derive(Clone, Debug)]
struct LogicalRoot {
    path: Vec<RelationSelectorPathStep>,
    root_use: BoundTreeRootUse,
    ordered_moduli: Vec<SuiteModulusReference>,
}

impl PublicAggregateRelationGeometry {
    fn trace_domain_size(&self) -> Result<u64, RelationPlanError> {
        self.ring_degree
            .checked_div(2)
            .filter(|trace_domain_size| {
                *trace_domain_size > 1 && *trace_domain_size * 2 == self.ring_degree
            })
            .ok_or(RelationPlanError::InvalidDomain)
    }

    fn validate(&self, context: &RelationPlanCheckContext) -> Result<(), RelationPlanError> {
        RelationPlanChecker::new(context).check_context()?;
        self.trace_domain_size()?;
        if self.ring_degree < 2
            || !self.ring_degree.is_power_of_two()
            || self.evaluation_domain_size == 0
            || !self.evaluation_domain_size.is_power_of_two()
            || self.opening_degree_bound_exclusive <= 1
            || self.public_polynomial_column_degree_bound_exclusive == 0
            || self.public_polynomial_column_degree_bound_exclusive > self.ring_degree
            || self.participant_count < 2
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        let exact_product_degree = u64::from(self.participant_count)
            .checked_mul(
                self.public_polynomial_column_degree_bound_exclusive
                    .checked_sub(1)
                    .ok_or(RelationPlanError::DegreeBoundExceeded)?,
            )
            .ok_or(RelationPlanError::DegreeBoundExceeded)?;
        if exact_product_degree >= self.opening_degree_bound_exclusive {
            return Err(RelationPlanError::DegreeBoundExceeded);
        }
        let next_degree_domain = self
            .opening_degree_bound_exclusive
            .checked_next_power_of_two()
            .ok_or(RelationPlanError::CountOverflow)?;
        if next_degree_domain
            .checked_mul(u64::from(context.evaluation_blowup_factor))
            .ok_or(RelationPlanError::CountOverflow)?
            != self.evaluation_domain_size
        {
            return Err(RelationPlanError::InvalidDomain);
        }
        Ok(())
    }

    fn validate_component_moduli(
        &self,
        ordered_moduli: &[SuiteModulusReference],
        context: &RelationPlanCheckContext,
    ) -> Result<(), RelationPlanError> {
        if ordered_moduli.is_empty() {
            return Err(RelationPlanError::InvalidModulus);
        }
        for modulus_reference in ordered_moduli {
            let modulus = context.resolved_modulus(*modulus_reference)?;
            let maximum_factor_magnitude = u128::from(self.participant_count)
                .checked_mul(u128::from(modulus))
                .ok_or(RelationPlanError::IntegerBoundOverflow)?;
            if modulus >= context.base_field_modulus
                || maximum_factor_magnitude >= u128::from(context.base_field_modulus)
            {
                return Err(RelationPlanError::NoWrapBoundViolated);
            }
        }
        Ok(())
    }
}

pub(crate) fn compile_collective_public_key_aggregate_relation_plan(
    input: &CollectivePublicKeyAggregatePlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    input.geometry.validate(context)?;
    input
        .geometry
        .validate_component_moduli(&input.ordered_component_moduli, context)?;
    let participant_count = usize::from(input.geometry.participant_count);
    let component = AggregateComponent {
        source_root_paths: (0..participant_count)
            .map(|source_ordinal| {
                root_in_list_path(1, source_ordinal).ok_or(RelationPlanError::CountOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?,
        aggregate_root_path: root_field_path(2),
        ordered_moduli: input.ordered_component_moduli.clone(),
        constraint_role_coordinates: vec![0],
    };
    let variant =
        compile_public_aggregate_variant(&input.geometry, None, None, &[component], context)?;
    finish_plan(
        COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        vec![variant],
        context,
    )
}

pub(crate) fn compile_rkg_round_one_aggregate_relation_plan(
    input: &RkgRoundOneAggregatePlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    input.geometry.validate(context)?;
    if input.ordered_variants.is_empty()
        || !input
            .ordered_variants
            .windows(2)
            .all(|window| window[0].schedule_position < window[1].schedule_position)
    {
        return Err(RelationPlanError::NonCanonicalOrder);
    }
    let participant_count = usize::from(input.geometry.participant_count);
    let variants = input
        .ordered_variants
        .iter()
        .map(|variant| {
            input
                .geometry
                .validate_component_moduli(&variant.ordered_left_component_moduli, context)?;
            input
                .geometry
                .validate_component_moduli(&variant.ordered_right_component_moduli, context)?;
            let components = [
                AggregateComponent {
                    source_root_paths: (0..participant_count)
                        .map(|source_ordinal| {
                            root_in_nested_pair_list_path(2, source_ordinal, 0)
                                .ok_or(RelationPlanError::CountOverflow)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    aggregate_root_path: root_field_path(3),
                    ordered_moduli: variant.ordered_left_component_moduli.clone(),
                    constraint_role_coordinates: vec![u64::from(variant.schedule_position), 0],
                },
                AggregateComponent {
                    source_root_paths: (0..participant_count)
                        .map(|source_ordinal| {
                            root_in_nested_pair_list_path(2, source_ordinal, 1)
                                .ok_or(RelationPlanError::CountOverflow)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    aggregate_root_path: root_field_path(4),
                    ordered_moduli: variant.ordered_right_component_moduli.clone(),
                    constraint_role_coordinates: vec![u64::from(variant.schedule_position), 1],
                },
            ];
            compile_public_aggregate_variant(
                &input.geometry,
                Some(variant.schedule_position),
                None,
                &components,
                context,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    finish_plan(
        RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        variants,
        context,
    )
}

pub(crate) fn compile_evaluator_key_aggregate_relation_plan(
    input: &EvaluatorKeyAggregatePlanInput,
    context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    input.geometry.validate(context)?;
    if input.ordered_variants.is_empty()
        || input.ordered_variants[0].top_count != 1
        || input.ordered_variants[0].entry_ordinal != 0
        || input
            .ordered_variants
            .last()
            .map(|variant| variant.top_count)
            != Some(20)
        || !input.ordered_variants.windows(2).all(|window| {
            (window[1].top_count == window[0].top_count
                && window[1].entry_ordinal == window[0].entry_ordinal + 1)
                || (window[1].top_count == window[0].top_count + 1 && window[1].entry_ordinal == 0)
        })
    {
        return Err(RelationPlanError::InvalidVariantSelector);
    }
    let participant_count = usize::from(input.geometry.participant_count);
    let variants = input
        .ordered_variants
        .iter()
        .map(|variant| {
            let entry = &variant.entry;
            input
                .geometry
                .validate_component_moduli(&entry.ordered_runtime_component_moduli, context)?;
            let components = [AggregateComponent {
                source_root_paths: (0..participant_count)
                    .map(|source_ordinal| {
                        root_in_evaluator_entry_source_list_path(0, source_ordinal)
                            .ok_or(RelationPlanError::CountOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                aggregate_root_path: root_in_evaluator_entry_aggregate_list_path(0, 0)
                    .ok_or(RelationPlanError::CountOverflow)?,
                ordered_moduli: entry.ordered_runtime_component_moduli.clone(),
                constraint_role_coordinates: vec![
                    u64::from(variant.entry_ordinal),
                    u64::from(entry.schedule_position),
                ],
            }];
            compile_public_aggregate_variant(
                &input.geometry,
                Some(variant.entry_ordinal),
                Some(variant.top_count),
                &components,
                context,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    finish_plan(
        EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        variants,
        context,
    )
}

fn finish_plan(
    application_statement_schema_identifier: u16,
    variants: Vec<RelationPlanVariant>,
    context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    let compiled = CompiledRelationPlan {
        plan: RelationPlan {
            application_statement_schema_identifier,
            variants,
        },
    };
    compiled.check(context)?;
    Ok(compiled)
}

fn compile_public_aggregate_variant(
    geometry: &PublicAggregateRelationGeometry,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    components: &[AggregateComponent],
    context: &RelationPlanCheckContext,
) -> Result<RelationPlanVariant, RelationPlanError> {
    if components.is_empty() {
        return Err(RelationPlanError::InvalidRoot);
    }
    let logical_roots = logical_roots(components, usize::from(geometry.participant_count))?;
    let (ordered_verifier_sources, source_ordinals) = ordered_root_sources(&logical_roots)?;
    let ordered_non_native_moduli = components
        .iter()
        .flat_map(|component| component.ordered_moduli.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut ordered_columns = Vec::new();
    let mut ordered_trees = Vec::with_capacity(logical_roots.len());
    let mut root_columns = BTreeMap::<Vec<RelationSelectorPathStep>, Vec<u32>>::new();
    for logical_root in &logical_roots {
        let expected_root_source_ordinal = *source_ordinals
            .get(&logical_root.path)
            .ok_or(RelationPlanError::MissingRoot)?;
        let mut ordered_column_ordinals = Vec::with_capacity(logical_root.ordered_moduli.len());
        for modulus_reference in &logical_root.ordered_moduli {
            let column_ordinal = u32::try_from(ordered_columns.len())
                .map_err(|_| RelationPlanError::CountOverflow)?;
            ordered_columns.push(RelationColumnDescriptor {
                origin: RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                value_type: RelationColumnValueType::BaseField,
                source_degree_bound_exclusive: geometry
                    .public_polynomial_column_degree_bound_exclusive,
                canonical_residue_modulus: Some(*modulus_reference),
            });
            ordered_column_ordinals.push(column_ordinal);
        }
        if root_columns
            .insert(logical_root.path.clone(), ordered_column_ordinals.clone())
            .is_some()
        {
            return Err(RelationPlanError::DuplicateItem);
        }
        ordered_trees.push(RelationTreeDescriptor::BoundPublic {
            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
            expected_root_source_ordinal,
            root_use: logical_root.root_use,
            ordered_column_ordinals,
        });
    }

    let mut ordered_constraints = Vec::new();
    for (component_ordinal, component) in components.iter().enumerate() {
        for (modulus_ordinal, modulus_reference) in
            component.ordered_moduli.iter().copied().enumerate()
        {
            let source_column_ordinals = component
                .source_root_paths
                .iter()
                .map(|path| {
                    root_columns
                        .get(path)
                        .and_then(|columns| columns.get(modulus_ordinal))
                        .copied()
                        .ok_or(RelationPlanError::InvalidColumn)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let aggregate_column_ordinal = root_columns
                .get(&component.aggregate_root_path)
                .and_then(|columns| columns.get(modulus_ordinal))
                .copied()
                .ok_or(RelationPlanError::InvalidColumn)?;
            let difference_expression =
                aggregate_difference_expression(&source_column_ordinals, aggregate_column_ordinal)?;
            let factor_expressions = (0..geometry.participant_count)
                .map(|multiple| {
                    aggregate_factor_expression(&difference_expression, modulus_reference, multiple)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut role_coordinates = component.constraint_role_coordinates.clone();
            role_coordinates.push(
                u64::try_from(component_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            );
            role_coordinates.push(
                u64::try_from(modulus_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            );
            ordered_constraints.push(RelationConstraintDescriptor {
                constraint_role: AGGREGATE_CONSTRAINT_ROLE,
                role_coordinates,
                numerator_postfix_expression: ordered_injective_integer_factor_product_expression(
                    &factor_expressions,
                )?,
                zeroifier_postfix_expression: full_trace_zeroifier_expression(
                    geometry.trace_domain_size()?,
                ),
                enforce_proof_base_field_no_wrap: false,
                ordered_injective_integer_factor_expressions: factor_expressions,
            });
        }
    }

    let ordered_opening_points = (0..context.deep_point_count)
        .map(|deep_point_ordinal| RelationOpeningPointDescriptor {
            deep_point_ordinal,
            trace_rotation_is_negative: false,
            trace_rotation_magnitude: 0,
            conjugate_index: 0,
        })
        .collect::<Vec<_>>();
    let mut ordered_opening_claims = Vec::new();
    for (tree_ordinal, tree) in ordered_trees.iter().enumerate() {
        let tree_ordinal =
            u32::try_from(tree_ordinal).map_err(|_| RelationPlanError::CountOverflow)?;
        for column_ordinal in tree.ordered_column_ordinals() {
            for opening_point_ordinal in 0..ordered_opening_points.len() {
                ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                    source_class: RelationOpeningSourceClass::TreeColumn,
                    source_ordinal: tree_ordinal,
                    column_ordinal: Some(*column_ordinal),
                    opening_point_ordinal: u32::try_from(opening_point_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                    source_degree_bound_exclusive: geometry
                        .public_polynomial_column_degree_bound_exclusive,
                });
            }
        }
    }
    for quotient_ordinal in 0..context.quotient_component_count {
        for opening_point_ordinal in 0..ordered_opening_points.len() {
            ordered_opening_claims.push(RelationOpeningClaimDescriptor {
                source_class: RelationOpeningSourceClass::Quotient,
                source_ordinal: quotient_ordinal,
                column_ordinal: None,
                opening_point_ordinal: u32::try_from(opening_point_ordinal)
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                source_degree_bound_exclusive: context.quotient_component_degree_bound_exclusive,
            });
        }
    }

    Ok(RelationPlanVariant {
        schedule_position,
        top_count,
        proof_privacy_mode: ProofPrivacyMode::PublicOnly,
        trace_domain_size: geometry.trace_domain_size()?,
        evaluation_domain_size: geometry.evaluation_domain_size,
        opening_degree_bound_exclusive: geometry.opening_degree_bound_exclusive,
        ordered_non_native_moduli,
        ordered_verifier_sources,
        ordered_public_samplers: Vec::new(),
        ordered_columns,
        ordered_semantic_cells: Vec::new(),
        ordered_radix_convolutions: Vec::new(),
        ordered_integer_lift_batches: Vec::new(),
        ordered_coefficient_local_identity_batches: Vec::new(),
        ordered_trees,
        ordered_constraints,
        ordered_opening_points,
        ordered_opening_claims,
        ordered_masks: Vec::new(),
    })
}

fn logical_roots(
    components: &[AggregateComponent],
    participant_count: usize,
) -> Result<Vec<LogicalRoot>, RelationPlanError> {
    let mut roots = Vec::new();
    let mut paths = BTreeSet::new();
    for component in components {
        if component.source_root_paths.len() != participant_count
            || component.ordered_moduli.is_empty()
        {
            return Err(RelationPlanError::InvalidRoot);
        }
        for path in &component.source_root_paths {
            if !paths.insert(path.clone()) {
                return Err(RelationPlanError::DuplicateItem);
            }
            roots.push(LogicalRoot {
                path: path.clone(),
                root_use: BoundTreeRootUse::Input,
                ordered_moduli: component.ordered_moduli.clone(),
            });
        }
        if !paths.insert(component.aggregate_root_path.clone()) {
            return Err(RelationPlanError::DuplicateItem);
        }
        roots.push(LogicalRoot {
            path: component.aggregate_root_path.clone(),
            root_use: BoundTreeRootUse::Output,
            ordered_moduli: component.ordered_moduli.clone(),
        });
    }
    Ok(roots)
}

type OrderedRootSourceCatalog = (
    Vec<RelationVerifierSource>,
    BTreeMap<Vec<RelationSelectorPathStep>, u32>,
);

fn ordered_root_sources(
    roots: &[LogicalRoot],
) -> Result<OrderedRootSourceCatalog, RelationPlanError> {
    let mut entries = roots
        .iter()
        .map(|root| {
            let source = RelationVerifierSource::ApplicationStatement {
                value_path: root.path.clone(),
                value_layout: RelationValueLayout::scalar_hash(),
            };
            Ok((source.canonical_bytes()?, root.path.clone(), source))
        })
        .collect::<Result<Vec<_>, RelationPlanError>>()?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|window| window[0].0 == window[1].0) {
        return Err(RelationPlanError::DuplicateItem);
    }
    let mut source_ordinals = BTreeMap::new();
    let mut ordered_sources = Vec::with_capacity(entries.len());
    for (_, path, source) in entries {
        let ordinal =
            u32::try_from(ordered_sources.len()).map_err(|_| RelationPlanError::CountOverflow)?;
        source_ordinals.insert(path, ordinal);
        ordered_sources.push(source);
    }
    Ok((ordered_sources, source_ordinals))
}

fn aggregate_difference_expression(
    source_column_ordinals: &[u32],
    aggregate_column_ordinal: u32,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    let first = source_column_ordinals
        .first()
        .copied()
        .ok_or(RelationPlanError::InvalidConstraint)?;
    let mut expression = vec![unrotated_column_expression(first)];
    for source_column_ordinal in &source_column_ordinals[1..] {
        expression.extend([
            unrotated_column_expression(*source_column_ordinal),
            RelationExpressionInstruction::Addition,
        ]);
    }
    expression.extend([
        unrotated_column_expression(aggregate_column_ordinal),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ]);
    Ok(expression)
}

fn aggregate_factor_expression(
    difference_expression: &[RelationExpressionInstruction],
    modulus_reference: SuiteModulusReference,
    multiple: u16,
) -> Result<Vec<RelationExpressionInstruction>, RelationPlanError> {
    if difference_expression.is_empty() {
        return Err(RelationPlanError::InvalidConstraint);
    }
    let mut expression = difference_expression.to_vec();
    if multiple > 0 {
        expression.extend([
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference,
                multiplier: multiple,
            },
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ]);
    }
    Ok(expression)
}

fn root_field_path(field_ordinal: u64) -> Vec<RelationSelectorPathStep> {
    vec![RelationSelectorPathStep::tuple_field(field_ordinal)]
}

fn root_in_list_path(
    field_ordinal: u64,
    list_ordinal: usize,
) -> Option<Vec<RelationSelectorPathStep>> {
    Some(vec![
        RelationSelectorPathStep::tuple_field(field_ordinal),
        literal_list_index(list_ordinal)?,
    ])
}

fn root_in_nested_pair_list_path(
    field_ordinal: u64,
    list_ordinal: usize,
    pair_field_ordinal: u64,
) -> Option<Vec<RelationSelectorPathStep>> {
    Some(vec![
        RelationSelectorPathStep::tuple_field(field_ordinal),
        literal_list_index(list_ordinal)?,
        RelationSelectorPathStep::tuple_field(pair_field_ordinal),
    ])
}

fn root_in_evaluator_entry_source_list_path(
    entry_ordinal: usize,
    source_ordinal: usize,
) -> Option<Vec<RelationSelectorPathStep>> {
    Some(vec![
        RelationSelectorPathStep::tuple_field(1),
        literal_list_index(entry_ordinal)?,
        RelationSelectorPathStep::tuple_field(1),
        literal_list_index(source_ordinal)?,
    ])
}

fn root_in_evaluator_entry_aggregate_list_path(
    entry_ordinal: usize,
    aggregate_ordinal: usize,
) -> Option<Vec<RelationSelectorPathStep>> {
    Some(vec![
        RelationSelectorPathStep::tuple_field(1),
        literal_list_index(entry_ordinal)?,
        RelationSelectorPathStep::tuple_field(2),
        literal_list_index(aggregate_ordinal)?,
    ])
}

fn literal_list_index(ordinal: usize) -> Option<RelationSelectorPathStep> {
    Some(RelationSelectorPathStep {
        step_kind: SelectorPathStepKind::LiteralListIndex,
        argument: u64::try_from(ordinal).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{ProofBaseFieldElement, ProofChallengeExtensionElement};

    fn check_context() -> RelationPlanCheckContext {
        let evaluation_domain_size = 128_u64;
        let maximum_two_adic_order = 1_u64 << 32;
        RelationPlanCheckContext {
            base_field_modulus: crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: modular_power(
                crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                maximum_two_adic_order / evaluation_domain_size,
                crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 2,
            quotient_component_count: 2,
            quotient_component_degree_bound_exclusive: 64,
            fri_fold_count: 3,
            final_polynomial_degree_bound_exclusive: 8,
            unique_query_count: 8,
            non_native_modular_identity_challenge_count: 2,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![
                ResolvedSuiteModulus::new(SuiteModulusReference::data(0), 97),
                ResolvedSuiteModulus::new(SuiteModulusReference::special(0), 193),
            ],
        }
    }

    fn geometry() -> PublicAggregateRelationGeometry {
        PublicAggregateRelationGeometry {
            ring_degree: 16,
            evaluation_domain_size: 128,
            opening_degree_bound_exclusive: 64,
            public_polynomial_column_degree_bound_exclusive: 16,
            participant_count: 3,
        }
    }

    #[test]
    fn collective_public_key_plan_is_maskless_and_covers_every_root_coordinate() {
        let plan = compile_collective_public_key_aggregate_relation_plan(
            &CollectivePublicKeyAggregatePlanInput {
                geometry: geometry(),
                ordered_component_moduli: vec![
                    SuiteModulusReference::data(0),
                    SuiteModulusReference::special(0),
                ],
            },
            &check_context(),
        )
        .expect("exact collective public-key aggregate plan");
        let variant = &plan.variants()[0];
        assert_eq!(plan.application_statement_schema_identifier(), 0x1213);
        assert_eq!(variant.ordered_columns.len(), 8);
        assert_eq!(variant.ordered_trees.len(), 4);
        assert_eq!(variant.ordered_constraints.len(), 2);
        assert!(variant.ordered_masks.is_empty());
        assert!(variant.ordered_columns.iter().all(|column| {
            matches!(column.origin, RelationColumnOrigin::BoundTree { .. })
                && column.canonical_residue_modulus.is_some()
        }));
        assert!(variant.ordered_constraints.iter().all(|constraint| {
            constraint
                .ordered_injective_integer_factor_expressions
                .len()
                == 3
                && !constraint.enforce_proof_base_field_no_wrap
        }));
    }

    #[test]
    fn later_deep_candidate_rejects_a_cross_ordinal_translated_collision() {
        let context = check_context();
        let plan = compile_collective_public_key_aggregate_relation_plan(
            &CollectivePublicKeyAggregatePlanInput {
                geometry: geometry(),
                ordered_component_moduli: vec![SuiteModulusReference::data(0)],
            },
            &context,
        )
        .expect("exact collective public-key aggregate plan");
        let mut variant = plan.variants()[0].clone();
        variant.ordered_opening_points = vec![
            RelationOpeningPointDescriptor {
                deep_point_ordinal: 0,
                trace_rotation_is_negative: false,
                trace_rotation_magnitude: 0,
                conjugate_index: 0,
            },
            RelationOpeningPointDescriptor {
                deep_point_ordinal: 1,
                trace_rotation_is_negative: false,
                trace_rotation_magnitude: 0,
                conjugate_index: 0,
            },
        ];
        let evaluation_generator =
            ProofBaseFieldElement::from_canonical(context.evaluation_domain_generator)
                .expect("the test context has a canonical evaluation generator");
        let trace_generator =
            evaluation_generator.power(variant.evaluation_domain_size / variant.trace_domain_size);
        let trace_generator_inverse = trace_generator
            .inverse()
            .expect("the trace generator is nonzero");

        let (prior_point, translated_candidate) = (2..128_u64)
            .find_map(|coordinate| {
                let prior_point = ProofChallengeExtensionElement::from_canonical_coordinates([
                    coordinate, 1, 0, 0, 0,
                ])
                .ok()?;
                let translated_candidate = prior_point.multiply_base(trace_generator_inverse);
                (translated_candidate != prior_point
                    && variant
                        .deep_point_candidate_is_forbidden(
                            &context,
                            1,
                            translated_candidate,
                            &[prior_point],
                        )
                        .ok()
                        == Some(false))
                .then_some((prior_point, translated_candidate))
            })
            .expect("the deterministic candidate set contains an admissible point");

        variant.ordered_opening_points[1].trace_rotation_magnitude = 1;
        assert!(
            variant
                .deep_point_candidate_is_forbidden(
                    &context,
                    1,
                    translated_candidate,
                    &[prior_point],
                )
                .expect("candidate classification succeeds")
        );
    }

    #[test]
    fn every_factor_must_remain_canonically_bound_to_the_product() {
        let mut plan = compile_collective_public_key_aggregate_relation_plan(
            &CollectivePublicKeyAggregatePlanInput {
                geometry: geometry(),
                ordered_component_moduli: vec![SuiteModulusReference::data(0)],
            },
            &check_context(),
        )
        .expect("exact collective public-key aggregate plan");
        plan.plan.variants[0].ordered_constraints[0]
            .ordered_injective_integer_factor_expressions
            .pop();
        assert_eq!(
            plan.check(&check_context()),
            Err(RelationPlanError::InvalidConstraint)
        );
    }

    #[test]
    fn suite_validation_rejects_a_modulus_without_an_injective_factor_interval() {
        let mut context = check_context();
        context.resolved_moduli[0] = ResolvedSuiteModulus::new(
            SuiteModulusReference::data(0),
            crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS / 2,
        );
        assert_eq!(
            compile_collective_public_key_aggregate_relation_plan(
                &CollectivePublicKeyAggregatePlanInput {
                    geometry: geometry(),
                    ordered_component_moduli: vec![SuiteModulusReference::data(0)],
                },
                &context,
            ),
            Err(RelationPlanError::NoWrapBoundViolated)
        );
    }

    #[test]
    fn scheduled_and_action_selected_variant_catalogs_are_closed() {
        let context = check_context();
        let rkg_plan = compile_rkg_round_one_aggregate_relation_plan(
            &RkgRoundOneAggregatePlanInput {
                geometry: geometry(),
                ordered_variants: vec![
                    RkgRoundOneAggregateVariantInput {
                        schedule_position: 2,
                        ordered_left_component_moduli: vec![SuiteModulusReference::data(0)],
                        ordered_right_component_moduli: vec![SuiteModulusReference::special(0)],
                    },
                    RkgRoundOneAggregateVariantInput {
                        schedule_position: 7,
                        ordered_left_component_moduli: vec![SuiteModulusReference::data(0)],
                        ordered_right_component_moduli: vec![SuiteModulusReference::special(0)],
                    },
                ],
            },
            &context,
        )
        .expect("exact scheduled round-one aggregate plan");
        assert_eq!(rkg_plan.variants().len(), 2);
        assert_eq!(rkg_plan.variants()[0].schedule_position(), Some(2));
        assert_eq!(rkg_plan.variants()[1].schedule_position(), Some(7));

        let evaluator_variants = (1..=20)
            .flat_map(|top_count| {
                [
                    EvaluatorKeyAggregateVariantInput {
                        top_count,
                        entry_ordinal: 0,
                        entry: EvaluatorKeyAggregateEntryPlanInput {
                            schedule_position: 3,
                            ordered_runtime_component_moduli: vec![SuiteModulusReference::data(0)],
                        },
                    },
                    EvaluatorKeyAggregateVariantInput {
                        top_count,
                        entry_ordinal: 1,
                        entry: EvaluatorKeyAggregateEntryPlanInput {
                            schedule_position: 1,
                            ordered_runtime_component_moduli: vec![SuiteModulusReference::special(
                                0,
                            )],
                        },
                    },
                ]
            })
            .collect::<Vec<_>>();
        let evaluator_plan = compile_evaluator_key_aggregate_relation_plan(
            &EvaluatorKeyAggregatePlanInput {
                geometry: geometry(),
                ordered_variants: evaluator_variants.clone(),
            },
            &context,
        )
        .expect("exact action-selected evaluator aggregate plan");
        assert_eq!(evaluator_plan.variants().len(), 40);
        assert_eq!(evaluator_plan.variants()[0].schedule_position(), Some(0));
        assert_eq!(evaluator_plan.variants()[0].top_count(), Some(1));
        assert_eq!(evaluator_plan.variants()[39].schedule_position(), Some(1));
        assert_eq!(evaluator_plan.variants()[39].top_count(), Some(20));

        let mut incomplete_variants = evaluator_variants;
        incomplete_variants.pop();
        incomplete_variants.pop();
        assert_eq!(
            compile_evaluator_key_aggregate_relation_plan(
                &EvaluatorKeyAggregatePlanInput {
                    geometry: geometry(),
                    ordered_variants: incomplete_variants,
                },
                &context,
            ),
            Err(RelationPlanError::InvalidVariantSelector)
        );
    }
}
