use std::collections::BTreeMap;

use num_bigint::BigInt;
use num_traits::Signed;

use super::{
    BoundTreeConstructionKind, BoundTreeRootUse, RelationBoundCertificate, RelationColumnOrigin,
    RelationPlanCheckContext, RelationPlanError, RelationPlanVariant, RelationTreeDescriptor,
    check_expression, evaluate_integer_interval, expression_column_ordinals,
};
use crate::{
    bgv::proof_suite::{
        MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, ProofBodyLayout,
        ProofLeafVisibility, ProofTreeCatalogInput, ProofTreeRole, RelationProofTreeInput,
        SelectedApplicationStatementContext, StatementOwnedProofTreeInput,
        build_complete_proof_tree_catalog, canonical_common_proof_byte_length_ceiling,
        canonical_selected_application_statement_for_ceiling,
        selected_committed_material_relation_plan_input, selected_relation_plan_check_context,
    },
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings,
        ProofObjectHeader,
    },
};

use super::committed_material::{
    CommittedMaterialRangeCandidate, CommittedMaterialTraceWitnessStructureMemoryAccounting,
    vss_share_linkage_range_candidate_trace_witness_structure_memory_accounting,
};
use super::committed_material_adapter::{
    CommittedMaterialSourceProviderMemoryAccounting,
    vss_share_linkage_source_provider_memory_accounting,
};
use super::vss_share_linkage::compile_vss_share_linkage_range_candidate;
use crate::bgv::proof_suite::prover::{
    CommonProofExternalMemoryRequirement, CommonProofResidentMemoryPhase,
    CommonProofResidentMemoryPlan, common_proof_external_memory_requirement,
    common_proof_resident_memory_requirement, common_proof_source_provider_is_live_during_phase,
};

const THREE_SIXTEEN_BIT_LIMB_CAPACITY: u64 = 1_u64 << 48;

struct CandidateSizing {
    proof_byte_length: usize,
    maximum_prefetched_query_byte_length: u64,
    resident_memory: CommonProofResidentMemoryPlan,
    external_memory: CommonProofExternalMemoryRequirement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CandidateProviderSizing {
    loading_persistent_byte_length: u64,
    post_source_finish_persistent_byte_length: u64,
    preparation_peak_byte_length: u64,
    construction_peak_byte_length: u64,
    combined_common_proof_peak_byte_length: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct CandidateRangeMetrics {
    bound_column_count: usize,
    prover_column_count: usize,
    trinary_column_count: usize,
    binary_column_count: usize,
    nonary_column_count: usize,
    recomposition_target_column_count: usize,
    constraint_count: usize,
    no_wrap_constraint_count: usize,
    maximum_numerator_degree: u64,
    application_deep_identity_degree: u64,
    maximum_no_wrap_absolute_value: BigInt,
    integer_lift_batch_count: usize,
    integer_lift_component_count: usize,
    coefficient_local_batch_count: usize,
    coefficient_local_residual_count: usize,
    opening_point_count: usize,
    opening_claim_count: usize,
    bound_tree_count: usize,
    proof_created_tree_count: usize,
}

fn candidate_range_metrics(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<CandidateRangeMetrics, RelationPlanError> {
    let bound_column_count = variant
        .ordered_columns
        .iter()
        .filter(|column| matches!(column.origin, RelationColumnOrigin::BoundTree { .. }))
        .count();
    let prover_column_count = variant
        .ordered_columns
        .iter()
        .filter(|column| matches!(column.origin, RelationColumnOrigin::Prover))
        .count();
    let mut trinary_column_count = 0_usize;
    let mut binary_column_count = 0_usize;
    let mut nonary_column_count = 0_usize;
    let mut recomposition_target_column_count = 0_usize;
    let mut semantic_bounds = BTreeMap::new();
    for semantic_cell in &variant.ordered_semantic_cells {
        semantic_bounds.insert(
            semantic_cell.column_ordinal,
            semantic_cell.claimed_interval.clone(),
        );
        match &semantic_cell.bound_certificate {
            RelationBoundCertificate::Trinary { .. } => trinary_column_count += 1,
            RelationBoundCertificate::Binary { .. } => binary_column_count += 1,
            RelationBoundCertificate::FiniteIntegerSet { ordered_values, .. }
                if ordered_values == &(0..9).map(BigInt::from).collect::<Vec<_>>() =>
            {
                nonary_column_count += 1;
            }
            RelationBoundCertificate::UnsignedRadixRecomposition { .. }
            | RelationBoundCertificate::ShiftedRadixRecomposition { .. } => {
                recomposition_target_column_count += 1;
            }
            _ => {}
        }
    }

    let mut no_wrap_constraint_count = 0_usize;
    let mut maximum_numerator_degree = 0_u64;
    let mut maximum_no_wrap_absolute_value = BigInt::from(0_u8);
    for constraint in &variant.ordered_constraints {
        maximum_numerator_degree = maximum_numerator_degree.max(
            check_expression(
                &constraint.numerator_postfix_expression,
                variant,
                context,
                false,
            )?
            .degree,
        );
        if constraint.enforce_proof_base_field_no_wrap {
            no_wrap_constraint_count += 1;
            let declared_bounds =
                expression_column_ordinals(&constraint.numerator_postfix_expression, variant)?
                    .into_iter()
                    .map(|column_ordinal| {
                        semantic_bounds
                            .get(&column_ordinal)
                            .cloned()
                            .map(|interval| (column_ordinal, interval))
                            .ok_or(RelationPlanError::InvalidSemanticCell)
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
            let interval = evaluate_integer_interval(
                &constraint.numerator_postfix_expression,
                &declared_bounds,
                variant,
                context,
            )?;
            maximum_no_wrap_absolute_value = maximum_no_wrap_absolute_value
                .max(interval.minimum.abs())
                .max(interval.maximum.abs());
        }
    }

    Ok(CandidateRangeMetrics {
        bound_column_count,
        prover_column_count,
        trinary_column_count,
        binary_column_count,
        nonary_column_count,
        recomposition_target_column_count,
        constraint_count: variant.ordered_constraints.len(),
        no_wrap_constraint_count,
        maximum_numerator_degree,
        application_deep_identity_degree: variant
            .application_deep_identity_degree_bound(context)?,
        maximum_no_wrap_absolute_value,
        integer_lift_batch_count: variant.ordered_integer_lift_batches().len(),
        integer_lift_component_count: variant
            .ordered_integer_lift_batches()
            .iter()
            .map(|batch| batch.ordered_components.len())
            .sum(),
        coefficient_local_batch_count: variant.ordered_coefficient_local_identity_batches.len(),
        coefficient_local_residual_count: variant
            .ordered_coefficient_local_identity_batches
            .iter()
            .map(|batch| batch.ordered_residuals.len())
            .sum(),
        opening_point_count: variant.ordered_opening_points.len(),
        opening_claim_count: variant.ordered_opening_claims.len(),
        bound_tree_count: variant
            .ordered_trees
            .iter()
            .filter(|tree| matches!(tree, RelationTreeDescriptor::BoundPublic { .. }))
            .count(),
        proof_created_tree_count: variant
            .ordered_trees
            .iter()
            .filter(|tree| matches!(tree, RelationTreeDescriptor::ProofCreated { .. }))
            .count(),
    })
}

fn candidate_relation_tree_inputs(
    variant: &RelationPlanVariant,
) -> Result<Vec<RelationProofTreeInput>, RelationPlanError> {
    variant
        .ordered_trees()
        .iter()
        .map(|tree| match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => Ok(RelationProofTreeInput::ProofCreated {
                tree_role: match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(RelationPlanError::InvalidRoot),
                },
                row_width: u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| RelationPlanError::CountOverflow)?,
                leaf_visibility: if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|column_index| variant.ordered_columns().get(column_index))
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::Prover)
                        })
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                },
            }),
            RelationTreeDescriptor::BoundPublic {
                construction_kind, ..
            } => {
                if *construction_kind != BoundTreeConstructionKind::CommittedMaterial {
                    return Err(RelationPlanError::InvalidRoot);
                }
                Ok(RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: [0; Hash512::BYTE_LENGTH],
                        expected_root: [0; Hash512::BYTE_LENGTH],
                    },
                ))
            }
        })
        .collect()
}

fn candidate_sizing(
    variant: &RelationPlanVariant,
    context: &RelationPlanCheckContext,
) -> Result<CandidateSizing, String> {
    let schema_identifier =
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
    let statement_context = SelectedApplicationStatementContext::new(
        FOUNDATION_PROFILE.protocol_version,
        [0; Hash512::BYTE_LENGTH],
        None,
        None,
    );
    let statement_bytes =
        canonical_selected_application_statement_for_ceiling(schema_identifier, statement_context)
            .map_err(|error| format!("canonical statement: {error:?}"))?;
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        statement_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|error| format!("proof header: {error:?}"))?;
    let proof_header_bytes = proof_header
        .encode()
        .map_err(|error| format!("proof header encoding: {error:?}"))?;
    let transcript_schedule = variant
        .common_proof_transcript_schedule(context)
        .map_err(|error| format!("transcript schedule: {error:?}"))?;
    let catalog = build_complete_proof_tree_catalog(
        ProofTreeCatalogInput {
            suite_identifier: [0; Hash512::BYTE_LENGTH],
            canonical_proof_object_header_bytes: proof_header_bytes.clone(),
            application_statement_schema_identifier: schema_identifier,
            proof_field_index: 0,
            evaluation_domain_size: variant.evaluation_domain_size(),
            relation_trees: candidate_relation_tree_inputs(variant)
                .map_err(|error| format!("tree inputs: {error:?}"))?,
        },
        &transcript_schedule,
    )
    .map_err(|error| format!("tree catalog: {error:?}"))?;
    let layout = ProofBodyLayout::new(
        catalog,
        &transcript_schedule,
        transcript_schedule.terminal_coefficient_count(),
    )
    .map_err(|error| format!("body layout: {error:?}"))?;
    let ceiling = canonical_common_proof_byte_length_ceiling(proof_header_bytes.len(), &layout)
        .map_err(|error| format!("proof ceiling: {error:?}"))?;
    let maximum_prefetched_query_byte_length = ceiling
        .query_trees()
        .iter()
        .map(|tree| {
            tree.opened_leaf_payload_byte_length()
                .checked_add(tree.authentication_frontier_digest_byte_length())
                .ok_or_else(|| "query prefetch length overflow".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or_else(|| "empty query tree catalog".to_owned())?;
    let resident_memory = common_proof_resident_memory_requirement(
        variant,
        context,
        &transcript_schedule,
        layout.catalog(),
        schema_identifier,
        u64::try_from(proof_header_bytes.len())
            .map_err(|_| "proof header length does not fit u64".to_owned())?,
        u64::try_from(maximum_prefetched_query_byte_length)
            .map_err(|_| "query prefetch length does not fit u64".to_owned())?,
        u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
            .map_err(|_| "proof chunk length does not fit u64".to_owned())?,
    )
    .map_err(|error| format!("resident memory: {error:?}"))?;
    let external_memory = common_proof_external_memory_requirement(
        variant,
        context,
        layout.catalog(),
        &transcript_schedule,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    )
    .map_err(|error| format!("external memory: {error:?}"))?;
    Ok(CandidateSizing {
        proof_byte_length: ceiling.proof_byte_length(),
        maximum_prefetched_query_byte_length: u64::try_from(maximum_prefetched_query_byte_length)
            .map_err(|_| {
            "query prefetch length does not fit u64".to_owned()
        })?,
        resident_memory,
        external_memory,
    })
}

fn exact_candidate_provider_sizing(
    candidate_variant: &RelationPlanVariant,
    candidate_resident_memory: &CommonProofResidentMemoryPlan,
    candidate_trace_structure: CommittedMaterialTraceWitnessStructureMemoryAccounting,
    selected_variant: &RelationPlanVariant,
    selected_trace_structure: CommittedMaterialTraceWitnessStructureMemoryAccounting,
    selected_accounting: CommittedMaterialSourceProviderMemoryAccounting,
) -> Result<CandidateProviderSizing, String> {
    if candidate_variant.ordered_trees().len() != selected_variant.ordered_trees().len()
        || candidate_variant.trace_domain_size() != selected_variant.trace_domain_size()
        || selected_accounting.resolved_modulus_catalog_byte_length()
            != selected_trace_structure.resolved_modulus_catalog_byte_length()
        || selected_accounting.recipe_catalog_byte_length()
            != selected_trace_structure.recipe_catalog_byte_length()
        || selected_accounting.nested_recipe_catalog_byte_length()
            != selected_trace_structure.nested_recipe_catalog_byte_length()
    {
        return Err(
            "candidate provider adjustment requires identical trees and exact selected structure accounting"
                .to_owned(),
        );
    }
    let selected_column_count = u64::try_from(selected_variant.ordered_columns().len())
        .map_err(|_| "selected column count does not fit u64".to_owned())?;
    let candidate_column_count = u64::try_from(candidate_variant.ordered_columns().len())
        .map_err(|_| "candidate column count does not fit u64".to_owned())?;
    if selected_column_count == 0
        || selected_accounting
            .bound_material_column_lookup_catalog_byte_length()
            .checked_rem(selected_column_count)
            != Some(0)
        || selected_accounting
            .ordered_column_catalog_byte_length()
            .checked_rem(selected_column_count)
            != Some(0)
    {
        return Err(
            "selected provider column catalogs are not exact fixed-width arrays".to_owned(),
        );
    }
    let bound_lookup_byte_length_per_column = selected_accounting
        .bound_material_column_lookup_catalog_byte_length()
        / selected_column_count;
    let ordered_descriptor_byte_length_per_column =
        selected_accounting.ordered_column_catalog_byte_length() / selected_column_count;
    let selected_variable_byte_length = selected_accounting
        .bound_material_column_lookup_catalog_byte_length()
        .checked_add(selected_accounting.ordered_column_catalog_byte_length())
        .and_then(|total| {
            total.checked_add(selected_trace_structure.resolved_modulus_catalog_byte_length())
        })
        .and_then(|total| total.checked_add(selected_trace_structure.recipe_catalog_byte_length()))
        .and_then(|total| {
            total.checked_add(selected_trace_structure.nested_recipe_catalog_byte_length())
        })
        .ok_or_else(|| "selected provider variable memory overflow".to_owned())?;
    let candidate_variable_byte_length = candidate_column_count
        .checked_mul(bound_lookup_byte_length_per_column)
        .and_then(|lookup| {
            candidate_column_count
                .checked_mul(ordered_descriptor_byte_length_per_column)
                .and_then(|descriptors| lookup.checked_add(descriptors))
        })
        .and_then(|total| {
            total.checked_add(candidate_trace_structure.resolved_modulus_catalog_byte_length())
        })
        .and_then(|total| total.checked_add(candidate_trace_structure.recipe_catalog_byte_length()))
        .and_then(|total| {
            total.checked_add(candidate_trace_structure.nested_recipe_catalog_byte_length())
        })
        .ok_or_else(|| "candidate provider variable memory overflow".to_owned())?;
    let fixed_loading_byte_length = selected_accounting
        .loading_persistent_resident_byte_length()
        .checked_sub(selected_variable_byte_length)
        .ok_or_else(|| "selected provider variable memory exceeds its total".to_owned())?;
    let loading_persistent_byte_length = fixed_loading_byte_length
        .checked_add(candidate_variable_byte_length)
        .ok_or_else(|| "candidate provider loading memory overflow".to_owned())?;
    let post_source_finish_persistent_byte_length =
        selected_accounting.post_source_polynomial_finish_persistent_resident_byte_length();
    let preparation_peak_byte_length = loading_persistent_byte_length
        .checked_add(selected_accounting.preparation_transient_byte_length())
        .ok_or_else(|| "candidate provider preparation memory overflow".to_owned())?;
    let construction_peak_byte_length = loading_persistent_byte_length
        .checked_add(selected_accounting.relation_tree_input_catalog_byte_length())
        .and_then(|total| {
            total.checked_add(selected_accounting.construction_transient_peak_byte_length())
        })
        .ok_or_else(|| "candidate provider construction memory overflow".to_owned())?;
    let combined_common_proof_peak_byte_length = candidate_resident_memory
        .phases()
        .iter()
        .map(|phase| {
            let provider_byte_length =
                if common_proof_source_provider_is_live_during_phase(phase.phase()) {
                    if phase.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
                        loading_persistent_byte_length
                    } else {
                        post_source_finish_persistent_byte_length
                    }
                } else {
                    0
                };
            phase
                .total_byte_length()
                .checked_add(provider_byte_length)
                .ok_or_else(|| "candidate combined resident memory overflow".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or_else(|| "candidate resident plan is empty".to_owned())?;
    Ok(CandidateProviderSizing {
        loading_persistent_byte_length,
        post_source_finish_persistent_byte_length,
        preparation_peak_byte_length,
        construction_peak_byte_length,
        combined_common_proof_peak_byte_length,
    })
}

fn bound_tree_mapping(variant: &RelationPlanVariant) -> Vec<(u32, BoundTreeRootUse, usize)> {
    variant
        .ordered_trees()
        .iter()
        .filter_map(|tree| match tree {
            RelationTreeDescriptor::BoundPublic {
                expected_root_source_ordinal,
                root_use,
                ordered_column_ordinals,
                ..
            } => Some((
                *expected_root_source_ordinal,
                *root_use,
                ordered_column_ordinals.len(),
            )),
            RelationTreeDescriptor::ProofCreated { .. } => None,
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[ignore = "manual guarded VSS range-candidate compiler comparison"]
fn selected_vss_range_candidates_report_exact_compiler_comparison() {
    let input = selected_committed_material_relation_plan_input()
        .expect("selected committed-material relation input");
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("selected VSS relation context");

    let full_ternary = compile_vss_share_linkage_range_candidate(
        &input,
        &context,
        CommittedMaterialRangeCandidate::FullTernary,
    )
    .expect("full-ternary VSS range candidate compiles");
    let adjacent_pair_nonary = compile_vss_share_linkage_range_candidate(
        &input,
        &context,
        CommittedMaterialRangeCandidate::AdjacentPairNonary,
    )
    .expect("adjacent-pair nonary VSS range candidate compiles");
    let full_ternary_variant = full_ternary
        .select_variant(None, None)
        .expect("full-ternary candidate variant");
    let adjacent_pair_nonary_variant = adjacent_pair_nonary
        .select_variant(None, None)
        .expect("adjacent-pair candidate variant");
    let full_ternary_metrics =
        candidate_range_metrics(full_ternary_variant, &context).expect("full-ternary metrics");
    let adjacent_pair_nonary_metrics =
        candidate_range_metrics(adjacent_pair_nonary_variant, &context)
            .expect("adjacent-pair metrics");
    let full_ternary_sizing =
        candidate_sizing(full_ternary_variant, &context).expect("full-ternary sizing");
    let adjacent_pair_nonary_sizing =
        candidate_sizing(adjacent_pair_nonary_variant, &context).expect("adjacent-pair sizing");
    let full_ternary_trace_structure =
        vss_share_linkage_range_candidate_trace_witness_structure_memory_accounting(
            &input,
            &context,
            CommittedMaterialRangeCandidate::FullTernary,
        )
        .expect("full-ternary trace-witness structure accounting");
    let adjacent_pair_nonary_trace_structure =
        vss_share_linkage_range_candidate_trace_witness_structure_memory_accounting(
            &input,
            &context,
            CommittedMaterialRangeCandidate::AdjacentPairNonary,
        )
        .expect("adjacent-pair trace-witness structure accounting");
    let selected_provider_accounting = vss_share_linkage_source_provider_memory_accounting(
        &input,
        &context,
        &adjacent_pair_nonary,
    )
    .expect("selected VSS source-provider accounting");
    let full_ternary_provider_sizing = exact_candidate_provider_sizing(
        full_ternary_variant,
        &full_ternary_sizing.resident_memory,
        full_ternary_trace_structure,
        adjacent_pair_nonary_variant,
        adjacent_pair_nonary_trace_structure,
        selected_provider_accounting,
    )
    .expect("full-ternary provider sizing");
    let adjacent_pair_nonary_provider_sizing = exact_candidate_provider_sizing(
        adjacent_pair_nonary_variant,
        &adjacent_pair_nonary_sizing.resident_memory,
        adjacent_pair_nonary_trace_structure,
        adjacent_pair_nonary_variant,
        adjacent_pair_nonary_trace_structure,
        selected_provider_accounting,
    )
    .expect("adjacent-pair provider sizing");
    let roots_per_sharing_limb = usize::from(input.threshold)
        .checked_add(usize::from(input.participant_count))
        .expect("selected VSS roots per sharing limb fit usize");
    let packed_material_group_count = input
        .sharing_data_modulus_indices
        .len()
        .checked_mul(roots_per_sharing_limb.div_ceil(8))
        .expect("selected VSS packed material group count fits usize");
    let material_comparator_borrow_column_count = packed_material_group_count * 2;
    let material_value_target_column_count = packed_material_group_count * 4;
    let material_difference_target_column_count = packed_material_group_count * 4;
    let logical_quotient_count = input
        .sharing_data_modulus_indices
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_mul(usize::from(input.participant_count)))
        .expect("selected VSS quotient count fits usize");
    let packed_quotient_target_column_count = logical_quotient_count.div_ceil(8);
    let full_ternary_quotient_decomposition_column_count = packed_quotient_target_column_count * 2;
    let adjacent_pair_quotient_decomposition_column_count = packed_quotient_target_column_count;

    assert_eq!(
        bound_tree_mapping(full_ternary_variant),
        bound_tree_mapping(adjacent_pair_nonary_variant),
        "proof-internal packing must preserve the persistent root order, use, and width",
    );
    assert_eq!(full_ternary_metrics.bound_column_count, 364 * 4);
    assert_eq!(
        full_ternary_metrics.bound_column_count,
        adjacent_pair_nonary_metrics.bound_column_count,
    );
    assert_eq!(full_ternary_metrics.nonary_column_count, 0);
    assert!(adjacent_pair_nonary_metrics.nonary_column_count > 0);
    assert_eq!(
        full_ternary_metrics.recomposition_target_column_count,
        material_value_target_column_count
            + material_difference_target_column_count
            + packed_quotient_target_column_count,
    );
    assert_eq!(
        full_ternary_metrics.recomposition_target_column_count,
        adjacent_pair_nonary_metrics.recomposition_target_column_count,
    );
    assert!(
        adjacent_pair_nonary_metrics.prover_column_count < full_ternary_metrics.prover_column_count
    );
    assert!(adjacent_pair_nonary_sizing.proof_byte_length < full_ternary_sizing.proof_byte_length);
    assert!(
        adjacent_pair_nonary_trace_structure.total_byte_length()
            < full_ternary_trace_structure.total_byte_length()
    );
    assert!(
        adjacent_pair_nonary_provider_sizing.loading_persistent_byte_length
            < full_ternary_provider_sizing.loading_persistent_byte_length
    );
    assert!(
        adjacent_pair_nonary_provider_sizing.combined_common_proof_peak_byte_length
            <= full_ternary_provider_sizing.combined_common_proof_peak_byte_length
    );
    assert_eq!(
        adjacent_pair_nonary_provider_sizing.loading_persistent_byte_length,
        selected_provider_accounting.loading_persistent_resident_byte_length(),
    );
    assert_eq!(
        adjacent_pair_nonary_provider_sizing.post_source_finish_persistent_byte_length,
        selected_provider_accounting
            .post_source_polynomial_finish_persistent_resident_byte_length(),
    );
    assert_eq!(
        adjacent_pair_nonary_provider_sizing.preparation_peak_byte_length,
        selected_provider_accounting.preparation_peak_resident_byte_length(),
    );
    assert_eq!(
        adjacent_pair_nonary_provider_sizing.construction_peak_byte_length,
        selected_provider_accounting.construction_peak_resident_byte_length(),
    );
    assert_eq!(
        full_ternary_metrics.coefficient_local_batch_count,
        adjacent_pair_nonary_metrics.coefficient_local_batch_count,
    );
    assert_eq!(full_ternary_metrics.integer_lift_batch_count, 0);
    assert_eq!(full_ternary_metrics.integer_lift_component_count, 0);
    assert_eq!(
        full_ternary_metrics.integer_lift_batch_count,
        adjacent_pair_nonary_metrics.integer_lift_batch_count,
    );
    assert_eq!(
        full_ternary_metrics.integer_lift_component_count,
        adjacent_pair_nonary_metrics.integer_lift_component_count,
    );
    assert_eq!(
        full_ternary_metrics.coefficient_local_residual_count,
        adjacent_pair_nonary_metrics.coefficient_local_residual_count,
    );

    let (full_ternary_plan_byte_length, full_ternary_plan_hash) = full_ternary
        .canonical_byte_length_and_hash()
        .expect("full-ternary canonical plan");
    let (adjacent_pair_plan_byte_length, adjacent_pair_plan_hash) = adjacent_pair_nonary
        .canonical_byte_length_and_hash()
        .expect("adjacent-pair canonical plan");
    assert_ne!(full_ternary_plan_hash, adjacent_pair_plan_hash);
    eprintln!(
        "vss_range_candidate name=full_ternary persistent_radix={} persistent_digit_count=2 persistent_root_encoding=unchanged common_witness_mapping=persistent_bound_source_use_width_unchanged material_value_trits=34 committed_columns={} material_value_targets={} material_difference_targets={} material_decomposition_columns={} logical_quotients={} packed_quotient_targets={} quotient_decomposition_columns={} prover_columns={} trinary_columns={} binary_columns={} nonary_columns={} recomposition_targets={} borrow_columns={} shift_selector_columns={} carry_columns=0 lookup_columns=0 lookup_table_rows=0 lookup_opening_claims=0 accumulator_columns=0 integer_lift_batches={} integer_lift_components={} constraints={} no_wrap_constraints={} maximum_numerator_degree={} application_deep_identity_degree={} maximum_no_wrap_absolute_value={} coefficient_local_batches={} coefficient_local_residuals={} opening_points={} opening_claims={} bound_trees={} proof_created_trees={} plan_bytes={} plan_hash={} proof_ceiling={} maximum_prefetched_query_bytes={} base_resident_peak={} combined_resident_peak={} provider_live_phase_count=4 provider_loading_persistent={} provider_post_finish_persistent={} provider_preparation_peak={} provider_construction_peak={} external_scratch_peak={} external_total_written={} external_total_read={} external_transactions={} trace_provider_structure_bytes={} resident_phases={:?} external_plan={:?}",
        129_140_163_u64,
        full_ternary_metrics.bound_column_count,
        material_value_target_column_count,
        material_difference_target_column_count,
        full_ternary_metrics.trinary_column_count
            - full_ternary_quotient_decomposition_column_count,
        logical_quotient_count,
        packed_quotient_target_column_count,
        full_ternary_quotient_decomposition_column_count,
        full_ternary_metrics.prover_column_count,
        full_ternary_metrics.trinary_column_count,
        full_ternary_metrics.binary_column_count,
        full_ternary_metrics.nonary_column_count,
        full_ternary_metrics.recomposition_target_column_count,
        material_comparator_borrow_column_count,
        full_ternary_metrics.binary_column_count - material_comparator_borrow_column_count,
        full_ternary_metrics.integer_lift_batch_count,
        full_ternary_metrics.integer_lift_component_count,
        full_ternary_metrics.constraint_count,
        full_ternary_metrics.no_wrap_constraint_count,
        full_ternary_metrics.maximum_numerator_degree,
        full_ternary_metrics.application_deep_identity_degree,
        full_ternary_metrics.maximum_no_wrap_absolute_value,
        full_ternary_metrics.coefficient_local_batch_count,
        full_ternary_metrics.coefficient_local_residual_count,
        full_ternary_metrics.opening_point_count,
        full_ternary_metrics.opening_claim_count,
        full_ternary_metrics.bound_tree_count,
        full_ternary_metrics.proof_created_tree_count,
        full_ternary_plan_byte_length,
        bytes_to_hex(&full_ternary_plan_hash),
        full_ternary_sizing.proof_byte_length,
        full_ternary_sizing.maximum_prefetched_query_byte_length,
        full_ternary_sizing.resident_memory.peak_byte_length(),
        full_ternary_provider_sizing.combined_common_proof_peak_byte_length,
        full_ternary_provider_sizing.loading_persistent_byte_length,
        full_ternary_provider_sizing.post_source_finish_persistent_byte_length,
        full_ternary_provider_sizing.preparation_peak_byte_length,
        full_ternary_provider_sizing.construction_peak_byte_length,
        full_ternary_sizing
            .external_memory
            .peak_stored_byte_length(),
        full_ternary_sizing
            .external_memory
            .total_written_byte_length(),
        full_ternary_sizing.external_memory.total_read_byte_length(),
        full_ternary_sizing.external_memory.transaction_count(),
        full_ternary_trace_structure.total_byte_length(),
        full_ternary_sizing.resident_memory.phases(),
        full_ternary_sizing.external_memory,
    );
    eprintln!(
        "vss_range_candidate name=adjacent_pair_nonary persistent_radix={} persistent_digit_count=2 persistent_root_encoding=unchanged common_witness_mapping=persistent_bound_source_use_width_unchanged material_value_nonary_columns_per_low_digit=8 material_value_top_trits_per_low_digit=1 committed_columns={} material_value_targets={} material_difference_targets={} material_nonary_decomposition_columns={} material_top_trinary_columns={} logical_quotients={} packed_quotient_targets={} quotient_decomposition_columns={} prover_columns={} trinary_columns={} binary_columns={} nonary_columns={} recomposition_targets={} borrow_columns={} shift_selector_columns={} carry_columns=0 lookup_columns=0 lookup_table_rows=0 lookup_opening_claims=0 accumulator_columns=0 integer_lift_batches={} integer_lift_components={} constraints={} no_wrap_constraints={} maximum_numerator_degree={} application_deep_identity_degree={} maximum_no_wrap_absolute_value={} coefficient_local_batches={} coefficient_local_residuals={} opening_points={} opening_claims={} bound_trees={} proof_created_trees={} plan_bytes={} plan_hash={} proof_ceiling={} proof_byte_reduction={} proof_reduction_ratio={:.9} maximum_prefetched_query_bytes={} base_resident_peak={} combined_resident_peak={} provider_live_phase_count=4 provider_loading_persistent={} provider_loading_reduction={} provider_post_finish_persistent={} provider_preparation_peak={} provider_construction_peak={} external_scratch_peak={} external_total_written={} external_total_read={} external_transactions={} trace_provider_structure_bytes={} trace_provider_structure_reduction={} resident_phases={:?} external_plan={:?}",
        129_140_163_u64,
        adjacent_pair_nonary_metrics.bound_column_count,
        material_value_target_column_count,
        material_difference_target_column_count,
        adjacent_pair_nonary_metrics.nonary_column_count
            - adjacent_pair_quotient_decomposition_column_count,
        adjacent_pair_nonary_metrics.trinary_column_count,
        logical_quotient_count,
        packed_quotient_target_column_count,
        adjacent_pair_quotient_decomposition_column_count,
        adjacent_pair_nonary_metrics.prover_column_count,
        adjacent_pair_nonary_metrics.trinary_column_count,
        adjacent_pair_nonary_metrics.binary_column_count,
        adjacent_pair_nonary_metrics.nonary_column_count,
        adjacent_pair_nonary_metrics.recomposition_target_column_count,
        material_comparator_borrow_column_count,
        adjacent_pair_nonary_metrics.binary_column_count - material_comparator_borrow_column_count,
        adjacent_pair_nonary_metrics.integer_lift_batch_count,
        adjacent_pair_nonary_metrics.integer_lift_component_count,
        adjacent_pair_nonary_metrics.constraint_count,
        adjacent_pair_nonary_metrics.no_wrap_constraint_count,
        adjacent_pair_nonary_metrics.maximum_numerator_degree,
        adjacent_pair_nonary_metrics.application_deep_identity_degree,
        adjacent_pair_nonary_metrics.maximum_no_wrap_absolute_value,
        adjacent_pair_nonary_metrics.coefficient_local_batch_count,
        adjacent_pair_nonary_metrics.coefficient_local_residual_count,
        adjacent_pair_nonary_metrics.opening_point_count,
        adjacent_pair_nonary_metrics.opening_claim_count,
        adjacent_pair_nonary_metrics.bound_tree_count,
        adjacent_pair_nonary_metrics.proof_created_tree_count,
        adjacent_pair_plan_byte_length,
        bytes_to_hex(&adjacent_pair_plan_hash),
        adjacent_pair_nonary_sizing.proof_byte_length,
        full_ternary_sizing.proof_byte_length - adjacent_pair_nonary_sizing.proof_byte_length,
        adjacent_pair_nonary_sizing.proof_byte_length as f64
            / full_ternary_sizing.proof_byte_length as f64,
        adjacent_pair_nonary_sizing.maximum_prefetched_query_byte_length,
        adjacent_pair_nonary_sizing
            .resident_memory
            .peak_byte_length(),
        adjacent_pair_nonary_provider_sizing.combined_common_proof_peak_byte_length,
        adjacent_pair_nonary_provider_sizing.loading_persistent_byte_length,
        full_ternary_provider_sizing.loading_persistent_byte_length
            - adjacent_pair_nonary_provider_sizing.loading_persistent_byte_length,
        adjacent_pair_nonary_provider_sizing.post_source_finish_persistent_byte_length,
        adjacent_pair_nonary_provider_sizing.preparation_peak_byte_length,
        adjacent_pair_nonary_provider_sizing.construction_peak_byte_length,
        adjacent_pair_nonary_sizing
            .external_memory
            .peak_stored_byte_length(),
        adjacent_pair_nonary_sizing
            .external_memory
            .total_written_byte_length(),
        adjacent_pair_nonary_sizing
            .external_memory
            .total_read_byte_length(),
        adjacent_pair_nonary_sizing
            .external_memory
            .transaction_count(),
        adjacent_pair_nonary_trace_structure.total_byte_length(),
        full_ternary_trace_structure.total_byte_length()
            - adjacent_pair_nonary_trace_structure.total_byte_length(),
        adjacent_pair_nonary_sizing.resident_memory.phases(),
        adjacent_pair_nonary_sizing.external_memory,
    );

    let resolved_moduli = input
        .validate(&context)
        .expect("selected committed-material moduli resolve");
    let unsupported_three_limb_moduli = resolved_moduli
        .iter()
        .enumerate()
        .filter_map(|(sharing_limb_ordinal, (modulus_reference, modulus))| {
            (*modulus >= THREE_SIXTEEN_BIT_LIMB_CAPACITY).then_some((
                sharing_limb_ordinal,
                modulus_reference.modulus_index,
                *modulus,
            ))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        resolved_moduli.len(),
        26,
        "the selected candidate comparison must cover the complete data basis",
    );
    assert_eq!(
        unsupported_three_limb_moduli.len(),
        18,
        "the exact selected basis must expose every modulus above the three-limb capacity",
    );
    assert!(
        !unsupported_three_limb_moduli.is_empty(),
        "the real three-16-bit encoding must be rejected when it cannot represent a selected modulus",
    );
    eprintln!(
        "vss_range_candidate name=three_sixteen_bit_limbs selected_suite_result=rejected capacity_exclusive={} selected_modulus_count={} unsupported_modulus_count={} unsupported_moduli={:?} persistent_columns_per_physical_half=3 persistent_tree_width=6 value_binary_columns_per_physical_half=48 maximum_difference_target_columns_per_physical_half=3 maximum_difference_binary_columns_per_physical_half=48 borrow_columns_per_physical_half=2 maximum_total_columns_per_physical_half=104 lookup_columns=0 accumulator_columns=0 carry_columns=0 proof_ceiling=unavailable resident_plan=unavailable scratch_plan=unavailable common_witness_mapping=requires_six_column_persistent_schema",
        THREE_SIXTEEN_BIT_LIMB_CAPACITY,
        resolved_moduli.len(),
        unsupported_three_limb_moduli.len(),
        unsupported_three_limb_moduli,
    );
}
